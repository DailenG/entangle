//! Versioned NDJSON control connections for handshakes and state-sync offers.
//!
//! This module knows only the wire protocol and TCP. It deliberately does not
//! discover peers or start payload transfers; those remain orchestrator work.

use async_trait::async_trait;
use entangle_core::{Manifest, RelayTicket, StateKind};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, time::Duration};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

/// Maximum number of bytes accepted in a single newline-terminated frame.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
const FRAME_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// Control protocol message encoded as one JSON object per line.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Frame {
    /// Initial exchange of capability manifests.
    Hello {
        /// Local particle manifest.
        manifest: Manifest,
    },
    /// Announces a payload and its one-time croc access details.
    SyncOffer {
        /// Sender's particle identity.
        from: entangle_core::ParticleId,
        /// Unique transfer identifier.
        sync_id: String,
        /// Maximum time allowed for the payload transfer, in seconds.
        timeout_secs: u64,
        /// Payload format.
        kind: StateKind,
        /// Safe leaf filename.
        name: String,
        /// Payload length in bytes.
        size: u64,
        /// Lowercase SHA-256 digest.
        sha256: String,
        /// Optional human-readable description.
        label: Option<String>,
        /// Reachable local croc relay details.
        relay: RelayTicket,
        /// One-time payload secret.
        secret: String,
    },
    /// Receiver agrees to accept the offered payload.
    SyncAccept {
        /// Transfer identifier.
        sync_id: String,
    },
    /// Receiver declines the offered payload.
    SyncReject {
        /// Transfer identifier.
        sync_id: String,
        /// Human-readable rejection reason.
        reason: String,
    },
    /// Receiver verified the payload hash and size.
    SyncComplete {
        /// Transfer identifier.
        sync_id: String,
        /// Verified SHA-256 digest.
        sha256: String,
    },
    /// Receiver or sender failed to complete the state sync.
    SyncFailed {
        /// Transfer identifier.
        sync_id: String,
        /// Human-readable failure reason.
        reason: String,
    },
}

/// State-sync offer contents excluding the serde enum wrapper.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncOffer {
    /// Sender's particle identity.
    pub from: entangle_core::ParticleId,
    /// Unique transfer identifier.
    pub sync_id: String,
    /// Maximum time allowed for the payload transfer, in seconds.
    pub timeout_secs: u64,
    /// Payload format.
    pub kind: StateKind,
    /// Safe leaf filename.
    pub name: String,
    /// Payload length in bytes.
    pub size: u64,
    /// Lowercase SHA-256 digest.
    pub sha256: String,
    /// Optional human-readable description.
    pub label: Option<String>,
    /// Reachable local croc relay details.
    pub relay: RelayTicket,
    /// One-time payload secret.
    pub secret: String,
}

impl From<SyncOffer> for Frame {
    fn from(offer: SyncOffer) -> Self {
        Self::SyncOffer {
            from: offer.from,
            sync_id: offer.sync_id,
            timeout_secs: offer.timeout_secs,
            kind: offer.kind,
            name: offer.name,
            size: offer.size,
            sha256: offer.sha256,
            label: offer.label,
            relay: offer.relay,
            secret: offer.secret,
        }
    }
}

/// Result of receiver-side validation of an incoming offer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncDecision {
    /// Allow transfer after starting the receiver-side payload operation.
    Accept,
    /// Refuse the offer with a useful explanation.
    Reject(String),
}

/// Response to a completed sender-side offer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OfferOutcome {
    /// The receiver reports successful hash verification.
    Complete { sha256: String },
    /// The receiver rejected or failed the transfer.
    Failed(String),
}

/// Errors arising from TCP connections, framing, or peer responses.
#[derive(Debug, Error)]
pub enum LinkError {
    /// TCP or I/O operation failed.
    #[error("link I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A frame exceeded the protocol maximum.
    #[error("link frame exceeds {MAX_FRAME_BYTES} bytes")]
    Oversize,
    /// A frame did not contain valid JSON.
    #[error("invalid link frame: {0}")]
    Json(#[from] serde_json::Error),
    /// The peer sent a frame inappropriate for the current exchange.
    #[error("unexpected link frame: {0}")]
    Unexpected(String),
    /// A link operation exceeded its deadline.
    #[error("link operation timed out")]
    Timeout,
    /// An application handler rejected or failed an operation.
    #[error("{0}")]
    Handler(String),
}

/// Receiver hooks invoked by a link listener without transport coupling.
#[async_trait]
pub trait LinkHandler: Send + Sync + 'static {
    /// Validates an incoming manifest and returns this particle's manifest.
    async fn on_hello(
        &self,
        peer_addr: SocketAddr,
        manifest: Manifest,
    ) -> Result<Manifest, LinkError>;

    /// Validates an incoming offer before the listener acknowledges it.
    async fn on_offer(
        &self,
        peer_addr: SocketAddr,
        offer: SyncOffer,
    ) -> Result<SyncDecision, LinkError>;

    /// Runs the receiver payload operation after its offer was accepted.
    async fn on_accepted(&self, peer_addr: SocketAddr, offer: SyncOffer) -> Result<String, String>;
}

/// Bound TCP listener for short-lived control connections.
pub struct LinkListener {
    listener: TcpListener,
}

impl LinkListener {
    /// Binds a TCP listener and returns its actual port.
    pub async fn bind(addr: SocketAddr) -> Result<(Self, u16), LinkError> {
        let listener = TcpListener::bind(addr).await?;
        let port = listener.local_addr()?.port();
        Ok((Self { listener }, port))
    }

    /// Accepts peers indefinitely and dispatches each connection independently.
    pub async fn run(self, handler: std::sync::Arc<dyn LinkHandler>) -> Result<(), LinkError> {
        loop {
            let (stream, peer_addr) = self.listener.accept().await?;
            let handler = std::sync::Arc::clone(&handler);
            tokio::spawn(async move {
                let _ = serve_connection(stream, peer_addr, handler).await;
            });
        }
    }
}

/// Connects to a peer and exchanges manifests, returning the peer manifest.
pub async fn handshake(
    addr: SocketAddr,
    manifest: &Manifest,
    duration: Duration,
) -> Result<Manifest, LinkError> {
    let exchange = async {
        let mut stream = TcpStream::connect(addr).await?;
        write_frame(
            &mut stream,
            &Frame::Hello {
                manifest: manifest.clone(),
            },
        )
        .await?;
        match read_frame(&mut stream).await? {
            Frame::Hello { manifest } => Ok(manifest),
            frame => Err(LinkError::Unexpected(format!("{frame:?}"))),
        }
    };
    timeout(duration, exchange)
        .await
        .map_err(|_| LinkError::Timeout)?
}

/// Sends a sync offer and waits for the receiver's verified completion.
pub async fn offer(
    addr: SocketAddr,
    offer: SyncOffer,
    duration: Duration,
) -> Result<OfferOutcome, LinkError> {
    offer_with_idle_timeout(addr, offer, duration, FRAME_IDLE_TIMEOUT).await
}

async fn offer_with_idle_timeout(
    addr: SocketAddr,
    offer: SyncOffer,
    duration: Duration,
    idle_timeout: Duration,
) -> Result<OfferOutcome, LinkError> {
    let exchange = async {
        let mut stream = TcpStream::connect(addr).await?;
        let sync_id = offer.sync_id.clone();
        write_frame(&mut stream, &offer.clone().into()).await?;
        match read_frame_within(&mut stream, idle_timeout).await? {
            Frame::SyncAccept { sync_id: accepted } if accepted == sync_id => {}
            Frame::SyncReject {
                sync_id: rejected,
                reason,
            } if rejected == sync_id => {
                return Ok(OfferOutcome::Failed(reason));
            }
            frame => return Err(LinkError::Unexpected(format!("{frame:?}"))),
        }
        match read_frame_within(&mut stream, duration).await? {
            Frame::SyncComplete {
                sync_id: completed,
                sha256,
            } if completed == sync_id => Ok(OfferOutcome::Complete { sha256 }),
            Frame::SyncFailed {
                sync_id: failed,
                reason,
            } if failed == sync_id => Ok(OfferOutcome::Failed(reason)),
            frame => Err(LinkError::Unexpected(format!("{frame:?}"))),
        }
    };
    timeout(duration, exchange)
        .await
        .map_err(|_| LinkError::Timeout)?
}

async fn serve_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    handler: std::sync::Arc<dyn LinkHandler>,
) -> Result<(), LinkError> {
    match read_frame(&mut stream).await? {
        Frame::Hello { manifest } => {
            let own = handler.on_hello(peer_addr, manifest).await?;
            write_frame(&mut stream, &Frame::Hello { manifest: own }).await
        }
        Frame::SyncOffer {
            from,
            sync_id,
            timeout_secs,
            kind,
            name,
            size,
            sha256,
            label,
            relay,
            secret,
        } => {
            let offer = SyncOffer {
                from,
                sync_id: sync_id.clone(),
                timeout_secs,
                kind,
                name,
                size,
                sha256,
                label,
                relay,
                secret,
            };
            match handler.on_offer(peer_addr, offer.clone()).await? {
                SyncDecision::Reject(reason) => {
                    write_frame(&mut stream, &Frame::SyncReject { sync_id, reason }).await
                }
                SyncDecision::Accept => {
                    write_frame(
                        &mut stream,
                        &Frame::SyncAccept {
                            sync_id: sync_id.clone(),
                        },
                    )
                    .await?;
                    match handler.on_accepted(peer_addr, offer).await {
                        Ok(sha256) => {
                            write_frame(&mut stream, &Frame::SyncComplete { sync_id, sha256 }).await
                        }
                        Err(reason) => {
                            write_frame(&mut stream, &Frame::SyncFailed { sync_id, reason }).await
                        }
                    }
                }
            }
        }
        frame => Err(LinkError::Unexpected(format!("{frame:?}"))),
    }
}

/// Writes a length-bounded newline-terminated JSON frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
) -> Result<(), LinkError> {
    let mut bytes = serde_json::to_vec(frame)?;
    if bytes.len() + 1 > MAX_FRAME_BYTES {
        return Err(LinkError::Oversize);
    }
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads a bounded newline-terminated JSON frame.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame, LinkError> {
    read_frame_within(reader, FRAME_IDLE_TIMEOUT).await
}

async fn read_frame_within<R: AsyncRead + Unpin>(
    reader: &mut R,
    idle_timeout: Duration,
) -> Result<Frame, LinkError> {
    let mut bytes = Vec::with_capacity(1024);
    loop {
        // Read one byte at a time so an untrusted peer cannot allocate an unbounded line.
        if bytes.len() >= MAX_FRAME_BYTES {
            return Err(LinkError::Oversize);
        }
        let mut byte = [0_u8; 1];
        let read = timeout(idle_timeout, reader.read(&mut byte))
            .await
            .map_err(|_| LinkError::Timeout)??;
        if read == 0 {
            return Err(LinkError::Unexpected(
                "connection closed before frame".into(),
            ));
        }
        if byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_core::{ParticleId, StateKind, PROTOCOL_VERSION};
    use std::sync::Arc;

    fn manifest() -> Manifest {
        Manifest {
            particle_id: ParticleId::generate(),
            name: "test".into(),
            version: "0.1.0".into(),
            protocol: PROTOCOL_VERSION,
            link_port: 0,
            context: None,
            tools: vec![],
            accepts: vec![StateKind::Json],
            max_payload_bytes: 1024,
        }
    }

    struct Handler(Manifest);

    #[async_trait]
    impl LinkHandler for Handler {
        async fn on_hello(
            &self,
            _peer_addr: SocketAddr,
            _manifest: Manifest,
        ) -> Result<Manifest, LinkError> {
            Ok(self.0.clone())
        }
        async fn on_offer(
            &self,
            _peer_addr: SocketAddr,
            _offer: SyncOffer,
        ) -> Result<SyncDecision, LinkError> {
            Ok(SyncDecision::Reject("test".into()))
        }
        async fn on_accepted(
            &self,
            _peer_addr: SocketAddr,
            _offer: SyncOffer,
        ) -> Result<String, String> {
            Err("not expected".into())
        }
    }

    #[tokio::test]
    async fn frame_codec_roundtrip() {
        let frame = Frame::SyncOffer {
            from: ParticleId::generate(),
            sync_id: "sync".into(),
            timeout_secs: 120,
            kind: StateKind::Json,
            name: "payload.json".into(),
            size: 3,
            sha256: "abc".into(),
            label: None,
            relay: RelayTicket {
                host: "127.0.0.1".into(),
                port: 9109,
                password: "private".into(),
            },
            secret: "secret".into(),
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).await.unwrap();
        assert_eq!(read_frame(&mut bytes.as_slice()).await.unwrap(), frame);
    }

    #[tokio::test]
    async fn oversize_frame_is_rejected() {
        let bytes = vec![b'x'; MAX_FRAME_BYTES + 1];
        assert!(matches!(
            read_frame(&mut bytes.as_slice()).await,
            Err(LinkError::Oversize)
        ));
    }

    #[tokio::test]
    async fn handshake_over_loopback() {
        let (listener, port) = LinkListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let expected = manifest();
        tokio::spawn(listener.run(Arc::new(Handler(expected.clone()))));
        let peer = handshake(
            SocketAddr::from(([127, 0, 0, 1], port)),
            &manifest(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(peer, expected);
    }

    struct DelayedAcceptHandler(Manifest);

    #[async_trait]
    impl LinkHandler for DelayedAcceptHandler {
        async fn on_hello(
            &self,
            _peer_addr: SocketAddr,
            _manifest: Manifest,
        ) -> Result<Manifest, LinkError> {
            Ok(self.0.clone())
        }

        async fn on_offer(
            &self,
            _peer_addr: SocketAddr,
            _offer: SyncOffer,
        ) -> Result<SyncDecision, LinkError> {
            Ok(SyncDecision::Accept)
        }

        async fn on_accepted(
            &self,
            _peer_addr: SocketAddr,
            _offer: SyncOffer,
        ) -> Result<String, String> {
            tokio::time::sleep(Duration::from_millis(80)).await;
            Ok("digest".into())
        }
    }

    #[tokio::test]
    async fn offer_completion_uses_overall_timeout_after_accept() {
        let (listener, port) = LinkListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        tokio::spawn(listener.run(Arc::new(DelayedAcceptHandler(manifest()))));
        let outcome = offer_with_idle_timeout(
            SocketAddr::from(([127, 0, 0, 1], port)),
            SyncOffer {
                from: ParticleId::generate(),
                sync_id: "slow-sync".into(),
                timeout_secs: 1,
                kind: StateKind::Json,
                name: "payload.json".into(),
                size: 2,
                sha256: "digest".into(),
                label: None,
                relay: RelayTicket {
                    host: "127.0.0.1".into(),
                    port: 9109,
                    password: "private".into(),
                },
                secret: "secret".into(),
            },
            Duration::from_secs(1),
            Duration::from_millis(20),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            OfferOutcome::Complete {
                sha256: "digest".into()
            }
        );
    }
}
