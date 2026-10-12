//! Noise-protected control frames and bounded state-sync payload streams.

use async_trait::async_trait;
use entangle_core::{GroupUpdate, Manifest, Member, ParticleId, StateKind};
use entangle_transport::{
    self, KeyRing, SecureStream, SharedKeyRing, TransportError, MAX_PLAINTEXT,
};
pub use entangle_transport::{BoxedIo, LinkIo};
use serde::{Deserialize, Serialize};
use std::{fmt, io, net::SocketAddr, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::TcpListener,
    time::timeout,
};

/// Maximum size of a serialized JSON control frame.
pub const MAX_FRAME_BYTES: usize = 60 * 1024;
const FRAME_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MIN_TIMEOUT_SECS: u64 = 5;
const MAX_TIMEOUT_SECS: u64 = 3600;

/// Opens fresh byte streams to a peer through a tunnel.
#[async_trait]
pub trait TunnelOpener: Send + Sync + 'static {
    /// Opens a fresh byte stream to the peer (e.g. through the Quantum Repeater).
    async fn open(&self) -> io::Result<BoxedIo>;
    /// Short human description for logs, e.g. "repeater wss://host".
    fn describe(&self) -> String;
}

/// A direct TCP connection or a stream opened by a tunnel.
#[derive(Clone)]
pub enum Route {
    /// Connect directly to the peer over TCP.
    Direct(SocketAddr),
    /// Open a fresh stream through a tunnel.
    Tunnel(Arc<dyn TunnelOpener>),
}

impl fmt::Debug for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct(addr) => f.debug_tuple("Direct").field(addr).finish(),
            Self::Tunnel(opener) => f.debug_tuple("Tunnel").field(&opener.describe()).finish(),
        }
    }
}

/// One authenticated remote endpoint and its Noise identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerInfo {
    /// TCP address for a direct connection.
    pub addr: SocketAddr,
    /// Authenticated remote Noise static public key.
    pub remote_static: [u8; 32],
    /// Group ID authenticated by this Noise session.
    pub group: [u8; 4],
    /// Whether this connection arrived through a tunnel.
    pub relayed: bool,
    /// Group key epoch negotiated by the Noise transport.
    pub epoch: u32,
}

/// Control protocol message; each frame is one encrypted Noise message.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Frame {
    /// Initial exchange of capability manifests.
    Hello {
        /// Local particle manifest.
        manifest: Manifest,
    },
    /// Introduces members vouched for by the authenticated sender.
    Introduce {
        /// Membership records added by the sender, excluding the recipient.
        members: Vec<Member>,
    },
    /// Acknowledges how many introduced members were newly stored.
    IntroduceAck {
        /// Number of records newly added.
        added: u32,
    },
    /// Signed group update history needed to reach this link's key epoch.
    GroupUpdates { updates: Vec<GroupUpdate> },
    /// Acknowledges the last applied group update epoch.
    GroupUpdatesAck { epoch: u32 },
    /// Requests removal of the authenticated sender from this group.
    Leave,
    /// Acknowledges a leave notice.
    LeaveAck,
    /// Announces a payload to the receiver.
    SyncOffer {
        /// Sender's particle identity.
        from: ParticleId,
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
    pub from: ParticleId,
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

/// Errors arising from encrypted connections, framing, or payload size checks.
#[derive(Debug, Error)]
pub enum LinkError {
    /// Link or source I/O failed.
    #[error("link I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Noise handshake or transport failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
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
    /// Source or received payload length differed from the offer.
    #[error("payload size mismatch: expected {expected} bytes, got {actual}")]
    PayloadSize { expected: u64, actual: u64 },
    /// The peer failed an application operation.
    #[error("{0}")]
    Handler(String),
    /// The update chain was applied; the connection must be redialed at the new epoch.
    #[error("group key epoch changed; reload keys and redial")]
    Stale,
}

/// Reader for the exact-size raw payload following an accepted offer.
pub struct PayloadReader<'a> {
    stream: &'a mut SecureStream,
    size: u64,
    received: u64,
}

impl<'a> PayloadReader<'a> {
    fn new(stream: &'a mut SecureStream, size: u64) -> Self {
        Self {
            stream,
            size,
            received: 0,
        }
    }

    /// Reads one encrypted payload chunk, returning `None` after exactly `size` bytes.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        if self.received == self.size {
            return Ok(None);
        }
        let chunk = self.stream.recv(FRAME_IDLE_TIMEOUT).await?;
        let actual = self.received.saturating_add(chunk.len() as u64);
        if chunk.is_empty() || actual > self.size {
            return Err(LinkError::PayloadSize {
                expected: self.size,
                actual,
            });
        }
        self.received = actual;
        Ok(Some(chunk))
    }

    fn is_complete(&self) -> bool {
        self.received == self.size
    }
}

/// Receiver hooks invoked by a link listener.
#[async_trait]
pub trait LinkHandler: Send + Sync + 'static {
    /// Validates an incoming manifest and returns this particle's manifest.
    async fn on_hello(&self, peer: &PeerInfo, manifest: Manifest) -> Result<Manifest, LinkError>;

    /// Returns members this particle added in the authenticated group.
    fn members_to_introduce(
        &self,
        _peer: &PeerInfo,
        _recipient: &ParticleId,
    ) -> Result<Vec<Member>, LinkError> {
        Ok(Vec::new())
    }

    /// Validates an incoming offer before the listener acknowledges it.
    async fn on_offer(&self, peer: &PeerInfo, offer: SyncOffer) -> Result<SyncDecision, LinkError>;

    /// Consumes the offered payload after the receiver has accepted it.
    async fn on_accepted(
        &self,
        peer: &PeerInfo,
        offer: SyncOffer,
        payload: &mut PayloadReader<'_>,
    ) -> Result<String, String>;

    /// Validates and stores one-hop member introductions.
    async fn on_introduce(
        &self,
        _peer: &PeerInfo,
        _sender: &ParticleId,
        _members: Vec<Member>,
    ) -> Result<u32, LinkError> {
        Ok(0)
    }

    /// Returns this particle's current group epoch.
    fn group_epoch(&self, _peer: &PeerInfo) -> u32 {
        0
    }

    /// Enables the signed-update prelude for this link handler.
    fn supports_group_updates(&self) -> bool {
        false
    }

    /// Returns the authenticated current member associated with this peer.
    fn peer_particle_id(&self, _peer: &PeerInfo) -> Option<ParticleId> {
        None
    }

    /// Returns signed updates after the given epoch for a current member.
    fn updates_since(&self, _peer: &PeerInfo, _epoch: u32) -> Vec<GroupUpdate> {
        Vec::new()
    }

    /// Applies updates relayed by an authenticated current member.
    fn on_updates(
        &self,
        _peer: &PeerInfo,
        _sender: &ParticleId,
        _updates: Vec<GroupUpdate>,
    ) -> Result<u32, LinkError> {
        Ok(self.group_epoch(_peer))
    }

    /// Handles a leave notice from an authenticated current member.
    fn on_leave(&self, _peer: &PeerInfo, _sender: &ParticleId) -> Result<(), LinkError> {
        Ok(())
    }

    /// Records a peer that acknowledged a signed update epoch.
    fn on_updates_ack(&self, _peer: &PeerInfo, _epoch: u32) {}

    /// Records that a peer completed a link at its current signed update epoch.
    fn on_link_epoch(&self, _peer: &PeerInfo, _epoch: u32) {}
}

/// Bound TCP listener for short-lived encrypted control connections.
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

    /// Accepts peers and completes each Noise handshake in its own task.
    pub async fn run(
        self,
        keys: SharedKeyRing,
        handler: Arc<dyn LinkHandler>,
    ) -> Result<(), LinkError> {
        loop {
            let (stream, addr) = self.listener.accept().await?;
            let keys = Arc::clone(&keys);
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let _ = serve_io(Box::new(stream), addr, false, keys, handler).await;
            });
        }
    }
}

/// Accepts one byte stream and serves an authenticated link over it.
pub async fn serve_io(
    io: BoxedIo,
    peer_addr: SocketAddr,
    relayed: bool,
    keys: SharedKeyRing,
    handler: Arc<dyn LinkHandler>,
) -> Result<(), LinkError> {
    let current = current_keys(&keys)?;
    let mut stream = entangle_transport::accept_io(io, &current, HANDSHAKE_TIMEOUT).await?;
    let peer = PeerInfo {
        addr: peer_addr,
        remote_static: stream.remote_static(),
        group: stream.group_id(),
        relayed,
        epoch: stream.epoch(),
    };
    if handler.supports_group_updates() {
        synchronize_updates(&mut stream, &peer, handler.as_ref()).await?;
    }
    serve_connection(stream, peer, handler).await
}

/// Opens a route and completes only the Noise handshake, without sending Hello.
pub async fn connect_secure(
    route: &Route,
    keys: SharedKeyRing,
    group_id: [u8; 4],
    duration: Duration,
) -> Result<SecureStream, LinkError> {
    let keys = current_keys(&keys)?;
    timeout(duration, connect_route(route, &keys, group_id, duration))
        .await
        .map_err(|_| LinkError::Timeout)?
}

/// Opens a route and exchanges any necessary signed group updates.
pub async fn connect_secure_with_handler(
    route: &Route,
    keys: SharedKeyRing,
    group_id: [u8; 4],
    handler: &dyn LinkHandler,
    duration: Duration,
) -> Result<SecureStream, LinkError> {
    let keys = current_keys(&keys)?;
    timeout(duration, async {
        let mut stream = connect_route(route, &keys, group_id, duration).await?;
        let peer = PeerInfo {
            addr: match route {
                Route::Direct(addr) => *addr,
                Route::Tunnel(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
            },
            remote_static: stream.remote_static(),
            group: stream.group_id(),
            relayed: matches!(route, Route::Tunnel(_)),
            epoch: stream.epoch(),
        };
        if handler.supports_group_updates() {
            synchronize_updates(&mut stream, &peer, handler).await?;
        }
        Ok(stream)
    })
    .await
    .map_err(|_| LinkError::Timeout)?
}

/// Connects to a peer, exchanges manifests, and returns its static key.
pub async fn handshake(
    route: &Route,
    keys: SharedKeyRing,
    group_id: [u8; 4],
    manifest: &Manifest,
    duration: Duration,
) -> Result<(Manifest, [u8; 32]), LinkError> {
    let (manifest, remote_static, _) =
        handshake_stream(route, keys, group_id, manifest, duration).await?;
    Ok((manifest, remote_static))
}

/// Connects, exchanges manifests, and returns the authenticated stream.
pub async fn handshake_stream(
    route: &Route,
    keys: SharedKeyRing,
    group_id: [u8; 4],
    manifest: &Manifest,
    duration: Duration,
) -> Result<(Manifest, [u8; 32], SecureStream), LinkError> {
    handshake_stream_inner(route, keys, group_id, manifest, duration, None).await
}

/// Connects, catches up signed group updates, and then exchanges manifests.
pub async fn handshake_stream_with_handler(
    route: &Route,
    keys: SharedKeyRing,
    group_id: [u8; 4],
    manifest: &Manifest,
    handler: &dyn LinkHandler,
    duration: Duration,
) -> Result<(Manifest, [u8; 32], SecureStream), LinkError> {
    handshake_stream_inner(route, keys, group_id, manifest, duration, Some(handler)).await
}

async fn handshake_stream_inner(
    route: &Route,
    keys: SharedKeyRing,
    group_id: [u8; 4],
    manifest: &Manifest,
    duration: Duration,
    handler: Option<&dyn LinkHandler>,
) -> Result<(Manifest, [u8; 32], SecureStream), LinkError> {
    let keys = current_keys(&keys)?;
    timeout(duration, async {
        let mut stream = connect_route(route, &keys, group_id, duration).await?;
        let peer = PeerInfo {
            addr: match route {
                Route::Direct(addr) => *addr,
                Route::Tunnel(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
            },
            remote_static: stream.remote_static(),
            group: stream.group_id(),
            relayed: matches!(route, Route::Tunnel(_)),
            epoch: stream.epoch(),
        };
        if let Some(handler) = handler.filter(|handler| handler.supports_group_updates()) {
            synchronize_updates(&mut stream, &peer, handler).await?;
        }
        write_frame(
            &mut stream,
            &Frame::Hello {
                manifest: manifest.clone(),
            },
        )
        .await?;
        match read_frame(&mut stream).await {
            Ok(Frame::Hello { manifest }) => {
                let remote_static = stream.remote_static();
                Ok((manifest, remote_static, stream))
            }
            Ok(frame) => Err(LinkError::Unexpected(format!("{frame:?}"))),
            Err(LinkError::Transport(TransportError::Io(error)))
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                ) =>
            {
                Err(LinkError::Transport(TransportError::Handshake(
                    "remote rejected the Noise group key".into(),
                )))
            }
            Err(error) => Err(error),
        }
    })
    .await
    .map_err(|_| LinkError::Timeout)?
}

async fn synchronize_updates(
    stream: &mut SecureStream,
    peer: &PeerInfo,
    handler: &dyn LinkHandler,
) -> Result<(), LinkError> {
    let local_epoch = handler.group_epoch(peer);
    let link_epoch = stream.epoch();
    let updates = if local_epoch > link_epoch {
        let updates = handler.updates_since(peer, link_epoch);
        if updates.is_empty() {
            return Err(LinkError::Stale);
        }
        oldest_updates_that_fit(updates, link_epoch)?
    } else {
        Vec::new()
    };
    write_frame(stream, &Frame::GroupUpdates { updates }).await?;
    match read_frame(stream).await? {
        Frame::GroupUpdates { updates } if !updates.is_empty() => {
            let sender = handler.peer_particle_id(peer).ok_or_else(|| {
                LinkError::Handler("update sender is not a current group member".into())
            })?;
            let epoch = handler.on_updates(peer, &sender, updates)?;
            write_frame(stream, &Frame::GroupUpdatesAck { epoch }).await?;
            Err(LinkError::Stale)
        }
        Frame::GroupUpdates { updates } if updates.is_empty() && local_epoch > link_epoch => {
            match read_frame(stream).await? {
                Frame::GroupUpdatesAck { epoch } if epoch > link_epoch && epoch <= local_epoch => {
                    handler.on_updates_ack(peer, epoch);
                    Err(LinkError::Stale)
                }
                frame => Err(LinkError::Unexpected(format!("{frame:?}"))),
            }
        }
        Frame::GroupUpdates { updates } if updates.is_empty() && local_epoch == link_epoch => {
            handler.on_link_epoch(peer, link_epoch);
            Ok(())
        }
        frame => Err(LinkError::Unexpected(format!("{frame:?}"))),
    }
}

fn oldest_updates_that_fit(
    updates: Vec<GroupUpdate>,
    link_epoch: u32,
) -> Result<Vec<GroupUpdate>, LinkError> {
    let mut selected = Vec::new();
    let mut expected_epoch = Some(
        link_epoch
            .checked_add(1)
            .ok_or_else(|| LinkError::Handler("group update epoch overflow".into()))?,
    );
    for update in updates {
        if expected_epoch != Some(update.epoch) {
            return Err(LinkError::Handler(
                "group update history is not contiguous".into(),
            ));
        }
        let mut candidate = selected.clone();
        candidate.push(update.clone());
        let frame = Frame::GroupUpdates { updates: candidate };
        if serde_json::to_vec(&frame)?.len() > MAX_FRAME_BYTES {
            if selected.is_empty() {
                return Err(LinkError::Oversize);
            }
            break;
        }
        let update_epoch = update.epoch;
        selected.push(update);
        expected_epoch = update_epoch.checked_add(1);
    }
    Ok(selected)
}

/// Opens a link, sends a sync offer, streams its declared bytes, and waits for completion.
pub async fn offer<R>(
    route: &Route,
    keys: SharedKeyRing,
    group_id: [u8; 4],
    offer: SyncOffer,
    source: R,
    duration: Duration,
) -> Result<OfferOutcome, LinkError>
where
    R: AsyncRead + Unpin + Send,
{
    let stream = connect_secure(route, keys, group_id, duration).await?;
    offer_on(stream, offer, source, duration).await
}

/// Sends a sync offer over an already-authenticated link stream.
pub async fn offer_on<R>(
    mut stream: SecureStream,
    offer: SyncOffer,
    mut source: R,
    duration: Duration,
) -> Result<OfferOutcome, LinkError>
where
    R: AsyncRead + Unpin + Send,
{
    timeout(duration, async {
        let sync_id = offer.sync_id.clone();
        let size = offer.size;
        write_frame(&mut stream, &offer.into()).await?;
        match read_frame(&mut stream).await? {
            Frame::SyncAccept { sync_id: accepted } if accepted == sync_id => {}
            Frame::SyncReject {
                sync_id: rejected,
                reason,
            } if rejected == sync_id => return Ok(OfferOutcome::Failed(reason)),
            frame => return Err(LinkError::Unexpected(format!("{frame:?}"))),
        }

        send_payload(&mut stream, &mut source, size).await?;
        match read_frame(&mut stream).await? {
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
    })
    .await
    .map_err(|_| LinkError::Timeout)?
}

/// Exchanges member introductions on an authenticated outbound Hello stream.
pub async fn introduce_on<H: LinkHandler + ?Sized>(
    mut stream: SecureStream,
    peer: PeerInfo,
    sender: ParticleId,
    handler: &H,
    duration: Duration,
) -> Result<u32, LinkError> {
    timeout(duration, async {
        let members = handler.members_to_introduce(&peer, &sender)?;
        write_frame(&mut stream, &Frame::Introduce { members }).await?;
        let members = match read_frame(&mut stream).await? {
            Frame::Introduce { members } => members,
            frame => return Err(LinkError::Unexpected(format!("{frame:?}"))),
        };
        let added = handler.on_introduce(&peer, &sender, members).await?;
        write_frame(&mut stream, &Frame::IntroduceAck { added }).await?;
        match read_frame(&mut stream).await? {
            Frame::IntroduceAck { added } => Ok(added),
            frame => Err(LinkError::Unexpected(format!("{frame:?}"))),
        }
    })
    .await
    .map_err(|_| LinkError::Timeout)?
}

/// Sends a leave notice and waits for the authenticated member's acknowledgement.
pub async fn leave_on(mut stream: SecureStream, duration: Duration) -> Result<(), LinkError> {
    timeout(duration, async {
        write_frame(&mut stream, &Frame::Leave).await?;
        match read_frame(&mut stream).await? {
            Frame::LeaveAck => Ok(()),
            frame => Err(LinkError::Unexpected(format!("{frame:?}"))),
        }
    })
    .await
    .map_err(|_| LinkError::Timeout)?
}

async fn connect_route(
    route: &Route,
    keys: &KeyRing,
    group_id: [u8; 4],
    duration: Duration,
) -> Result<SecureStream, LinkError> {
    match route {
        Route::Direct(addr) => {
            Ok(entangle_transport::connect(*addr, keys, group_id, duration).await?)
        }
        Route::Tunnel(opener) => {
            let io = opener.open().await?;
            Ok(entangle_transport::connect_io(io, keys, group_id, duration).await?)
        }
    }
}

fn current_keys(keys: &SharedKeyRing) -> Result<Arc<KeyRing>, LinkError> {
    Ok(keys
        .read()
        .map_err(|_| LinkError::Handler("link key ring lock is poisoned".into()))?
        .clone())
}

async fn send_payload<R: AsyncRead + Unpin>(
    stream: &mut SecureStream,
    source: &mut R,
    size: u64,
) -> Result<(), LinkError> {
    let mut sent = 0_u64;
    while sent < size {
        let length = MAX_PLAINTEXT.min((size - sent).min(usize::MAX as u64) as usize);
        let mut chunk = vec![0_u8; length];
        let mut filled = 0;
        while filled < length {
            let count = source.read(&mut chunk[filled..]).await?;
            if count == 0 {
                return Err(LinkError::PayloadSize {
                    expected: size,
                    actual: sent + filled as u64,
                });
            }
            filled += count;
        }
        stream.send(&chunk).await?;
        sent += length as u64;
    }
    Ok(())
}

async fn serve_connection(
    mut stream: SecureStream,
    peer: PeerInfo,
    handler: std::sync::Arc<dyn LinkHandler>,
) -> Result<(), LinkError> {
    match read_frame(&mut stream).await? {
        Frame::Leave => {
            let sender = handler.peer_particle_id(&peer).ok_or_else(|| {
                LinkError::Handler("leave sender is not a current group member".into())
            })?;
            handler.on_leave(&peer, &sender)?;
            write_frame(&mut stream, &Frame::LeaveAck).await
        }
        Frame::Hello { manifest } => {
            let sender = manifest.particle_id.clone();
            let own = handler.on_hello(&peer, manifest).await?;
            let members = handler.members_to_introduce(&peer, &sender)?;
            write_frame(&mut stream, &Frame::Hello { manifest: own }).await?;
            timeout(Duration::from_secs(5), async {
                write_frame(&mut stream, &Frame::Introduce { members }).await?;
                let members = match read_frame(&mut stream).await {
                    Ok(Frame::Introduce { members }) => members,
                    Ok(frame) => return Err(LinkError::Unexpected(format!("{frame:?}"))),
                    Err(LinkError::Transport(TransportError::Io(error)))
                        if matches!(
                            error.kind(),
                            io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        return Ok(())
                    }
                    Err(error) => return Err(error),
                };
                let added = handler.on_introduce(&peer, &sender, members).await?;
                write_frame(&mut stream, &Frame::IntroduceAck { added }).await?;
                match read_frame(&mut stream).await {
                    Ok(Frame::IntroduceAck { .. }) => Ok(()),
                    Ok(frame) => Err(LinkError::Unexpected(format!("{frame:?}"))),
                    Err(LinkError::Transport(TransportError::Io(error)))
                        if matches!(
                            error.kind(),
                            io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            })
            .await
            .map_err(|_| LinkError::Timeout)?
        }
        frame => match offer_from_frame(frame) {
            Ok(offer) => serve_offer(&mut stream, &peer, &handler, offer).await,
            Err(frame) => Err(LinkError::Unexpected(format!("{frame:?}"))),
        },
    }
}

fn offer_from_frame(frame: Frame) -> Result<SyncOffer, Box<Frame>> {
    match frame {
        Frame::SyncOffer {
            from,
            sync_id,
            timeout_secs,
            kind,
            name,
            size,
            sha256,
            label,
        } => Ok(SyncOffer {
            from,
            sync_id,
            timeout_secs,
            kind,
            name,
            size,
            sha256,
            label,
        }),
        frame => Err(Box::new(frame)),
    }
}

async fn serve_offer(
    stream: &mut SecureStream,
    peer: &PeerInfo,
    handler: &std::sync::Arc<dyn LinkHandler>,
    offer: SyncOffer,
) -> Result<(), LinkError> {
    let sync_id = offer.sync_id.clone();
    match handler.on_offer(peer, offer.clone()).await? {
        SyncDecision::Reject(reason) => {
            write_frame(stream, &Frame::SyncReject { sync_id, reason }).await
        }
        SyncDecision::Accept => {
            write_frame(
                stream,
                &Frame::SyncAccept {
                    sync_id: sync_id.clone(),
                },
            )
            .await?;
            let duration =
                Duration::from_secs(offer.timeout_secs.clamp(MIN_TIMEOUT_SECS, MAX_TIMEOUT_SECS));
            let result = {
                let mut payload = PayloadReader::new(stream, offer.size);
                match timeout(duration, handler.on_accepted(peer, offer, &mut payload)).await {
                    Ok(Ok(hash)) if payload.is_complete() => Ok(hash),
                    Ok(Ok(_)) => Err("payload ended before the offered size".to_owned()),
                    Ok(Err(reason)) => Err(reason),
                    Err(_) => Err("payload transfer timed out".to_owned()),
                }
            };
            match result {
                Ok(sha256) => write_frame(stream, &Frame::SyncComplete { sync_id, sha256 }).await,
                Err(reason) => write_frame(stream, &Frame::SyncFailed { sync_id, reason }).await,
            }
        }
    }
}

/// Writes one JSON control frame as a single encrypted message.
pub async fn write_frame(stream: &mut SecureStream, frame: &Frame) -> Result<(), LinkError> {
    let bytes = serde_json::to_vec(frame)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(LinkError::Oversize);
    }
    stream.send(&bytes).await?;
    Ok(())
}

/// Reads one bounded JSON control frame from an encrypted stream.
pub async fn read_frame(stream: &mut SecureStream) -> Result<Frame, LinkError> {
    let bytes = stream.recv(FRAME_IDLE_TIMEOUT).await?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(LinkError::Oversize);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_core::{GroupUpdate, ParticleId, UpdateKind, PROTOCOL_VERSION};
    use sha2::{Digest, Sha256};
    use std::{
        collections::{BTreeMap, HashMap},
        sync::atomic::{AtomicU32, Ordering},
        sync::{Arc, Mutex, RwLock},
    };

    const GROUP: [u8; 4] = [0x42; 4];

    fn manifest() -> Manifest {
        Manifest {
            particle_id: ParticleId::generate(),
            name: "test".into(),
            version: "0.2.0".into(),
            protocol: PROTOCOL_VERSION,
            link_port: 0,
            context: None,
            tools: vec![],
            accepts: vec![StateKind::Json, StateKind::File],
            max_payload_bytes: 1024 * 1024,
        }
    }

    fn keys() -> KeyRing {
        KeyRing {
            static_private: entangle_transport::generate_static(),
            groups: HashMap::from([(
                GROUP,
                entangle_transport::GroupKeys {
                    current: 0,
                    keys: BTreeMap::from([(0, [0x33; 32])]),
                },
            )]),
        }
    }

    fn key_slot(keys: &KeyRing) -> SharedKeyRing {
        Arc::new(RwLock::new(Arc::new(keys.clone())))
    }

    struct AcceptingHandler {
        manifest: Manifest,
        received: Arc<Mutex<Vec<u8>>>,
        relayed: Arc<Mutex<Vec<bool>>>,
    }

    fn accepting_handler(manifest: Manifest, received: Arc<Mutex<Vec<u8>>>) -> AcceptingHandler {
        AcceptingHandler {
            manifest,
            received,
            relayed: Arc::new(Mutex::new(Vec::new())),
        }
    }

    struct CatchUpHandler {
        manifest: Manifest,
        particle_id: ParticleId,
        epoch: AtomicU32,
        updates: Vec<GroupUpdate>,
        received_updates: Mutex<Vec<GroupUpdate>>,
        acknowledged: Mutex<Vec<u32>>,
    }

    fn group_update(epoch: u32) -> GroupUpdate {
        GroupUpdate {
            group_id: "42424242".into(),
            epoch,
            key_hex: "44".repeat(32),
            admin: "admin".into(),
            admin_sign_key: "sign-key".into(),
            revoked: Vec::new(),
            kind: UpdateKind::Rekey,
            issued_by: "admin".into(),
            issued_at: "2026-10-12T00:00:00Z".into(),
            signature: "signature".into(),
        }
    }

    fn group_update_with_revocations(epoch: u32) -> GroupUpdate {
        let mut update = group_update(epoch);
        update.revoked = (0..40)
            .map(|_| entangle_core::Revocation {
                particle_id: ParticleId::generate().to_string(),
                static_key: "55".repeat(32),
            })
            .collect();
        update
    }

    #[async_trait]
    impl LinkHandler for CatchUpHandler {
        async fn on_hello(
            &self,
            _peer: &PeerInfo,
            _manifest: Manifest,
        ) -> Result<Manifest, LinkError> {
            Ok(self.manifest.clone())
        }

        async fn on_offer(
            &self,
            _peer: &PeerInfo,
            _offer: SyncOffer,
        ) -> Result<SyncDecision, LinkError> {
            Ok(SyncDecision::Reject("not accepted".into()))
        }

        async fn on_accepted(
            &self,
            _peer: &PeerInfo,
            _offer: SyncOffer,
            _payload: &mut PayloadReader<'_>,
        ) -> Result<String, String> {
            Err("should not be called".into())
        }

        fn group_epoch(&self, _peer: &PeerInfo) -> u32 {
            self.epoch.load(Ordering::SeqCst)
        }

        fn supports_group_updates(&self) -> bool {
            true
        }

        fn peer_particle_id(&self, _peer: &PeerInfo) -> Option<ParticleId> {
            Some(self.particle_id.clone())
        }

        fn updates_since(&self, _peer: &PeerInfo, epoch: u32) -> Vec<GroupUpdate> {
            self.updates
                .iter()
                .filter(|update| update.epoch > epoch)
                .cloned()
                .collect()
        }

        fn on_updates(
            &self,
            _peer: &PeerInfo,
            _sender: &ParticleId,
            updates: Vec<GroupUpdate>,
        ) -> Result<u32, LinkError> {
            let epoch = updates.iter().map(|update| update.epoch).max().unwrap_or(0);
            self.received_updates.lock().unwrap().extend(updates);
            self.epoch.store(epoch, Ordering::SeqCst);
            Ok(epoch)
        }

        fn on_updates_ack(&self, _peer: &PeerInfo, epoch: u32) {
            self.acknowledged.lock().unwrap().push(epoch);
        }
    }

    fn payload_hash(payload: &[u8]) -> String {
        format!("{:x}", Sha256::digest(payload))
    }

    #[async_trait]
    impl LinkHandler for AcceptingHandler {
        async fn on_hello(
            &self,
            peer: &PeerInfo,
            _manifest: Manifest,
        ) -> Result<Manifest, LinkError> {
            self.relayed.lock().unwrap().push(peer.relayed);
            Ok(self.manifest.clone())
        }

        async fn on_offer(
            &self,
            peer: &PeerInfo,
            _offer: SyncOffer,
        ) -> Result<SyncDecision, LinkError> {
            self.relayed.lock().unwrap().push(peer.relayed);
            Ok(SyncDecision::Accept)
        }

        async fn on_accepted(
            &self,
            _peer: &PeerInfo,
            _offer: SyncOffer,
            payload: &mut PayloadReader<'_>,
        ) -> Result<String, String> {
            let mut hasher = Sha256::new();
            while let Some(chunk) = payload.next_chunk().await.map_err(|e| e.to_string())? {
                hasher.update(&chunk);
                self.received.lock().unwrap().extend_from_slice(&chunk);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
    }

    struct DuplexTunnel {
        keys: SharedKeyRing,
        handler: Arc<dyn LinkHandler>,
    }

    #[async_trait]
    impl TunnelOpener for DuplexTunnel {
        async fn open(&self) -> io::Result<BoxedIo> {
            let (client, server) = tokio::io::duplex(64 * 1024);
            let keys = Arc::clone(&self.keys);
            let handler = Arc::clone(&self.handler);
            tokio::spawn(async move {
                let _ = serve_io(
                    Box::new(server),
                    SocketAddr::from(([127, 0, 0, 1], 0)),
                    true,
                    keys,
                    handler,
                )
                .await;
            });
            Ok(Box::new(client))
        }

        fn describe(&self) -> String {
            "test duplex tunnel".into()
        }
    }

    struct RejectingHandler(Manifest);

    #[async_trait]
    impl LinkHandler for RejectingHandler {
        async fn on_hello(
            &self,
            _peer: &PeerInfo,
            _manifest: Manifest,
        ) -> Result<Manifest, LinkError> {
            Ok(self.0.clone())
        }

        async fn on_offer(
            &self,
            _peer: &PeerInfo,
            _offer: SyncOffer,
        ) -> Result<SyncDecision, LinkError> {
            Ok(SyncDecision::Reject("not accepted".into()))
        }

        async fn on_accepted(
            &self,
            _peer: &PeerInfo,
            _offer: SyncOffer,
            _payload: &mut PayloadReader<'_>,
        ) -> Result<String, String> {
            Err("should not be called".into())
        }
    }

    async fn start_listener(
        key: KeyRing,
        handler: Arc<dyn LinkHandler>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let (listener, port) = LinkListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let keys = key_slot(&key);
        let task = tokio::spawn(async move {
            let _ = listener.run(keys, handler).await;
        });
        (SocketAddr::from(([127, 0, 0, 1], port)), task)
    }

    fn make_offer(size: usize) -> SyncOffer {
        SyncOffer {
            from: ParticleId::generate(),
            sync_id: "0123456789abcdef0123456789abcdef".into(),
            timeout_secs: 10,
            kind: StateKind::File,
            name: "payload.bin".into(),
            size: size as u64,
            sha256: "digest".into(),
            label: None,
        }
    }

    #[tokio::test]
    async fn handshake_and_multichunk_offer_roundtrip() {
        let key = keys();
        let received = Arc::new(Mutex::new(Vec::new()));
        let expected = manifest();
        let (address, task) = start_listener(
            key.clone(),
            Arc::new(accepting_handler(expected.clone(), Arc::clone(&received))),
        )
        .await;
        let route = Route::Direct(address);
        let (peer, remote_static) = handshake(
            &route,
            key_slot(&key),
            GROUP,
            &manifest(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(peer, expected);
        assert_ne!(remote_static, [0; 32]);

        let payload = vec![0x5a; 210 * 1024];
        let outcome = offer(
            &route,
            key_slot(&key),
            GROUP,
            make_offer(payload.len()),
            &payload[..],
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            OfferOutcome::Complete {
                sha256: payload_hash(&payload)
            }
        );
        assert_eq!(*received.lock().unwrap(), payload);
        task.abort();
    }

    #[tokio::test]
    async fn same_epoch_with_handler_completes_the_link() {
        let key = keys();
        let expected = manifest();
        let remote = Arc::new(CatchUpHandler {
            manifest: expected.clone(),
            particle_id: ParticleId::generate(),
            epoch: AtomicU32::new(0),
            updates: Vec::new(),
            received_updates: Mutex::new(Vec::new()),
            acknowledged: Mutex::new(Vec::new()),
        });
        let local = CatchUpHandler {
            manifest: manifest(),
            particle_id: ParticleId::generate(),
            epoch: AtomicU32::new(0),
            updates: Vec::new(),
            received_updates: Mutex::new(Vec::new()),
            acknowledged: Mutex::new(Vec::new()),
        };
        let (address, task) = start_listener(key.clone(), remote as Arc<dyn LinkHandler>).await;
        let (peer, _, _) = handshake_stream_with_handler(
            &Route::Direct(address),
            key_slot(&key),
            GROUP,
            &manifest(),
            &local,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(peer, expected);
        task.abort();
    }

    #[tokio::test]
    async fn behind_member_applies_updates_and_acknowledges_before_linking() {
        let group_key_0 = [0x33; 32];
        let group_key_1 = [0x44; 32];
        let mut responder_keys = keys();
        responder_keys.groups.insert(
            GROUP,
            entangle_transport::GroupKeys {
                current: 1,
                keys: BTreeMap::from([(0, group_key_0), (1, group_key_1)]),
            },
        );
        let mut initiator_keys = keys();
        initiator_keys.groups.insert(
            GROUP,
            entangle_transport::GroupKeys {
                current: 0,
                keys: BTreeMap::from([(0, group_key_0)]),
            },
        );
        let update = group_update(1);
        let responder = Arc::new(CatchUpHandler {
            manifest: manifest(),
            particle_id: ParticleId::generate(),
            epoch: AtomicU32::new(1),
            updates: vec![update.clone()],
            received_updates: Mutex::new(Vec::new()),
            acknowledged: Mutex::new(Vec::new()),
        });
        let initiator = CatchUpHandler {
            manifest: manifest(),
            particle_id: ParticleId::generate(),
            epoch: AtomicU32::new(0),
            updates: Vec::new(),
            received_updates: Mutex::new(Vec::new()),
            acknowledged: Mutex::new(Vec::new()),
        };
        let (address, task) =
            start_listener(responder_keys, responder.clone() as Arc<dyn LinkHandler>).await;
        let result = connect_secure_with_handler(
            &Route::Direct(address),
            key_slot(&initiator_keys),
            GROUP,
            &initiator,
            Duration::from_secs(2),
        )
        .await;
        assert!(matches!(result, Err(LinkError::Stale)));
        assert_eq!(*initiator.received_updates.lock().unwrap(), vec![update]);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if responder.acknowledged.lock().unwrap().contains(&1) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the ahead member should receive an update acknowledgement");
        task.abort();
    }

    #[tokio::test]
    async fn oversized_update_history_catches_up_over_multiple_links() {
        let updates = (1..=17)
            .map(group_update_with_revocations)
            .collect::<Vec<_>>();
        assert!(
            serde_json::to_vec(&Frame::GroupUpdates {
                updates: updates.clone()
            })
            .unwrap()
            .len()
                > MAX_FRAME_BYTES
        );
        let mut responder_keys = keys();
        responder_keys.groups.insert(
            GROUP,
            entangle_transport::GroupKeys {
                current: 17,
                keys: (0..=17)
                    .map(|epoch| (epoch, if epoch == 0 { [0x33; 32] } else { [0x44; 32] }))
                    .collect(),
            },
        );
        let mut initiator_keys = keys();
        initiator_keys.groups.insert(
            GROUP,
            entangle_transport::GroupKeys {
                current: 0,
                keys: BTreeMap::from([(0, [0x33; 32])]),
            },
        );
        let responder = Arc::new(CatchUpHandler {
            manifest: manifest(),
            particle_id: ParticleId::generate(),
            epoch: AtomicU32::new(17),
            updates: updates.clone(),
            received_updates: Mutex::new(Vec::new()),
            acknowledged: Mutex::new(Vec::new()),
        });
        let initiator = CatchUpHandler {
            manifest: manifest(),
            particle_id: ParticleId::generate(),
            epoch: AtomicU32::new(0),
            updates: Vec::new(),
            received_updates: Mutex::new(Vec::new()),
            acknowledged: Mutex::new(Vec::new()),
        };
        let initiator_keys = key_slot(&initiator_keys);
        let (address, task) =
            start_listener(responder_keys, responder.clone() as Arc<dyn LinkHandler>).await;
        let mut redials = 0;
        while initiator.epoch.load(Ordering::SeqCst) < 17 {
            let result = connect_secure_with_handler(
                &Route::Direct(address),
                Arc::clone(&initiator_keys),
                GROUP,
                &initiator,
                Duration::from_secs(2),
            )
            .await;
            assert!(matches!(result, Err(LinkError::Stale)));
            redials += 1;
            let epoch = initiator.epoch.load(Ordering::SeqCst);
            let mut keys = initiator_keys.write().unwrap();
            let mut updated = (**keys).clone();
            let group_keys = updated.groups.get_mut(&GROUP).unwrap();
            group_keys.current = epoch;
            group_keys.keys.insert(epoch, [0x44; 32]);
            *keys = Arc::new(updated);
        }
        assert!(redials > 1);
        assert_eq!(*initiator.received_updates.lock().unwrap(), updates);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if responder.acknowledged.lock().unwrap().len() == redials {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the ahead member should receive every partial update acknowledgement");

        let final_link = connect_secure_with_handler(
            &Route::Direct(address),
            Arc::clone(&initiator_keys),
            GROUP,
            &initiator,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        drop(final_link);
        task.abort();
    }

    #[tokio::test]
    async fn tunnel_route_handshakes_and_transfers_payload() {
        let key = keys();
        let expected = manifest();
        let received = Arc::new(Mutex::new(Vec::new()));
        let relayed = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(AcceptingHandler {
            manifest: expected.clone(),
            received: Arc::clone(&received),
            relayed: Arc::clone(&relayed),
        });
        let route = Route::Tunnel(Arc::new(DuplexTunnel {
            keys: key_slot(&key),
            handler,
        }));

        let (remote, remote_static) = handshake(
            &route,
            key_slot(&key),
            GROUP,
            &manifest(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(remote, expected);
        assert_ne!(remote_static, [0; 32]);

        let payload = vec![0x5a; 4 * 1024];
        let expected_hash = payload_hash(&payload);
        let mut sync_offer = make_offer(payload.len());
        sync_offer.sha256 = expected_hash.clone();
        let outcome = offer(
            &route,
            key_slot(&key),
            GROUP,
            sync_offer,
            &payload[..],
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        assert_eq!(
            outcome,
            OfferOutcome::Complete {
                sha256: expected_hash
            }
        );
        assert_eq!(*received.lock().unwrap(), payload);
        assert_eq!(*relayed.lock().unwrap(), vec![true, true]);
    }

    #[tokio::test]
    async fn sync_offer_after_hello_is_rejected_to_preserve_wire_compatibility() {
        let key = keys();
        let received = Arc::new(Mutex::new(Vec::new()));
        let (address, task) = start_listener(
            key.clone(),
            Arc::new(accepting_handler(manifest(), Arc::clone(&received))),
        )
        .await;
        let route = Route::Direct(address);
        let (_, _, stream) = handshake_stream(
            &route,
            key_slot(&key),
            GROUP,
            &manifest(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();

        let result = offer_on(stream, make_offer(1), &b"x"[..], Duration::from_secs(2)).await;
        assert!(result.is_err());
        assert!(received.lock().unwrap().is_empty());
        task.abort();
    }

    #[tokio::test]
    async fn source_shorter_than_offer_size_fails() {
        let key = keys();
        let received = Arc::new(Mutex::new(Vec::new()));
        let (address, task) = start_listener(
            key.clone(),
            Arc::new(accepting_handler(manifest(), received)),
        )
        .await;
        let route = Route::Direct(address);
        let result = offer(
            &route,
            key_slot(&key),
            GROUP,
            make_offer(5),
            &b"abc"[..],
            Duration::from_secs(2),
        )
        .await;
        assert!(matches!(result, Err(LinkError::PayloadSize { .. })));
        task.abort();
    }

    #[tokio::test]
    async fn sender_ignores_bytes_beyond_the_offered_size() {
        let key = keys();
        let received = Arc::new(Mutex::new(Vec::new()));
        let (address, task) = start_listener(
            key.clone(),
            Arc::new(accepting_handler(manifest(), Arc::clone(&received))),
        )
        .await;
        let route = Route::Direct(address);
        let outcome = offer(
            &route,
            key_slot(&key),
            GROUP,
            make_offer(3),
            &b"abcdef"[..],
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            OfferOutcome::Complete {
                sha256: payload_hash(b"abc")
            }
        );
        assert_eq!(*received.lock().unwrap(), b"abc".to_vec());
        task.abort();
    }

    #[tokio::test]
    async fn receiver_rejects_a_chunk_larger_than_the_offer() {
        let key = keys();
        let received = Arc::new(Mutex::new(Vec::new()));
        let (address, task) = start_listener(
            key.clone(),
            Arc::new(accepting_handler(manifest(), received)),
        )
        .await;
        let mut stream = entangle_transport::connect(address, &key, GROUP, Duration::from_secs(2))
            .await
            .unwrap();
        write_frame(&mut stream, &make_offer(2).into())
            .await
            .unwrap();
        assert!(matches!(
            read_frame(&mut stream).await.unwrap(),
            Frame::SyncAccept { .. }
        ));
        stream.send(b"abc").await.unwrap();
        assert!(matches!(
            read_frame(&mut stream).await.unwrap(),
            Frame::SyncFailed { reason, .. } if reason.contains("payload size mismatch")
        ));
        task.abort();
    }

    #[tokio::test]
    async fn reject_path_returns_the_receiver_reason() {
        let key = keys();
        let (address, task) =
            start_listener(key.clone(), Arc::new(RejectingHandler(manifest()))).await;
        let route = Route::Direct(address);
        let outcome = offer(
            &route,
            key_slot(&key),
            GROUP,
            make_offer(0),
            &b""[..],
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(outcome, OfferOutcome::Failed("not accepted".into()));
        task.abort();
    }

    #[tokio::test]
    async fn wrong_group_key_is_reported_as_a_handshake_error() {
        let server_key = keys();
        let mut client_key = server_key.clone();
        client_key
            .groups
            .get_mut(&GROUP)
            .unwrap()
            .keys
            .get_mut(&0)
            .unwrap()[0] ^= 0x80;
        let (address, task) =
            start_listener(server_key, Arc::new(RejectingHandler(manifest()))).await;
        let route = Route::Direct(address);
        let result = handshake(
            &route,
            key_slot(&client_key),
            GROUP,
            &manifest(),
            Duration::from_secs(2),
        )
        .await;
        assert!(matches!(
            result,
            Err(LinkError::Transport(TransportError::Handshake(_)))
        ));
        task.abort();
    }
}
