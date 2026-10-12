//! Noise-encrypted byte streams for Entangle links.

use snow::{
    params::DHChoice,
    resolvers::{CryptoResolver, DefaultResolver},
    Builder, HandshakeState, TransportState,
};
use std::{
    collections::{BTreeMap, HashMap},
    fmt, io,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

/// Noise pattern used to authenticate peers with a group-derived PSK.
pub const NOISE_PATTERN: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";
const MAX_MESSAGE: usize = u16::MAX as usize;
const TAG_LENGTH: usize = 16;
const PREFACE: &[u8; 4] = b"ENTG";
const PREFACE_VERSION: u8 = 2;
const ACK_CONTINUE: u8 = 0;
const ACK_RETRY_EPOCH: u8 = 1;
const ACK_TOO_FAR_BEHIND: u8 = 2;
/// Maximum plaintext bytes carried by one Noise transport message.
pub const MAX_PLAINTEXT: usize = MAX_MESSAGE - TAG_LENGTH;

/// An asynchronous, owned byte stream suitable for carrying a Noise link.
pub trait LinkIo: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> LinkIo for T {}

/// An owned byte stream that can be used by a Noise link.
pub type BoxedIo = Box<dyn LinkIo>;

/// Shared, reloadable static identity and group PSKs.
pub type SharedKeyRing = Arc<RwLock<Arc<KeyRing>>>;

/// Static Noise identity and all locally available group PSKs.
#[derive(Clone)]
pub struct KeyRing {
    /// X25519 static private key.
    pub static_private: [u8; 32],
    /// Group-ID-to-current-and-retained Noise PSKs.
    pub groups: HashMap<[u8; 4], GroupKeys>,
}

#[derive(Clone, Debug)]
pub struct GroupKeys {
    pub current: u32,
    pub keys: BTreeMap<u32, [u8; 32]>,
}

impl fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRing")
            .field("static_private", &"[REDACTED]")
            .field("groups", &format_args!("[REDACTED; {}]", self.groups.len()))
            .finish()
    }
}

/// Generates a new X25519 static private key using Snow's Noise resolver.
pub fn generate_static() -> [u8; 32] {
    let params = NOISE_PATTERN
        .parse()
        .expect("the configured Noise pattern is valid");
    let keypair = Builder::new(params)
        .generate_keypair()
        .expect("Snow's default resolver can generate an X25519 key");
    keypair
        .private
        .try_into()
        .expect("X25519 private keys are 32 bytes")
}

/// Derives the X25519 public key for a persisted static private key.
pub fn public_key(private: &[u8; 32]) -> [u8; 32] {
    let mut dh = DefaultResolver
        .resolve_dh(&DHChoice::Curve25519)
        .expect("Snow's default resolver supports X25519");
    dh.set(private);
    dh.pubkey()
        .try_into()
        .expect("X25519 public keys are 32 bytes")
}

/// Errors from Noise handshakes and encrypted byte streams.
#[derive(Debug, Error)]
pub enum TransportError {
    /// TCP or stream framing failed.
    #[error("secure stream I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Noise could not authenticate or complete a handshake.
    #[error("Noise handshake failed: {0}")]
    Handshake(String),
    /// The group preface or epoch acknowledgement was malformed.
    #[error("invalid group preface")]
    BadPreface,
    /// The requested group is not present in this key ring.
    #[error("unknown group")]
    UnknownGroup,
    /// The responder retains the group, but not this older epoch.
    #[error("local group epoch {local} is too far behind; peer is at epoch {current}")]
    TooFarBehind { local: u32, current: u32 },
    /// The responder's epoch is not retained by the initiator.
    #[error("peer group epoch {peer_epoch} is too far behind")]
    PeerTooFarBehind { peer_epoch: u32 },
    /// A Noise transport message could not be encrypted or authenticated.
    #[error("Noise transport failed: {0}")]
    Noise(String),
    /// The plaintext exceeds the maximum size of one Noise message.
    #[error("plaintext exceeds the {MAX_PLAINTEXT}-byte maximum")]
    Oversize,
    /// An operation exceeded its idle or handshake timeout.
    #[error("secure stream operation timed out")]
    Timeout,
}

/// A byte stream protected by an established Noise session.
pub struct SecureStream {
    stream: BoxedIo,
    noise: TransportState,
    remote_static: [u8; 32],
    group_id: [u8; 4],
    epoch: u32,
}

impl SecureStream {
    /// Encrypts and sends one length-prefixed Noise message.
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<(), TransportError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(TransportError::Oversize);
        }
        let mut ciphertext = vec![0_u8; plaintext.len() + TAG_LENGTH];
        let written = self
            .noise
            .write_message(plaintext, &mut ciphertext)
            .map_err(|error| TransportError::Noise(error.to_string()))?;
        write_message(&mut self.stream, &ciphertext[..written]).await?;
        Ok(())
    }

    /// Receives and decrypts one message, failing if no complete message arrives while idle.
    pub async fn recv(&mut self, idle: Duration) -> Result<Vec<u8>, TransportError> {
        let message = timeout(idle, read_message(&mut self.stream))
            .await
            .map_err(|_| TransportError::Timeout)??;
        let mut plaintext = vec![0_u8; message.len()];
        let written = self
            .noise
            .read_message(&message, &mut plaintext)
            .map_err(|error| TransportError::Noise(error.to_string()))?;
        plaintext.truncate(written);
        Ok(plaintext)
    }

    /// Returns the authenticated remote X25519 static public key.
    pub fn remote_static(&self) -> [u8; 32] {
        self.remote_static
    }

    /// Returns the group ID authenticated by this Noise session.
    pub fn group_id(&self) -> [u8; 4] {
        self.group_id
    }

    /// Returns the group key epoch used by this authenticated session.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }
}

/// Connects as a Noise initiator and completes the XXpsk3 handshake.
pub async fn connect(
    addr: SocketAddr,
    ring: &KeyRing,
    group_id: [u8; 4],
    duration: Duration,
) -> Result<SecureStream, TransportError> {
    timeout(duration, async {
        let stream = TcpStream::connect(addr).await?;
        connect_io(Box::new(stream), ring, group_id, duration).await
    })
    .await
    .map_err(|_| TransportError::Timeout)?
}

/// Completes the Noise initiator handshake over an already-open byte stream.
pub async fn connect_io(
    mut stream: BoxedIo,
    ring: &KeyRing,
    group_id: [u8; 4],
    duration: Duration,
) -> Result<SecureStream, TransportError> {
    timeout(duration, async {
        let group_keys = ring
            .groups
            .get(&group_id)
            .ok_or(TransportError::UnknownGroup)?;
        let requested_epoch = group_keys.current;
        write_preface(&mut stream, group_id, requested_epoch).await?;
        let mut ack = [0_u8; 1];
        stream.read_exact(&mut ack).await?;
        let epoch = match ack[0] {
            ACK_CONTINUE => requested_epoch,
            ACK_RETRY_EPOCH => {
                let mut epoch_bytes = [0_u8; 4];
                stream.read_exact(&mut epoch_bytes).await?;
                let epoch = u32::from_be_bytes(epoch_bytes);
                if !group_keys.keys.contains_key(&epoch) {
                    return Err(TransportError::PeerTooFarBehind { peer_epoch: epoch });
                }
                stream.write_all(&epoch.to_be_bytes()).await?;
                stream.flush().await?;
                epoch
            }
            ACK_TOO_FAR_BEHIND => {
                let mut epoch_bytes = [0_u8; 4];
                stream.read_exact(&mut epoch_bytes).await?;
                return Err(TransportError::TooFarBehind {
                    local: requested_epoch,
                    current: u32::from_be_bytes(epoch_bytes),
                });
            }
            _ => return Err(TransportError::BadPreface),
        };
        let (noise, remote_static) =
            initiator_handshake(&mut stream, ring, group_id, epoch).await?;
        Ok(SecureStream {
            stream,
            noise,
            remote_static,
            group_id,
            epoch,
        })
    })
    .await
    .map_err(|_| TransportError::Timeout)?
}

/// Accepts a TCP stream as a Noise responder and completes the XXpsk3 handshake.
pub async fn accept(
    stream: TcpStream,
    ring: &KeyRing,
    duration: Duration,
) -> Result<SecureStream, TransportError> {
    accept_io(Box::new(stream), ring, duration).await
}

/// Completes the Noise responder handshake over an already-open byte stream.
pub async fn accept_io(
    mut stream: BoxedIo,
    ring: &KeyRing,
    duration: Duration,
) -> Result<SecureStream, TransportError> {
    timeout(duration, async {
        let (group_id, requested_epoch) = read_preface(&mut stream).await?;
        let group_keys = ring
            .groups
            .get(&group_id)
            .ok_or(TransportError::UnknownGroup)?;
        let epoch = if group_keys.keys.contains_key(&requested_epoch) {
            stream.write_all(&[ACK_CONTINUE]).await?;
            stream.flush().await?;
            requested_epoch
        } else if requested_epoch > group_keys.current {
            stream.write_all(&[ACK_RETRY_EPOCH]).await?;
            stream.write_all(&group_keys.current.to_be_bytes()).await?;
            stream.flush().await?;
            let mut retry = [0_u8; 4];
            stream.read_exact(&mut retry).await?;
            let retry_epoch = u32::from_be_bytes(retry);
            if retry_epoch != group_keys.current || !group_keys.keys.contains_key(&retry_epoch) {
                return Err(TransportError::UnknownGroup);
            }
            retry_epoch
        } else if group_keys
            .keys
            .keys()
            .next()
            .is_some_and(|oldest| requested_epoch < *oldest)
        {
            stream.write_all(&[ACK_TOO_FAR_BEHIND]).await?;
            stream.write_all(&group_keys.current.to_be_bytes()).await?;
            stream.flush().await?;
            return Err(TransportError::UnknownGroup);
        } else {
            return Err(TransportError::UnknownGroup);
        };
        let (noise, remote_static) =
            responder_handshake(&mut stream, ring, group_id, epoch).await?;
        Ok(SecureStream {
            stream,
            noise,
            remote_static,
            group_id,
            epoch,
        })
    })
    .await
    .map_err(|_| TransportError::Timeout)?
}

async fn write_preface(
    stream: &mut (impl AsyncWrite + Unpin),
    group_id: [u8; 4],
    epoch: u32,
) -> Result<(), TransportError> {
    let mut preface = [0_u8; 13];
    preface[..4].copy_from_slice(PREFACE);
    preface[4] = PREFACE_VERSION;
    preface[5..9].copy_from_slice(&group_id);
    preface[9..].copy_from_slice(&epoch.to_be_bytes());
    stream.write_all(&preface).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_preface(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<([u8; 4], u32), TransportError> {
    let mut preface = [0_u8; 13];
    stream.read_exact(&mut preface).await?;
    if &preface[..4] != PREFACE || preface[4] != PREFACE_VERSION {
        return Err(TransportError::BadPreface);
    }
    Ok((
        preface[5..9]
            .try_into()
            .expect("the preface has four group-ID bytes"),
        u32::from_be_bytes(preface[9..].try_into().expect("four epoch bytes")),
    ))
}

fn handshake_state(
    ring: &KeyRing,
    group_id: [u8; 4],
    epoch: u32,
    initiator: bool,
) -> Result<HandshakeState, TransportError> {
    let params = NOISE_PATTERN
        .parse()
        .map_err(|error: snow::Error| TransportError::Handshake(error.to_string()))?;
    let psk = ring
        .groups
        .get(&group_id)
        .and_then(|keys| keys.keys.get(&epoch))
        .ok_or(TransportError::UnknownGroup)?;
    let mut prologue = b"entangle-link-v5".to_vec();
    prologue.extend_from_slice(&group_id);
    prologue.extend_from_slice(&epoch.to_be_bytes());
    let builder = Builder::new(params)
        .local_private_key(&ring.static_private)
        .map_err(|error| TransportError::Handshake(error.to_string()))?
        .psk(3, psk)
        .map_err(|error| TransportError::Handshake(error.to_string()))?
        .prologue(&prologue)
        .map_err(|error| TransportError::Handshake(error.to_string()))?;
    if initiator {
        builder
            .build_initiator()
            .map_err(|error| TransportError::Handshake(error.to_string()))
    } else {
        builder
            .build_responder()
            .map_err(|error| TransportError::Handshake(error.to_string()))
    }
}

async fn initiator_handshake(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    ring: &KeyRing,
    group_id: [u8; 4],
    epoch: u32,
) -> Result<(TransportState, [u8; 32]), TransportError> {
    let mut state = handshake_state(ring, group_id, epoch, true)?;
    let mut message = vec![0_u8; MAX_MESSAGE];
    let length = state
        .write_message(&[], &mut message)
        .map_err(|error| TransportError::Handshake(error.to_string()))?;
    write_message(stream, &message[..length])
        .await
        .map_err(handshake_io_error)?;

    let incoming = read_message(stream).await.map_err(handshake_io_error)?;
    let mut payload = vec![0_u8; MAX_MESSAGE];
    state
        .read_message(&incoming, &mut payload)
        .map_err(|error| TransportError::Handshake(error.to_string()))?;

    let length = state
        .write_message(&[], &mut message)
        .map_err(|error| TransportError::Handshake(error.to_string()))?;
    write_message(stream, &message[..length])
        .await
        .map_err(handshake_io_error)?;

    let remote_static = remote_static(&state)?;
    let noise = state
        .into_transport_mode()
        .map_err(|error| TransportError::Handshake(error.to_string()))?;
    Ok((noise, remote_static))
}

async fn responder_handshake(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    ring: &KeyRing,
    group_id: [u8; 4],
    epoch: u32,
) -> Result<(TransportState, [u8; 32]), TransportError> {
    let mut state = handshake_state(ring, group_id, epoch, false)?;
    let incoming = read_message(stream).await.map_err(handshake_io_error)?;
    let mut payload = vec![0_u8; MAX_MESSAGE];
    state
        .read_message(&incoming, &mut payload)
        .map_err(|error| TransportError::Handshake(error.to_string()))?;

    let mut message = vec![0_u8; MAX_MESSAGE];
    let length = state
        .write_message(&[], &mut message)
        .map_err(|error| TransportError::Handshake(error.to_string()))?;
    write_message(stream, &message[..length])
        .await
        .map_err(handshake_io_error)?;

    let incoming = read_message(stream).await.map_err(handshake_io_error)?;
    state
        .read_message(&incoming, &mut payload)
        .map_err(|error| TransportError::Handshake(error.to_string()))?;

    let remote_static = remote_static(&state)?;
    let noise = state
        .into_transport_mode()
        .map_err(|error| TransportError::Handshake(error.to_string()))?;
    Ok((noise, remote_static))
}

fn remote_static(state: &HandshakeState) -> Result<[u8; 32], TransportError> {
    state
        .get_remote_static()
        .ok_or_else(|| TransportError::Handshake("remote static key is missing".into()))?
        .try_into()
        .map_err(|_| TransportError::Handshake("remote static key has an invalid length".into()))
}

fn handshake_io_error(error: TransportError) -> TransportError {
    TransportError::Handshake(error.to_string())
}

async fn write_message(
    stream: &mut (impl AsyncWrite + Unpin),
    message: &[u8],
) -> Result<(), TransportError> {
    if message.len() > MAX_MESSAGE {
        return Err(TransportError::Oversize);
    }
    stream
        .write_all(&(message.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(message).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_message(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, TransportError> {
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length).await?;
    let length = usize::from(u16::from_be_bytes(length));
    let mut message = vec![0_u8; length];
    stream.read_exact(&mut message).await?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::net::TcpListener;

    const GROUP_A: [u8; 4] = [0xa1; 4];
    const GROUP_B: [u8; 4] = [0xb2; 4];

    fn ring(psk_a: [u8; 32], psk_b: [u8; 32]) -> KeyRing {
        let keys = |psk| GroupKeys {
            current: 0,
            keys: BTreeMap::from([(0, psk)]),
        };
        KeyRing {
            static_private: generate_static(),
            groups: HashMap::from([(GROUP_A, keys(psk_a)), (GROUP_B, keys(psk_b))]),
        }
    }

    fn ring_at(current: u32, keys: BTreeMap<u32, [u8; 32]>) -> KeyRing {
        KeyRing {
            static_private: generate_static(),
            groups: HashMap::from([(GROUP_A, GroupKeys { current, keys })]),
        }
    }

    async fn connected_pair(
        client_ring: KeyRing,
        server_ring: KeyRing,
        group_id: [u8; 4],
    ) -> (SecureStream, SecureStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accept(stream, &server_ring, Duration::from_secs(2))
                .await
                .unwrap()
        });
        let client = connect(address, &client_ring, group_id, Duration::from_secs(2))
            .await
            .unwrap();
        (client, accept.await.unwrap())
    }

    async fn connected_pair_result(
        client_ring: KeyRing,
        server_ring: KeyRing,
    ) -> (
        Result<SecureStream, TransportError>,
        Result<SecureStream, TransportError>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accept(stream, &server_ring, Duration::from_secs(2)).await
        });
        let client = connect(address, &client_ring, GROUP_A, Duration::from_secs(2)).await;
        (client, accept.await.unwrap())
    }

    #[tokio::test]
    async fn retained_epochs_negotiate_both_directions_and_report_epoch() {
        let psk = [0x31; 32];
        let (client, server) =
            connected_pair(ring(psk, [0x32; 32]), ring(psk, [0x32; 32]), GROUP_A).await;
        assert_eq!(client.epoch(), 0);
        assert_eq!(server.epoch(), 0);

        let client = ring_at(0, BTreeMap::from([(0, psk)]));
        let server = ring_at(1, BTreeMap::from([(0, psk), (1, [0x33; 32])]));
        let (client, server) = connected_pair(client, server, GROUP_A).await;
        assert_eq!(client.epoch(), 0);
        assert_eq!(server.epoch(), 0);

        let client = ring_at(1, BTreeMap::from([(0, psk), (1, [0x33; 32])]));
        let server = ring_at(0, BTreeMap::from([(0, psk)]));
        let (client, server) = connected_pair(client, server, GROUP_A).await;
        assert_eq!(client.epoch(), 0);
        assert_eq!(server.epoch(), 0);
    }

    #[tokio::test]
    async fn epochs_older_than_retained_keys_return_too_far_behind_before_noise() {
        let client = ring_at(0, BTreeMap::from([(0, [0; 32])]));
        let server = ring_at(
            17,
            (1..=17).map(|epoch| (epoch, [epoch as u8; 32])).collect(),
        );
        let (client, server) = connected_pair_result(client, server).await;
        assert!(matches!(
            client,
            Err(TransportError::TooFarBehind {
                local: 0,
                current: 17
            })
        ));
        assert!(server.is_err());
    }

    #[tokio::test]
    async fn epoch_before_oldest_retained_key_is_too_far_behind_before_noise() {
        let client = ring_at(1, BTreeMap::from([(1, [1; 32])]));
        let server = ring_at(
            18,
            (2..=18).map(|epoch| (epoch, [epoch as u8; 32])).collect(),
        );
        let (client, server) = connected_pair_result(client, server).await;
        assert!(matches!(
            client,
            Err(TransportError::TooFarBehind {
                local: 1,
                current: 18
            })
        ));
        assert!(server.is_err());
    }

    #[tokio::test]
    async fn initiator_without_responder_epoch_returns_peer_too_far_behind_before_noise() {
        let client = ring_at(
            17,
            (1..=17).map(|epoch| (epoch, [epoch as u8; 32])).collect(),
        );
        let server = ring_at(0, BTreeMap::from([(0, [0; 32])]));
        let (client, server) = connected_pair_result(client, server).await;
        assert!(matches!(
            client,
            Err(TransportError::PeerTooFarBehind { peer_epoch: 0 })
        ));
        assert!(server.is_err());
    }

    #[tokio::test]
    async fn responder_rejects_an_unknown_epoch() {
        let client = ring_at(1, BTreeMap::from([(1, [1; 32])]));
        let server = ring_at(2, BTreeMap::from([(0, [0; 32]), (2, [2; 32])]));
        let (client, server) = connected_pair_result(client, server).await;
        assert!(client.is_err());
        assert!(matches!(server, Err(TransportError::UnknownGroup)));
    }

    #[tokio::test]
    async fn two_group_ring_roundtrips_and_streams_report_the_selected_group() {
        let client_ring = ring([0x5a; 32], [0x6b; 32]);
        let server_ring = ring([0x5a; 32], [0x6b; 32]);
        let client_public = public_key(&client_ring.static_private);
        let server_public = public_key(&server_ring.static_private);
        for group_id in [GROUP_A, GROUP_B] {
            let (mut client, mut server) =
                connected_pair(client_ring.clone(), server_ring.clone(), group_id).await;
            assert_eq!(client.remote_static(), server_public);
            assert_eq!(server.remote_static(), client_public);
            assert_eq!(client.group_id(), group_id);
            assert_eq!(server.group_id(), group_id);
            client.send(b"hello").await.unwrap();
            assert_eq!(server.recv(Duration::from_secs(1)).await.unwrap(), b"hello");
            server.send(b"world").await.unwrap();
            assert_eq!(client.recv(Duration::from_secs(1)).await.unwrap(), b"world");
        }
    }

    #[tokio::test]
    async fn responder_rejects_a_group_missing_from_its_ring() {
        let client_ring = ring([0x5a; 32], [0x6b; 32]);
        let mut server_ring = ring([0x5a; 32], [0x6b; 32]);
        server_ring.groups.remove(&GROUP_B);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accept(stream, &server_ring, Duration::from_secs(2)).await
        });
        let _ = connect(address, &client_ring, GROUP_B, Duration::from_secs(2)).await;
        assert!(matches!(
            server.await.unwrap(),
            Err(TransportError::UnknownGroup)
        ));
    }

    #[tokio::test]
    async fn responder_rejects_same_group_id_with_a_different_psk() {
        let client_ring = ring([0x5a; 32], [0x6b; 32]);
        let server_ring = ring([0x5a; 32], [0x6b; 32]);
        let mut server_ring = server_ring;
        server_ring
            .groups
            .get_mut(&GROUP_A)
            .unwrap()
            .keys
            .get_mut(&0)
            .unwrap()[0] ^= 1;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accept(stream, &server_ring, Duration::from_secs(2)).await
        });
        let _client_result = connect(address, &client_ring, GROUP_A, Duration::from_secs(2)).await;
        assert!(matches!(
            server.await.unwrap(),
            Err(TransportError::Handshake(_))
        ));
    }

    #[tokio::test]
    async fn malformed_preface_is_rejected_before_noise() {
        let ring = ring([0x5a; 32], [0x6b; 32]);
        let (client, server) = tokio::io::duplex(128);
        let accept = tokio::spawn(async move {
            accept_io(Box::new(server), &ring, Duration::from_secs(1)).await
        });
        let mut client = client;
        client
            .write_all(b"NOPE\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            .await
            .unwrap();
        assert!(matches!(
            accept.await.unwrap(),
            Err(TransportError::BadPreface)
        ));
    }

    #[tokio::test]
    async fn oversized_plaintext_is_rejected() {
        let (mut client, _server) = connected_pair(
            ring([0x5a; 32], [0x6b; 32]),
            ring([0x5a; 32], [0x6b; 32]),
            GROUP_A,
        )
        .await;
        let error = client.send(&vec![0; MAX_PLAINTEXT + 1]).await.unwrap_err();
        assert!(matches!(error, TransportError::Oversize));
    }

    #[test]
    fn generated_static_keys_and_key_ring_debug_are_safe() {
        let key = generate_static();
        assert_eq!(key.len(), 32);
        let keys = KeyRing {
            static_private: key,
            groups: HashMap::from([(
                GROUP_A,
                GroupKeys {
                    current: 0,
                    keys: BTreeMap::from([(0, [0xa5; 32])]),
                },
            )]),
        };
        let debug = format!("{keys:?}");
        assert!(debug.contains("static_private: \"[REDACTED]\""));
        assert!(debug.contains("[REDACTED; 1]"));
    }
}
