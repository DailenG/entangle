//! Noise-encrypted byte streams for Entangle links.

use snow::{
    params::DHChoice,
    resolvers::{CryptoResolver, DefaultResolver},
    Builder, HandshakeState, TransportState,
};
use std::{fmt, io, net::SocketAddr, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

/// Noise pattern used to authenticate peers with a pairing-derived PSK.
pub const NOISE_PATTERN: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";
const MAX_MESSAGE: usize = u16::MAX as usize;
const TAG_LENGTH: usize = 16;
/// Maximum plaintext bytes carried by one Noise transport message.
pub const MAX_PLAINTEXT: usize = MAX_MESSAGE - TAG_LENGTH;

/// An asynchronous, owned byte stream suitable for carrying a Noise link.
pub trait LinkIo: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> LinkIo for T {}

/// An owned byte stream that can be used by a Noise link.
pub type BoxedIo = Box<dyn LinkIo>;

/// Shared, reloadable keys used by listeners and outbound links.
pub type KeySlot = Arc<std::sync::RwLock<Option<Arc<LinkKeys>>>>;

/// Static Noise identity and pairing-derived pre-shared key.
#[derive(Clone)]
pub struct LinkKeys {
    /// X25519 static private key.
    pub static_private: [u8; 32],
    /// Pairing-derived Noise PSK.
    pub psk: [u8; 32],
}

impl fmt::Debug for LinkKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkKeys")
            .field("static_private", &"[REDACTED]")
            .field("psk", &"[REDACTED]")
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
}

/// Connects as a Noise initiator and completes the XXpsk3 handshake.
pub async fn connect(
    addr: SocketAddr,
    keys: &LinkKeys,
    duration: Duration,
) -> Result<SecureStream, TransportError> {
    timeout(duration, async {
        let stream = TcpStream::connect(addr).await?;
        connect_io(Box::new(stream), keys, duration).await
    })
    .await
    .map_err(|_| TransportError::Timeout)?
}

/// Completes the Noise initiator handshake over an already-open byte stream.
pub async fn connect_io(
    mut stream: BoxedIo,
    keys: &LinkKeys,
    duration: Duration,
) -> Result<SecureStream, TransportError> {
    timeout(duration, async {
        let (noise, remote_static) = initiator_handshake(&mut stream, keys).await?;
        Ok(SecureStream {
            stream,
            noise,
            remote_static,
        })
    })
    .await
    .map_err(|_| TransportError::Timeout)?
}

/// Accepts a TCP stream as a Noise responder and completes the XXpsk3 handshake.
pub async fn accept(
    stream: TcpStream,
    keys: &LinkKeys,
    duration: Duration,
) -> Result<SecureStream, TransportError> {
    accept_io(Box::new(stream), keys, duration).await
}

/// Completes the Noise responder handshake over an already-open byte stream.
pub async fn accept_io(
    mut stream: BoxedIo,
    keys: &LinkKeys,
    duration: Duration,
) -> Result<SecureStream, TransportError> {
    timeout(duration, async {
        let (noise, remote_static) = responder_handshake(&mut stream, keys).await?;
        Ok(SecureStream {
            stream,
            noise,
            remote_static,
        })
    })
    .await
    .map_err(|_| TransportError::Timeout)?
}

fn handshake_state(keys: &LinkKeys, initiator: bool) -> Result<HandshakeState, TransportError> {
    let params = NOISE_PATTERN
        .parse()
        .map_err(|error: snow::Error| TransportError::Handshake(error.to_string()))?;
    let builder = Builder::new(params)
        .local_private_key(&keys.static_private)
        .map_err(|error| TransportError::Handshake(error.to_string()))?
        .psk(3, &keys.psk)
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
    keys: &LinkKeys,
) -> Result<(TransportState, [u8; 32]), TransportError> {
    let mut state = handshake_state(keys, true)?;
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
    keys: &LinkKeys,
) -> Result<(TransportState, [u8; 32]), TransportError> {
    let mut state = handshake_state(keys, false)?;
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
    use tokio::net::TcpListener;

    fn keys() -> LinkKeys {
        LinkKeys {
            static_private: generate_static(),
            psk: [0x5a; 32],
        }
    }

    async fn connected_pair(
        client_keys: LinkKeys,
        server_keys: LinkKeys,
    ) -> (SecureStream, SecureStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accept(stream, &server_keys, Duration::from_secs(2))
                .await
                .unwrap()
        });
        let client = connect(address, &client_keys, Duration::from_secs(2))
            .await
            .unwrap();
        (client, accept.await.unwrap())
    }

    #[tokio::test]
    async fn noise_handshake_and_bidirectional_messages_roundtrip() {
        let client_keys = keys();
        let server_keys = keys();
        let client_public = public_key(&client_keys.static_private);
        let server_public = public_key(&server_keys.static_private);
        let (mut client, mut server) = connected_pair(client_keys, server_keys).await;

        assert_eq!(client.remote_static(), server_public);
        assert_eq!(server.remote_static(), client_public);
        client.send(b"hello").await.unwrap();
        assert_eq!(server.recv(Duration::from_secs(1)).await.unwrap(), b"hello");
        server.send(b"world").await.unwrap();
        assert_eq!(client.recv(Duration::from_secs(1)).await.unwrap(), b"world");
    }

    #[tokio::test]
    async fn wrong_psk_fails_with_a_handshake_error() {
        let client_keys = keys();
        let mut server_keys = client_keys.clone();
        server_keys.psk[0] ^= 1;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accept(stream, &server_keys, Duration::from_secs(2)).await
        });

        let _ = connect(address, &client_keys, Duration::from_secs(2)).await;
        assert!(matches!(
            server.await.unwrap(),
            Err(TransportError::Handshake(_))
        ));
    }

    #[tokio::test]
    async fn oversized_plaintext_is_rejected() {
        let (mut client, _server) = connected_pair(keys(), keys()).await;
        let error = client.send(&vec![0; MAX_PLAINTEXT + 1]).await.unwrap_err();
        assert!(matches!(error, TransportError::Oversize));
    }

    #[test]
    fn generated_static_keys_and_link_key_debug_are_safe() {
        let key = generate_static();
        assert_eq!(key.len(), 32);
        let keys = LinkKeys {
            static_private: key,
            psk: [0xa5; 32],
        };
        let debug = format!("{keys:?}");
        assert_eq!(
            debug,
            "LinkKeys { static_private: \"[REDACTED]\", psk: \"[REDACTED]\" }"
        );
    }
}
