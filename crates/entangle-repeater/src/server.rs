//! WebSocket endpoint and the opaque, bounded stream multiplexer.

use crate::{
    store::{Device, Store},
    wire::{Frame, MAX_MESSAGE},
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use snow::{params::NoiseParams, Builder, TransportState};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufStream},
    net::TcpListener,
    sync::{mpsc, Mutex},
};
use tokio_tungstenite::{accept_async, tungstenite::Message};

const NOISE: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

#[derive(Clone, Debug)]
/// Host configuration; device and invite state live under `root`.
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub path: String,
    pub root: PathBuf,
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("repeater I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("repeater WebSocket failed: {0}")]
    WebSocket(#[source] Box<tokio_tungstenite::tungstenite::Error>),
    #[error("repeater store failed: {0}")]
    Store(#[from] crate::store::StoreError),
    #[error("repeater JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<tokio_tungstenite::tungstenite::Error> for ServerError {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::WebSocket(Box::new(error))
    }
}

#[derive(Clone)]
struct Peer {
    key: [u8; 32],
    session_id: u64,
    group: String,
    since: Instant,
    tx: mpsc::Sender<Frame>,
}

#[derive(Clone)]
struct Link {
    peer_session_id: u64,
    peer_stream_id: u32,
    outbound: mpsc::Sender<Frame>,
}

type Peers = Arc<Mutex<HashMap<[u8; 32], Peer>>>;
type Links = Arc<Mutex<HashMap<(u64, u32), Link>>>;

struct Shared {
    store: Arc<Store>,
    peers: Peers,
    links: Links,
    incoming_ids: AtomicU32,
    session_ids: AtomicU64,
    session_gate: Arc<Mutex<()>>,
}

struct SessionContext {
    key: [u8; 32],
    session_id: u64,
    group: String,
    tx: mpsc::Sender<Frame>,
    rx: mpsc::Receiver<Frame>,
    shared: Arc<Shared>,
}

#[derive(Deserialize)]
struct Hello {
    v: u8,
    mode: String,
    group: Option<String>,
    invite: Option<String>,
    label: Option<String>,
}

#[cfg(test)]
static FORWARDED_DATA: std::sync::OnceLock<std::sync::Mutex<Vec<u8>>> = std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) fn clear_forwarded_data() {
    FORWARDED_DATA
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .clear();
}

#[cfg(test)]
pub(crate) fn forwarded_data() -> Vec<u8> {
    FORWARDED_DATA
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .clone()
}

fn noise_params() -> NoiseParams {
    NOISE.parse().expect("valid repeater Noise pattern")
}

/// Binds the configured WebSocket endpoint and serves until Ctrl+C.
pub async fn serve(config: ServerConfig) -> Result<(), ServerError> {
    let listener = TcpListener::bind(config.listen).await?;
    let shared = Arc::new(Shared {
        store: Arc::new(Store::new(config.root)),
        peers: Arc::new(Mutex::new(HashMap::new())),
        links: Arc::new(Mutex::new(HashMap::new())),
        incoming_ids: AtomicU32::new(0x8000_0000),
        session_ids: AtomicU64::new(1),
        session_gate: Arc::new(Mutex::new(())),
    });
    let watcher = spawn_device_watcher(Arc::clone(&shared));
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        let (stream, addr) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = &mut shutdown => {
                watcher.abort();
                return Ok(());
            }
        };
        let path = config.path.clone();
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let mut stream = BufStream::new(stream);
            let headers = match read_http_headers(&mut stream).await {
                Ok(Some(headers)) if is_websocket_upgrade(&headers, &path) => headers,
                _ => {
                    let _ = write_not_found(&mut stream).await;
                    return;
                }
            };
            // Replay validated headers so tungstenite still performs the upgrade.
            let (websocket_io, mut relay_io) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                if relay_io.write_all(&headers).await.is_ok() {
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut relay_io).await;
                }
            });
            match accept_async(websocket_io).await {
                Ok(ws) => {
                    if let Err(error) = handle(ws, addr, shared).await {
                        tracing::debug!(%error, "repeater connection closed");
                    }
                }
                Err(error) => tracing::debug!(%error, "rejected repeater WebSocket"),
            }
        });
    }
}

async fn read_http_headers<S>(stream: &mut S) -> io::Result<Option<Vec<u8>>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut headers = Vec::new();
    while headers.len() < 8192 {
        let mut byte = [0];
        if let Err(error) = stream.read_exact(&mut byte).await {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                return Ok(None);
            }
            return Err(error);
        }
        headers.push(byte[0]);
        if headers.ends_with(b"\r\n\r\n") {
            return Ok(Some(headers));
        }
    }
    Ok(None)
}

fn is_websocket_upgrade(headers: &[u8], expected_path: &str) -> bool {
    let Ok(headers) = std::str::from_utf8(headers) else {
        return false;
    };
    let mut lines = headers.split("\r\n");
    let Some(request_line) = lines.next() else {
        return false;
    };
    let mut request_parts = request_line.split_whitespace();
    let (Some("GET"), Some(target), Some("HTTP/1.1")) = (
        request_parts.next(),
        request_parts.next(),
        request_parts.next(),
    ) else {
        return false;
    };
    if request_parts.next().is_some() {
        return false;
    }
    let path = target.split('?').next().unwrap_or(target);
    if path != expected_path {
        return false;
    }
    let mut upgrade = false;
    let mut connection_upgrade = false;
    let mut key = false;
    let mut version = false;
    let mut host = false;
    let mut bodyless = true;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "upgrade" => upgrade = value.eq_ignore_ascii_case("websocket"),
            "connection" => {
                connection_upgrade = value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            }
            "sec-websocket-key" => {
                key = data_encoding::BASE64
                    .decode(value.as_bytes())
                    .is_ok_and(|decoded| decoded.len() == 16)
            }
            "sec-websocket-version" => version = value == "13",
            "host" => host = !value.is_empty(),
            "content-length" => bodyless = value == "0",
            "transfer-encoding" => bodyless = false,
            _ => {}
        }
    }
    upgrade && connection_upgrade && key && version && host && bodyless
}

async fn write_not_found<S>(stream: &mut S) -> io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await?;
    stream.flush().await
}

fn spawn_device_watcher(shared: Arc<Shared>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut previous = None;
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let stamp = shared.store.device_stamp().ok().flatten();
            if stamp == previous {
                continue;
            }
            previous = stamp;
            let Ok(devices) = shared.store.devices() else {
                continue;
            };
            let mut peers = shared.peers.lock().await;
            let revoked = peers
                .iter()
                .filter(|(key, _)| !allowed(&devices.devices, key))
                .map(|(key, peer)| (*key, peer.tx.clone()))
                .collect::<Vec<_>>();
            for (key, _) in &revoked {
                peers.remove(key);
            }
            drop(peers);
            for (_, tx) in revoked {
                let _ = tx
                    .send(Frame {
                        kind: 4,
                        stream: 0,
                        body: Vec::new(),
                    })
                    .await;
            }
        }
    })
}

fn allowed(devices: &std::collections::BTreeMap<String, Device>, key: &[u8; 32]) -> bool {
    devices
        .get(&hex::encode(key))
        .is_some_and(|device| !device.revoked)
}

async fn handle<S>(
    mut ws: tokio_tungstenite::WebSocketStream<S>,
    _addr: SocketAddr,
    shared: Arc<Shared>,
) -> Result<(), ServerError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Some(Ok(Message::Binary(first))) = ws.next().await else {
        return Ok(());
    };
    if first.len() > MAX_MESSAGE {
        return Ok(());
    }
    let private = shared.store.key()?;
    let mut handshake = Builder::new(noise_params())
        .local_private_key(&private)
        .map_err(|error| io::Error::other(error.to_string()))?
        .build_responder()
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut plaintext = vec![0; u16::MAX as usize];
    let size = handshake
        .read_message(&first, &mut plaintext)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let remote: [u8; 32] = handshake
        .get_remote_static()
        .ok_or_else(|| io::Error::other("missing client static key"))?
        .try_into()
        .map_err(|_| io::Error::other("invalid client static key"))?;
    let hello: Hello = serde_json::from_slice(&plaintext[..size])
        .map_err(|error| io::Error::other(error.to_string()))?;

    // Reject invalid first messages before msg2. This prevents the repeater
    // from becoming an enrollment or allowlist oracle.
    if hello.v != 1
        || !matches!(hello.mode.as_str(), "session" | "enroll")
        || hello.mode == "session"
            && (!valid_group(hello.group.as_deref()) || !shared.store.device_allowed(&remote)?)
        || hello.mode == "enroll"
            && (!valid_label(hello.label.as_deref())
                || !valid_invite(&shared.store, hello.invite.as_deref())?)
    {
        return Ok(());
    }

    // Serialize capacity checks through registration so concurrent sessions
    // cannot exceed the global limit between validation and msg2.
    let session_permit = if hello.mode == "session" {
        let permit = Arc::clone(&shared.session_gate).lock_owned().await;
        let peers = shared.peers.lock().await;
        if peers.len() >= 256 && !peers.contains_key(&remote) {
            return Ok(());
        }
        Some(permit)
    } else {
        None
    };

    let mut response = vec![0; u16::MAX as usize];
    let response_size = handshake
        .write_message(br#"{"ok":true}"#, &mut response)
        .map_err(|error| io::Error::other(error.to_string()))?;
    if hello.mode == "enroll" {
        let secret: [u8; 32] = hex::decode(hello.invite.unwrap())
            .map_err(|_| io::Error::other("invalid invitation"))?
            .try_into()
            .map_err(|_| io::Error::other("invalid invitation"))?;
        if !shared.store.consume_invite(&secret, remote, hello.label)? {
            return Ok(());
        }
        ws.send(Message::Binary(response[..response_size].to_vec()))
            .await?;
        return Ok(());
    }

    ws.send(Message::Binary(response[..response_size].to_vec()))
        .await?;
    let mut transport = handshake
        .into_transport_mode()
        .map_err(|error| io::Error::other(error.to_string()))?;
    let group = hello.group.unwrap();
    let session_id = shared.session_ids.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = mpsc::channel::<Frame>(32);
    let replaced = shared.peers.lock().await.insert(
        remote,
        Peer {
            key: remote,
            session_id,
            group: group.clone(),
            since: Instant::now(),
            tx: tx.clone(),
        },
    );
    if let Some(old) = replaced {
        let _ = old
            .tx
            .send(Frame {
                kind: 4,
                stream: 0,
                body: Vec::new(),
            })
            .await;
    }
    drop(session_permit);

    let result = session(
        ws,
        &mut transport,
        SessionContext {
            key: remote,
            session_id,
            group,
            tx: tx.clone(),
            rx,
            shared: Arc::clone(&shared),
        },
    )
    .await;

    let mut peers = shared.peers.lock().await;
    if peers
        .get(&remote)
        .is_some_and(|peer| peer.tx.same_channel(&tx))
    {
        peers.remove(&remote);
    }
    drop(peers);
    close_session_links(&shared, session_id).await;
    result
}

fn valid_group(group: Option<&str>) -> bool {
    group.is_some_and(|value| {
        value.len() == 8
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_label(label: Option<&str>) -> bool {
    label.is_none_or(|value| value.len() <= 64 && !value.chars().any(char::is_control))
}

fn valid_invite(store: &Store, invite: Option<&str>) -> Result<bool, ServerError> {
    let Some(invite) = invite else {
        return Ok(false);
    };
    if invite.len() != 64 || !invite.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(false);
    }
    let hash = hex::encode(Sha256::digest(hex::decode(invite).unwrap()));
    let now = chrono::Utc::now();
    Ok(store.invites()?.invites.iter().any(|record| {
        !record.used
            && record.secret_sha256 == hash
            && chrono::DateTime::parse_from_rfc3339(&record.expires_at)
                .map(|expiry| expiry.with_timezone(&chrono::Utc) > now)
                .unwrap_or(false)
    }))
}

async fn close_session_links(shared: &Shared, session_id: u64) {
    let mut links = shared.links.lock().await;
    let active = links
        .iter()
        .filter(|((id, _), _)| *id == session_id)
        .map(|(key, link)| (*key, link.clone()))
        .collect::<Vec<_>>();
    for ((_, stream_id), link) in &active {
        links.remove(&(session_id, *stream_id));
        links.remove(&(link.peer_session_id, link.peer_stream_id));
    }
    drop(links);
    for (_, link) in active {
        let _ = link
            .outbound
            .send(Frame {
                kind: 4,
                stream: link.peer_stream_id,
                body: Vec::new(),
            })
            .await;
    }
}

async fn send_noise_frame<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    noise: &mut TransportState,
    frame: Frame,
) -> Result<(), ServerError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let plaintext = frame
        .encode()
        .map_err(|_| io::Error::other("frame too large"))?;
    let mut encrypted = vec![0; u16::MAX as usize];
    let size = noise
        .write_message(&plaintext, &mut encrypted)
        .map_err(|error| io::Error::other(error.to_string()))?;
    ws.send(Message::Binary(encrypted[..size].to_vec())).await?;
    Ok(())
}

async fn session<S>(
    mut ws: tokio_tungstenite::WebSocketStream<S>,
    noise: &mut TransportState,
    context: SessionContext,
) -> Result<(), ServerError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let SessionContext {
        key,
        session_id,
        group,
        tx,
        mut rx,
        shared,
    } = context;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(60)) => return Ok(()),
            Some(frame) = rx.recv() => {
                let plaintext = frame.encode().map_err(|_| io::Error::other("frame too large"))?;
                let mut encrypted = vec![0; u16::MAX as usize];
                let size = noise.write_message(&plaintext, &mut encrypted)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                ws.send(Message::Binary(encrypted[..size].to_vec())).await?;
                if frame.kind == 4 && frame.stream == 0 {
                    let _ = ws.close(None).await;
                    return Ok(());
                }
            }
            message = ws.next() => {
                let Some(message) = message else { return Ok(()) };
                let Message::Binary(data) = message? else { continue };
                if data.len() > MAX_MESSAGE {
                    return Ok(());
                }
                let mut plaintext = vec![0; u16::MAX as usize];
                let size = noise.read_message(&data, &mut plaintext)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                let frame = Frame::decode(&plaintext[..size])
                    .map_err(|_| io::Error::other("invalid frame"))?;
                match frame.kind {
                    1 => {
                        if frame.body.len() != 32 || frame.stream & 0x8000_0000 != 0 {
                            continue;
                        }
                        let target: [u8; 32] = frame.body.try_into().unwrap();
                        if target == key || !shared.store.device_allowed(&target)? {
                            send_noise_frame(&mut ws, noise, Frame {
                                kind: 5,
                                stream: frame.stream,
                                body: b"target is not enrolled".to_vec(),
                            }).await?;
                            continue;
                        }
                        let target_peer = shared.peers.lock().await.get(&target).cloned();
                        let Some(target_peer) = target_peer.filter(|peer| peer.group == group) else {
                            send_noise_frame(&mut ws, noise, Frame {
                                kind: 5,
                                stream: frame.stream,
                                body: b"target offline or not in your group".to_vec(),
                            }).await?;
                            continue;
                        };
                        let mut links = shared.links.lock().await;
                        let local_count = links.keys().filter(|(id, _)| *id == session_id).count();
                        let target_count = links.keys()
                            .filter(|(id, _)| *id == target_peer.session_id).count();
                        if local_count >= 64 || target_count >= 64
                            || links.contains_key(&(session_id, frame.stream))
                        {
                            drop(links);
                            send_noise_frame(&mut ws, noise, Frame {
                                kind: 5,
                                stream: frame.stream,
                                body: b"stream limit".to_vec(),
                            }).await?;
                            continue;
                        }
                        let incoming_id = loop {
                            let id = shared.incoming_ids.fetch_add(1, Ordering::Relaxed) | 0x8000_0000;
                            if !links.contains_key(&(target_peer.session_id, id)) {
                                break id;
                            }
                        };
                        // Each direction has a 32-frame queue. Slow consumers
                        // backpressure only the affected stream.
                        let (to_target, mut target_queue) = mpsc::channel::<Frame>(32);
                        let target_session = target_peer.tx.clone();
                        tokio::spawn(async move {
                            while let Some(frame) = target_queue.recv().await {
                                if target_session.send(frame).await.is_err() {
                                    break;
                                }
                            }
                        });
                        let (to_source, mut source_queue) = mpsc::channel::<Frame>(32);
                        let source_session = tx.clone();
                        tokio::spawn(async move {
                            while let Some(frame) = source_queue.recv().await {
                                if source_session.send(frame).await.is_err() {
                                    break;
                                }
                            }
                        });
                        links.insert((session_id, frame.stream), Link {
                            peer_session_id: target_peer.session_id,
                            peer_stream_id: incoming_id,
                            outbound: to_target,
                        });
                        links.insert((target_peer.session_id, incoming_id), Link {
                            peer_session_id: session_id,
                            peer_stream_id: frame.stream,
                            outbound: to_source,
                        });
                        drop(links);
                        if target_peer.tx.send(Frame {
                            kind: 2,
                            stream: incoming_id,
                            body: key.to_vec(),
                        }).await.is_err() {
                            shared.links.lock().await.remove(&(session_id, frame.stream));
                            shared.links.lock().await.remove(&(target_peer.session_id, incoming_id));
                            send_noise_frame(&mut ws, noise, Frame {
                                kind: 5,
                                stream: frame.stream,
                                body: b"target offline".to_vec(),
                            }).await?;
                        }
                    }
                    3 => {
                        let link = shared.links.lock().await
                            .get(&(session_id, frame.stream)).cloned();
                        if let Some(link) = link
                        {
                            // This tap is test-only; production never stores or
                            // logs forwarded DATA bodies.
                            #[cfg(test)]
                            FORWARDED_DATA.get_or_init(Default::default)
                                .lock().unwrap().extend_from_slice(&frame.body);
                            let _ = link.outbound.send(Frame {
                                kind: 3,
                                stream: link.peer_stream_id,
                                body: frame.body,
                            }).await;
                        }
                    }
                    4 => {
                        let link = shared.links.lock().await.remove(&(session_id, frame.stream));
                        if let Some(link) = link
                        {
                            shared.links.lock().await
                                .remove(&(link.peer_session_id, link.peer_stream_id));
                            let _ = link.outbound.send(Frame {
                                kind: 4,
                                stream: link.peer_stream_id,
                                body: Vec::new(),
                            }).await;
                        }
                    }
                    6 if frame.body.is_empty() => {
                        let list = {
                            let peers = shared.peers.lock().await;
                            peers.values().filter(|peer| peer.key != key && peer.group == group)
                                .map(|peer| serde_json::json!({
                                    "key": hex::encode(peer.key),
                                    "since_secs": peer.since.elapsed().as_secs(),
                                })).collect::<Vec<_>>()
                        };
                        send_noise_frame(&mut ws, noise, Frame {
                            kind: 7,
                            stream: 0,
                            body: serde_json::to_vec(&list)?,
                        }).await?;
                    }
                    8 if frame.body.is_empty() => {
                        send_noise_frame(&mut ws, noise, Frame {
                            kind: 9,
                            stream: frame.stream,
                            body: Vec::new(),
                        }).await?;
                    }
                    9 => {}
                    _ => {}
                }
            }
        }
    }
}
