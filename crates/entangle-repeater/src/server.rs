//! WebSocket endpoint and the opaque, bounded stream multiplexer.

use crate::{
    store::{Device, Store},
    wire::{
        Frame, CLOSE, DATA, INCOMING, INCOMING_BIT, LIST, LIST_REPLY, MAX_MESSAGE, OPEN, OPEN_FAIL,
        PING, PONG, SESSION_STREAM,
    },
};
use entangle_core::sas;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use snow::{params::NoiseParams, Builder, TransportState};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufStream},
    net::TcpListener,
    sync::{mpsc, watch, Mutex},
    task::JoinSet,
};
use tokio_tungstenite::{accept_async, tungstenite::Message};

const NOISE: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const MAX_FAILED_HANDSHAKES: usize = 10;
const HANDSHAKE_FAILURE_WINDOW: Duration = Duration::from_secs(60);
const HANDSHAKE_COOLDOWN: Duration = Duration::from_secs(5 * 60);
const SERVER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING_REQUESTS: usize = 8;
const REQUEST_DECISION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const REQUEST_SAS_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Default)]
struct HandshakeLimiter {
    sources: HashMap<IpAddr, SourceFailures>,
}

#[derive(Default)]
struct SourceFailures {
    failures: VecDeque<Instant>,
    blocked_until: Option<Instant>,
}

impl HandshakeLimiter {
    fn is_blocked(&mut self, ip: IpAddr, now: Instant) -> bool {
        let Some(source) = self.sources.get_mut(&ip) else {
            return false;
        };
        if source.blocked_until.is_some_and(|until| now < until) {
            return true;
        }
        source.blocked_until = None;
        Self::prune_failures(source, now);
        if source.failures.is_empty() {
            self.sources.remove(&ip);
        }
        false
    }

    fn record_failure(&mut self, ip: IpAddr, now: Instant) {
        let source = self.sources.entry(ip).or_default();
        if source.blocked_until.is_some_and(|until| now < until) {
            return;
        }
        source.blocked_until = None;
        Self::prune_failures(source, now);
        source.failures.push_back(now);
        if source.failures.len() >= MAX_FAILED_HANDSHAKES {
            source.blocked_until = Some(now + HANDSHAKE_COOLDOWN);
            source.failures.clear();
        }
    }

    fn prune_failures(source: &mut SourceFailures, now: Instant) {
        source
            .failures
            .retain(|failure| now.saturating_duration_since(*failure) < HANDSHAKE_FAILURE_WINDOW);
    }
}

#[derive(Clone, Debug)]
/// Host configuration; device and invite state live under `root`.
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub path: String,
    pub root: PathBuf,
    pub requests: bool,
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
    side: LinkSide,
    state: Arc<StdMutex<LinkState>>,
}

#[derive(Clone, Copy)]
enum LinkSide {
    Source,
    Target,
}

#[derive(Default)]
struct LinkState {
    source_closed: bool,
    target_closed: bool,
}

type Peers = Arc<Mutex<HashMap<[u8; 32], Peer>>>;
type Links = Arc<Mutex<HashMap<(u64, u32), Link>>>;

struct Shared {
    store: Arc<Store>,
    peers: Peers,
    links: Links,
    handshake_limiter: StdMutex<HandshakeLimiter>,
    incoming_ids: AtomicU32,
    session_ids: AtomicU64,
    session_gate: Arc<Mutex<()>>,
    requests: bool,
    pending_requests: Arc<Mutex<PendingRequests>>,
}

#[derive(Default)]
struct PendingRequests {
    requests: Vec<crate::store::EnrollmentRequest>,
    reserved_ips: std::collections::HashSet<IpAddr>,
}

struct SessionContext {
    key: [u8; 32],
    session_id: u64,
    group: String,
    tx: mpsc::Sender<Frame>,
    rx: mpsc::Receiver<Frame>,
    shared: Arc<Shared>,
}

struct ReaderContext {
    key: [u8; 32],
    session_id: u64,
    group: String,
    tx: mpsc::Sender<Frame>,
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

#[derive(Deserialize)]
struct RequestHello {
    v: u8,
    mode: String,
    label: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Endpoint {
    Session,
    Request,
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
    serve_with_listener(
        listener,
        config.path,
        config.root,
        config.requests,
        SERVER_HANDSHAKE_TIMEOUT,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn serve_on_listener_with_timeout(
    listener: TcpListener,
    config: ServerConfig,
    handshake_timeout: Duration,
) -> Result<(), ServerError> {
    serve_with_listener(
        listener,
        config.path,
        config.root,
        config.requests,
        handshake_timeout,
    )
    .await
}

async fn serve_with_listener(
    listener: TcpListener,
    path: String,
    root: PathBuf,
    requests: bool,
    handshake_timeout: Duration,
) -> Result<(), ServerError> {
    let store = Arc::new(Store::new(root));
    store.save_requests(&[])?;
    let shared = Arc::new(Shared {
        store: Arc::clone(&store),
        peers: Arc::new(Mutex::new(HashMap::new())),
        links: Arc::new(Mutex::new(HashMap::new())),
        handshake_limiter: StdMutex::new(HandshakeLimiter::default()),
        incoming_ids: AtomicU32::new(0x8000_0000),
        session_ids: AtomicU64::new(1),
        session_gate: Arc::new(Mutex::new(())),
        requests,
        pending_requests: Arc::new(Mutex::new(PendingRequests::default())),
    });
    let requests = shared.requests;
    let watcher = spawn_device_watcher(Arc::clone(&shared));
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, addr) = accepted?;
                let path = path.clone();
                let shared = Arc::clone(&shared);
                connections.spawn(async move {
                    let deadline = tokio::time::Instant::now() + handshake_timeout;
                    let mut stream = BufStream::new(stream);
                    let headers = match tokio::time::timeout_at(
                        deadline,
                        read_http_headers(&mut stream),
                    )
                    .await
                    {
                        Ok(Ok(Some(headers))) => {
                            let Some(endpoint) = is_websocket_upgrade(&headers, &path) else {
                                let _ = write_not_found(&mut stream).await;
                                return;
                            };
                            if endpoint == Endpoint::Request && !requests {
                                let _ = write_not_found(&mut stream).await;
                                return;
                            }
                            (headers, endpoint)
                        }
                        Err(_) => return,
                        _ => {
                            let _ = write_not_found(&mut stream).await;
                            return;
                        }
                    };
                    let (headers, endpoint) = headers;
                    if source_is_blocked(&shared, addr.ip()) {
                        return;
                    }
                    // Replay validated headers so tungstenite still performs the upgrade.
                    let (websocket_io, mut relay_io) = tokio::io::duplex(64 * 1024);
                    tokio::spawn(async move {
                        if relay_io.write_all(&headers).await.is_ok() {
                            let _ = tokio::io::copy_bidirectional(&mut stream, &mut relay_io).await;
                        }
                    });
                    match tokio::time::timeout_at(deadline, accept_async(websocket_io)).await {
                        Ok(Ok(ws)) => {
                            if let Err(error) = handle(ws, addr, shared, deadline, endpoint).await {
                                tracing::debug!(%error, "repeater connection closed");
                            }
                        }
                        Ok(Err(error)) => tracing::debug!(%error, "rejected repeater WebSocket"),
                        Err(_) => {}
                    }
                });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    tracing::debug!(%error, "repeater connection task failed");
                }
            }
            _ = &mut shutdown => {
                watcher.abort();
                connections.abort_all();
                while connections.join_next().await.is_some() {}
                return Ok(());
            }
        }
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

fn is_websocket_upgrade(headers: &[u8], expected_path: &str) -> Option<Endpoint> {
    let Ok(headers) = std::str::from_utf8(headers) else {
        return None;
    };
    let mut lines = headers.split("\r\n");
    let request_line = lines.next()?;
    let mut request_parts = request_line.split_whitespace();
    let (Some("GET"), Some(target), Some("HTTP/1.1")) = (
        request_parts.next(),
        request_parts.next(),
        request_parts.next(),
    ) else {
        return None;
    };
    if request_parts.next().is_some() {
        return None;
    }
    let path = target.split('?').next().unwrap_or(target);
    let base = expected_path.trim_end_matches('/');
    let endpoint = if path == expected_path {
        Endpoint::Session
    } else if path == format!("{base}/request") {
        Endpoint::Request
    } else {
        return None;
    };
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
    (upgrade && connection_upgrade && key && version && host && bodyless).then_some(endpoint)
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
                        kind: CLOSE,
                        stream: SESSION_STREAM,
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

fn source_is_blocked(shared: &Shared, ip: IpAddr) -> bool {
    shared
        .handshake_limiter
        .lock()
        .map(|mut limiter| limiter.is_blocked(ip, Instant::now()))
        .unwrap_or(true)
}

fn record_failed_handshake(shared: &Shared, ip: IpAddr) {
    if let Ok(mut limiter) = shared.handshake_limiter.lock() {
        limiter.record_failure(ip, Instant::now());
    }
}

async fn handle<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    addr: SocketAddr,
    shared: Arc<Shared>,
    deadline: tokio::time::Instant,
    endpoint: Endpoint,
) -> Result<(), ServerError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    match endpoint {
        Endpoint::Session => handle_session(ws, addr, shared, deadline).await,
        Endpoint::Request => handle_request(ws, addr, shared, deadline).await,
    }
}

async fn handle_session<S>(
    mut ws: tokio_tungstenite::WebSocketStream<S>,
    addr: SocketAddr,
    shared: Arc<Shared>,
    deadline: tokio::time::Instant,
) -> Result<(), ServerError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let first = match tokio::time::timeout_at(deadline, ws.next()).await {
        Ok(Some(Ok(Message::Binary(first)))) => first,
        Err(_) => return Ok(()),
        _ => {
            record_failed_handshake(&shared, addr.ip());
            return Ok(());
        }
    };
    if first.len() > MAX_MESSAGE {
        record_failed_handshake(&shared, addr.ip());
        return Ok(());
    }
    let private = shared.store.key()?;
    let mut handshake = Builder::new(noise_params())
        .local_private_key(&private)
        .map_err(|error| io::Error::other(error.to_string()))?
        .build_responder()
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut plaintext = vec![0; u16::MAX as usize];
    let size = match handshake.read_message(&first, &mut plaintext) {
        Ok(size) => size,
        Err(_) => {
            record_failed_handshake(&shared, addr.ip());
            return Ok(());
        }
    };
    let remote: [u8; 32] = match handshake
        .get_remote_static()
        .and_then(|key| key.try_into().ok())
    {
        Some(remote) => remote,
        None => {
            record_failed_handshake(&shared, addr.ip());
            return Ok(());
        }
    };
    let hello: Hello = match serde_json::from_slice(&plaintext[..size]) {
        Ok(hello) => hello,
        Err(_) => {
            record_failed_handshake(&shared, addr.ip());
            return Ok(());
        }
    };

    // Reject invalid first messages before msg2. This prevents the repeater
    // from becoming an enrollment or allowlist oracle.
    let valid = if hello.v != 1 {
        false
    } else {
        match hello.mode.as_str() {
            "session" => {
                valid_group(hello.group.as_deref()) && shared.store.device_allowed(&remote)?
            }
            "enroll" => {
                valid_label(hello.label.as_deref())
                    && valid_invite(&shared.store, hello.invite.as_deref())?
            }
            _ => false,
        }
    };
    if !valid {
        record_failed_handshake(&shared, addr.ip());
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
            record_failed_handshake(&shared, addr.ip());
            return Ok(());
        }
        ws.send(Message::Binary(response[..response_size].to_vec()))
            .await?;
        return Ok(());
    }

    ws.send(Message::Binary(response[..response_size].to_vec()))
        .await?;
    let transport = handshake
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
                kind: CLOSE,
                stream: SESSION_STREAM,
                body: Vec::new(),
            })
            .await;
    }
    drop(session_permit);

    let result = session(
        ws,
        transport,
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

async fn handle_request<S>(
    mut ws: tokio_tungstenite::WebSocketStream<S>,
    addr: SocketAddr,
    shared: Arc<Shared>,
    deadline: tokio::time::Instant,
) -> Result<(), ServerError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let first = match tokio::time::timeout_at(deadline, ws.next()).await {
        Ok(Some(Ok(Message::Binary(first)))) => first,
        Err(_) => return Ok(()),
        _ => {
            record_failed_handshake(&shared, addr.ip());
            return Ok(());
        }
    };
    if first.len() > MAX_MESSAGE {
        record_failed_handshake(&shared, addr.ip());
        return Ok(());
    }
    let private = shared.store.key()?;
    let mut handshake = Builder::new(request_noise_params())
        .local_private_key(&private)
        .map_err(|error| io::Error::other(error.to_string()))?
        .build_responder()
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut plaintext = vec![0; u16::MAX as usize];
    if handshake.read_message(&first, &mut plaintext).is_err() {
        record_failed_handshake(&shared, addr.ip());
        return Ok(());
    }
    let mut response = vec![0; u16::MAX as usize];
    let response_size = handshake
        .write_message(&[], &mut response)
        .map_err(|error| io::Error::other(error.to_string()))?;
    ws.send(Message::Binary(response[..response_size].to_vec()))
        .await?;
    let msg3 = match tokio::time::timeout_at(deadline, ws.next()).await {
        Ok(Some(Ok(Message::Binary(message)))) => message,
        _ => {
            record_failed_handshake(&shared, addr.ip());
            return Ok(());
        }
    };
    if msg3.len() > MAX_MESSAGE {
        record_failed_handshake(&shared, addr.ip());
        return Ok(());
    }
    let size = match handshake.read_message(&msg3, &mut plaintext) {
        Ok(size) => size,
        Err(_) => {
            record_failed_handshake(&shared, addr.ip());
            return Ok(());
        }
    };
    let hello: RequestHello = match serde_json::from_slice::<RequestHello>(&plaintext[..size]) {
        Ok(hello) if hello.v == 1 && hello.mode == "request" => hello,
        _ => {
            record_failed_handshake(&shared, addr.ip());
            return Ok(());
        }
    };
    if !valid_label(hello.label.as_deref()) {
        record_failed_handshake(&shared, addr.ip());
        return Ok(());
    }
    let remote: [u8; 32] = match handshake
        .get_remote_static()
        .and_then(|key| key.try_into().ok())
    {
        Some(remote) => remote,
        None => {
            record_failed_handshake(&shared, addr.ip());
            return Ok(());
        }
    };
    let local_public = entangle_transport::public_key(&private);
    let mut transport = handshake
        .into_transport_mode()
        .map_err(|error| io::Error::other(error.to_string()))?;

    let original_device;
    {
        let mut pending = shared.pending_requests.lock().await;
        if pending.requests.len() + pending.reserved_ips.len() >= MAX_PENDING_REQUESTS
            || pending.reserved_ips.contains(&addr.ip())
            || pending
                .requests
                .iter()
                .any(|request| request.source == addr.ip().to_string())
        {
            send_request_json(
                &mut ws,
                &mut transport,
                &serde_json::json!({"ok": false, "error": "busy"}),
            )
            .await?;
            return Ok(());
        }
        original_device = shared
            .store
            .devices()?
            .devices
            .get(&hex::encode(remote))
            .cloned();
        pending.reserved_ips.insert(addr.ip());
    }
    if let Err(error) =
        send_request_json(&mut ws, &mut transport, &serde_json::json!({"ok": true})).await
    {
        release_request(&shared, addr.ip()).await;
        return Err(error);
    }
    let sas = match tokio::time::timeout(
        REQUEST_SAS_TIMEOUT,
        sas_exchange_server(&mut ws, &mut transport, local_public, remote),
    )
    .await
    {
        Ok(Ok(sas)) => sas,
        _ => {
            release_request(&shared, addr.ip()).await;
            return Ok(());
        }
    };
    let request = crate::store::EnrollmentRequest {
        key: hex::encode(remote),
        label: hello.label,
        source: addr.ip().to_string(),
        requested_at: chrono::Utc::now().to_rfc3339(),
        sas,
    };
    {
        let mut pending = shared.pending_requests.lock().await;
        pending.reserved_ips.remove(&addr.ip());
        pending.requests.push(request.clone());
        if let Err(error) = shared.store.save_requests(&pending.requests) {
            pending.requests.pop();
            return Err(error.into());
        }
    }
    tracing::info!(
        fingerprint = %short_fingerprint(&remote),
        label = ?request.label,
        source = %addr.ip(),
        "enrollment request admitted; run `entangle repeater approve`"
    );
    let result = wait_for_request_decision(
        &mut ws,
        &mut transport,
        &shared,
        &request,
        remote,
        original_device,
    )
    .await;
    if let Err(error) = &result {
        tracing::info!(
            fingerprint = %short_fingerprint(&remote),
            label = ?request.label,
            source = %request.source,
            outcome = "error",
            %error,
            "enrollment request ended"
        );
    }
    remove_request(&shared, &request).await;
    result
}

fn request_noise_params() -> NoiseParams {
    "Noise_XX_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .expect("valid request Noise pattern")
}

fn short_fingerprint(public: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(public))[..8].to_owned()
}

async fn send_request_json<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    transport: &mut TransportState,
    value: &serde_json::Value,
) -> Result<(), ServerError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let plaintext = serde_json::to_vec(value)?;
    let mut encrypted = vec![0; MAX_MESSAGE];
    let size = transport
        .write_message(&plaintext, &mut encrypted)
        .map_err(|error| io::Error::other(error.to_string()))?;
    ws.send(Message::Binary(encrypted[..size].to_vec())).await?;
    Ok(())
}

async fn recv_request_json<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    transport: &mut TransportState,
) -> Result<serde_json::Value, ServerError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Some(message) = ws.next().await else {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "request closed").into());
    };
    let Message::Binary(message) = message? else {
        return Err(io::Error::other("invalid request message").into());
    };
    let mut plaintext = vec![0; u16::MAX as usize];
    let size = transport
        .read_message(&message, &mut plaintext)
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(serde_json::from_slice(&plaintext[..size])?)
}

async fn sas_exchange_server<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    transport: &mut TransportState,
    local: [u8; 32],
    remote: [u8; 32],
) -> Result<sas::Sas, ServerError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let role = sas::role(&local, &remote).ok_or_else(|| io::Error::other("equal SAS keys"))?;
    let mut nonce = [0; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    match role {
        sas::Role::Committer => {
            let commit = sas::commitment(&nonce, &local, &remote);
            send_request_json(
                ws,
                transport,
                &serde_json::json!({"commit": hex::encode(commit)}),
            )
            .await?;
            let remote_nonce = parse_nonce(&recv_request_json(ws, transport).await?, "nonce")?;
            send_request_json(
                ws,
                transport,
                &serde_json::json!({"nonce": hex::encode(nonce)}),
            )
            .await?;
            Ok(sas::derive(&local, &remote, &nonce, &remote_nonce))
        }
        sas::Role::Revealer => {
            let commit = parse_digest(&recv_request_json(ws, transport).await?, "commit")?;
            send_request_json(
                ws,
                transport,
                &serde_json::json!({"nonce": hex::encode(nonce)}),
            )
            .await?;
            let remote_nonce = parse_nonce(&recv_request_json(ws, transport).await?, "nonce")?;
            if !verify_sas_commitment(&commit, &remote_nonce, &remote, &local) {
                return Err(io::Error::other("SAS commitment mismatch").into());
            }
            Ok(sas::derive(&remote, &local, &remote_nonce, &nonce))
        }
    }
}

pub(crate) fn verify_sas_commitment(
    commitment: &[u8; 32],
    nonce: &[u8; 32],
    committer: &[u8; 32],
    revealer: &[u8; 32],
) -> bool {
    sas::commitment(nonce, committer, revealer) == *commitment
}

fn parse_digest(value: &serde_json::Value, field: &str) -> Result<[u8; 32], ServerError> {
    let text = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| io::Error::other("invalid SAS message"))?;
    hex::decode(text)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| io::Error::other("invalid SAS message").into())
}

fn parse_nonce(value: &serde_json::Value, field: &str) -> Result<[u8; 32], ServerError> {
    parse_digest(value, field)
}

async fn release_request(shared: &Shared, ip: IpAddr) {
    let mut pending = shared.pending_requests.lock().await;
    pending.reserved_ips.remove(&ip);
}

async fn remove_request(shared: &Shared, request: &crate::store::EnrollmentRequest) {
    let mut pending = shared.pending_requests.lock().await;
    if let Some(index) = pending
        .requests
        .iter()
        .position(|candidate| candidate == request)
    {
        pending.requests.remove(index);
        if let Err(error) = shared.store.save_requests(&pending.requests) {
            tracing::warn!(%error, "could not remove enrollment request");
        }
    }
}

async fn wait_for_request_decision<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    transport: &mut TransportState,
    shared: &Shared,
    request: &crate::store::EnrollmentRequest,
    remote: [u8; 32],
    original: Option<Device>,
) -> Result<(), ServerError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let deadline = tokio::time::Instant::now() + REQUEST_DECISION_TIMEOUT;
    let mut poll = tokio::time::interval(Duration::from_secs(1));
    let ping_period = Duration::from_secs(30);
    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + ping_period, ping_period);
    loop {
        tokio::select! {
            _ = poll.tick() => {
                let current = shared.store.devices()?.devices.get(&hex::encode(remote)).cloned();
                if current != original {
                    if let Some(device) = current {
                        let approved = !device.revoked;
                        send_request_json(ws, transport, &serde_json::json!({"approved": approved})).await?;
                        tracing::info!(
                            fingerprint = %short_fingerprint(&remote),
                            label = ?request.label,
                            source = %request.source,
                            outcome = if approved { "approved" } else { "denied" },
                            "enrollment request decided"
                        );
                        remove_request(shared, request).await;
                        let _ = ws.close(None).await;
                        return Ok(());
                    }
                }
            }
            _ = ping.tick() => {
                ws.send(Message::Ping(Vec::new())).await?;
            }
            result = ws.next() => {
                match result {
                    Some(Ok(Message::Pong(_))) | Some(Ok(Message::Ping(_))) => {}
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => {
                        tracing::info!(
                            fingerprint = %short_fingerprint(&remote),
                            label = ?request.label,
                            source = %request.source,
                            outcome = "disconnected",
                            "enrollment request ended"
                        );
                        remove_request(shared, request).await;
                        return Ok(());
                    }
                    Some(Ok(_)) => {}
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                tracing::info!(
                    fingerprint = %short_fingerprint(&remote),
                    label = ?request.label,
                    source = %request.source,
                    outcome = "timed out",
                    "enrollment request ended"
                );
                remove_request(shared, request).await;
                return Ok(());
            }
        }
    }
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
                kind: CLOSE,
                stream: link.peer_stream_id,
                body: Vec::new(),
            })
            .await;
    }
}

async fn session<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    noise: TransportState,
    context: SessionContext,
) -> Result<(), ServerError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let SessionContext {
        key,
        session_id,
        group,
        tx,
        rx,
        shared,
    } = context;
    let noise = Arc::new(StdMutex::new(noise));
    let (sink, stream) = ws.split();
    let (shutdown, shutdown_rx) = watch::channel(false);
    let writer_noise = Arc::clone(&noise);
    let mut writer = tokio::spawn(server_writer(sink, rx, writer_noise, shutdown_rx.clone()));
    let mut reader = tokio::spawn(server_reader(
        stream,
        noise,
        ReaderContext {
            key,
            session_id,
            group,
            tx,
            shared,
        },
        shutdown_rx,
    ));
    tokio::select! {
        result = &mut writer => {
            let _ = shutdown.send(true);
            let _ = reader.await;
            result.map_err(|error| io::Error::other(error.to_string()))?
        }
        result = &mut reader => {
            let _ = shutdown.send(true);
            let _ = writer.await;
            result.map_err(|error| io::Error::other(error.to_string()))?
        }
    }
}

fn encrypt_frame(noise: &StdMutex<TransportState>, frame: Frame) -> Result<Vec<u8>, ServerError> {
    let plaintext = frame
        .encode()
        .map_err(|_| io::Error::other("frame too large"))?;
    let mut encrypted = vec![0; MAX_MESSAGE];
    let size = noise
        .lock()
        .map_err(|_| io::Error::other("Noise state lock poisoned"))?
        .write_message(&plaintext, &mut encrypted)
        .map_err(|error| io::Error::other(error.to_string()))?;
    encrypted.truncate(size);
    Ok(encrypted)
}

fn decrypt_frame(noise: &StdMutex<TransportState>, encrypted: &[u8]) -> Result<Frame, ServerError> {
    if encrypted.len() > MAX_MESSAGE {
        return Err(io::Error::other("message too large").into());
    }
    let mut plaintext = vec![0; u16::MAX as usize];
    let size = noise
        .lock()
        .map_err(|_| io::Error::other("Noise state lock poisoned"))?
        .read_message(encrypted, &mut plaintext)
        .map_err(|error| io::Error::other(error.to_string()))?;
    Frame::decode(&plaintext[..size]).map_err(|_| io::Error::other("invalid frame").into())
}

async fn enqueue(
    queue: &mpsc::Sender<Frame>,
    frame: Frame,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        changed = shutdown.changed() => changed.is_ok() && !*shutdown.borrow(),
        result = queue.send(frame) => result.is_ok(),
    }
}

async fn server_writer<S>(
    mut sink: futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<S>, Message>,
    mut rx: mpsc::Receiver<Frame>,
    noise: Arc<StdMutex<TransportState>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServerError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let frame = tokio::select! {
            changed = shutdown.changed() => {
                let _ = changed;
                return Ok(());
            }
            frame = rx.recv() => match frame {
                Some(frame) => frame,
                None => return Ok(()),
            }
        };
        let encrypted = encrypt_frame(&noise, frame.clone())?;
        tokio::select! {
            changed = shutdown.changed() => {
                let _ = changed;
                return Ok(());
            }
            result = sink.send(Message::Binary(encrypted)) => result?,
        }
        if frame.kind == CLOSE && frame.stream == SESSION_STREAM {
            let _ = sink.close().await;
            return Ok(());
        }
    }
}

async fn server_reader<S>(
    mut stream: futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<S>>,
    noise: Arc<StdMutex<TransportState>>,
    context: ReaderContext,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServerError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let ReaderContext {
        key,
        session_id,
        group,
        tx,
        shared,
    } = context;
    let mut silence_deadline = Box::pin(tokio::time::sleep(Duration::from_secs(60)));
    loop {
        let message = tokio::select! {
            _ = &mut silence_deadline => return Ok(()),
            changed = shutdown.changed() => {
                let _ = changed;
                return Ok(());
            }
            message = stream.next() => message,
        };
        let Some(message) = message else {
            return Ok(());
        };
        let Message::Binary(data) = message? else {
            continue;
        };
        silence_deadline
            .as_mut()
            .reset(tokio::time::Instant::now() + Duration::from_secs(60));
        let frame = decrypt_frame(&noise, &data)?;
        match frame.kind {
            OPEN => {
                if frame.body.len() != 32 || frame.stream & INCOMING_BIT != 0 {
                    continue;
                }
                let target: [u8; 32] = frame.body.try_into().unwrap();
                if target == key || !shared.store.device_allowed(&target)? {
                    if !enqueue(
                        &tx,
                        Frame {
                            kind: OPEN_FAIL,
                            stream: frame.stream,
                            body: b"target is not enrolled".to_vec(),
                        },
                        &mut shutdown,
                    )
                    .await
                    {
                        return Ok(());
                    }
                    continue;
                }
                let target_peer = shared.peers.lock().await.get(&target).cloned();
                let Some(target_peer) = target_peer.filter(|peer| peer.group == group) else {
                    if !enqueue(
                        &tx,
                        Frame {
                            kind: OPEN_FAIL,
                            stream: frame.stream,
                            body: b"target offline or not in your group".to_vec(),
                        },
                        &mut shutdown,
                    )
                    .await
                    {
                        return Ok(());
                    }
                    continue;
                };
                let mut links = shared.links.lock().await;
                let local_count = links.keys().filter(|(id, _)| *id == session_id).count();
                let target_count = links
                    .keys()
                    .filter(|(id, _)| *id == target_peer.session_id)
                    .count();
                if local_count >= 64
                    || target_count >= 64
                    || links.contains_key(&(session_id, frame.stream))
                {
                    drop(links);
                    if !enqueue(
                        &tx,
                        Frame {
                            kind: OPEN_FAIL,
                            stream: frame.stream,
                            body: b"stream limit".to_vec(),
                        },
                        &mut shutdown,
                    )
                    .await
                    {
                        return Ok(());
                    }
                    continue;
                }
                let incoming_id = loop {
                    let id = shared.incoming_ids.fetch_add(1, Ordering::Relaxed) | INCOMING_BIT;
                    if !links.contains_key(&(target_peer.session_id, id)) {
                        break id;
                    }
                };
                // Each stream has a bounded queue; a slow stream can apply
                // backpressure to all streams on this session.
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
                let link_state = Arc::new(StdMutex::new(LinkState::default()));
                links.insert(
                    (session_id, frame.stream),
                    Link {
                        peer_session_id: target_peer.session_id,
                        peer_stream_id: incoming_id,
                        outbound: to_target,
                        side: LinkSide::Source,
                        state: Arc::clone(&link_state),
                    },
                );
                links.insert(
                    (target_peer.session_id, incoming_id),
                    Link {
                        peer_session_id: session_id,
                        peer_stream_id: frame.stream,
                        outbound: to_source,
                        side: LinkSide::Target,
                        state: link_state,
                    },
                );
                drop(links);
                if !enqueue(
                    &target_peer.tx,
                    Frame {
                        kind: INCOMING,
                        stream: incoming_id,
                        body: key.to_vec(),
                    },
                    &mut shutdown,
                )
                .await
                {
                    shared
                        .links
                        .lock()
                        .await
                        .remove(&(session_id, frame.stream));
                    shared
                        .links
                        .lock()
                        .await
                        .remove(&(target_peer.session_id, incoming_id));
                    if !enqueue(
                        &tx,
                        Frame {
                            kind: OPEN_FAIL,
                            stream: frame.stream,
                            body: b"target offline".to_vec(),
                        },
                        &mut shutdown,
                    )
                    .await
                    {
                        return Ok(());
                    }
                }
            }
            DATA => {
                let link = shared
                    .links
                    .lock()
                    .await
                    .get(&(session_id, frame.stream))
                    .cloned();
                if let Some(link) = link {
                    // This tap is test-only; production never stores or logs DATA.
                    #[cfg(test)]
                    FORWARDED_DATA
                        .get_or_init(Default::default)
                        .lock()
                        .unwrap()
                        .extend_from_slice(&frame.body);
                    if !enqueue(
                        &link.outbound,
                        Frame {
                            kind: DATA,
                            stream: link.peer_stream_id,
                            body: frame.body,
                        },
                        &mut shutdown,
                    )
                    .await
                    {
                        return Ok(());
                    }
                }
            }
            CLOSE => {
                if frame.stream == SESSION_STREAM {
                    return Ok(());
                }
                let link = shared
                    .links
                    .lock()
                    .await
                    .get(&(session_id, frame.stream))
                    .cloned();
                if let Some(link) = link {
                    let (forward_close, fully_closed) = {
                        let mut state = link.state.lock().expect("link state lock");
                        let forward = match link.side {
                            LinkSide::Source if !state.source_closed => {
                                state.source_closed = true;
                                true
                            }
                            LinkSide::Target if !state.target_closed => {
                                state.target_closed = true;
                                true
                            }
                            _ => false,
                        };
                        (forward, state.source_closed && state.target_closed)
                    };
                    if forward_close
                        && !enqueue(
                            &link.outbound,
                            Frame {
                                kind: CLOSE,
                                stream: link.peer_stream_id,
                                body: Vec::new(),
                            },
                            &mut shutdown,
                        )
                        .await
                    {
                        return Ok(());
                    }
                    if fully_closed {
                        let mut links = shared.links.lock().await;
                        links.remove(&(session_id, frame.stream));
                        links.remove(&(link.peer_session_id, link.peer_stream_id));
                    }
                }
            }
            LIST if frame.body.is_empty() => {
                let list = {
                    let peers = shared.peers.lock().await;
                    peers
                        .values()
                        .filter(|peer| peer.key != key && peer.group == group)
                        .map(|peer| {
                            serde_json::json!({
                                "key": hex::encode(peer.key),
                                "since_secs": peer.since.elapsed().as_secs(),
                            })
                        })
                        .collect::<Vec<_>>()
                };
                if !enqueue(
                    &tx,
                    Frame {
                        kind: LIST_REPLY,
                        stream: SESSION_STREAM,
                        body: serde_json::to_vec(&list)?,
                    },
                    &mut shutdown,
                )
                .await
                {
                    return Ok(());
                }
            }
            PING if frame.body.is_empty() => {
                if !enqueue(
                    &tx,
                    Frame {
                        kind: PONG,
                        stream: frame.stream,
                        body: Vec::new(),
                    },
                    &mut shutdown,
                )
                .await
                {
                    return Ok(());
                }
            }
            PONG => {}
            _ => {}
        }
    }
}

#[cfg(test)]
mod limiter_tests {
    use super::*;

    fn loopback() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    #[test]
    fn handshake_limiter_blocks_on_the_tenth_failure() {
        let mut limiter = HandshakeLimiter::default();
        let now = Instant::now();
        let ip = loopback();

        for _ in 0..MAX_FAILED_HANDSHAKES - 1 {
            limiter.record_failure(ip, now);
        }
        assert!(!limiter.is_blocked(ip, now));
        limiter.record_failure(ip, now);
        assert!(limiter.is_blocked(ip, now));
    }

    #[test]
    fn handshake_limiter_expires_failures_outside_the_window() {
        let mut limiter = HandshakeLimiter::default();
        let now = Instant::now();
        let ip = loopback();
        for _ in 0..MAX_FAILED_HANDSHAKES - 1 {
            limiter.record_failure(ip, now);
        }

        let after_window = now + HANDSHAKE_FAILURE_WINDOW + Duration::from_secs(1);
        limiter.record_failure(ip, after_window);
        for _ in 0..MAX_FAILED_HANDSHAKES - 2 {
            limiter.record_failure(ip, after_window);
        }
        assert!(!limiter.is_blocked(ip, after_window));
        limiter.record_failure(ip, after_window);
        assert!(limiter.is_blocked(ip, after_window));
    }

    #[test]
    fn handshake_limiter_expires_the_cooldown() {
        let mut limiter = HandshakeLimiter::default();
        let now = Instant::now();
        let ip = loopback();
        for _ in 0..MAX_FAILED_HANDSHAKES {
            limiter.record_failure(ip, now);
        }

        assert!(limiter.is_blocked(ip, now + HANDSHAKE_COOLDOWN - Duration::from_secs(1)));
        assert!(!limiter.is_blocked(ip, now + HANDSHAKE_COOLDOWN));
    }
}

#[cfg(test)]
mod request_tests {
    use super::verify_sas_commitment;
    use entangle_core::sas;

    #[test]
    fn wrong_sas_commitment_or_nonce_aborts_verification() {
        let committer = [1; 32];
        let revealer = [2; 32];
        let nonce = [3; 32];
        let commitment = sas::commitment(&nonce, &committer, &revealer);
        assert!(verify_sas_commitment(
            &commitment,
            &nonce,
            &committer,
            &revealer
        ));
        assert!(!verify_sas_commitment(
            &[0; 32], &nonce, &committer, &revealer
        ));
        assert!(!verify_sas_commitment(
            &commitment,
            &[4; 32],
            &committer,
            &revealer
        ));
    }
}
