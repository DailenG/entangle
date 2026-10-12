//! Client-side Noise handshake and asynchronous stream multiplexer.

use crate::wire::{
    Frame, CLOSE, DATA, INCOMING, LIST, LIST_REPLY, MAX_MESSAGE, OPEN, OPEN_FAIL, PING, PONG,
    SESSION_STREAM,
};
use entangle_core::sas;
use entangle_transport::BoxedIo;
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde_json::json;
use snow::{params::NoiseParams, Builder, TransportState};
use std::{
    collections::HashMap,
    io,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex as StdMutex,
    },
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, oneshot, watch, Mutex},
    time::Duration,
};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tracing::debug;

const NOISE: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const INCOMING_QUEUE_CAPACITY: usize = 32;

/// Errors returned while establishing or using a repeater session.
#[derive(Debug, Error)]
pub enum ClientError {
    /// WebSocket transport failure.
    #[error("repeater WebSocket failed: {0}")]
    WebSocket(#[source] Box<tokio_tungstenite::tungstenite::Error>),
    /// Socket I/O failure.
    #[error("repeater I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Noise handshake or transport failure.
    #[error("repeater Noise failed: {0}")]
    Noise(String),
    /// The repeater returned or sent an invalid protocol message.
    #[error("repeater protocol error")]
    Protocol,
    /// The repeater did not complete its handshake before the deadline.
    #[error("repeater handshake timed out")]
    HandshakeTimeout,
    /// The repeater session has ended.
    #[error("repeater session is closed")]
    SessionClosed,
    /// The administrator did not decide before the enrollment request expired.
    #[error("repeater enrollment request timed out")]
    RequestTimeout,
    /// The repeater has reached its pending request capacity.
    #[error("the repeater has too many pending requests; try again shortly")]
    Busy,
    /// A protocol JSON payload could not be encoded or decoded.
    #[error("repeater JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Result of an administrator-approved request enrollment.
#[derive(Debug, Eq, PartialEq)]
pub enum RequestOutcome {
    /// The host approved the device and authenticated this repeater key.
    Approved { repeater_public: [u8; 32] },
    /// The host denied the request.
    Denied,
}

impl From<tokio_tungstenite::tungstenite::Error> for ClientError {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::WebSocket(Box::new(error))
    }
}

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
type Routes = Arc<Mutex<HashMap<u32, mpsc::Sender<Frame>>>>;

struct DialerInner {
    outgoing: mpsc::Sender<Frame>,
    control: Mutex<mpsc::Receiver<Frame>>,
    routes: Routes,
    session_shutdown: watch::Receiver<bool>,
    next_stream: AtomicU32,
    list_lock: Mutex<()>,
    _shutdown: Option<oneshot::Sender<()>>,
}

/// An authenticated client session to a repeater.
pub struct RepeaterClient {
    inner: Arc<DialerInner>,
    incoming: IncomingStreams,
    /// This session's Noise static public key.
    pub static_public: [u8; 32],
}

/// Shared, cheap-to-clone access to an authenticated repeater session.
#[derive(Clone)]
pub struct RepeaterDialer {
    inner: Arc<DialerInner>,
}

/// Directory entry for a live peer in this repeater group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    /// The peer's authenticated Noise static public key.
    pub key: [u8; 32],
    /// Seconds since the peer joined the live directory.
    pub since_secs: u64,
}

/// Receiver for streams opened by other repeater clients.
pub struct IncomingStreams {
    incoming: mpsc::Receiver<IncomingStream>,
}

/// An incoming relayed stream and the remote client's static key.
pub struct IncomingStream {
    /// Static public key of the session that opened this stream.
    pub source: [u8; 32],
    /// The byte stream to pass to the end-to-end link handshake.
    pub stream: RepeaterStream,
}

/// One multiplexed byte stream carried by a repeater session.
pub struct RepeaterStream {
    /// Stream identifier assigned by the client or repeater.
    pub id: u32,
    io: BoxedIo,
}

fn params() -> NoiseParams {
    NOISE.parse().expect("valid Noise pattern")
}

async fn handshake(
    url: &str,
    private: [u8; 32],
    repeater_public: [u8; 32],
    payload: serde_json::Value,
) -> Result<(Socket, TransportState, [u8; 32]), ClientError> {
    handshake_with_timeout(url, private, repeater_public, payload, HANDSHAKE_TIMEOUT).await
}

async fn handshake_with_timeout(
    url: &str,
    private: [u8; 32],
    repeater_public: [u8; 32],
    payload: serde_json::Value,
    timeout: Duration,
) -> Result<(Socket, TransportState, [u8; 32]), ClientError> {
    tokio::time::timeout(
        timeout,
        handshake_inner(url, private, repeater_public, payload),
    )
    .await
    .map_err(|_| ClientError::HandshakeTimeout)?
}

async fn handshake_inner(
    url: &str,
    private: [u8; 32],
    repeater_public: [u8; 32],
    payload: serde_json::Value,
) -> Result<(Socket, TransportState, [u8; 32]), ClientError> {
    let (mut ws, _) = connect_async(url).await?;
    let mut state = Builder::new(params())
        .local_private_key(&private)
        .map_err(|e| ClientError::Noise(e.to_string()))?
        .remote_public_key(&repeater_public)
        .map_err(|e| ClientError::Noise(e.to_string()))?
        .build_initiator()
        .map_err(|e| ClientError::Noise(e.to_string()))?;
    let mut message = vec![0; u16::MAX as usize];
    let n = state
        .write_message(&serde_json::to_vec(&payload)?, &mut message)
        .map_err(|e| ClientError::Noise(e.to_string()))?;
    ws.send(Message::Binary(message[..n].to_vec())).await?;
    let Some(message) = ws.next().await else {
        return Err(ClientError::Protocol);
    };
    let Message::Binary(message) = message? else {
        return Err(ClientError::Protocol);
    };
    if message.len() > MAX_MESSAGE {
        return Err(ClientError::Protocol);
    }
    let mut plaintext = vec![0; u16::MAX as usize];
    let n = state
        .read_message(&message, &mut plaintext)
        .map_err(|e| ClientError::Noise(e.to_string()))?;
    let reply: serde_json::Value = serde_json::from_slice(&plaintext[..n])?;
    if reply.get("ok") != Some(&serde_json::Value::Bool(true)) {
        return Err(ClientError::Protocol);
    }
    let public = entangle_transport::public_key(&private);
    Ok((
        ws,
        state
            .into_transport_mode()
            .map_err(|e| ClientError::Noise(e.to_string()))?,
        public,
    ))
}

/// Establishes a repeater session with a pinned server key and self-declared group.
///
/// The group is ephemeral routing metadata and is not persisted by the repeater.
pub async fn connect(
    url: &str,
    private: [u8; 32],
    repeater_public: [u8; 32],
    group: &str,
) -> Result<RepeaterClient, ClientError> {
    let (ws, noise, static_public) = handshake(
        url,
        private,
        repeater_public,
        json!({"v": 1, "mode": "session", "group": group}),
    )
    .await?;
    Ok(start_session(ws, noise, static_public))
}

/// Enrolls the particle's static key with a single-use invitation.
///
/// The repeater does not retain the invitation secret after enrollment.
pub async fn enroll(
    url: &str,
    private: [u8; 32],
    repeater_public: [u8; 32],
    secret: [u8; 32],
    label: Option<&str>,
) -> Result<(), ClientError> {
    let (mut ws, _, _) = handshake(
        url,
        private,
        repeater_public,
        json!({"v": 1, "mode": "enroll", "invite": hex::encode(secret), "label": label}),
    )
    .await?;
    let _ = ws.close(None).await;
    Ok(())
}

/// Requests host approval for this device over the unauthenticated request path.
pub async fn request<F>(
    url: &str,
    private: [u8; 32],
    label: Option<&str>,
    on_sas: F,
) -> Result<RequestOutcome, ClientError>
where
    F: FnOnce([u8; 32], sas::Sas) + Send,
{
    tokio::time::timeout(
        Duration::from_secs(10 * 60 + 30),
        request_inner(url, private, label, on_sas),
    )
    .await
    .map_err(|_| ClientError::RequestTimeout)?
}

async fn request_inner<F>(
    url: &str,
    private: [u8; 32],
    label: Option<&str>,
    on_sas: F,
) -> Result<RequestOutcome, ClientError>
where
    F: FnOnce([u8; 32], sas::Sas) + Send,
{
    let request_url = request_url(url);
    let (mut ws, mut transport, repeater_public) =
        request_handshake_with_timeout(&request_url, private, label, HANDSHAKE_TIMEOUT).await?;
    let reply = recv_request_json(&mut ws, &mut transport).await?;
    if reply.get("ok") != Some(&serde_json::Value::Bool(true)) {
        if reply.get("error").and_then(serde_json::Value::as_str) == Some("busy") {
            return Err(ClientError::Busy);
        }
        return Err(ClientError::Protocol);
    }
    let device_public = entangle_transport::public_key(&private);
    let short_authentication_string =
        sas_exchange_client(&mut ws, &mut transport, device_public, repeater_public).await?;
    on_sas(repeater_public, short_authentication_string);

    let outcome = wait_for_request_outcome(&mut ws, &mut transport, repeater_public).await?;
    let _ = ws.close(None).await;
    Ok(outcome)
}

fn request_url(url: &str) -> String {
    let (base, query) = url.split_once('?').unwrap_or((url, ""));
    let base = base.trim_end_matches('/');
    if query.is_empty() {
        format!("{base}/request")
    } else {
        format!("{base}/request?{query}")
    }
}

async fn request_handshake_with_timeout(
    url: &str,
    private: [u8; 32],
    label: Option<&str>,
    timeout: Duration,
) -> Result<(Socket, TransportState, [u8; 32]), ClientError> {
    tokio::time::timeout(timeout, async {
        let (mut ws, _) = connect_async(url).await?;
        let mut state = Builder::new(
            "Noise_XX_25519_ChaChaPoly_BLAKE2s"
                .parse()
                .expect("valid request Noise pattern"),
        )
        .local_private_key(&private)
        .map_err(|error| ClientError::Noise(error.to_string()))?
        .build_initiator()
        .map_err(|error| ClientError::Noise(error.to_string()))?;
        let mut message = vec![0; u16::MAX as usize];
        let size = state
            .write_message(&[], &mut message)
            .map_err(|error| ClientError::Noise(error.to_string()))?;
        ws.send(Message::Binary(message[..size].to_vec())).await?;
        let Some(Message::Binary(message)) = ws.next().await.transpose()? else {
            return Err(ClientError::Protocol);
        };
        let mut plaintext = vec![0; u16::MAX as usize];
        state
            .read_message(&message, &mut plaintext)
            .map_err(|error| ClientError::Noise(error.to_string()))?;
        let repeater_public: [u8; 32] = state
            .get_remote_static()
            .and_then(|key| key.try_into().ok())
            .ok_or_else(|| ClientError::Protocol)?;
        let mut message = vec![0; u16::MAX as usize];
        let size = state
            .write_message(
                &serde_json::to_vec(&json!({"v": 1, "mode": "request", "label": label}))?,
                &mut message,
            )
            .map_err(|error| ClientError::Noise(error.to_string()))?;
        ws.send(Message::Binary(message[..size].to_vec())).await?;
        let transport = state
            .into_transport_mode()
            .map_err(|error| ClientError::Noise(error.to_string()))?;
        Ok((ws, transport, repeater_public))
    })
    .await
    .map_err(|_| ClientError::HandshakeTimeout)?
}

async fn send_request_json(
    ws: &mut Socket,
    transport: &mut TransportState,
    value: &serde_json::Value,
) -> Result<(), ClientError> {
    let mut encrypted = vec![0; MAX_MESSAGE];
    let size = transport
        .write_message(&serde_json::to_vec(value)?, &mut encrypted)
        .map_err(|error| ClientError::Noise(error.to_string()))?;
    ws.send(Message::Binary(encrypted[..size].to_vec())).await?;
    Ok(())
}

async fn recv_request_json(
    ws: &mut Socket,
    transport: &mut TransportState,
) -> Result<serde_json::Value, ClientError> {
    let Some(message) = ws.next().await else {
        return Err(ClientError::SessionClosed);
    };
    let Message::Binary(message) = message? else {
        return Err(ClientError::Protocol);
    };
    let mut plaintext = vec![0; u16::MAX as usize];
    let size = transport
        .read_message(&message, &mut plaintext)
        .map_err(|error| ClientError::Noise(error.to_string()))?;
    Ok(serde_json::from_slice(&plaintext[..size])?)
}

async fn sas_exchange_client(
    ws: &mut Socket,
    transport: &mut TransportState,
    local: [u8; 32],
    remote: [u8; 32],
) -> Result<sas::Sas, ClientError> {
    let role = sas::role(&local, &remote).ok_or(ClientError::Protocol)?;
    let mut nonce = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    match role {
        sas::Role::Committer => {
            let commit = sas::commitment(&nonce, &local, &remote);
            send_request_json(ws, transport, &json!({"commit": hex::encode(commit)})).await?;
            let remote_nonce =
                parse_request_bytes(&recv_request_json(ws, transport).await?, "nonce")?;
            send_request_json(ws, transport, &json!({"nonce": hex::encode(nonce)})).await?;
            Ok(sas::derive(&local, &remote, &nonce, &remote_nonce))
        }
        sas::Role::Revealer => {
            let commit = parse_request_bytes(&recv_request_json(ws, transport).await?, "commit")?;
            send_request_json(ws, transport, &json!({"nonce": hex::encode(nonce)})).await?;
            let remote_nonce =
                parse_request_bytes(&recv_request_json(ws, transport).await?, "nonce")?;
            if !crate::server::verify_sas_commitment(&commit, &remote_nonce, &remote, &local) {
                return Err(ClientError::Protocol);
            }
            Ok(sas::derive(&remote, &local, &remote_nonce, &nonce))
        }
    }
}

fn parse_request_bytes(value: &serde_json::Value, field: &str) -> Result<[u8; 32], ClientError> {
    let text = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or(ClientError::Protocol)?;
    hex::decode(text)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ClientError::Protocol)
}

async fn wait_for_request_outcome(
    ws: &mut Socket,
    transport: &mut TransportState,
    repeater_public: [u8; 32],
) -> Result<RequestOutcome, ClientError> {
    loop {
        let Some(message) = ws.next().await else {
            return Err(ClientError::SessionClosed);
        };
        match message? {
            Message::Ping(payload) => {
                ws.send(Message::Pong(payload)).await?;
            }
            Message::Binary(message) => {
                let reply = recv_request_json_from_message(transport, &message)?;
                let approved = reply
                    .get("approved")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or(ClientError::Protocol)?;
                return Ok(if approved {
                    RequestOutcome::Approved { repeater_public }
                } else {
                    RequestOutcome::Denied
                });
            }
            Message::Close(_) => return Err(ClientError::SessionClosed),
            _ => {}
        }
    }
}

fn recv_request_json_from_message(
    transport: &mut TransportState,
    message: &[u8],
) -> Result<serde_json::Value, ClientError> {
    let mut plaintext = vec![0; u16::MAX as usize];
    let size = transport
        .read_message(message, &mut plaintext)
        .map_err(|error| ClientError::Noise(error.to_string()))?;
    Ok(serde_json::from_slice(&plaintext[..size])?)
}

fn start_session(ws: Socket, noise: TransportState, static_public: [u8; 32]) -> RepeaterClient {
    let (outgoing, outgoing_rx) = mpsc::channel::<Frame>(128);
    let (control_tx, control) = mpsc::channel(32);
    let (incoming_tx, incoming) = mpsc::channel(INCOMING_QUEUE_CAPACITY);
    let (shutdown, mut shutdown_rx) = oneshot::channel();
    let routes: Routes = Arc::new(Mutex::new(HashMap::new()));
    let (session_shutdown, watch_rx) = watch::channel(false);
    let noise = Arc::new(StdMutex::new(noise));
    let client_shutdown = watch_rx.clone();
    let (sink, stream) = ws.split();
    let writer_noise = Arc::clone(&noise);
    let mut writer = tokio::spawn(client_writer(
        sink,
        outgoing_rx,
        writer_noise,
        watch_rx.clone(),
    ));
    let reader_routes = routes.clone();
    let reader_outgoing = outgoing.clone();
    let mut reader = tokio::spawn(client_reader(
        stream,
        noise,
        control_tx,
        incoming_tx,
        reader_routes,
        reader_outgoing,
        watch_rx,
    ));
    let pump_routes = routes.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = &mut shutdown_rx => {
                let _ = session_shutdown.send(true);
                let _ = writer.await;
                let _ = reader.await;
            }
            _ = &mut writer => {
                let _ = session_shutdown.send(true);
                let _ = reader.await;
            }
            _ = &mut reader => {
                let _ = session_shutdown.send(true);
                let _ = writer.await;
            }
        }
        pump_routes.lock().await.clear();
    });
    RepeaterClient {
        inner: Arc::new(DialerInner {
            outgoing,
            control: Mutex::new(control),
            routes,
            session_shutdown: client_shutdown,
            next_stream: AtomicU32::new(1),
            list_lock: Mutex::new(()),
            _shutdown: Some(shutdown),
        }),
        incoming: IncomingStreams { incoming },
        static_public,
    }
}

async fn send_or_shutdown<T: Send>(
    queue: &mpsc::Sender<T>,
    value: T,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        changed = shutdown.changed() => {
            let _ = changed;
            false
        }
        result = queue.send(value) => result.is_ok(),
    }
}

fn encrypt_frame(noise: &StdMutex<TransportState>, frame: &Frame) -> io::Result<Vec<u8>> {
    let plaintext = frame
        .encode()
        .map_err(|_| io::Error::other("invalid frame"))?;
    let mut encrypted = vec![0; MAX_MESSAGE];
    let size = noise
        .lock()
        .map_err(|_| io::Error::other("Noise state lock poisoned"))?
        .write_message(&plaintext, &mut encrypted)
        .map_err(|error| io::Error::other(error.to_string()))?;
    encrypted.truncate(size);
    Ok(encrypted)
}

fn decrypt_frame(noise: &StdMutex<TransportState>, encrypted: &[u8]) -> io::Result<Frame> {
    if encrypted.len() > MAX_MESSAGE {
        return Err(io::Error::other("message too large"));
    }
    let mut plaintext = vec![0; u16::MAX as usize];
    let size = noise
        .lock()
        .map_err(|_| io::Error::other("Noise state lock poisoned"))?
        .read_message(encrypted, &mut plaintext)
        .map_err(|error| io::Error::other(error.to_string()))?;
    Frame::decode(&plaintext[..size]).map_err(|_| io::Error::other("invalid frame"))
}

async fn client_writer(
    mut sink: futures_util::stream::SplitSink<Socket, Message>,
    mut outgoing: mpsc::Receiver<Frame>,
    noise: Arc<StdMutex<TransportState>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
    heartbeat.tick().await;
    loop {
        let frame = tokio::select! {
            changed = shutdown.changed() => {
                let _ = changed;
                return;
            }
            frame = outgoing.recv() => match frame {
                Some(frame) => frame,
                None => return,
            },
            _ = heartbeat.tick() => {
                Frame {
                    kind: PING,
                    stream: SESSION_STREAM,
                    body: Vec::new(),
                }
            }
        };
        let Ok(encrypted) = encrypt_frame(&noise, &frame) else {
            return;
        };
        tokio::select! {
            changed = shutdown.changed() => {
                let _ = changed;
                return;
            }
            result = sink.send(Message::Binary(encrypted)) => {
                if result.is_err() {
                    return;
                }
            }
        }
    }
}

async fn client_reader(
    mut stream: futures_util::stream::SplitStream<Socket>,
    noise: Arc<StdMutex<TransportState>>,
    control: mpsc::Sender<Frame>,
    incoming: mpsc::Sender<IncomingStream>,
    routes: Routes,
    outgoing: mpsc::Sender<Frame>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut silence_deadline = Box::pin(tokio::time::sleep(Duration::from_secs(60)));
    loop {
        let message = tokio::select! {
            _ = &mut silence_deadline => return,
            changed = shutdown.changed() => {
                let _ = changed;
                return;
            }
            message = stream.next() => message,
        };
        let Some(message) = message else {
            return;
        };
        let Ok(Message::Binary(message)) = message else {
            return;
        };
        silence_deadline
            .as_mut()
            .reset(tokio::time::Instant::now() + Duration::from_secs(60));
        let Ok(frame) = decrypt_frame(&noise, &message) else {
            return;
        };
        match frame.kind {
            PONG => {}
            OPEN_FAIL => {
                let route = routes.lock().await.get(&frame.stream).cloned();
                if let Some(route) = route {
                    if !send_or_shutdown(
                        &route,
                        Frame {
                            kind: CLOSE,
                            stream: frame.stream,
                            body: Vec::new(),
                        },
                        &mut shutdown,
                    )
                    .await
                    {
                        return;
                    }
                } else if !send_or_shutdown(&control, frame, &mut shutdown).await {
                    return;
                }
            }
            INCOMING => {
                let Ok(source) = <[u8; 32]>::try_from(frame.body.as_slice()) else {
                    if !send_or_shutdown(
                        &outgoing,
                        Frame {
                            kind: CLOSE,
                            stream: frame.stream,
                            body: Vec::new(),
                        },
                        &mut shutdown,
                    )
                    .await
                    {
                        return;
                    }
                    continue;
                };
                let (stream, pump) =
                    make_stream(frame.stream, &routes, &outgoing, shutdown.clone()).await;
                if let Err(error) = incoming.try_send(IncomingStream { source, stream }) {
                    pump.abort();
                    routes.lock().await.remove(&frame.stream);
                    drop(error.into_inner());
                    debug!(
                        stream_id = frame.stream,
                        "closing incoming repeater stream because the accept queue is unavailable"
                    );
                    if !send_or_shutdown(
                        &outgoing,
                        Frame {
                            kind: CLOSE,
                            stream: frame.stream,
                            body: Vec::new(),
                        },
                        &mut shutdown,
                    )
                    .await
                    {
                        return;
                    }
                }
            }
            DATA | CLOSE => {
                let route = routes.lock().await.get(&frame.stream).cloned();
                if let Some(route) = route {
                    if !send_or_shutdown(&route, frame, &mut shutdown).await {
                        return;
                    }
                } else if frame.stream == SESSION_STREAM
                    && !send_or_shutdown(&control, frame, &mut shutdown).await
                {
                    return;
                }
            }
            PING => {
                if !send_or_shutdown(
                    &outgoing,
                    Frame {
                        kind: PONG,
                        stream: frame.stream,
                        body: Vec::new(),
                    },
                    &mut shutdown,
                )
                .await
                {
                    return;
                }
            }
            _ => {
                if !send_or_shutdown(&control, frame, &mut shutdown).await {
                    return;
                }
            }
        }
    }
}

async fn make_stream(
    id: u32,
    routes: &Routes,
    outgoing: &mpsc::Sender<Frame>,
    mut shutdown: watch::Receiver<bool>,
) -> (RepeaterStream, tokio::task::JoinHandle<()>) {
    let (app, pump) = tokio::io::duplex(64 * 1024);
    let (route_tx, mut route_rx) = mpsc::channel(32);
    routes.lock().await.insert(id, route_tx);
    let (mut read, mut write) = tokio::io::split(pump);
    let output = outgoing.clone();
    let routes = routes.clone();
    let pump_task = tokio::spawn(async move {
        let mut buffer = vec![0; crate::wire::MAX_DATA];
        let mut read_shutdown = shutdown.clone();
        let mut route_shutdown = shutdown.clone();
        let mut local_closed = false;
        let mut remote_closed = false;
        loop {
            if local_closed && remote_closed {
                break;
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    let _ = changed;
                    let _ = write.shutdown().await;
                    break;
                }
                read_result = read.read(&mut buffer), if !local_closed => {
                    match read_result {
                        Ok(0) => {
                            if !send_or_shutdown(&output, Frame {
                                kind: CLOSE,
                                stream: id,
                                body: Vec::new(),
                            }, &mut read_shutdown).await {
                                break;
                            }
                            local_closed = true;
                        }
                        Ok(size) => {
                            if !send_or_shutdown(&output, Frame {
                                kind: DATA,
                                stream: id,
                                body: buffer[..size].to_vec(),
                            }, &mut read_shutdown).await {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                frame = route_rx.recv(), if !remote_closed => {
                    match frame {
                        Some(frame) => match frame.kind {
                            DATA => {
                                let result = tokio::select! {
                                    changed = route_shutdown.changed() => {
                                        let _ = changed;
                                        let _ = write.shutdown().await;
                                        break;
                                    }
                                    result = write.write_all(&frame.body) => result,
                                };
                                if result.is_err() { break; }
                            }
                            CLOSE => {
                                let _ = write.shutdown().await;
                                remote_closed = true;
                            }
                            _ => {}
                        },
                        None => {
                            let _ = write.shutdown().await;
                            break;
                        }
                    }
                }
            }
        }
        routes.lock().await.remove(&id);
    });
    (
        RepeaterStream {
            id,
            io: Box::new(app),
        },
        pump_task,
    )
}

impl RepeaterClient {
    /// Lists other live sessions in the group's ephemeral directory.
    pub async fn list(&mut self) -> Result<Vec<serde_json::Value>, ClientError> {
        let frame = self.inner.list_frame().await?;
        serde_json::from_slice(&frame.body).map_err(Into::into)
    }

    /// Queues a protocol frame for the session writer.
    pub async fn send_frame(&mut self, frame: Frame) -> Result<(), ClientError> {
        self.inner
            .outgoing
            .send(frame)
            .await
            .map_err(|_| ClientError::SessionClosed)
    }

    /// Waits for a control frame that is not associated with an open stream.
    pub async fn recv_frame(&mut self) -> Result<Frame, ClientError> {
        self.inner
            .control
            .lock()
            .await
            .recv()
            .await
            .ok_or(ClientError::SessionClosed)
    }

    /// Opens an opaque byte stream to another enrolled session.
    pub async fn open(&mut self, target: [u8; 32]) -> Result<RepeaterStream, ClientError> {
        self.inner.open(target).await
    }

    /// Waits for an incoming stream opened by another session.
    pub async fn accept(&mut self) -> Result<RepeaterStream, ClientError> {
        self.incoming
            .accept()
            .await
            .map(|incoming| incoming.stream)
            .ok_or(ClientError::SessionClosed)
    }

    /// Splits this session into a shared dialer and an incoming-stream receiver.
    pub fn split(self) -> (RepeaterDialer, IncomingStreams) {
        (
            RepeaterDialer {
                inner: Arc::clone(&self.inner),
            },
            self.incoming,
        )
    }
}

impl DialerInner {
    async fn list_frame(&self) -> Result<Frame, ClientError> {
        let _guard = self.list_lock.lock().await;
        if *self.session_shutdown.borrow() {
            return Err(ClientError::SessionClosed);
        }
        self.outgoing
            .send(Frame {
                kind: LIST,
                stream: SESSION_STREAM,
                body: Vec::new(),
            })
            .await
            .map_err(|_| ClientError::SessionClosed)?;
        let frame = self
            .control
            .lock()
            .await
            .recv()
            .await
            .ok_or(ClientError::SessionClosed)?;
        if frame.kind != LIST_REPLY {
            return Err(ClientError::Protocol);
        }
        Ok(frame)
    }

    async fn open(&self, target: [u8; 32]) -> Result<RepeaterStream, ClientError> {
        if *self.session_shutdown.borrow() {
            return Err(ClientError::SessionClosed);
        }
        let id = allocate_stream_id(&self.next_stream);
        let (stream, _pump) = make_stream(
            id,
            &self.routes,
            &self.outgoing,
            self.session_shutdown.clone(),
        )
        .await;
        self.outgoing
            .send(Frame {
                kind: OPEN,
                stream: id,
                body: target.to_vec(),
            })
            .await
            .map_err(|_| ClientError::SessionClosed)?;
        if *self.session_shutdown.borrow() {
            return Err(ClientError::SessionClosed);
        }
        Ok(stream)
    }
}

fn allocate_stream_id(next_stream: &AtomicU32) -> u32 {
    loop {
        let candidate = next_stream.fetch_add(1, Ordering::Relaxed) & !crate::wire::INCOMING_BIT;
        if candidate != SESSION_STREAM {
            return candidate;
        }
    }
}

impl RepeaterDialer {
    /// Opens an opaque byte stream to another enrolled session.
    ///
    /// The protocol has no positive OPEN acknowledgement. This returns after
    /// queuing OPEN; a rejected stream is closed and the end-to-end Noise
    /// handshake observes EOF. Waiting for DATA would deadlock because Noise
    /// cannot send it until this method returns the stream.
    pub async fn open(&self, target: [u8; 32]) -> Result<RepeaterStream, ClientError> {
        self.inner.open(target).await
    }

    /// Lists live sessions in this group's ephemeral directory.
    pub async fn list(&self) -> Result<Vec<DirectoryEntry>, ClientError> {
        let frame = self.inner.list_frame().await?;
        let raw: Vec<serde_json::Value> = serde_json::from_slice(&frame.body)?;
        raw.into_iter()
            .map(|entry| {
                let key = entry
                    .get("key")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(ClientError::Protocol)?;
                let key = hex::decode(key)
                    .map_err(|_| ClientError::Protocol)?
                    .try_into()
                    .map_err(|_| ClientError::Protocol)?;
                let since_secs = entry
                    .get("since_secs")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or(ClientError::Protocol)?;
                Ok(DirectoryEntry { key, since_secs })
            })
            .collect()
    }

    /// Reports whether the session reader or writer has exited.
    pub fn is_closed(&self) -> bool {
        *self.inner.session_shutdown.borrow()
    }
}

impl IncomingStreams {
    /// Waits for an incoming stream, returning `None` when the session ends.
    pub async fn accept(&mut self) -> Option<IncomingStream> {
        self.incoming.recv().await
    }

    #[cfg(test)]
    pub(crate) fn queued(&self) -> usize {
        self.incoming.len()
    }
}

impl RepeaterStream {
    /// Returns the relayed stream for use with `entangle_transport`.
    pub fn into_io(self) -> BoxedIo {
        self.io
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    #[test]
    fn request_url_handles_trailing_slashes_and_queries() {
        assert_eq!(
            request_url("ws://repeater.example/entangle/"),
            "ws://repeater.example/entangle/request"
        );
        assert_eq!(
            request_url("wss://repeater.example/entangle?token=abc"),
            "wss://repeater.example/entangle/request?token=abc"
        );
    }

    #[test]
    fn stream_id_allocator_skips_reserved_session_id_on_wrap() {
        let next_stream = AtomicU32::new(u32::MAX);
        assert_eq!(allocate_stream_id(&next_stream), 0x7fff_ffff);
        assert_eq!(allocate_stream_id(&next_stream), 1);
    }

    #[tokio::test]
    async fn handshake_times_out_after_silent_websocket_upgrade() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _websocket = accept_async(stream).await.unwrap();
            std::future::pending::<()>().await;
        });
        let result = handshake_with_timeout(
            &format!("ws://{address}/entangle"),
            entangle_transport::generate_static(),
            [0; 32],
            json!({"v": 1, "mode": "session", "group": "aaaaaaaa"}),
            Duration::from_millis(50),
        )
        .await;
        assert!(matches!(result, Err(ClientError::HandshakeTimeout)));
        server.abort();
    }
}
