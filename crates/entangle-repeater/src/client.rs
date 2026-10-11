//! Client-side Noise handshake and asynchronous stream multiplexer.

use crate::wire::{
    Frame, CLOSE, DATA, INCOMING, LIST, LIST_REPLY, MAX_MESSAGE, OPEN, OPEN_FAIL, PING, PONG,
    SESSION_STREAM,
};
use entangle_transport::BoxedIo;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use snow::{params::NoiseParams, Builder, TransportState};
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex as StdMutex},
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, oneshot, watch, Mutex},
    time::Duration,
};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

const NOISE: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

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
    /// A protocol JSON payload could not be encoded or decoded.
    #[error("repeater JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<tokio_tungstenite::tungstenite::Error> for ClientError {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::WebSocket(Box::new(error))
    }
}

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
type Routes = std::sync::Arc<Mutex<HashMap<u32, mpsc::Sender<Frame>>>>;

/// An authenticated client session to a repeater.
pub struct RepeaterClient {
    outgoing: mpsc::Sender<Frame>,
    control: mpsc::Receiver<Frame>,
    incoming: mpsc::Receiver<RepeaterStream>,
    routes: Routes,
    shutdown: Option<oneshot::Sender<()>>,
    session_shutdown: watch::Receiver<bool>,
    /// This session's Noise static public key.
    pub static_public: [u8; 32],
    next_stream: u32,
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

fn start_session(ws: Socket, noise: TransportState, static_public: [u8; 32]) -> RepeaterClient {
    let (outgoing, outgoing_rx) = mpsc::channel::<Frame>(128);
    let (control_tx, control) = mpsc::channel(32);
    let (incoming_tx, incoming) = mpsc::channel(32);
    let (shutdown, mut shutdown_rx) = oneshot::channel();
    let routes: Routes = std::sync::Arc::new(Mutex::new(HashMap::new()));
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
        outgoing,
        control,
        incoming,
        routes,
        shutdown: Some(shutdown),
        session_shutdown: client_shutdown,
        static_public,
        next_stream: 0,
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
    incoming: mpsc::Sender<RepeaterStream>,
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
                let route = routes.lock().await.remove(&frame.stream);
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
                let stream = make_stream(frame.stream, &routes, &outgoing, shutdown.clone()).await;
                if !send_or_shutdown(&incoming, stream, &mut shutdown).await {
                    return;
                }
            }
            DATA | CLOSE => {
                let route = routes.lock().await.get(&frame.stream).cloned();
                if let Some(route) = route {
                    if !send_or_shutdown(&route, frame, &mut shutdown).await {
                        return;
                    }
                } else if !send_or_shutdown(&control, frame, &mut shutdown).await {
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
) -> RepeaterStream {
    let (app, pump) = tokio::io::duplex(64 * 1024);
    let (route_tx, mut route_rx) = mpsc::channel(32);
    routes.lock().await.insert(id, route_tx);
    let (mut read, mut write) = tokio::io::split(pump);
    let output = outgoing.clone();
    let routes = routes.clone();
    tokio::spawn(async move {
        let mut buffer = vec![0; crate::wire::MAX_DATA];
        let mut read_shutdown = shutdown.clone();
        let mut route_shutdown = shutdown.clone();
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    let _ = changed;
                    let _ = write.shutdown().await;
                    break;
                }
                read_result = read.read(&mut buffer) => {
                    match read_result {
                        Ok(0) => {
                            let _ = output.send(Frame { kind: CLOSE, stream: id, body: Vec::new() }).await;
                            break;
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
                frame = route_rx.recv() => {
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
                                break;
                            }
                            _ => {}
                        },
                        None => {
                            let _ = write.shutdown().await;
                            break;
                        }
                    }
                }
                else => break,
            }
        }
        routes.lock().await.remove(&id);
    });
    RepeaterStream {
        id,
        io: Box::new(app),
    }
}

impl RepeaterClient {
    /// Lists other live sessions in the group's ephemeral directory.
    pub async fn list(&mut self) -> Result<Vec<serde_json::Value>, ClientError> {
        self.send_frame(Frame {
            kind: LIST,
            stream: SESSION_STREAM,
            body: Vec::new(),
        })
        .await?;
        let frame = self.recv_frame().await?;
        if frame.kind != LIST_REPLY {
            return Err(ClientError::Protocol);
        }
        serde_json::from_slice(&frame.body).map_err(Into::into)
    }

    /// Queues a protocol frame for the session writer.
    pub async fn send_frame(&mut self, frame: Frame) -> Result<(), ClientError> {
        self.outgoing
            .send(frame)
            .await
            .map_err(|_| ClientError::Protocol)
    }

    /// Waits for a control frame that is not associated with an open stream.
    pub async fn recv_frame(&mut self) -> Result<Frame, ClientError> {
        self.control.recv().await.ok_or(ClientError::Protocol)
    }

    /// Opens an opaque byte stream to another enrolled session.
    pub async fn open(&mut self, target: [u8; 32]) -> Result<RepeaterStream, ClientError> {
        let id = self.next_stream & !crate::wire::INCOMING_BIT;
        self.next_stream = self.next_stream.wrapping_add(1) & !crate::wire::INCOMING_BIT;
        let stream = make_stream(
            id,
            &self.routes,
            &self.outgoing,
            self.session_shutdown.clone(),
        )
        .await;
        self.send_frame(Frame {
            kind: OPEN,
            stream: id,
            body: target.to_vec(),
        })
        .await?;
        Ok(stream)
    }

    /// Waits for an incoming stream opened by another session.
    pub async fn accept(&mut self) -> Result<RepeaterStream, ClientError> {
        self.incoming.recv().await.ok_or(ClientError::Protocol)
    }
}

impl RepeaterStream {
    /// Returns the relayed stream for use with `entangle_transport`.
    pub fn into_io(self) -> BoxedIo {
        self.io
    }
}

impl Drop for RepeaterClient {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}
