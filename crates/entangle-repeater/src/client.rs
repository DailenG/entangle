//! Client-side Noise handshake and asynchronous stream multiplexer.

use crate::wire::{Frame, MAX_MESSAGE};
use entangle_transport::BoxedIo;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use snow::{params::NoiseParams, Builder, TransportState};
use std::{collections::HashMap, io};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, oneshot, Mutex},
    time::Duration,
};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

const NOISE: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("repeater WebSocket failed: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("repeater I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("repeater Noise failed: {0}")]
    Noise(String),
    #[error("repeater protocol error")]
    Protocol,
    #[error("repeater JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
type Routes = std::sync::Arc<Mutex<HashMap<u32, mpsc::Sender<Frame>>>>;

pub struct RepeaterClient {
    outgoing: mpsc::Sender<Frame>,
    control: mpsc::Receiver<Frame>,
    incoming: mpsc::Receiver<RepeaterStream>,
    routes: Routes,
    shutdown: Option<oneshot::Sender<()>>,
    pub static_public: [u8; 32],
    next_stream: u32,
}

pub struct RepeaterStream {
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

fn start_session(ws: Socket, mut noise: TransportState, static_public: [u8; 32]) -> RepeaterClient {
    let (outgoing, mut outgoing_rx) = mpsc::channel::<Frame>(128);
    let (control_tx, control) = mpsc::channel(32);
    let (incoming_tx, incoming) = mpsc::channel(32);
    let (shutdown, mut shutdown_rx) = oneshot::channel();
    let routes: Routes = std::sync::Arc::new(Mutex::new(HashMap::new()));
    let pump_routes = routes.clone();
    let pump_outgoing = outgoing.clone();
    tokio::spawn(async move {
        let mut ws = ws;
        let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
        heartbeat.tick().await;
        let silence_deadline = tokio::time::sleep(Duration::from_secs(60));
        tokio::pin!(silence_deadline);
        loop {
            tokio::select! {
                _ = &mut silence_deadline => break,
                Some(frame) = outgoing_rx.recv() => {
                    let Ok(plain) = frame.encode() else { continue };
                    let mut encrypted = vec![0; u16::MAX as usize];
                    let Ok(size) = noise.write_message(&plain, &mut encrypted) else { break };
                    if ws.send(Message::Binary(encrypted[..size].to_vec())).await.is_err() {
                        break;
                    }
                }
                Some(message) = ws.next() => {
                    let Ok(Message::Binary(message)) = message else { break };
                    if message.len() > MAX_MESSAGE {
                        break;
                    }
                    silence_deadline.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(60));
                    let mut plain = vec![0; u16::MAX as usize];
                    let Ok(size) = noise.read_message(&message, &mut plain) else { break };
                    let Ok(frame) = Frame::decode(&plain[..size]) else { break };
                    if frame.kind == 9 {
                        continue;
                    } else if frame.kind == 5 {
                        let route = pump_routes.lock().await.remove(&frame.stream);
                        if let Some(route) = route {
                            let _ = route
                                .send(Frame { kind: 4, stream: frame.stream, body: Vec::new() })
                                .await;
                        } else if control_tx.send(frame).await.is_err() {
                            break;
                        }
                    } else if frame.kind == 2 {
                        let stream = make_stream(frame.stream, &pump_routes, &pump_outgoing).await;
                        if incoming_tx.send(stream).await.is_err() {
                            break;
                        }
                    } else if matches!(frame.kind, 3 | 4) {
                        let route = pump_routes.lock().await.get(&frame.stream).cloned();
                        if let Some(route) = route {
                            let _ = route.send(frame).await;
                        } else if control_tx.send(frame).await.is_err() {
                            break;
                        }
                    } else if control_tx.send(frame).await.is_err() {
                        break;
                    }
                }
                _ = heartbeat.tick() => {
                    let Ok(plain) = (Frame { kind: 8, stream: 0, body: Vec::new() }).encode() else { break };
                    let mut encrypted = vec![0; u16::MAX as usize];
                    let Ok(size) = noise.write_message(&plain, &mut encrypted) else { break };
                    if ws.send(Message::Binary(encrypted[..size].to_vec())).await.is_err() {
                        break;
                    }
                }
                _ = &mut shutdown_rx => break,
                else => break,
            }
        }
    });
    RepeaterClient {
        outgoing,
        control,
        incoming,
        routes,
        shutdown: Some(shutdown),
        static_public,
        next_stream: 0,
    }
}

async fn make_stream(id: u32, routes: &Routes, outgoing: &mpsc::Sender<Frame>) -> RepeaterStream {
    let (app, pump) = tokio::io::duplex(64 * 1024);
    let (route_tx, mut route_rx) = mpsc::channel(32);
    routes.lock().await.insert(id, route_tx);
    let (mut read, mut write) = tokio::io::split(pump);
    let output = outgoing.clone();
    let routes = routes.clone();
    tokio::spawn(async move {
        let mut buffer = vec![0; crate::wire::MAX_DATA];
        loop {
            tokio::select! {
                read_result = read.read(&mut buffer) => {
                    match read_result {
                        Ok(0) => {
                            let _ = output.send(Frame { kind: 4, stream: id, body: Vec::new() }).await;
                            break;
                        }
                        Ok(size) => {
                            if output.send(Frame { kind: 3, stream: id, body: buffer[..size].to_vec() }).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                Some(frame) = route_rx.recv() => {
                    match frame.kind {
                        3 => if write.write_all(&frame.body).await.is_err() { break; },
                        4 => {
                            let _ = write.shutdown().await;
                            break;
                        }
                        _ => {}
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
            kind: 6,
            stream: 0,
            body: Vec::new(),
        })
        .await?;
        let frame = self.recv_frame().await?;
        if frame.kind != 7 {
            return Err(ClientError::Protocol);
        }
        serde_json::from_slice(&frame.body).map_err(Into::into)
    }

    pub async fn send_frame(&mut self, frame: Frame) -> Result<(), ClientError> {
        self.outgoing
            .send(frame)
            .await
            .map_err(|_| ClientError::Protocol)
    }

    pub async fn recv_frame(&mut self) -> Result<Frame, ClientError> {
        self.control.recv().await.ok_or(ClientError::Protocol)
    }

    /// Opens an opaque byte stream to another enrolled session.
    pub async fn open(&mut self, target: [u8; 32]) -> Result<RepeaterStream, ClientError> {
        let id = self.next_stream & 0x7fff_ffff;
        self.next_stream = self.next_stream.wrapping_add(1) & 0x7fff_ffff;
        let stream = make_stream(id, &self.routes, &self.outgoing).await;
        self.send_frame(Frame {
            kind: 1,
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
