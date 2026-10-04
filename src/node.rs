//! Particle lifecycle, peer handshakes, local relay ownership, and inbound syncs.

use crate::{
    config::Options,
    field::{Field, PeerRecord, PeerState},
    inbox::InboxItem,
};
use anyhow::{Context, Result};
use chrono::Utc;
use entangle_core::{Manifest, ParticleId, RelayTicket, StateKind, PROTOCOL_VERSION};
use entangle_link::{LinkError, LinkHandler, LinkListener, SyncDecision, SyncOffer};
use entangle_resonance::{Advertisement, Resonance, ResonanceEvent, Resonator};
use entangle_transport::{Croc, LocalRelay, Secret};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::{lookup_host, TcpStream},
    sync::{mpsc, Mutex, Semaphore},
    time::sleep,
};
use tracing::{debug, info};

/// A single running Entangle process and its stateful local services.
pub struct Particle {
    /// This process manifest.
    pub manifest: Manifest,
    field: Arc<RwLock<Field>>,
    options: Options,
    croc: Croc,
    data_dir: PathBuf,
    relay: Mutex<Option<LocalRelay>>,
    resonator: Mutex<Option<Resonator>>,
    inbox: Mutex<Vec<InboxItem>>,
    notifications: Option<mpsc::Sender<Value>>,
    inbound_limit: Arc<Semaphore>,
}

struct SendPayload {
    peer: PeerRecord,
    target: Manifest,
    kind: StateKind,
    sync_id: String,
    path: PathBuf,
    name: String,
    args: Value,
    timeout_secs: u64,
}

impl Particle {
    /// Creates and starts the local listener, optional mDNS, and static peer dialer.
    pub async fn start(
        options: Options,
        notifications: Option<mpsc::Sender<Value>>,
    ) -> Result<(Arc<Self>, Manifest)> {
        let croc = Croc::locate(options.croc.clone())?;
        let particle_id = ParticleId::generate();
        let name = options.particle_name();
        let root = options.data_root().join(particle_id.short());
        let data_dir = root;
        tokio::fs::create_dir_all(data_dir.join("inbox")).await?;
        tokio::fs::create_dir_all(data_dir.join("outbox")).await?;
        let (listener, link_port) =
            LinkListener::bind(SocketAddr::from(([0, 0, 0, 0], options.link_port)))
                .await
                .context("could not bind Entangle TCP link listener")?;
        let manifest = Manifest {
            particle_id: particle_id.clone(),
            name: name.clone(),
            version: env!("CARGO_PKG_VERSION").into(),
            protocol: PROTOCOL_VERSION,
            link_port,
            context: options.context.clone(),
            tools: vec![
                "find_entangled_particles".into(),
                "sync_entangled_state".into(),
                "observe_entangled_states".into(),
            ],
            accepts: vec![StateKind::Json, StateKind::File],
            max_payload_bytes: options.max_payload_mb.saturating_mul(1024 * 1024),
        };
        let field = Arc::new(RwLock::new(Field::default()));
        let resonator = if options.no_mdns {
            None
        } else {
            Some(Resonator::start(Advertisement {
                particle_id,
                name,
                port: link_port,
                context: options.context.clone(),
                version: env!("CARGO_PKG_VERSION").into(),
            })?)
        };
        let (resonator, events) = match resonator {
            Some((daemon, events)) => (Some(daemon), Some(events)),
            None => (None, None),
        };
        let particle = Arc::new(Self {
            manifest: manifest.clone(),
            field,
            options,
            croc,
            data_dir,
            relay: Mutex::new(None),
            resonator: Mutex::new(resonator),
            inbox: Mutex::new(Vec::new()),
            notifications,
            inbound_limit: Arc::new(Semaphore::new(4)),
        });
        tokio::spawn(listener.run(particle.clone()));
        if let Some(mut events) = events {
            let peer_node = particle.clone();
            tokio::spawn(async move {
                while let Some(event) = events.recv().await {
                    match event {
                        ResonanceEvent::Detected(peer) => peer_node.on_detected(peer).await,
                        ResonanceEvent::Lost(id) => {
                            peer_node.field.write().expect("field lock").remove(&id);
                            info!("peer resonance lost: {}", id.short());
                        }
                    }
                }
            });
        }
        let static_node = particle.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                for peer in &static_node.options.peer {
                    if let Ok(addresses) = lookup_host(peer).await {
                        for address in addresses {
                            if static_node
                                .field
                                .read()
                                .expect("field lock")
                                .all()
                                .iter()
                                .any(|entry| {
                                    entry.state == PeerState::Entangled
                                        && entry.resonance.port == address.port()
                                })
                            {
                                continue;
                            }
                            static_node.dial(address, None).await;
                        }
                    }
                }
            }
        });
        if !particle.options.no_mdns {
            info!(
                "particle {} listening on TCP {}",
                particle.manifest.particle_id.short(),
                link_port
            );
        } else {
            info!(
                "particle {} listening on TCP {} (mDNS disabled)",
                particle.manifest.particle_id.short(),
                link_port
            );
        }
        Ok((particle, manifest))
    }

    /// Waits for Ctrl-C, used by the headless node command.
    pub async fn wait_for_shutdown(&self) {
        let _ = tokio::signal::ctrl_c().await;
    }

    /// Stops the owned relay and unregisters this particle from mDNS.
    pub async fn shutdown(&self) {
        if let Some(relay) = self.relay.lock().await.take() {
            let _ = relay.shutdown().await;
        }
        if let Some(resonator) = self.resonator.lock().await.take() {
            let _ = resonator.shutdown();
        }
    }

    /// Returns peers as MCP tool output.
    pub fn find_particles(&self, args: &Value) -> Value {
        let context = args.get("context").and_then(Value::as_str);
        let include_unentangled = args
            .get("include_unentangled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        json!({
            "self": self.manifest,
            "particles": self.field.read().expect("field lock").view(context, include_unentangled)
        })
    }

    /// Reads inbox entries, optionally consuming those returned to the caller.
    pub async fn observe(&self, args: &Value) -> Value {
        let limit = args
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(20)
            .clamp(1, 100) as usize;
        let since = args.get("since_sync_id").and_then(Value::as_str);
        let collapse = args
            .get("collapse")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let mut inbox = self.inbox.lock().await;
        let start = match since {
            Some(id) => inbox
                .iter()
                .position(|item| item.sync_id == id)
                .map_or(inbox.len(), |index| index + 1),
            None => 0,
        };
        let selected: Vec<_> = inbox.iter().skip(start).take(limit).cloned().collect();
        if collapse {
            let ids: Vec<_> = selected.iter().map(|item| item.sync_id.as_str()).collect();
            inbox.retain(|item| !ids.contains(&item.sync_id.as_str()));
        }
        let remaining = inbox.len();
        let states = selected
            .into_iter()
            .map(|item| {
                json!({
                    "sync_id": item.sync_id,
                    "from_particle_id": item.from_particle_id,
                    "from_name": item.from_name,
                    "kind": item.kind,
                    "label": item.label,
                    "received_at": item.received_at,
                    "bytes": item.bytes,
                    "sha256": item.sha256,
                    "state": item.state,
                    "path": item.path,
                    "text": item.text
                })
            })
            .collect::<Vec<_>>();
        json!({ "states": states, "remaining": remaining })
    }

    /// Sends a JSON or file payload to an already-entangled peer.
    pub async fn sync_state(&self, args: Value) -> Result<Value, String> {
        let peer_id = args
            .get("particle_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "particle_id is required".to_owned())?;
        let has_state = args.get("state").is_some();
        let has_file = args.get("file_path").is_some();
        if has_state == has_file {
            return Err("provide exactly one of state or file_path".into());
        }
        let peer = {
            let peers = self
                .field
                .read()
                .map_err(|_| "peer field lock poisoned".to_owned())?;
            let matched = peers.resolve(peer_id);
            if matched.is_empty() {
                return Err(format!("unknown particle: {peer_id}"));
            }
            if matched.len() > 1 {
                return Err(format!("ambiguous particle ID: {peer_id}"));
            }
            matched.into_iter().next().unwrap()
        };
        if peer.state != PeerState::Entangled {
            return Err(format!(
                "particle {} is not entangled",
                peer.resonance.particle_id.short()
            ));
        }
        let target = peer
            .manifest
            .clone()
            .ok_or_else(|| "peer manifest missing".to_owned())?;
        let kind = if has_state {
            StateKind::Json
        } else {
            StateKind::File
        };
        if !target.accepts.contains(&kind) {
            return Err(format!(
                "particle does not accept {} payloads",
                kind_name(&kind)
            ));
        }
        let timeout_secs = args
            .get("timeout_secs")
            .and_then(Value::as_u64)
            .unwrap_or(120)
            .clamp(5, 3600);
        let sync_id = uuid::Uuid::new_v4().simple().to_string();
        let (path, name, cleanup) = if has_state {
            let path = self.data_dir.join("outbox").join(format!("{sync_id}.json"));
            let bytes = serde_json::to_vec(&args["state"]).map_err(|e| e.to_string())?;
            tokio::fs::write(&path, bytes)
                .await
                .map_err(|e| e.to_string())?;
            (path, format!("{sync_id}.json"), true)
        } else {
            let input = PathBuf::from(args["file_path"].as_str().unwrap_or_default());
            let metadata = tokio::fs::metadata(&input)
                .await
                .map_err(|e| format!("cannot read file {}: {e}", input.display()))?;
            if !metadata.is_file() {
                return Err("file_path must name a single regular file; directories and symlinks to directories are not supported".into());
            }
            let name = input
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| "file_path has no valid filename".to_owned())?
                .to_owned();
            (input, name, false)
        };
        let result = self
            .send_file(SendPayload {
                peer,
                target,
                kind,
                sync_id,
                path: path.clone(),
                name,
                args,
                timeout_secs,
            })
            .await;
        if cleanup {
            let _ = tokio::fs::remove_file(path).await;
        }
        result
    }

    async fn send_file(&self, payload: SendPayload) -> Result<Value, String> {
        let SendPayload {
            peer,
            target,
            kind,
            sync_id,
            path,
            name,
            args,
            timeout_secs,
        } = payload;
        let (size, sha256) = hash_file(&path).await.map_err(|e| e.to_string())?;
        if size > target.max_payload_bytes {
            return Err(format!(
                "payload is {size} bytes, exceeding peer limit of {} bytes",
                target.max_payload_bytes
            ));
        }
        let peer_addr = peer
            .resonance
            .addrs
            .iter()
            .find(|ip| !ip.is_loopback())
            .or_else(|| peer.resonance.addrs.first())
            .copied()
            .ok_or_else(|| "peer has no usable address".to_owned())?;
        let socket = SocketAddr::new(peer_addr, peer.resonance.port);
        let relay_host = match &self.options.advertise_ip {
            Some(ip) => ip.clone(),
            None => TcpStream::connect(socket)
                .await
                .and_then(|stream| stream.local_addr())
                .map_err(|e| format!("could not determine a route to peer: {e}"))?
                .ip()
                .to_string(),
        };
        let ticket = self
            .local_ticket(relay_host)
            .await
            .map_err(|e| e.to_string())?;
        let secret = Secret::generate();
        let mut transfer = self
            .croc
            .send(&path, &secret, &ticket)
            .await
            .map_err(|e| e.to_string())?;
        transfer.ready().await;
        let label = args.get("label").and_then(Value::as_str).map(str::to_owned);
        let started = std::time::Instant::now();
        let result = entangle_link::offer(
            socket,
            SyncOffer {
                sync_id: sync_id.clone(),
                kind: kind.clone(),
                name,
                size,
                sha256: sha256.clone(),
                label,
                relay: ticket,
                secret: secret.expose().to_owned(),
            },
            Duration::from_secs(timeout_secs),
        )
        .await
        .map_err(|e| e.to_string());
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                let _ = transfer.abort().await;
                return Err(error);
            }
        };
        match outcome {
            entangle_link::OfferOutcome::Complete {
                sha256: remote_hash,
            } if remote_hash == sha256 => {}
            entangle_link::OfferOutcome::Complete { .. } => {
                let _ = transfer.abort().await;
                return Err("receiver reported a mismatched SHA-256".into());
            }
            entangle_link::OfferOutcome::Failed(reason) => {
                let _ = transfer.abort().await;
                return Err(format!("receiver failed state sync: {reason}"));
            }
        }
        transfer
            .wait(Duration::from_secs(timeout_secs))
            .await
            .map_err(|e| e.to_string())?;
        Ok(json!({
            "sync_id": sync_id,
            "particle_id": peer.resonance.particle_id,
            "kind": kind_name(&kind),
            "bytes": size,
            "sha256": sha256,
            "delivered": true,
            "elapsed_ms": started.elapsed().as_millis()
        }))
    }

    async fn local_ticket(&self, host: String) -> Result<RelayTicket> {
        let mut relay = self.relay.lock().await;
        if relay.is_none() {
            let relay_password = Secret::generate();
            let running = self
                .croc
                .start_relay(self.options.relay_port, relay_password.expose())
                .await?;
            *relay = Some(running);
        }
        Ok(relay.as_ref().expect("relay initialized").ticket(host))
    }

    async fn on_detected(&self, peer: Resonance) {
        if peer.particle_id == self.manifest.particle_id {
            return;
        }
        self.field
            .write()
            .expect("field lock")
            .resonate(peer.clone());
        for address in &peer.addrs {
            for attempt in 0..3 {
                if self
                    .dial(SocketAddr::new(*address, peer.port), Some(peer.clone()))
                    .await
                {
                    return;
                }
                sleep(Duration::from_millis(150 * (attempt + 1))).await;
            }
        }
    }

    async fn dial(&self, address: SocketAddr, discovery: Option<Resonance>) -> bool {
        match entangle_link::handshake(address, &self.manifest, Duration::from_secs(5)).await {
            Ok(manifest) if manifest.protocol == PROTOCOL_VERSION => {
                if manifest.particle_id == self.manifest.particle_id {
                    return false;
                }
                let resonance = discovery.unwrap_or_else(|| Resonance {
                    particle_id: manifest.particle_id.clone(),
                    name: manifest.name.clone(),
                    hostname: address.ip().to_string(),
                    addrs: vec![address.ip()],
                    port: manifest.link_port,
                    context: manifest.context.clone(),
                    proto: manifest.protocol,
                });
                self.field
                    .write()
                    .expect("field lock")
                    .entangle(resonance, manifest.clone());
                info!(
                    "peer entangled: {} ({})",
                    manifest.name,
                    manifest.particle_id.short()
                );
                true
            }
            Ok(manifest) => {
                debug!("peer protocol mismatch: {}", manifest.protocol);
                false
            }
            Err(error) => {
                debug!("handshake to {address} failed: {error}");
                false
            }
        }
    }

    async fn receive_offer(
        &self,
        peer_addr: SocketAddr,
        offer: SyncOffer,
    ) -> Result<String, String> {
        let _permit = Arc::clone(&self.inbound_limit)
            .acquire_owned()
            .await
            .map_err(|_| "inbound transfer capacity is closed".to_owned())?;
        let peer = self
            .field
            .read()
            .map_err(|_| "peer field lock poisoned".to_owned())?
            .by_addr(peer_addr.ip())
            .ok_or_else(|| "sender is not entangled; handshake first".to_owned())?;
        let Some(manifest) = peer.manifest else {
            return Err("sender is not entangled; handshake first".into());
        };
        if !self.manifest.accepts.contains(&offer.kind) {
            return Err(format!(
                "this particle does not accept {} payloads",
                kind_name(&offer.kind)
            ));
        }
        if offer.size > self.manifest.max_payload_bytes {
            return Err("offered payload exceeds this particle's maximum size".into());
        }
        let name = entangle_core::sanitize_name(&offer.name)
            .ok_or_else(|| "offered filename is unsafe".to_owned())?;
        if offer
            .label
            .as_ref()
            .is_some_and(|label| label.chars().count() > 200)
        {
            return Err("offer label exceeds 200 characters".into());
        }
        let directory = self.data_dir.join("inbox").join(&offer.sync_id);
        tokio::fs::create_dir_all(&directory)
            .await
            .map_err(|e| e.to_string())?;
        let result = self
            .receive_payload(manifest, offer, name, directory.clone())
            .await;
        if result.is_err() {
            let _ = tokio::fs::remove_dir_all(directory).await;
        }
        result
    }

    async fn receive_payload(
        &self,
        manifest: Manifest,
        offer: SyncOffer,
        name: String,
        directory: PathBuf,
    ) -> Result<String, String> {
        let receiver = self
            .croc
            .receive(
                &directory,
                &Secret::from_string(offer.secret.clone()),
                &offer.relay,
            )
            .await
            .map_err(|e| e.to_string())?;
        receiver
            .wait(Duration::from_secs(3600))
            .await
            .map_err(|e| e.to_string())?;
        let path = directory.join(name);
        if !path.is_file() {
            return Err(format!(
                "croc completed but expected file {} is missing",
                path.display()
            ));
        }
        let (size, hash) = hash_file(&path).await.map_err(|e| e.to_string())?;
        if size != offer.size || hash != offer.sha256 {
            let _ = tokio::fs::remove_dir_all(&directory).await;
            return Err("received payload size or SHA-256 did not match the offer".into());
        }
        let (state, text) = match &offer.kind {
            StateKind::Json => {
                let data = tokio::fs::read(&path).await.map_err(|e| e.to_string())?;
                (
                    Some(
                        serde_json::from_slice(&data)
                            .map_err(|e| format!("invalid JSON payload: {e}"))?,
                    ),
                    None,
                )
            }
            StateKind::File if size <= 64 * 1024 => {
                let data = tokio::fs::read(&path).await.map_err(|e| e.to_string())?;
                (None, String::from_utf8(data).ok())
            }
            StateKind::File => (None, None),
        };
        self.inbox.lock().await.push(InboxItem {
            sync_id: offer.sync_id.clone(),
            from_particle_id: manifest.particle_id.to_string(),
            from_name: manifest.name.clone(),
            kind: offer.kind.clone(),
            label: offer.label.clone(),
            received_at: Utc::now().to_rfc3339(),
            bytes: size,
            sha256: hash.clone(),
            state,
            path: (offer.kind == StateKind::File).then_some(path),
            text,
        });
        if let Some(notifications) = &self.notifications {
            let _ = notifications
                .send(json!({
                    "event": "state_sync_received",
                    "sync_id": offer.sync_id,
                    "from_particle_id": manifest.particle_id,
                    "from_name": manifest.name,
                    "kind": kind_name(&offer.kind),
                    "label": offer.label,
                    "bytes": size
                }))
                .await;
        }
        Ok(hash)
    }
}

#[async_trait::async_trait]
impl LinkHandler for Particle {
    async fn on_hello(
        &self,
        peer_addr: SocketAddr,
        manifest: Manifest,
    ) -> std::result::Result<Manifest, LinkError> {
        if manifest.protocol != PROTOCOL_VERSION {
            return Err(LinkError::Handler(format!(
                "protocol mismatch: expected {PROTOCOL_VERSION}, received {}",
                manifest.protocol
            )));
        }
        if manifest.particle_id != self.manifest.particle_id {
            let resonance = Resonance {
                particle_id: manifest.particle_id.clone(),
                name: manifest.name.clone(),
                hostname: peer_addr.ip().to_string(),
                addrs: vec![peer_addr.ip()],
                port: manifest.link_port,
                context: manifest.context.clone(),
                proto: manifest.protocol,
            };
            self.field
                .write()
                .expect("field lock")
                .entangle(resonance, manifest);
        }
        Ok(self.manifest.clone())
    }

    async fn on_offer(
        &self,
        peer_addr: SocketAddr,
        offer: SyncOffer,
    ) -> std::result::Result<SyncDecision, LinkError> {
        let result = self.validate_offer(peer_addr, &offer);
        Ok(match result {
            Ok(()) => SyncDecision::Accept,
            Err(reason) => SyncDecision::Reject(reason),
        })
    }

    async fn on_accepted(
        &self,
        peer_addr: SocketAddr,
        offer: SyncOffer,
    ) -> std::result::Result<String, String> {
        self.receive_offer(peer_addr, offer).await
    }
}

impl Particle {
    fn validate_offer(&self, peer_addr: SocketAddr, offer: &SyncOffer) -> Result<(), String> {
        self.field
            .read()
            .map_err(|_| "peer field lock poisoned".to_owned())?
            .by_addr(peer_addr.ip())
            .ok_or_else(|| "sender is not entangled; handshake first".to_owned())?;
        if !self.manifest.accepts.contains(&offer.kind) {
            return Err(format!(
                "this particle does not accept {} payloads",
                kind_name(&offer.kind)
            ));
        }
        if offer.size > self.manifest.max_payload_bytes {
            return Err("offered payload exceeds this particle's maximum size".into());
        }
        if entangle_core::sanitize_name(&offer.name).is_none() {
            return Err("offered filename is unsafe".into());
        }
        if offer
            .label
            .as_ref()
            .is_some_and(|label| label.chars().count() > 200)
        {
            return Err("offer label exceeds 200 characters".into());
        }
        Ok(())
    }
}

async fn hash_file(path: &Path) -> Result<(u64, String)> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut size = 0_u64;
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size += read as u64;
    }
    Ok((size, hex::encode(hasher.finalize())))
}

fn kind_name(kind: &StateKind) -> &'static str {
    match kind {
        StateKind::Json => "json",
        StateKind::File => "file",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(
        name: &str,
        link_port: u16,
        relay_port: u16,
        peer: String,
        data_dir: PathBuf,
    ) -> Options {
        Options {
            name: Some(name.into()),
            context: Some("node-test".into()),
            link_port,
            relay_port,
            advertise_ip: Some("127.0.0.1".into()),
            peer: vec![peer],
            data_dir: Some(data_dir),
            croc: None,
            max_payload_mb: 2,
            no_mdns: true,
            log_level: "warn".into(),
        }
    }

    fn free_base_port() -> u16 {
        for _ in 0..100 {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            if port <= u16::MAX - 4
                && (0..=4)
                    .all(|offset| std::net::TcpListener::bind(("127.0.0.1", port + offset)).is_ok())
            {
                return port;
            }
        }
        panic!("could not find an available relay port range");
    }

    #[tokio::test]
    async fn two_particles_handshake_and_sync_json_and_file() {
        if let Err(error) = Croc::locate(None) {
            if std::env::var("ENTANGLE_REQUIRE_CROC").as_deref() == Ok("1") {
                panic!("ENTANGLE_REQUIRE_CROC=1 but croc is unavailable: {error}");
            }
            eprintln!("skipping two-particle integration test: {error}");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let a_port = free_base_port();
        let b_port = free_base_port();
        let relay_a = free_base_port();
        let relay_b = free_base_port();
        let (a, _) = Particle::start(
            options(
                "particle-a",
                a_port,
                relay_a,
                format!("127.0.0.1:{b_port}"),
                temp.path().join("a"),
            ),
            None,
        )
        .await
        .unwrap();
        let (b, _) = Particle::start(
            options(
                "particle-b",
                b_port,
                relay_b,
                format!("127.0.0.1:{a_port}"),
                temp.path().join("b"),
            ),
            None,
        )
        .await
        .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let a_ready = a
                .field
                .read()
                .unwrap()
                .resolve(b.manifest.particle_id.as_str())
                .iter()
                .any(|peer| peer.state == PeerState::Entangled);
            let b_ready = b
                .field
                .read()
                .unwrap()
                .resolve(a.manifest.particle_id.as_str())
                .iter()
                .any(|peer| peer.state == PeerState::Entangled);
            if a_ready && b_ready {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "static-peer handshake did not finish"
            );
            sleep(Duration::from_millis(50)).await;
        }
        let json_result = a
            .sync_state(json!({
                "particle_id": b.manifest.particle_id.as_str(),
                "state": { "hello": "world", "count": 7 },
                "timeout_secs": 60
            }))
            .await
            .unwrap();
        assert_eq!(json_result["delivered"], true);
        let observed = b.observe(&json!({ "limit": 20 })).await;
        assert_eq!(observed["states"][0]["state"]["hello"], "world");

        let source = temp.path().join("sample.txt");
        tokio::fs::write(&source, b"file state sync").await.unwrap();
        let file_result = a
            .sync_state(json!({
                "particle_id": b.manifest.particle_id.as_str(),
                "file_path": source,
                "label": "sample file",
                "timeout_secs": 60
            }))
            .await
            .unwrap();
        assert_eq!(file_result["kind"], "file");
        let observed = b.observe(&json!({ "limit": 20 })).await;
        assert_eq!(observed["states"][1]["text"], "file state sync");
        assert_eq!(
            tokio::fs::read(observed["states"][1]["path"].as_str().unwrap())
                .await
                .unwrap(),
            b"file state sync"
        );
        assert!(a
            .sync_state(json!({ "particle_id": "unknown", "state": null }))
            .await
            .is_err());
        a.shutdown().await;
        b.shutdown().await;
    }
}
