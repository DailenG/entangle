//! Particle lifecycle, secure peer handshakes, and inbound syncs.

use crate::{
    config::Options,
    field::{Field, PeerRecord, PeerState},
    identity::{self, Identity},
    inbox::{self, InboxItem},
    pairing,
};
use anyhow::{Context, Result};
use chrono::Utc;
use entangle_core::{is_valid_sync_id, Manifest, StateKind, PROTOCOL_VERSION};
use entangle_link::{
    LinkError, LinkHandler, LinkListener, PayloadReader, PeerInfo, SyncDecision, SyncOffer,
};
use entangle_resonance::{Advertisement, Resonance, ResonanceEvent, Resonator};
use entangle_transport::LinkKeys;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::lookup_host,
    sync::{mpsc, Mutex, Semaphore},
    time::sleep,
};
use tracing::{debug, info, warn};

const MIN_TIMEOUT_SECS: u64 = 5;
const MAX_TIMEOUT_SECS: u64 = 3600;

/// A single running Entangle process and its stateful local services.
pub struct Particle {
    /// This process manifest.
    pub manifest: Manifest,
    field: Arc<RwLock<Field>>,
    options: Options,
    _identity: Identity,
    pairing_group: Option<String>,
    keys: Option<Arc<LinkKeys>>,
    data_dir: PathBuf,
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
        let root = options.data_root();
        let identity = identity::claim(&root);
        let pairing_key = match pairing::load(&root) {
            Ok(key) => key,
            Err(error) => {
                warn!(%error, "pairing key is unavailable; starting unpaired");
                None
            }
        };
        let pairing_group = pairing_key.as_ref().map(pairing::group_id);
        let keys = pairing_key.map(|key| {
            Arc::new(LinkKeys {
                static_private: identity.static_private,
                psk: pairing::derive_psk(&key),
            })
        });
        let particle_id = identity.id.clone();
        let name = options.particle_name(&particle_id);
        let data_dir = root.join(particle_id.short());
        let inbox_dir = data_dir.join("inbox");
        tokio::fs::create_dir_all(&inbox_dir).await?;
        tokio::fs::create_dir_all(data_dir.join("outbox")).await?;
        let persisted_inbox = inbox::load(&inbox_dir).await;
        let (listener, link_port) = if keys.is_some() {
            let (listener, link_port) = match LinkListener::bind(SocketAddr::from((
                [0, 0, 0, 0],
                options.link_port,
            )))
            .await
            {
                Ok(bound) => bound,
                Err(LinkError::Io(error)) if error.kind() == std::io::ErrorKind::AddrInUse => {
                    warn!(
                        configured_port = options.link_port,
                        "configured link port is occupied; using an ephemeral port; static --peer entries pointing at this machine need the new port"
                    );
                    LinkListener::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
                        .await
                        .context("could not bind Entangle TCP link listener")?
                }
                Err(error) => {
                    return Err(error).context("could not bind Entangle TCP link listener")
                }
            };
            (Some(listener), link_port)
        } else {
            (None, options.link_port)
        };
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
                group: pairing_group.clone(),
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
            _identity: identity,
            pairing_group,
            keys: keys.clone(),
            data_dir,
            resonator: Mutex::new(resonator),
            inbox: Mutex::new(persisted_inbox),
            notifications,
            inbound_limit: Arc::new(Semaphore::new(4)),
        });
        if let (Some(listener), Some(keys)) = (listener, keys) {
            tokio::spawn(listener.run(keys, particle.clone()));
        }
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
            if static_node.keys.is_none() {
                return;
            }
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
                                        && entry.resonance.addrs.contains(&address.ip())
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
        info!(
            "particle identity: id={} name={} status={}",
            particle.manifest.particle_id.as_str(),
            particle.manifest.name,
            if particle._identity.persistent {
                "persistent"
            } else {
                "ephemeral"
            }
        );
        if particle.keys.is_none() {
            info!("particle is unpaired; encrypted links are disabled");
        } else if !particle.options.no_mdns {
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

    /// Unregisters this particle from mDNS.
    pub async fn shutdown(&self) {
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
        let mut local = serde_json::to_value(&self.manifest).expect("manifest serializes");
        local["paired"] = json!(self.pairing_group.is_some());
        local["pairing_group"] = json!(self.pairing_group);
        if self.pairing_group.is_none() {
            local["hint"] = json!("Not paired: the human must run `entangle pair init` on one machine and `entangle pair join` on the others.");
        }
        json!({
            "self": local,
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
        let collapsed_ids = if collapse {
            let ids: Vec<_> = selected.iter().map(|item| item.sync_id.clone()).collect();
            inbox.retain(|item| !ids.contains(&item.sync_id));
            ids
        } else {
            Vec::new()
        };
        let remaining = inbox.len();
        drop(inbox);
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
        for sync_id in collapsed_ids {
            if let Err(error) = inbox::forget(&self.data_dir.join("inbox"), &sync_id).await {
                warn!(
                    sync_id,
                    error = %error,
                    "unable to remove collapsed inbox metadata"
                );
            }
        }
        json!({ "states": states, "remaining": remaining })
    }

    /// Sends a JSON or file payload to an already-entangled peer.
    pub async fn sync_state(&self, args: Value) -> Result<Value, String> {
        if self.keys.is_none() {
            return Err(
                "this particle is unpaired; pair it with a human-provided code first".into(),
            );
        }
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
        let target_peer_id = peer.resonance.particle_id.clone();
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
            .clamp(MIN_TIMEOUT_SECS, MAX_TIMEOUT_SECS);
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
        if result.is_ok() {
            if let Ok(mut field) = self.field.write() {
                field.touch(&target_peer_id);
            }
        }
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
        let label = args.get("label").and_then(Value::as_str).map(str::to_owned);
        let started = std::time::Instant::now();
        let keys = self.keys.as_ref().expect("paired check above");
        let source = tokio::fs::File::open(&path)
            .await
            .map_err(|error| error.to_string())?;
        let result = entangle_link::offer(
            socket,
            keys,
            SyncOffer {
                from: self.manifest.particle_id.clone(),
                sync_id: sync_id.clone(),
                timeout_secs,
                kind: kind.clone(),
                name,
                size,
                sha256: sha256.clone(),
                label,
            },
            source,
            Duration::from_secs(timeout_secs),
        )
        .await
        .map_err(|e| e.to_string())?;
        let outcome = result;
        match outcome {
            entangle_link::OfferOutcome::Complete {
                sha256: remote_hash,
            } if remote_hash == sha256 => {}
            entangle_link::OfferOutcome::Complete { .. } => {
                return Err("receiver reported a mismatched SHA-256".into());
            }
            entangle_link::OfferOutcome::Failed(reason) => {
                return Err(format!("receiver failed state sync: {reason}"));
            }
        }
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

    async fn on_detected(&self, peer: Resonance) {
        if peer.particle_id == self.manifest.particle_id {
            return;
        }
        self.field
            .write()
            .expect("field lock")
            .resonate(peer.clone());
        let Some(group) = self.pairing_group.as_deref() else {
            return;
        };
        if peer.group.as_deref() != Some(group) {
            return;
        }
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
        let Some(keys) = &self.keys else {
            return false;
        };
        match entangle_link::handshake(address, keys, &self.manifest, Duration::from_secs(5)).await
        {
            Ok((manifest, remote_static)) if manifest.protocol == PROTOCOL_VERSION => {
                if manifest.particle_id == self.manifest.particle_id {
                    return false;
                }
                if self
                    .field
                    .read()
                    .expect("field lock")
                    .by_id(&manifest.particle_id)
                    .is_some_and(|peer| {
                        peer.state == PeerState::Entangled && peer.static_key != Some(remote_static)
                    })
                {
                    warn!(
                        particle_id = %manifest.particle_id,
                        "refusing a peer whose Noise static key changed"
                    );
                    return false;
                }
                let resonance = discovery.unwrap_or_else(|| Resonance {
                    particle_id: manifest.particle_id.clone(),
                    name: manifest.name.clone(),
                    hostname: address.ip().to_string(),
                    addrs: vec![address.ip()],
                    port: manifest.link_port,
                    context: manifest.context.clone(),
                    group: None,
                    proto: manifest.protocol,
                });
                self.field.write().expect("field lock").entangle(
                    resonance,
                    manifest.clone(),
                    remote_static,
                );
                info!(
                    "peer entangled: {} ({})",
                    manifest.name,
                    manifest.particle_id.short()
                );
                true
            }
            Ok((manifest, _)) => {
                debug!("peer protocol mismatch: {}", manifest.protocol);
                false
            }
            Err(error) => {
                debug!("handshake to {address} failed: {error}");
                false
            }
        }
    }

    async fn receive_payload(
        &self,
        peer_info: &PeerInfo,
        offer: SyncOffer,
        payload: &mut PayloadReader<'_>,
    ) -> Result<String, String> {
        if !is_valid_sync_id(&offer.sync_id) {
            return Err("offered sync_id is malformed".to_owned());
        }
        let _permit = Arc::clone(&self.inbound_limit)
            .acquire_owned()
            .await
            .map_err(|_| "inbound transfer capacity is closed".to_owned())?;
        let peer = {
            let mut field = self
                .field
                .write()
                .map_err(|_| "peer field lock poisoned".to_owned())?;
            let peer = field.by_id(&offer.from).filter(|peer| {
                peer.state == PeerState::Entangled
                    && peer.static_key == Some(peer_info.remote_static)
            });
            if peer.is_some() {
                field.touch(&offer.from);
            }
            peer
        }
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
        let result: Result<String, String> = async {
            let path = directory.join(&name);
            let mut file = tokio::fs::File::create(&path)
                .await
                .map_err(|error| error.to_string())?;
            let mut hasher = Sha256::new();
            let mut size = 0_u64;
            while let Some(chunk) = payload.next_chunk().await.map_err(|e| e.to_string())? {
                hasher.update(&chunk);
                size = size.saturating_add(chunk.len() as u64);
                file.write_all(&chunk)
                    .await
                    .map_err(|error| error.to_string())?;
            }
            file.flush().await.map_err(|error| error.to_string())?;
            drop(file);
            let hash = hex::encode(hasher.finalize());
            if size != offer.size || hash != offer.sha256 {
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
            let item = InboxItem {
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
            };
            if let Err(error) = inbox::persist(&self.data_dir.join("inbox"), &item).await {
                warn!(
                    sync_id = %item.sync_id,
                    error = %error,
                    "unable to persist received inbox metadata"
                );
            }
            self.inbox.lock().await.push(item);
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
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_dir_all(directory).await;
        }
        result
    }
}

#[async_trait::async_trait]
impl LinkHandler for Particle {
    async fn on_hello(
        &self,
        peer: &PeerInfo,
        manifest: Manifest,
    ) -> std::result::Result<Manifest, LinkError> {
        if manifest.protocol != PROTOCOL_VERSION {
            return Err(LinkError::Handler(format!(
                "protocol mismatch: expected {PROTOCOL_VERSION}, received {}",
                manifest.protocol
            )));
        }
        if manifest.particle_id != self.manifest.particle_id {
            let mut field = self.field.write().expect("field lock");
            let existing = field.by_id(&manifest.particle_id);
            if existing.as_ref().is_some_and(|record| {
                record.state == PeerState::Entangled
                    && record.static_key != Some(peer.remote_static)
            }) {
                warn!(
                    particle_id = %manifest.particle_id,
                    "rejecting a manifest that claims an entangled particle with a different Noise static key"
                );
                return Err(LinkError::Handler(
                    "particle is already entangled with a different Noise static key".into(),
                ));
            }
            let resonance = Resonance {
                particle_id: manifest.particle_id.clone(),
                name: manifest.name.clone(),
                hostname: peer.addr.ip().to_string(),
                addrs: vec![peer.addr.ip()],
                port: manifest.link_port,
                context: manifest.context.clone(),
                group: existing.and_then(|record| record.resonance.group),
                proto: manifest.protocol,
            };
            field.entangle(resonance, manifest, peer.remote_static);
        }
        Ok(self.manifest.clone())
    }

    async fn on_offer(
        &self,
        peer: &PeerInfo,
        offer: SyncOffer,
    ) -> std::result::Result<SyncDecision, LinkError> {
        let result = self.validate_offer(peer, &offer);
        Ok(match result {
            Ok(()) => SyncDecision::Accept,
            Err(reason) => SyncDecision::Reject(reason),
        })
    }

    async fn on_accepted(
        &self,
        peer: &PeerInfo,
        offer: SyncOffer,
        payload: &mut PayloadReader<'_>,
    ) -> std::result::Result<String, String> {
        self.receive_payload(peer, offer, payload).await
    }
}

impl Particle {
    fn validate_offer(&self, peer_info: &PeerInfo, offer: &SyncOffer) -> Result<(), String> {
        let mut field = self
            .field
            .write()
            .map_err(|_| "peer field lock poisoned".to_owned())?;
        let peer = field
            .by_id(&offer.from)
            .filter(|peer| peer.state == PeerState::Entangled)
            .ok_or_else(|| "sender is not entangled; handshake first".to_owned())?;
        if peer.static_key != Some(peer_info.remote_static) {
            return Err("sender key does not match the entangled particle".into());
        }
        let source_ip = peer_info.addr.ip();
        if !peer.resonance.addrs.contains(&source_ip) {
            debug!(
                particle_id = %offer.from,
                source_ip = %source_ip,
                "offer arrived from an address not listed for the sender"
            );
            field.add_address(&offer.from, source_ip);
        }
        drop(field);
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
    use entangle_core::ParticleId;

    fn options(name: &str, link_port: u16, data_dir: PathBuf, peer: Option<String>) -> Options {
        Options {
            name: Some(name.into()),
            context: Some("node-test".into()),
            link_port,
            relay_port: None,
            advertise_ip: None,
            peer: peer.into_iter().collect(),
            data_dir: Some(data_dir),
            legacy_transfer_path: None,
            max_payload_mb: 2,
            no_mdns: true,
            log_level: "warn".into(),
        }
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn port_other_than(other: u16) -> u16 {
        loop {
            let port = free_port();
            if port != other {
                return port;
            }
        }
    }

    fn peer_manifest(id: ParticleId) -> Manifest {
        Manifest {
            particle_id: id,
            name: "peer".into(),
            version: "0.2.0".into(),
            protocol: PROTOCOL_VERSION,
            link_port: 7337,
            context: None,
            tools: vec![],
            accepts: vec![StateKind::Json, StateKind::File],
            max_payload_bytes: 2 * 1024 * 1024,
        }
    }

    #[tokio::test]
    async fn unpaired_particle_does_not_listen_or_dial() {
        let temp = tempfile::tempdir().unwrap();
        let target = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        target.set_nonblocking(true).unwrap();
        let target_addr = target.local_addr().unwrap();
        let port = free_port();
        let (particle, _) = Particle::start(
            options(
                "unpaired",
                port,
                temp.path().join("node"),
                Some(target_addr.to_string()),
            ),
            None,
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(particle.keys.is_none());
        assert!(particle.field.read().unwrap().all().is_empty());
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
        assert!(matches!(
            target.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        let local = particle.find_particles(&json!({}))["self"].clone();
        assert_eq!(local["paired"], false);
        assert_eq!(
            local["hint"],
            "Not paired: the human must run `entangle pair init` on one machine and `entangle pair join` on the others."
        );
        particle.shutdown().await;
    }

    #[tokio::test]
    async fn same_pairing_key_authenticates_and_syncs_payloads() {
        let temp = tempfile::tempdir().unwrap();
        let root_a = temp.path().join("a");
        let root_b = temp.path().join("b");
        let key = pairing::initialize(&root_a, false).unwrap();
        pairing::join(&root_b, &pairing::encode_code(&key), false).unwrap();
        let a_port = free_port();
        let b_port = port_other_than(a_port);
        let (b, _) = Particle::start(
            options(
                "particle-b",
                b_port,
                root_b,
                Some(format!("127.0.0.1:{a_port}")),
            ),
            None,
        )
        .await
        .unwrap();
        let (a, _) = Particle::start(
            options(
                "particle-a",
                a_port,
                root_a,
                Some(format!("127.0.0.1:{b_port}")),
            ),
            None,
        )
        .await
        .unwrap();
        let a_self = a.find_particles(&json!({}))["self"].clone();
        assert_eq!(a_self["paired"], true);
        assert_eq!(a_self["pairing_group"], pairing::group_id(&key));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let a_connected = a
                    .field
                    .read()
                    .unwrap()
                    .by_id(&b.manifest.particle_id)
                    .is_some_and(|peer| peer.state == PeerState::Entangled);
                let b_connected = b
                    .field
                    .read()
                    .unwrap()
                    .by_id(&a.manifest.particle_id)
                    .is_some_and(|peer| peer.state == PeerState::Entangled);
                if a_connected && b_connected {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("configured static peer dialers should entangle both particles");
        let result = a
            .sync_state(json!({
                "particle_id": b.manifest.particle_id.as_str(),
                "state": { "hello": "world", "count": 7 },
                "timeout_secs": 60
            }))
            .await
            .unwrap();
        assert_eq!(result["delivered"], true);
        let observed = b.observe(&json!({ "limit": 20 })).await;
        assert_eq!(observed["states"][0]["state"]["hello"], "world");
        let source = temp.path().join("source.txt");
        tokio::fs::write(&source, b"native transport file")
            .await
            .unwrap();
        let result = a
            .sync_state(json!({
                "particle_id": b.manifest.particle_id.as_str(),
                "file_path": source,
                "timeout_secs": 60
            }))
            .await
            .unwrap();
        assert_eq!(result["kind"], "file");
        let observed = b.observe(&json!({ "limit": 20 })).await;
        let file_item = observed["states"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["kind"] == "file")
            .unwrap();
        assert_eq!(file_item["text"], "native transport file");
        assert_eq!(
            b.field
                .read()
                .unwrap()
                .by_id(&a.manifest.particle_id)
                .unwrap()
                .static_key,
            Some(entangle_transport::public_key(&a._identity.static_private))
        );

        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn different_pairing_keys_cannot_handshake() {
        let temp = tempfile::tempdir().unwrap();
        let root_a = temp.path().join("a");
        let root_b = temp.path().join("b");
        pairing::initialize(&root_a, false).unwrap();
        pairing::initialize(&root_b, false).unwrap();
        let a_port = free_port();
        let b_port = port_other_than(a_port);
        let (a, _) = Particle::start(
            options(
                "particle-a",
                a_port,
                root_a,
                Some(format!("127.0.0.1:{b_port}")),
            ),
            None,
        )
        .await
        .unwrap();
        let (b, _) = Particle::start(
            options(
                "particle-b",
                b_port,
                root_b,
                Some(format!("127.0.0.1:{a_port}")),
            ),
            None,
        )
        .await
        .unwrap();
        assert!(
            !a.dial(SocketAddr::from(([127, 0, 0, 1], b_port)), None)
                .await
        );
        assert!(a.field.read().unwrap().all().is_empty());
        assert!(b.field.read().unwrap().all().is_empty());
        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn offer_claiming_an_entangled_identity_with_another_key_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("node");
        pairing::initialize(&root, false).unwrap();
        let (particle, _) = Particle::start(options("receiver", free_port(), root, None), None)
            .await
            .unwrap();
        let id = ParticleId::generate();
        let manifest = peer_manifest(id.clone());
        let resonance = Resonance {
            particle_id: id.clone(),
            name: manifest.name.clone(),
            hostname: "127.0.0.1".into(),
            addrs: vec!["127.0.0.1".parse().unwrap()],
            port: manifest.link_port,
            context: None,
            group: particle.pairing_group.clone(),
            proto: manifest.protocol,
        };
        particle
            .field
            .write()
            .unwrap()
            .entangle(resonance, manifest.clone(), [0x11; 32]);
        let hello_error = particle
            .on_hello(
                &PeerInfo {
                    addr: SocketAddr::from(([127, 0, 0, 1], 7337)),
                    remote_static: [0x22; 32],
                },
                manifest,
            )
            .await
            .unwrap_err();
        assert!(hello_error
            .to_string()
            .contains("different Noise static key"));
        let offer = SyncOffer {
            from: id,
            sync_id: "0123456789abcdef0123456789abcdef".into(),
            timeout_secs: 60,
            kind: StateKind::Json,
            name: "payload.json".into(),
            size: 0,
            sha256: hex::encode(Sha256::digest([])),
            label: None,
        };
        let error = particle
            .validate_offer(
                &PeerInfo {
                    addr: SocketAddr::from(([127, 0, 0, 1], 7337)),
                    remote_static: [0x22; 32],
                },
                &offer,
            )
            .unwrap_err();
        assert_eq!(error, "sender key does not match the entangled particle");
        particle.shutdown().await;
    }
}
