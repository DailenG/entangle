//! Particle lifecycle, secure peer handshakes, and inbound syncs.

use crate::{
    config::Options,
    field::{Field, PeerRecord, PeerState},
    identity::{self, Identity},
    inbox::{self, InboxItem},
    pairing,
    trust::{self, VerificationRecord},
};
use anyhow::{Context, Result};
use chrono::Utc;
use entangle_core::{is_valid_sync_id, Manifest, StateKind, PROTOCOL_VERSION};
use entangle_link::{
    LinkError, LinkHandler, LinkListener, PayloadReader, PeerInfo, Route, SyncDecision, SyncOffer,
    VerifyMessage,
};
use entangle_resonance::{Advertisement, Resonance, ResonanceEvent, Resonator};
use entangle_transport::{KeySlot, LinkKeys};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex as StdMutex, RwLock,
    },
    time::Duration,
};
use tokio::task::JoinHandle;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::lookup_host,
    sync::{mpsc, Mutex, Semaphore},
    time::sleep,
};
use tracing::{debug, info, warn};

const MIN_TIMEOUT_SECS: u64 = 5;
const MAX_TIMEOUT_SECS: u64 = 3600;

struct PartialTransferGuard {
    directory: PathBuf,
    armed: bool,
}

impl PartialTransferGuard {
    fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PartialTransferGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
}

struct InFlightGuard<'a> {
    sync_id: String,
    in_flight: &'a StdMutex<HashSet<String>>,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        match self.in_flight.lock() {
            Ok(mut in_flight) => {
                in_flight.remove(&self.sync_id);
            }
            Err(error) => {
                error.into_inner().remove(&self.sync_id);
            }
        }
    }
}

/// A single running Entangle process and its stateful local services.
pub struct Particle {
    /// This process manifest.
    pub manifest: Manifest,
    field: Arc<RwLock<Field>>,
    options: Options,
    _identity: Identity,
    pairing_group: Arc<RwLock<Option<String>>>,
    active_pairing_key: Arc<RwLock<Option<[u8; 32]>>>,
    keys: KeySlot,
    link_port_fallback: bool,
    pairing_root: PathBuf,
    data_dir: PathBuf,
    resonator: Mutex<Option<Resonator>>,
    resonance_task: Mutex<Option<JoinHandle<()>>>,
    discovery_generation: AtomicU64,
    discovery_failure_logged: AtomicBool,
    inbox: Mutex<Vec<InboxItem>>,
    in_flight: StdMutex<HashSet<String>>,
    verification_lock: StdMutex<()>,
    ephemeral_verifications: StdMutex<HashMap<entangle_core::ParticleId, VerificationRecord>>,
    verify_capacity_warned: AtomicBool,
    trust_reload_warned: AtomicBool,
    trust_stamp: StdMutex<Option<trust::FileStamp>>,
    notifications: Option<mpsc::Sender<Value>>,
    inbound_limit: Arc<Semaphore>,
    shutdown: tokio::sync::watch::Sender<bool>,
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
        let identity = identity::claim(&root)?;
        let pairing_key = match pairing::load(&root) {
            Ok(key) => key,
            Err(error @ pairing::PairingError::Io(_)) => {
                return Err(error).context("could not load pairing key")
            }
            Err(error) => {
                warn!(%error, "pairing key is unavailable; starting unpaired");
                None
            }
        };
        let active_pairing_key = Arc::new(RwLock::new(pairing_key));
        let pairing_group = Arc::new(RwLock::new(pairing_key.as_ref().map(pairing::group_id)));
        let keys: KeySlot = Arc::new(RwLock::new(pairing_key.map(|key| {
            Arc::new(LinkKeys {
                static_private: identity.static_private,
                psk: pairing::derive_psk(&key),
            })
        })));
        let particle_id = identity.id.clone();
        let name = options.particle_name(&particle_id);
        let data_dir = root.join(particle_id.short());
        let inbox_dir = data_dir.join("inbox");
        tokio::fs::create_dir_all(&inbox_dir).await?;
        tokio::fs::create_dir_all(data_dir.join("outbox")).await?;
        let persisted_inbox = inbox::load(&inbox_dir).await;
        let trust_stamp = if identity.persistent {
            match trust::file_stamp(&root) {
                Ok(stamp) => stamp,
                Err(error) => {
                    warn!(%error, "could not inspect peer trust store");
                    None
                }
            }
        } else {
            None
        };
        let (listener, link_port, link_port_fallback) = match LinkListener::bind(SocketAddr::from(
            ([0, 0, 0, 0], options.link_port),
        ))
        .await
        {
            Ok((listener, port)) => (listener, port, false),
            Err(LinkError::Io(error)) if error.kind() == std::io::ErrorKind::AddrInUse => {
                warn!(
                    configured_port = options.link_port,
                    "configured link port is occupied; using an ephemeral port; static --peer entries pointing at this machine need the new port"
                );
                let (listener, port) = LinkListener::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
                    .await
                    .context("could not bind Entangle TCP link listener")?;
                (listener, port, true)
            }
            Err(error) => return Err(error).context("could not bind Entangle TCP link listener"),
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
        let (shutdown, _) = tokio::sync::watch::channel(false);
        let particle = Arc::new(Self {
            manifest: manifest.clone(),
            field,
            options,
            _identity: identity,
            pairing_group,
            active_pairing_key,
            keys: keys.clone(),
            link_port_fallback,
            pairing_root: root,
            data_dir,
            resonator: Mutex::new(None),
            resonance_task: Mutex::new(None),
            discovery_generation: AtomicU64::new(0),
            discovery_failure_logged: AtomicBool::new(false),
            inbox: Mutex::new(persisted_inbox),
            in_flight: StdMutex::new(HashSet::new()),
            verification_lock: StdMutex::new(()),
            ephemeral_verifications: StdMutex::new(HashMap::new()),
            verify_capacity_warned: AtomicBool::new(false),
            trust_reload_warned: AtomicBool::new(false),
            trust_stamp: StdMutex::new(trust_stamp),
            notifications,
            inbound_limit: Arc::new(Semaphore::new(4)),
            shutdown,
        });
        if let Err(error) = particle.restart_resonator().await {
            particle.log_discovery_failure(&error);
        }
        tokio::spawn(listener.run(particle.keys.clone(), particle.clone()));
        let pairing_node = particle.clone();
        tokio::spawn(async move { pairing_node.pairing_watch().await });
        let static_node = particle.clone();
        tokio::spawn(async move { static_node.static_peer_loop().await });
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
        if particle.keys.read().expect("key slot lock").is_none() {
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
        if let Some(warning) = particle.identity_warning() {
            warn!("{warning}");
        }
        Ok((particle, manifest))
    }

    fn identity_warning(&self) -> Option<String> {
        let ephemeral = !self._identity.persistent;
        if !ephemeral && !self.link_port_fallback {
            return None;
        }
        let identity = if ephemeral { "ephemeral" } else { "persistent" };
        let reason = match (ephemeral, self.link_port_fallback) {
            (true, true) => "as a temporary particle using a fallback link port",
            (true, false) => "as a temporary particle",
            (false, true) => "using a fallback link port",
            (false, false) => unreachable!(),
        };
        let mut warning = format!(
            "Another Entangle process on this machine holds the saved identity and/or port {}. This node is running {reason} (identity: {identity}; link port: {}). Close the other MCP client or old Entangle process, then reload.",
            self.options.link_port, self.manifest.link_port
        );
        if ephemeral {
            warning
                .push_str(" peer approval is unavailable while running on a temporary identity.");
        }
        Some(warning)
    }

    fn load_trust_store(&self) -> std::result::Result<trust::TrustStore, LinkError> {
        if self._identity.persistent {
            trust::load(&self.pairing_root).map_err(|error| {
                LinkError::Handler(format!("peer trust store unavailable: {error}"))
            })
        } else {
            Ok(trust::TrustStore::default())
        }
    }

    fn check_verification_capacity(
        &self,
        particle_id: &entangle_core::ParticleId,
        store: &trust::TrustStore,
        has_record: bool,
    ) -> std::result::Result<(), LinkError> {
        if has_record || store.approved.contains_key(particle_id.as_str()) {
            return Ok(());
        }
        let count = if self._identity.persistent {
            trust::load_verifications(&self.pairing_root)
                .map_err(|error| {
                    LinkError::Handler(format!("peer verification state unavailable: {error}"))
                })?
                .into_iter()
                .filter(|record| !store.approved.contains_key(record.particle_id.as_str()))
                .count()
        } else {
            self.ephemeral_verifications
                .lock()
                .expect("ephemeral verification lock")
                .len()
        };
        if count < 16 {
            return Ok(());
        }
        if !self.verify_capacity_warned.swap(true, Ordering::Relaxed) {
            warn!("peer verification record limit reached; refusing new unknown peers");
        }
        Err(LinkError::Handler(
            "too many unapproved peers are waiting for verification".into(),
        ))
    }

    fn verification_step(
        &self,
        particle_id: &entangle_core::ParticleId,
        name: &str,
        remote_key: [u8; 32],
        incoming: Option<VerifyMessage>,
    ) -> std::result::Result<(VerifyMessage, VerificationRecord), LinkError> {
        let _lock = self
            .verification_lock
            .lock()
            .map_err(|_| LinkError::Handler("peer verification lock poisoned".into()))?;
        let local_key = entangle_transport::public_key(&self._identity.static_private);
        let mut record = if self._identity.persistent {
            match trust::load_verification(&self.pairing_root, particle_id).map_err(|error| {
                LinkError::Handler(format!("peer verification state unavailable: {error}"))
            })? {
                Some(record)
                    if record.local_key == hex::encode(local_key)
                        && record.remote_key == hex::encode(remote_key) =>
                {
                    record
                }
                _ => trust::new_verification(
                    particle_id.clone(),
                    name.to_owned(),
                    local_key,
                    remote_key,
                )
                .map_err(|error| LinkError::Handler(error.to_string()))?,
            }
        } else {
            let mut records = self
                .ephemeral_verifications
                .lock()
                .map_err(|_| LinkError::Handler("ephemeral verification lock poisoned".into()))?;
            match records.get(particle_id).filter(|record| {
                record.local_key == hex::encode(local_key)
                    && record.remote_key == hex::encode(remote_key)
            }) {
                Some(record) => record.clone(),
                None => {
                    let record = trust::new_verification(
                        particle_id.clone(),
                        name.to_owned(),
                        local_key,
                        remote_key,
                    )
                    .map_err(|error| LinkError::Handler(error.to_string()))?;
                    records.insert(particle_id.clone(), record.clone());
                    record
                }
            }
        };
        record.name = name.to_owned();
        trust::initialize_exchange_state(&mut record)
            .map_err(|error| LinkError::Handler(error.to_string()))?;
        if let Some(incoming) = incoming {
            trust::ingest(&mut record, incoming)
                .map_err(|_| LinkError::Handler("invalid verification message".into()))?;
        }
        if self._identity.persistent {
            trust::save_verification(&self.pairing_root, &record).map_err(|error| {
                LinkError::Handler(format!("peer verification state unavailable: {error}"))
            })?;
        } else {
            self.ephemeral_verifications
                .lock()
                .map_err(|_| LinkError::Handler("ephemeral verification lock poisoned".into()))?
                .insert(particle_id.clone(), record.clone());
        }
        let outgoing = trust::outgoing(&record);
        Ok((outgoing, record))
    }

    async fn run_verify_exchange(
        &self,
        stream: &mut entangle_transport::SecureStream,
        particle_id: &entangle_core::ParticleId,
        name: &str,
        remote_key: [u8; 32],
    ) -> std::result::Result<(), LinkError> {
        for _ in 0..4 {
            let (outgoing, _) = self.verification_step(particle_id, name, remote_key, None)?;
            entangle_link::send_verify(stream, &outgoing).await?;
            let incoming = entangle_link::recv_verify(stream).await?;
            let (_, record) =
                self.verification_step(particle_id, name, remote_key, Some(incoming))?;
            let complete = record.is_complete()
                && (record.role == entangle_core::sas::Role::Revealer || outgoing.reveal.is_some());
            if complete {
                break;
            }
        }
        Ok(())
    }

    fn advertisement(&self) -> Advertisement {
        Advertisement {
            particle_id: self.manifest.particle_id.clone(),
            name: self.manifest.name.clone(),
            port: self.manifest.link_port,
            context: self.manifest.context.clone(),
            group: self
                .pairing_group
                .read()
                .expect("pairing group lock")
                .clone(),
            version: self.manifest.version.clone(),
        }
    }

    async fn restart_resonator(self: &Arc<Self>) -> anyhow::Result<()> {
        let generation = self.discovery_generation.fetch_add(1, Ordering::SeqCst) + 1;
        let mut resonance_task = self.resonance_task.lock().await;
        if let Some(previous) = resonance_task.take() {
            previous.abort();
        }
        let mut resonator = self.resonator.lock().await;
        if let Some(previous) = resonator.take() {
            let _ = previous.shutdown();
        }
        if self.options.no_mdns {
            return Ok(());
        }
        let (next, events) = Resonator::start(self.advertisement())?;
        *resonator = Some(next);
        drop(resonator);
        *resonance_task = Some(self.spawn_resonance_events(events, generation));
        self.discovery_failure_logged
            .store(false, Ordering::Relaxed);
        Ok(())
    }

    fn spawn_resonance_events(
        self: &Arc<Self>,
        mut events: tokio::sync::mpsc::Receiver<ResonanceEvent>,
        generation: u64,
    ) -> JoinHandle<()> {
        let node = Arc::clone(self);
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                if node.discovery_generation.load(Ordering::SeqCst) != generation {
                    break;
                }
                match event {
                    ResonanceEvent::Detected(peer) => node.on_detected(peer).await,
                    ResonanceEvent::Lost(id) => {
                        node.field.write().expect("field lock").remove(&id);
                        info!("peer resonance lost: {}", id.short());
                    }
                }
            }
        })
    }

    fn log_discovery_failure(&self, error: &anyhow::Error) {
        if !self.discovery_failure_logged.swap(true, Ordering::Relaxed) {
            warn!(%error, "unable to start mDNS discovery; it will be retried");
        } else {
            debug!(%error, "mDNS discovery restart failed; it will be retried");
        }
    }

    async fn pairing_watch(self: Arc<Self>) {
        let mut shutdown = self.shutdown.subscribe();
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        let mut unavailable_logged = false;
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {}
            }
            let mut key_changed = false;
            match pairing::load(&self.pairing_root) {
                Ok(Some(key)) => {
                    unavailable_logged = false;
                    let current = self
                        .active_pairing_key
                        .read()
                        .expect("pairing key lock")
                        .to_owned();
                    key_changed = current != Some(key);
                    if key_changed {
                        if current.is_some() {
                            warn!("pairing key changed; dropping entangled peers and refreshing discovery");
                        }
                        let psk = pairing::derive_psk(&key);
                        *self.active_pairing_key.write().expect("pairing key lock") = Some(key);
                        *self.keys.write().expect("key slot lock") = Some(Arc::new(LinkKeys {
                            static_private: self._identity.static_private,
                            psk,
                        }));
                        *self.pairing_group.write().expect("pairing group lock") =
                            Some(pairing::group_id(&key));
                        self.field.write().expect("field lock").clear();
                    }
                }
                Ok(None) => {
                    let paired = self.keys.read().expect("key slot lock").is_some();
                    if paired && !unavailable_logged {
                        warn!("pairing.key was removed; keeping the active pairing");
                        unavailable_logged = true;
                    }
                    if !paired {
                        unavailable_logged = false;
                    }
                }
                Err(error) => {
                    if !unavailable_logged {
                        warn!(%error, "pairing key is unavailable; keeping the active pairing");
                        unavailable_logged = true;
                    }
                }
            }
            let paired = self.keys.read().expect("key slot lock").is_some();
            if paired && !self.options.no_mdns {
                let discovery_down = self.resonator.lock().await.is_none();
                if key_changed || discovery_down {
                    if let Err(error) = self.restart_resonator().await {
                        self.log_discovery_failure(&error);
                    }
                }
            }
            if key_changed {
                self.dial_static_peers().await;
            }
            if self._identity.persistent {
                match trust::file_stamp(&self.pairing_root) {
                    Ok(stamp) => {
                        let changed = {
                            let mut previous = self.trust_stamp.lock().expect("trust stamp lock");
                            if *previous == stamp {
                                false
                            } else {
                                *previous = stamp;
                                true
                            }
                        };
                        if changed {
                            match trust::load(&self.pairing_root) {
                                Ok(store) => {
                                    self.apply_trust_store(&store);
                                    self.trust_reload_warned.store(false, Ordering::Relaxed);
                                }
                                Err(error) => {
                                    if !self.trust_reload_warned.swap(true, Ordering::Relaxed) {
                                        warn!(%error, "could not reload peer trust decisions");
                                    }
                                }
                            }
                        }
                    }
                    Err(error) => {
                        if !self.trust_reload_warned.swap(true, Ordering::Relaxed) {
                            warn!(%error, "could not inspect peer trust decisions");
                        }
                    }
                }
            }
        }
    }

    async fn static_peer_loop(self: Arc<Self>) {
        let mut shutdown = self.shutdown.subscribe();
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => self.dial_static_peers().await,
            }
        }
    }

    async fn dial_static_peers(&self) {
        if self.keys.read().expect("key slot lock").is_none() {
            return;
        }
        let mut attempted = HashSet::new();
        for peer in &self.options.peer {
            if let Ok(addresses) = lookup_host(peer).await {
                for address in addresses {
                    attempted.insert(address);
                    if self
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
                    self.dial(address, None).await;
                }
            }
        }
        let pending = self
            .field
            .read()
            .expect("field lock")
            .all()
            .into_iter()
            .filter(|peer| peer.state == PeerState::Pending)
            .collect::<Vec<_>>();
        for peer in pending {
            let Some(remote_key) = peer.static_key else {
                continue;
            };
            if self.verification_is_complete(&peer.resonance.particle_id, remote_key) {
                continue;
            }
            for address in &peer.resonance.addrs {
                let socket = SocketAddr::new(*address, peer.resonance.port);
                if attempted.insert(socket) {
                    self.dial(socket, Some(peer.resonance.clone())).await;
                }
            }
        }
    }

    fn verification_is_complete(
        &self,
        particle_id: &entangle_core::ParticleId,
        remote_key: [u8; 32],
    ) -> bool {
        let local_key = entangle_transport::public_key(&self._identity.static_private);
        let record = if self._identity.persistent {
            trust::load_verification(&self.pairing_root, particle_id)
                .ok()
                .flatten()
        } else {
            self.ephemeral_verifications
                .lock()
                .ok()
                .and_then(|records| records.get(particle_id).cloned())
        };
        record.is_some_and(|record| {
            record.local_key == hex::encode(local_key)
                && record.remote_key == hex::encode(remote_key)
                && record.is_complete()
        })
    }

    fn apply_trust_store(&self, store: &trust::TrustStore) {
        let records = self.field.read().expect("field lock").all();
        let mut field = self.field.write().expect("field lock");
        for record in records {
            let (Some(manifest), Some(static_key)) = (record.manifest, record.static_key) else {
                continue;
            };
            let approved = trust::is_approved(store, &record.resonance.particle_id, &static_key);
            let denied = trust::is_denied(store, &static_key);
            if record.state == PeerState::Pending && approved {
                if field.entangle(record.resonance.clone(), manifest, static_key) {
                    info!(
                        "peer entangled: {} ({})",
                        record.resonance.name,
                        record.resonance.particle_id.short()
                    );
                }
            } else if denied || (record.state == PeerState::Entangled && !approved) {
                field.remove(&record.resonance.particle_id);
                field.unbind(&record.resonance.particle_id);
            }
        }
    }

    /// Waits for Ctrl-C, used by the headless node command.
    pub async fn wait_for_shutdown(&self) {
        let _ = tokio::signal::ctrl_c().await;
    }

    /// Unregisters this particle from mDNS.
    pub async fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        self.discovery_generation.fetch_add(1, Ordering::SeqCst);
        if let Some(task) = self.resonance_task.lock().await.take() {
            task.abort();
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
        let mut local = serde_json::to_value(&self.manifest).expect("manifest serializes");
        let paired = self.keys.read().expect("key slot lock").is_some();
        let pairing_group = self
            .pairing_group
            .read()
            .expect("pairing group lock")
            .clone();
        local["paired"] = json!(paired);
        local["pairing_group"] = json!(pairing_group);
        local["identity"] = json!(if self._identity.persistent {
            "persistent"
        } else {
            "ephemeral"
        });
        local["link_port_fallback"] = json!(self.link_port_fallback);
        if let Some(warning) = self.identity_warning() {
            local["warning"] = json!(warning);
        }
        if !paired {
            local["hint"] = json!("Not paired: the human must run `entangle pair init` on one machine and `entangle pair join` on the others.");
        }
        let pending_approvals = self
            .field
            .read()
            .expect("field lock")
            .all()
            .into_iter()
            .filter(|peer| peer.state == PeerState::Pending)
            .count();
        local["pending_approvals"] = json!(pending_approvals);
        if pending_approvals > 0 {
            let pending_hint =
                "The human must run `entangle peer approve` on this machine; agents must not.";
            let hint = local["hint"]
                .as_str()
                .map(|existing| format!("{existing} {pending_hint}"))
                .unwrap_or_else(|| pending_hint.to_owned());
            local["hint"] = json!(hint);
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
                    "trust": "untrusted",
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
        if self.keys.read().expect("key slot lock").is_none() {
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
            if peer.state == PeerState::Pending {
                return Err(format!(
                    "particle {} is waiting for approval: the human must run `entangle peer approve` on this machine (agents must not)",
                    peer.resonance.particle_id.short()
                ));
            }
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
        let source = tokio::fs::File::open(&path)
            .await
            .map_err(|error| error.to_string())?;
        let result = entangle_link::offer(
            &Route::Direct(socket),
            self.keys.clone(),
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
        let Some(group) = self
            .pairing_group
            .read()
            .expect("pairing group lock")
            .clone()
        else {
            return;
        };
        if peer.group.as_ref() != Some(&group) {
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
        if self.keys.read().expect("key slot lock").is_none() {
            return false;
        }
        match entangle_link::handshake_stream(
            &Route::Direct(address),
            self.keys.clone(),
            &self.manifest,
            Duration::from_secs(5),
        )
        .await
        {
            Ok((manifest, remote_static, mut stream)) if manifest.protocol == PROTOCOL_VERSION => {
                if manifest.particle_id == self.manifest.particle_id {
                    return false;
                }
                let store = match self.load_trust_store() {
                    Ok(store) => store,
                    Err(error) => {
                        debug!("peer trust store could not be read: {error}");
                        return false;
                    }
                };
                if trust::is_denied(&store, &remote_static) {
                    debug!("refusing a peer key present in the local denial list");
                    return false;
                }
                if store
                    .approved
                    .get(manifest.particle_id.as_str())
                    .is_some_and(|approval| approval.static_key != hex::encode(remote_static))
                {
                    warn!(
                        "approved particle presented a different key; run `entangle peer revoke` then re-approve if this is expected"
                    );
                    return false;
                }
                if self
                    .field
                    .read()
                    .expect("field lock")
                    .binding(&manifest.particle_id)
                    .is_some_and(|bound_key| bound_key != remote_static)
                {
                    warn!(
                        particle_id = %manifest.particle_id,
                        "refusing a peer whose Noise static key changed"
                    );
                    return false;
                }
                let approved = trust::is_approved(&store, &manifest.particle_id, &remote_static);
                let existing_verification = if self._identity.persistent {
                    match trust::load_verification(&self.pairing_root, &manifest.particle_id) {
                        Ok(record) => record.is_some(),
                        Err(error) => {
                            debug!("peer verification state could not be read: {error}");
                            return false;
                        }
                    }
                } else {
                    self.ephemeral_verifications
                        .lock()
                        .expect("ephemeral verification lock")
                        .contains_key(&manifest.particle_id)
                };
                if let Err(error) = self.check_verification_capacity(
                    &manifest.particle_id,
                    &store,
                    existing_verification,
                ) {
                    debug!("{error}");
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
                let newly_transitioned = if approved {
                    self.field.write().expect("field lock").entangle(
                        resonance,
                        manifest.clone(),
                        remote_static,
                    )
                } else {
                    self.field.write().expect("field lock").pend(
                        resonance,
                        manifest.clone(),
                        remote_static,
                    )
                };
                if approved {
                    if newly_transitioned {
                        info!(
                            "peer entangled: {} ({})",
                            manifest.name,
                            manifest.particle_id.short()
                        );
                    } else {
                        debug!(
                            "peer entangled: {} ({})",
                            manifest.name,
                            manifest.particle_id.short()
                        );
                    }
                } else if newly_transitioned {
                    info!(
                        "peer awaiting approval: {} ({}); run `entangle peer approve` to verify it",
                        manifest.name,
                        manifest.particle_id.short()
                    );
                }
                let (_, record) = match self.verification_step(
                    &manifest.particle_id,
                    &manifest.name,
                    remote_static,
                    None,
                ) {
                    Ok(record) => record,
                    Err(error) => {
                        debug!("peer verification state could not be prepared: {error}");
                        return true;
                    }
                };
                let needs_verification = !approved
                    || !record.is_complete()
                    || (record.role == entangle_core::sas::Role::Committer
                        && record.reveal.is_none());
                if needs_verification {
                    if let Err(error) = self
                        .run_verify_exchange(
                            &mut stream,
                            &manifest.particle_id,
                            &manifest.name,
                            remote_static,
                        )
                        .await
                    {
                        debug!("peer verification exchange failed: {error}");
                    }
                }
                true
            }
            Ok((manifest, _, _)) => {
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
        let _in_flight = InFlightGuard {
            sync_id: offer.sync_id.clone(),
            in_flight: &self.in_flight,
        };
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
            if field
                .binding(&offer.from)
                .is_some_and(|bound| bound != peer_info.remote_static)
            {
                return Err("sender key does not match the entangled particle".into());
            }
            let peer = field.by_id(&offer.from);
            let peer = peer
                .filter(|peer| peer.state == PeerState::Entangled)
                .ok_or_else(|| "this machine has not approved the sender yet".to_owned())?;
            if field.binding(&offer.from) != Some(peer_info.remote_static) {
                return Err("sender key does not match the entangled particle".into());
            }
            field.touch(&offer.from);
            peer
        };
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
        let mut cleanup = PartialTransferGuard::new(directory.clone());
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
                return Err(format!(
                    "unable to persist received inbox metadata: {error}"
                ));
            }
            cleanup.disarm();
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
            let store = self.load_trust_store()?;
            if trust::is_denied(&store, &peer.remote_static) {
                return Err(LinkError::Handler("peer key has been denied".into()));
            }
            if store
                .approved
                .get(manifest.particle_id.as_str())
                .is_some_and(|approval| approval.static_key != hex::encode(peer.remote_static))
            {
                warn!(
                    "approved particle presented a different key; run `entangle peer revoke` then re-approve if this is expected"
                );
                return Err(LinkError::Handler(
                    "approved particle presented a different key".into(),
                ));
            }
            if self
                .field
                .read()
                .map_err(|_| LinkError::Handler("peer field lock poisoned".into()))?
                .binding(&manifest.particle_id)
                .is_some_and(|bound_key| bound_key != peer.remote_static)
            {
                warn!(
                    particle_id = %manifest.particle_id,
                    "refusing a peer whose Noise static key changed"
                );
                return Err(LinkError::Handler(
                    "particle is already entangled with a different Noise static key".into(),
                ));
            }
            let existing_verification = if self._identity.persistent {
                trust::load_verification(&self.pairing_root, &manifest.particle_id)
                    .map_err(|error| {
                        LinkError::Handler(format!("peer verification state unavailable: {error}"))
                    })?
                    .is_some()
            } else {
                self.ephemeral_verifications
                    .lock()
                    .expect("ephemeral verification lock")
                    .contains_key(&manifest.particle_id)
            };
            let approved = trust::is_approved(&store, &manifest.particle_id, &peer.remote_static);
            self.check_verification_capacity(&manifest.particle_id, &store, existing_verification)?;
            self.verification_step(
                &manifest.particle_id,
                &manifest.name,
                peer.remote_static,
                None,
            )?;

            let mut field = self.field.write().expect("field lock");
            if field
                .binding(&manifest.particle_id)
                .is_some_and(|bound_key| bound_key != peer.remote_static)
            {
                warn!(
                    particle_id = %manifest.particle_id,
                    "rejecting a manifest that claims an entangled particle with a different Noise static key"
                );
                return Err(LinkError::Handler(
                    "particle is already entangled with a different Noise static key".into(),
                ));
            }
            let existing = field.by_id(&manifest.particle_id);
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
            let peer_name = manifest.name.clone();
            let particle_id = manifest.particle_id.clone();
            if approved {
                if field.entangle(resonance, manifest, peer.remote_static) {
                    info!("peer entangled: {} ({})", peer_name, particle_id.short());
                } else {
                    debug!("peer entangled: {} ({})", peer_name, particle_id.short());
                }
            } else {
                if field.pend(resonance, manifest, peer.remote_static) {
                    info!(
                        "peer awaiting approval: {} ({}); run `entangle peer approve` to verify it",
                        peer_name,
                        particle_id.short()
                    );
                }
            }
        }
        Ok(self.manifest.clone())
    }

    async fn on_verify(
        &self,
        peer: &PeerInfo,
        message: VerifyMessage,
    ) -> std::result::Result<VerifyMessage, LinkError> {
        let matched = self
            .field
            .read()
            .map_err(|_| LinkError::Handler("peer field lock poisoned".into()))?
            .all()
            .into_iter()
            .find(|record| record.static_key == Some(peer.remote_static))
            .ok_or_else(|| LinkError::Handler("verification peer has no Hello record".into()))?;
        let (response, _) = self.verification_step(
            &matched.resonance.particle_id,
            &matched.resonance.name,
            peer.remote_static,
            Some(message),
        )?;
        Ok(response)
    }

    async fn on_offer(
        &self,
        peer: &PeerInfo,
        offer: SyncOffer,
    ) -> std::result::Result<SyncDecision, LinkError> {
        let result = self.validate_offer(peer, &offer).await;
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
    async fn validate_offer(&self, peer_info: &PeerInfo, offer: &SyncOffer) -> Result<(), String> {
        if !is_valid_sync_id(&offer.sync_id) {
            return Err("offered sync_id is malformed".to_owned());
        }
        {
            let mut field = self
                .field
                .write()
                .map_err(|_| "peer field lock poisoned".to_owned())?;
            if field
                .binding(&offer.from)
                .is_some_and(|bound| bound != peer_info.remote_static)
            {
                return Err("sender key does not match the entangled particle".into());
            }
            let peer = field
                .by_id(&offer.from)
                .filter(|peer| peer.state == PeerState::Entangled)
                .ok_or_else(|| "this machine has not approved the sender yet".to_owned())?;
            let source_ip = peer_info.addr.ip();
            if !peer.resonance.addrs.contains(&source_ip) {
                debug!(
                    particle_id = %offer.from,
                    source_ip = %source_ip,
                    "offer arrived from an address not listed for the sender"
                );
                field.add_address(&offer.from, source_ip);
            }
        }
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
        let inbox = self.inbox.lock().await;
        if inbox.iter().any(|item| item.sync_id == offer.sync_id) {
            return Err("sync_id already in use".into());
        }
        let mut in_flight = self
            .in_flight
            .lock()
            .map_err(|_| "in-flight transfer lock poisoned".to_owned())?;
        if in_flight.contains(&offer.sync_id) {
            return Err("sync_id already in use".into());
        }
        match std::fs::symlink_metadata(self.data_dir.join("inbox").join(&offer.sync_id)) {
            Ok(_) => return Err("sync_id already in use".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("could not inspect sync_id path: {error}")),
        }
        in_flight.insert(offer.sync_id.clone());
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

    async fn approve_pair(a: &Particle, b: &Particle, root_a: &Path, root_b: &Path) {
        let (sas_a, sas_b) = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let a_pending = a
                    .field
                    .read()
                    .unwrap()
                    .by_id(&b.manifest.particle_id)
                    .is_some_and(|peer| peer.state == PeerState::Pending);
                let b_pending = b
                    .field
                    .read()
                    .unwrap()
                    .by_id(&a.manifest.particle_id)
                    .is_some_and(|peer| peer.state == PeerState::Pending);
                let sas_a = trust::load_verification(root_a, &b.manifest.particle_id)
                    .unwrap()
                    .and_then(|record| record.sas);
                let sas_b = trust::load_verification(root_b, &a.manifest.particle_id)
                    .unwrap()
                    .and_then(|record| record.sas);
                if let (true, true, Some(sas_a), Some(sas_b)) = (a_pending, b_pending, sas_a, sas_b)
                {
                    break (sas_a, sas_b);
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("both peers should complete verification and remain pending");
        assert_eq!(sas_a, sas_b);
        let key_a = entangle_transport::public_key(&a._identity.static_private);
        let key_b = entangle_transport::public_key(&b._identity.static_private);
        let mut trust_a = trust::load(root_a).unwrap();
        trust_a.approved.insert(
            b.manifest.particle_id.to_string(),
            trust::Approval {
                name: b.manifest.name.clone(),
                static_key: hex::encode(key_b),
                sas: sas_a,
                approved_at: chrono::Utc::now().to_rfc3339(),
            },
        );
        let mut trust_b = trust::load(root_b).unwrap();
        trust_b.approved.insert(
            a.manifest.particle_id.to_string(),
            trust::Approval {
                name: a.manifest.name.clone(),
                static_key: hex::encode(key_a),
                sas: sas_b,
                approved_at: chrono::Utc::now().to_rfc3339(),
            },
        );
        trust::save(root_a, &trust_a).unwrap();
        trust::save(root_b, &trust_b).unwrap();
        a.apply_trust_store(&trust_a);
        b.apply_trust_store(&trust_b);
    }

    #[tokio::test]
    async fn unpaired_particle_listens_but_does_not_dial() {
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

        assert!(particle.keys.read().unwrap().is_none());
        assert!(particle.field.read().unwrap().all().is_empty());
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
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
    async fn pending_peers_share_sas_and_sync_only_after_both_approve() {
        let temp = tempfile::tempdir().unwrap();
        let root_a = temp.path().join("a");
        let root_b = temp.path().join("b");
        let key = pairing::initialize(&root_a, false).unwrap();
        pairing::join(&root_b, &pairing::encode_code(&key), false).unwrap();
        let a_port = free_port();
        let b_port = port_other_than(a_port);
        let (notification_tx, mut notification_rx) = mpsc::channel(8);
        let (b, _) = Particle::start(
            options("particle-b", b_port, root_b.clone(), None),
            Some(notification_tx),
        )
        .await
        .unwrap();
        let (a, _) = Particle::start(
            options(
                "particle-a",
                a_port,
                root_a.clone(),
                Some(format!("127.0.0.1:{b_port}")),
            ),
            None,
        )
        .await
        .unwrap();
        let a_self = a.find_particles(&json!({}))["self"].clone();
        assert_eq!(a_self["paired"], true);
        assert_eq!(a_self["pairing_group"], pairing::group_id(&key));
        let (sas_a, sas_b) = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let a_pending = a
                    .field
                    .read()
                    .unwrap()
                    .by_id(&b.manifest.particle_id)
                    .is_some_and(|peer| peer.state == PeerState::Pending);
                let b_pending = b
                    .field
                    .read()
                    .unwrap()
                    .by_id(&a.manifest.particle_id)
                    .is_some_and(|peer| peer.state == PeerState::Pending);
                let sas_a = trust::load_verification(&root_a, &b.manifest.particle_id)
                    .unwrap()
                    .and_then(|record| record.sas);
                let sas_b = trust::load_verification(&root_b, &a.manifest.particle_id)
                    .unwrap()
                    .and_then(|record| record.sas);
                if let (true, true, Some(sas_a), Some(sas_b)) = (a_pending, b_pending, sas_a, sas_b)
                {
                    break (sas_a, sas_b);
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("both peers should complete verification and remain pending");
        assert_eq!(sas_a, sas_b);
        assert_eq!(
            a.sync_state(json!({
                "particle_id": b.manifest.particle_id.as_str(),
                "state": { "before": "approval" }
            }))
            .await
            .unwrap_err(),
            format!(
                "particle {} is waiting for approval: the human must run `entangle peer approve` on this machine (agents must not)",
                b.manifest.particle_id.short()
            )
        );
        assert_eq!(
            b.sync_state(json!({
                "particle_id": a.manifest.particle_id.as_str(),
                "state": { "before": "approval" }
            }))
            .await
            .unwrap_err(),
            format!(
                "particle {} is waiting for approval: the human must run `entangle peer approve` on this machine (agents must not)",
                a.manifest.particle_id.short()
            )
        );
        let key_a = entangle_transport::public_key(&a._identity.static_private);
        let key_b = entangle_transport::public_key(&b._identity.static_private);
        let mut trust_a = trust::load(&root_a).unwrap();
        trust_a.approved.insert(
            b.manifest.particle_id.to_string(),
            trust::Approval {
                name: b.manifest.name.clone(),
                static_key: hex::encode(key_b),
                sas: sas_a,
                approved_at: chrono::Utc::now().to_rfc3339(),
            },
        );
        let mut trust_b = trust::load(&root_b).unwrap();
        trust_b.approved.insert(
            a.manifest.particle_id.to_string(),
            trust::Approval {
                name: a.manifest.name.clone(),
                static_key: hex::encode(key_a),
                sas: sas_b,
                approved_at: chrono::Utc::now().to_rfc3339(),
            },
        );
        trust::save(&root_a, &trust_a).unwrap();
        trust::save(&root_b, &trust_b).unwrap();
        a.apply_trust_store(&trust_a);
        b.apply_trust_store(&trust_b);
        assert_eq!(
            a.field
                .read()
                .unwrap()
                .by_id(&b.manifest.particle_id)
                .unwrap()
                .state,
            PeerState::Entangled
        );
        assert_eq!(
            b.field
                .read()
                .unwrap()
                .by_id(&a.manifest.particle_id)
                .unwrap()
                .state,
            PeerState::Entangled
        );
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
        let duplicate_id = file_item["sync_id"].as_str().unwrap();
        let original_file = b
            .data_dir
            .join("inbox")
            .join(duplicate_id)
            .join("source.txt");
        assert!(original_file.exists());
        let decision = b
            .on_offer(
                &PeerInfo {
                    addr: SocketAddr::from(([127, 0, 0, 1], a.manifest.link_port)),
                    remote_static: entangle_transport::public_key(&a._identity.static_private),
                    relayed: false,
                },
                SyncOffer {
                    from: a.manifest.particle_id.clone(),
                    sync_id: duplicate_id.to_owned(),
                    timeout_secs: 60,
                    kind: StateKind::File,
                    name: "source.txt".into(),
                    size: b"native transport file".len() as u64,
                    sha256: file_item["sha256"].as_str().unwrap().into(),
                    label: None,
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            decision,
            SyncDecision::Reject(reason) if reason == "sync_id already in use"
        ));
        assert!(original_file.exists());
        while notification_rx.try_recv().is_ok() {}

        let failed_id = "d00dd00dd00dd00dd00dd00dd00dd00d";
        let inbox_dir = b.data_dir.join("inbox");
        tokio::fs::create_dir(inbox_dir.join(format!("{failed_id}.json")))
            .await
            .unwrap();
        let failed_payload = b"{\"persist\":\"failure\"}";
        let failed_source = temp.path().join("failure.json");
        tokio::fs::write(&failed_source, failed_payload)
            .await
            .unwrap();
        let failed_offer = entangle_link::offer(
            &Route::Direct(SocketAddr::from(([127, 0, 0, 1], b_port))),
            a.keys.clone(),
            SyncOffer {
                from: a.manifest.particle_id.clone(),
                sync_id: failed_id.into(),
                timeout_secs: 60,
                kind: StateKind::Json,
                name: "failure.json".into(),
                size: failed_payload.len() as u64,
                sha256: hex::encode(Sha256::digest(failed_payload)),
                label: None,
            },
            tokio::fs::File::open(failed_source).await.unwrap(),
            Duration::from_secs(15),
        )
        .await
        .unwrap();
        assert!(matches!(
            failed_offer,
            entangle_link::OfferOutcome::Failed(reason)
                if reason.contains("unable to persist received inbox metadata")
        ));
        assert!(!inbox_dir.join(failed_id).exists());
        assert!(!inbox_dir.join(format!("{failed_id}.json.tmp")).exists());
        assert!(!b
            .inbox
            .lock()
            .await
            .iter()
            .any(|item| item.sync_id == failed_id));
        assert!(notification_rx.try_recv().is_err());
        assert!(!b.in_flight.lock().unwrap().contains(failed_id));
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
    async fn concurrent_dials_converge_on_the_same_sas() {
        let temp = tempfile::tempdir().unwrap();
        let root_a = temp.path().join("a");
        let root_b = temp.path().join("b");
        let key = pairing::initialize(&root_a, false).unwrap();
        pairing::join(&root_b, &pairing::encode_code(&key), false).unwrap();
        let a_port = free_port();
        let b_port = port_other_than(a_port);
        let (result_a, result_b) = tokio::join!(
            Particle::start(
                options(
                    "concurrent-a",
                    a_port,
                    root_a.clone(),
                    Some(format!("127.0.0.1:{b_port}")),
                ),
                None,
            ),
            Particle::start(
                options(
                    "concurrent-b",
                    b_port,
                    root_b.clone(),
                    Some(format!("127.0.0.1:{a_port}")),
                ),
                None,
            ),
        );
        let (a, _) = result_a.unwrap();
        let (b, _) = result_b.unwrap();
        let (sas_a, sas_b) = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let sas_a = trust::load_verification(&root_a, &b.manifest.particle_id)
                    .unwrap()
                    .and_then(|record| record.sas);
                let sas_b = trust::load_verification(&root_b, &a.manifest.particle_id)
                    .unwrap()
                    .and_then(|record| record.sas);
                if let (Some(sas_a), Some(sas_b)) = (sas_a, sas_b) {
                    break (sas_a, sas_b);
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("concurrent dials should converge on complete verification records");
        assert_eq!(sas_a, sas_b);
        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn unpaired_particle_reloads_pairing_and_authenticates_pending_peer() {
        let temp = tempfile::tempdir().unwrap();
        let root_a = temp.path().join("a");
        let root_b = temp.path().join("b");
        let key = pairing::initialize(&root_b, false).unwrap();
        let a_port = free_port();
        let b_port = port_other_than(a_port);
        let (a, _) = Particle::start(
            options(
                "unpaired-a",
                a_port,
                root_a.clone(),
                Some(format!("127.0.0.1:{b_port}")),
            ),
            None,
        )
        .await
        .unwrap();
        assert_eq!(a.find_particles(&json!({}))["self"]["paired"], false);
        let (b, _) = Particle::start(
            options(
                "paired-b",
                b_port,
                root_b,
                Some(format!("127.0.0.1:{a_port}")),
            ),
            None,
        )
        .await
        .unwrap();
        tokio::fs::write(
            root_a.join("pairing.key"),
            format!("{}\n", hex::encode(key)),
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let paired = a.find_particles(&json!({}))["self"]["paired"] == true;
                let entangled = a
                    .field
                    .read()
                    .unwrap()
                    .by_id(&b.manifest.particle_id)
                    .is_some_and(|peer| peer.state == PeerState::Pending);
                if paired && entangled {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("pairing reload should authenticate a static peer within five seconds");
        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn timed_out_partial_transfer_removes_payload_and_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let root_a = temp.path().join("a");
        let root_b = temp.path().join("b");
        let key = pairing::initialize(&root_a, false).unwrap();
        std::fs::create_dir_all(&root_b).unwrap();
        std::fs::write(
            root_b.join("pairing.key"),
            format!("{}\n", hex::encode(key)),
        )
        .unwrap();
        let a_port = free_port();
        let b_port = port_other_than(a_port);
        let (a, _) = Particle::start(
            options(
                "sender",
                a_port,
                root_a.clone(),
                Some(format!("127.0.0.1:{b_port}")),
            ),
            None,
        )
        .await
        .unwrap();
        let (b, _) = Particle::start(
            options(
                "receiver",
                b_port,
                root_b.clone(),
                Some(format!("127.0.0.1:{a_port}")),
            ),
            None,
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let a_connected = a
                    .field
                    .read()
                    .unwrap()
                    .by_id(&b.manifest.particle_id)
                    .is_some_and(|peer| peer.state == PeerState::Pending);
                let b_connected = b
                    .field
                    .read()
                    .unwrap()
                    .by_id(&a.manifest.particle_id)
                    .is_some_and(|peer| peer.state == PeerState::Pending);
                if a_connected && b_connected {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        approve_pair(&a, &b, &root_a, &root_b).await;

        let sync_id = "fedcba9876543210fedcba9876543210";
        let keys = a.keys.read().unwrap().clone().unwrap();
        let mut stream = entangle_transport::connect(
            SocketAddr::from(([127, 0, 0, 1], b_port)),
            &keys,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let frame = entangle_link::Frame::SyncOffer {
            from: a.manifest.particle_id.clone(),
            sync_id: sync_id.into(),
            timeout_secs: 5,
            kind: StateKind::File,
            name: "partial.bin".into(),
            size: 100,
            sha256: "00".repeat(32),
            label: None,
        };
        stream
            .send(&serde_json::to_vec(&frame).unwrap())
            .await
            .unwrap();
        let accepted = stream.recv(Duration::from_secs(2)).await.unwrap();
        assert!(matches!(
            serde_json::from_slice::<entangle_link::Frame>(&accepted).unwrap(),
            entangle_link::Frame::SyncAccept { .. }
        ));
        stream.send(b"partial").await.unwrap();
        sleep(Duration::from_secs(6)).await;
        let inbox_dir = root_b.join(b.manifest.particle_id.short()).join("inbox");
        assert!(!inbox_dir.join(sync_id).exists());
        assert!(!inbox_dir.join(format!("{sync_id}.json")).exists());
        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn concurrent_particle_reports_ephemeral_identity_and_port_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("shared");
        let port = free_port();
        let (first, _) = Particle::start(options("first", port, root.clone(), None), None)
            .await
            .unwrap();
        let (second, manifest) = Particle::start(options("second", port, root.clone(), None), None)
            .await
            .unwrap();

        let local = second.find_particles(&json!({}))["self"].clone();
        assert_eq!(local["identity"], "ephemeral");
        assert_eq!(local["link_port_fallback"], true);
        assert_ne!(manifest.link_port, port);
        assert!(local["warning"]
            .as_str()
            .is_some_and(|warning| warning.contains("temporary particle")));
        assert!(local["hint"].is_string());
        assert!(!root.join("peers").exists());

        first.shutdown().await;
        second.shutdown().await;
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
    async fn lost_peer_binding_rejects_hello_and_offer_from_another_key() {
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
            group: particle.pairing_group.read().unwrap().clone(),
            proto: manifest.protocol,
        };
        assert!(particle
            .field
            .write()
            .unwrap()
            .entangle(resonance, manifest.clone(), [0x11; 32]));
        let invalid_offer = SyncOffer {
            from: id.clone(),
            sync_id: "../x".into(),
            timeout_secs: 60,
            kind: StateKind::Json,
            name: "payload.json".into(),
            size: 0,
            sha256: hex::encode(Sha256::digest([])),
            label: None,
        };
        let matching_peer = PeerInfo {
            addr: SocketAddr::from(([127, 0, 0, 1], 7337)),
            remote_static: [0x11; 32],
            relayed: false,
        };
        let decision = particle
            .on_offer(&matching_peer, invalid_offer)
            .await
            .unwrap();
        assert!(matches!(
            decision,
            SyncDecision::Reject(reason) if reason.contains("sync_id is malformed")
        ));
        particle.field.write().unwrap().remove(&id);
        assert_eq!(
            particle.field.read().unwrap().binding(&id),
            Some([0x11; 32])
        );
        let hello_error = particle
            .on_hello(
                &PeerInfo {
                    addr: SocketAddr::from(([127, 0, 0, 1], 7337)),
                    remote_static: [0x22; 32],
                    relayed: false,
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
                    relayed: false,
                },
                &offer,
            )
            .await
            .unwrap_err();
        assert_eq!(error, "sender key does not match the entangled particle");
        particle.shutdown().await;
    }

    #[tokio::test]
    async fn denied_and_changed_keys_are_rejected_and_revocation_blocks_hello() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("node");
        pairing::initialize(&root, false).unwrap();
        let (particle, _) =
            Particle::start(options("receiver", free_port(), root.clone(), None), None)
                .await
                .unwrap();
        let id = ParticleId::generate();
        let manifest = peer_manifest(id.clone());
        let address = SocketAddr::from(([127, 0, 0, 1], 7337));
        let key = [0x11; 32];
        let mut store = trust::TrustStore::default();
        store.denied.insert(
            hex::encode(key),
            trust::Denial {
                particle_id: id.clone(),
                name: manifest.name.clone(),
                denied_at: chrono::Utc::now().to_rfc3339(),
                reason: "denied by operator".into(),
            },
        );
        trust::save(&root, &store).unwrap();
        assert!(particle
            .on_hello(
                &PeerInfo {
                    addr: address,
                    remote_static: key,
                    relayed: false,
                },
                manifest.clone(),
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("peer key has been denied"));
        assert!(trust::load_verification(&root, &id).unwrap().is_none());

        store.denied.clear();
        store.approved.insert(
            id.to_string(),
            trust::Approval {
                name: manifest.name.clone(),
                static_key: hex::encode(key),
                sas: [1, 2, 3],
                approved_at: chrono::Utc::now().to_rfc3339(),
            },
        );
        trust::save(&root, &store).unwrap();
        assert!(particle
            .on_hello(
                &PeerInfo {
                    addr: address,
                    remote_static: [0x22; 32],
                    relayed: false,
                },
                manifest.clone(),
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("approved particle presented a different key"));
        assert!(trust::load_verification(&root, &id).unwrap().is_none());

        let resonance = Resonance {
            particle_id: id.clone(),
            name: manifest.name.clone(),
            hostname: address.ip().to_string(),
            addrs: vec![address.ip()],
            port: manifest.link_port,
            context: None,
            group: None,
            proto: manifest.protocol,
        };
        let _ = particle
            .field
            .write()
            .unwrap()
            .pend(resonance, manifest.clone(), key);
        particle.apply_trust_store(&store);
        assert_eq!(
            particle.field.read().unwrap().by_id(&id).unwrap().state,
            PeerState::Entangled
        );

        store.approved.remove(id.as_str());
        store.denied.insert(
            hex::encode(key),
            trust::Denial {
                particle_id: id.clone(),
                name: manifest.name,
                denied_at: chrono::Utc::now().to_rfc3339(),
                reason: "revoked by operator".into(),
            },
        );
        trust::save(&root, &store).unwrap();
        particle.apply_trust_store(&store);
        assert!(particle.field.read().unwrap().by_id(&id).is_none());
        assert!(particle.field.read().unwrap().binding(&id).is_none());
        assert!(particle
            .on_hello(
                &PeerInfo {
                    addr: address,
                    remote_static: key,
                    relayed: false,
                },
                peer_manifest(id.clone()),
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("peer key has been denied"));
        particle.shutdown().await;
    }
}
