//! Particle lifecycle, secure peer handshakes, and inbound syncs.

use crate::{
    config::Options,
    field::{Field, LinkPath, PeerRecord, PeerState},
    groups::{self, Group},
    identity::{self, Identity},
    inbox::{self, InboxItem},
};
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use entangle_core::{is_valid_sync_id, Manifest, StateKind, PROTOCOL_VERSION};
use entangle_link::{
    LinkError, LinkHandler, LinkListener, PayloadReader, PeerInfo, Route, SyncDecision, SyncOffer,
    TunnelOpener,
};
use entangle_repeater::{client as repeater_client, RepeaterDialer};
use entangle_resonance::{Advertisement, Resonance, ResonanceEvent, Resonator};
use entangle_transport::{BoxedIo, KeyRing, SecureStream, SharedKeyRing};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
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
const RELAY_PLACEHOLDER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
const REPEATER_CONFIG_POLL: Duration = Duration::from_secs(30);
const REPEATER_DIRECTORY_POLL: Duration = Duration::from_secs(15);
const REPEATER_RECONNECT_BASE: Duration = Duration::from_secs(1);
const REPEATER_RECONNECT_CAP: Duration = Duration::from_secs(60);

fn build_key_ring(static_private: [u8; 32], groups: &[Group]) -> KeyRing {
    KeyRing {
        static_private,
        groups: groups
            .iter()
            .map(|group| {
                (
                    groups::group_id_bytes(&group.key),
                    groups::derive_psk(&group.key),
                )
            })
            .collect(),
    }
}

struct RepeaterOpener {
    dialer: RepeaterDialer,
    target: [u8; 32],
}

#[async_trait::async_trait]
impl TunnelOpener for RepeaterOpener {
    async fn open(&self) -> io::Result<BoxedIo> {
        self.dialer
            .open(self.target)
            .await
            .map(|stream| stream.into_io())
            .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, error))
    }

    fn describe(&self) -> String {
        let fingerprint = Sha256::digest(self.target);
        format!("repeater:{}", hex::encode(&fingerprint[..4]))
    }
}

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
    groups: Arc<RwLock<Vec<Group>>>,
    keys: SharedKeyRing,
    repeater: RwLock<Option<RepeaterDialer>>,
    repeater_configured: AtomicBool,
    relay_directory: StdMutex<HashSet<[u8; 32]>>,
    relay_dialing: StdMutex<HashSet<[u8; 32]>>,
    reconnect_base_ms: AtomicU64,
    reconnect_cap_ms: AtomicU64,
    repeater_directory_poll_ms: AtomicU64,
    link_port_fallback: bool,
    data_root: PathBuf,
    data_dir: PathBuf,
    resonator: Mutex<Option<Resonator>>,
    resonance_task: Mutex<Option<JoinHandle<()>>>,
    discovery_generation: AtomicU64,
    discovery_failure_logged: AtomicBool,
    inbox: Mutex<Vec<InboxItem>>,
    in_flight: StdMutex<HashSet<String>>,
    groups_reload_warned: AtomicBool,
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
        if root.join("pairing.key").exists() || root.join("peers/trust.json").exists() {
            info!("ignoring pre-0.6 pairing/approval state; use entangle group create/join");
        }
        let initial_groups = groups::list(&root)?;
        let groups = Arc::new(RwLock::new(initial_groups.clone()));
        let keys: SharedKeyRing = Arc::new(RwLock::new(Arc::new(build_key_ring(
            identity.static_private,
            &initial_groups,
        ))));
        let particle_id = identity.id.clone();
        let name = options.particle_name(&particle_id);
        let data_dir = root.join(particle_id.short());
        let inbox_dir = data_dir.join("inbox");
        tokio::fs::create_dir_all(&inbox_dir).await?;
        tokio::fs::create_dir_all(data_dir.join("outbox")).await?;
        let persisted_inbox = inbox::load(&inbox_dir).await;
        let (listener, link_port, link_port_fallback) = if options.relay_only {
            (None, 0, false)
        } else {
            match LinkListener::bind(SocketAddr::from(([0, 0, 0, 0], options.link_port))).await {
                Ok((listener, port)) => (Some(listener), port, false),
                Err(LinkError::Io(error)) if error.kind() == std::io::ErrorKind::AddrInUse => {
                    warn!(
                        configured_port = options.link_port,
                        "configured link port is occupied; using an ephemeral port; static --peer entries pointing at this machine need the new port"
                    );
                    let (listener, port) = LinkListener::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
                        .await
                        .context("could not bind Entangle TCP link listener")?;
                    (Some(listener), port, true)
                }
                Err(error) => {
                    return Err(error).context("could not bind Entangle TCP link listener")
                }
            }
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
        let repeater_configured = match crate::repeater::read_config(&root.join("repeater.json")) {
            Ok(config) => config.is_some(),
            Err(error) => {
                warn!(%error, "could not read repeater configuration");
                false
            }
        };
        let particle = Arc::new(Self {
            manifest: manifest.clone(),
            field,
            options,
            _identity: identity,
            groups,
            keys: keys.clone(),
            repeater: RwLock::new(None),
            repeater_configured: AtomicBool::new(repeater_configured),
            relay_directory: StdMutex::new(HashSet::new()),
            relay_dialing: StdMutex::new(HashSet::new()),
            reconnect_base_ms: AtomicU64::new(REPEATER_RECONNECT_BASE.as_millis() as u64),
            reconnect_cap_ms: AtomicU64::new(REPEATER_RECONNECT_CAP.as_millis() as u64),
            repeater_directory_poll_ms: AtomicU64::new(REPEATER_DIRECTORY_POLL.as_millis() as u64),
            link_port_fallback,
            data_root: root,
            data_dir,
            resonator: Mutex::new(None),
            resonance_task: Mutex::new(None),
            discovery_generation: AtomicU64::new(0),
            discovery_failure_logged: AtomicBool::new(false),
            inbox: Mutex::new(persisted_inbox),
            in_flight: StdMutex::new(HashSet::new()),
            groups_reload_warned: AtomicBool::new(false),
            notifications,
            inbound_limit: Arc::new(Semaphore::new(4)),
            shutdown,
        });
        if let Err(error) = particle.restart_resonator().await {
            particle.log_discovery_failure(&error);
        }
        if let Some(listener) = listener {
            tokio::spawn(listener.run(particle.keys.clone(), particle.clone()));
        }
        let group_node = particle.clone();
        tokio::spawn(async move { group_node.group_watch().await });
        let static_node = particle.clone();
        tokio::spawn(async move { static_node.static_peer_loop().await });
        let repeater_node = particle.clone();
        tokio::spawn(async move { repeater_node.repeater_loop().await });
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
        if particle.options.relay_only {
            info!(
                "particle {} relay-only (no listener, mDNS disabled)",
                particle.manifest.particle_id.short()
            );
            if !repeater_configured {
                warn!("relay-only mode has no repeater.json; waiting for repeater configuration");
            }
            if !particle.options.peer.is_empty() {
                warn!("--peer entries are ignored in relay-only mode");
            }
        } else if particle
            .keys
            .read()
            .expect("key ring lock")
            .groups
            .is_empty()
        {
            info!("particle is not in a group; encrypted links are disabled");
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
        let warning = format!(
            "Another Entangle process on this machine holds the saved identity and/or port {}. This node is running {reason} (identity: {identity}; link port: {}). Close the other MCP client or old Entangle process, then reload.",
            self.options.link_port, self.manifest.link_port
        );
        Some(warning)
    }

    fn group_member(&self, group_id: [u8; 4], particle_id: &str, static_key: &[u8; 32]) -> bool {
        self.groups
            .read()
            .expect("group store lock")
            .iter()
            .find(|group| groups::group_id_bytes(&group.key) == group_id)
            .is_some_and(|group| {
                group.members.iter().any(|member| {
                    member.particle_id == particle_id
                        && member.static_key == hex::encode(static_key)
                })
            })
    }

    fn group_names_for_peer(&self, particle_id: &str, static_key: &[u8; 32]) -> Vec<String> {
        self.groups
            .read()
            .expect("group store lock")
            .iter()
            .filter(|group| {
                group.members.iter().any(|member| {
                    member.particle_id == particle_id
                        && member.static_key == hex::encode(static_key)
                })
            })
            .map(|group| group.meta.name.clone())
            .collect()
    }

    fn advertisement(&self) -> Advertisement {
        Advertisement {
            particle_id: self.manifest.particle_id.clone(),
            name: self.manifest.name.clone(),
            port: self.manifest.link_port,
            context: self.manifest.context.clone(),
            groups: self
                .groups
                .read()
                .expect("group store lock")
                .iter()
                .map(|group| group.id.clone())
                .collect(),
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
        if self.options.no_mdns || self.options.relay_only {
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

    async fn group_watch(self: Arc<Self>) {
        let mut shutdown = self.shutdown.subscribe();
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        let mut unavailable_logged = false;
        let mut previous = self.groups.read().expect("group store lock").clone();
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {}
            }
            match groups::list(&self.data_root) {
                Ok(current) if current != previous => {
                    let discovered = self
                        .field
                        .read()
                        .expect("field lock")
                        .all()
                        .into_iter()
                        .map(|peer| peer.resonance)
                        .collect::<Vec<_>>();
                    previous = current.clone();
                    *self.groups.write().expect("group store lock") = current.clone();
                    *self.keys.write().expect("key ring lock") =
                        Arc::new(build_key_ring(self._identity.static_private, &current));
                    self.field.write().expect("field lock").clear();
                    self.groups_reload_warned.store(false, Ordering::Relaxed);
                    if let Err(error) = self.restart_resonator().await {
                        self.log_discovery_failure(&error);
                    }
                    for peer in discovered {
                        self.on_detected(peer).await;
                    }
                    self.dial_static_peers().await;
                }
                Ok(_) => {
                    unavailable_logged = false;
                }
                Err(error) => {
                    if !unavailable_logged {
                        warn!(%error, "could not reload group store");
                        unavailable_logged = true;
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

    async fn repeater_loop(self: Arc<Self>) {
        let mut shutdown = self.shutdown.subscribe();
        let mut failures = 0_u32;
        loop {
            if *shutdown.borrow() {
                break;
            }
            let config_path = self.data_root.join("repeater.json");
            let config = match crate::repeater::read_config(&config_path) {
                Ok(config) => {
                    self.repeater_configured
                        .store(config.is_some(), Ordering::Relaxed);
                    config
                }
                Err(error) => {
                    self.repeater_configured.store(false, Ordering::Relaxed);
                    warn!(%error, "could not read repeater configuration");
                    None
                }
            };
            let Some(config) = config else {
                self.clear_repeater();
                if !self
                    .wait_or_shutdown(&mut shutdown, REPEATER_CONFIG_POLL)
                    .await
                {
                    break;
                }
                continue;
            };
            let has_groups = !self.keys.read().expect("key ring lock").groups.is_empty();
            if !self._identity.persistent || !has_groups {
                debug!(
                    persistent = self._identity.persistent,
                    has_groups, "repeater connection gated by identity or group membership"
                );
                self.clear_repeater();
                if !self
                    .wait_or_shutdown(&mut shutdown, Duration::from_secs(1))
                    .await
                {
                    break;
                }
                continue;
            }
            let Some(group) = self
                .groups
                .read()
                .expect("group store lock")
                .first()
                .map(|group| group.id.clone())
            else {
                self.clear_repeater();
                if !self
                    .wait_or_shutdown(&mut shutdown, Duration::from_secs(1))
                    .await
                {
                    break;
                }
                continue;
            };
            // TODO(#34 phase 3): the repeater keys sessions by device, not group.
            let repeater_public: [u8; 32] = match hex::decode(&config.repeater_public_key)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
            {
                Some(public) => public,
                None => {
                    warn!("repeater configuration contains an invalid pinned key");
                    self.clear_repeater();
                    if !self
                        .wait_or_shutdown(&mut shutdown, REPEATER_CONFIG_POLL)
                        .await
                    {
                        break;
                    }
                    continue;
                }
            };
            let host = crate::repeater::websocket_host(&config.url)
                .unwrap_or("unknown host")
                .to_owned();
            let fingerprint = hex::encode(&Sha256::digest(repeater_public)[..4]);
            let connect = tokio::time::timeout(
                Duration::from_secs(10),
                repeater_client::connect(
                    &config.url,
                    self._identity.static_private,
                    repeater_public,
                    &group,
                ),
            )
            .await;
            let client = match connect {
                Ok(Ok(client)) => client,
                Ok(Err(error)) => {
                    let _ = error;
                    info!(host, fingerprint, "unable to connect to repeater");
                    failures = failures.saturating_add(1);
                    let delay = self.reconnect_delay(failures);
                    info!(delay_ms = delay.as_millis(), "reconnecting to repeater");
                    self.clear_repeater();
                    if !self.wait_or_shutdown(&mut shutdown, delay).await {
                        break;
                    }
                    continue;
                }
                Err(_) => {
                    info!(host, fingerprint, "repeater connection attempt timed out");
                    failures = failures.saturating_add(1);
                    let delay = self.reconnect_delay(failures);
                    info!(delay_ms = delay.as_millis(), "reconnecting to repeater");
                    self.clear_repeater();
                    if !self.wait_or_shutdown(&mut shutdown, delay).await {
                        break;
                    }
                    continue;
                }
            };
            info!(host, fingerprint, "connected to repeater");
            let (dialer, incoming) = client.split();
            *self.repeater.write().expect("repeater dialer lock") = Some(dialer.clone());
            failures = 0;
            let session_ended = self
                .run_repeater_session(&dialer, incoming, &config, &group, &mut shutdown)
                .await;
            self.clear_repeater();
            if !session_ended || *shutdown.borrow() {
                break;
            }
            info!(host, fingerprint, "disconnected from repeater");
            failures = failures.saturating_add(1);
            let delay = self.reconnect_delay(failures);
            info!(delay_ms = delay.as_millis(), "reconnecting to repeater");
            if !self.wait_or_shutdown(&mut shutdown, delay).await {
                break;
            }
        }
        self.clear_repeater();
    }

    async fn run_repeater_session(
        self: &Arc<Self>,
        dialer: &RepeaterDialer,
        incoming: repeater_client::IncomingStreams,
        config: &crate::repeater::RepeaterConfig,
        group: &str,
        shutdown: &mut tokio::sync::watch::Receiver<bool>,
    ) -> bool {
        let directory_poll = Duration::from_millis(
            self.repeater_directory_poll_ms
                .load(Ordering::Relaxed)
                .max(1),
        );
        let mut directory_poll =
            tokio::time::interval_at(tokio::time::Instant::now() + directory_poll, directory_poll);
        let mut config_poll = tokio::time::interval_at(
            tokio::time::Instant::now() + REPEATER_CONFIG_POLL,
            REPEATER_CONFIG_POLL,
        );
        let mut health_poll = tokio::time::interval(Duration::from_secs(1));
        let accept_node = self.clone();
        let accept_dialer = dialer.clone();
        let mut accept_task = tokio::spawn(async move {
            accept_node
                .accept_repeater_streams(accept_dialer, incoming)
                .await;
        });
        if self.refresh_relay_directory(dialer).await.is_err() {
            accept_task.abort();
            let _ = accept_task.await;
            return true;
        }
        let mut session_ended = true;
        let mut accept_task_finished = false;
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        session_ended = false;
                        break;
                    }
                }
                _ = &mut accept_task => {
                    accept_task_finished = true;
                    debug!("repeater incoming stream accept task ended");
                    break;
                }
                _ = directory_poll.tick() => {
                    if let Err(error) = self.refresh_relay_directory(dialer).await {
                        debug!(%error, "repeater directory LIST failed");
                        break;
                    }
                }
                _ = config_poll.tick() => {
                    match crate::repeater::read_config(&self.data_root.join("repeater.json")) {
                        Ok(Some(current)) if current.url == config.url
                            && current.repeater_public_key == config.repeater_public_key => {}
                        _ => {
                            debug!("repeater configuration changed or became unreadable");
                            break;
                        }
                    }
                }
                _ = health_poll.tick() => {
                    let has_groups = !self.keys.read().expect("key ring lock").groups.is_empty();
                    let current_group = self
                        .groups
                        .read()
                        .expect("group store lock")
                        .first()
                        .map(|group| group.id.clone());
                    let closed = dialer.is_closed();
                    let group_changed = current_group.as_deref() != Some(group);
                    if closed || !has_groups || group_changed {
                        debug!(closed, has_groups, group_changed, "repeater session health check failed");
                        break;
                    }
                }
            }
        }
        if !accept_task_finished {
            accept_task.abort();
            let _ = accept_task.await;
        }
        session_ended
    }

    async fn accept_repeater_streams(
        self: Arc<Self>,
        dialer: RepeaterDialer,
        mut incoming: repeater_client::IncomingStreams,
    ) {
        loop {
            let Some(incoming_stream) = incoming.accept().await else {
                debug!("repeater incoming stream receiver closed");
                return;
            };
            let local_key = entangle_transport::public_key(&self._identity.static_private);
            let source_fingerprint = hex::encode(&Sha256::digest(incoming_stream.source)[..4]);
            let serve_fingerprint = source_fingerprint.clone();
            let known_in_session_directory = self
                .relay_directory
                .lock()
                .expect("relay directory lock")
                .contains(&incoming_stream.source);
            debug!(source_fingerprint, "accepted incoming repeater stream");
            if incoming_stream.source != local_key {
                self.relay_directory
                    .lock()
                    .expect("relay directory lock")
                    .insert(incoming_stream.source);
            }
            let stream = incoming_stream.stream.into_io();
            let node: Arc<dyn LinkHandler> = self.clone();
            let keys = self.keys.clone();
            tokio::spawn(async move {
                let result =
                    entangle_link::serve_io(stream, RELAY_PLACEHOLDER, true, keys, node).await;
                match result {
                    Ok(()) => debug!(
                        source_fingerprint = serve_fingerprint,
                        "relayed peer link ended"
                    ),
                    Err(error) => debug!(
                        source_fingerprint = serve_fingerprint,
                        %error,
                        "relayed peer link failed"
                    ),
                }
            });
            if !known_in_session_directory && incoming_stream.source != local_key {
                let node = self.clone();
                let dialer = dialer.clone();
                tokio::spawn(async move {
                    debug!(
                        source_fingerprint,
                        "refreshing directory for peer missing from the current repeater session"
                    );
                    if let Err(error) = node.refresh_relay_directory(&dialer).await {
                        debug!(%error, "repeater directory refresh after incoming stream failed");
                    }
                });
            }
        }
    }

    async fn refresh_relay_directory(self: &Arc<Self>, dialer: &RepeaterDialer) -> Result<()> {
        let entries = dialer.list().await?;
        let local_key = entangle_transport::public_key(&self._identity.static_private);
        let fingerprints = entries
            .iter()
            .map(|entry| hex::encode(&Sha256::digest(entry.key)[..4]))
            .collect::<Vec<_>>();
        debug!(
            count = entries.len(),
            ?fingerprints,
            "listed repeater directory peers"
        );
        {
            let mut directory = self.relay_directory.lock().expect("relay directory lock");
            directory.clear();
            directory.extend(
                entries
                    .iter()
                    .map(|entry| entry.key)
                    .filter(|key| *key != local_key),
            );
        }
        for entry in entries {
            if entry.key == local_key {
                continue;
            }
            let already_fresh = self
                .field
                .read()
                .expect("field lock")
                .all()
                .iter()
                .any(|record| {
                    record.static_key == Some(entry.key)
                        && record.state == PeerState::Entangled
                        && record.last_seen.elapsed() < Duration::from_secs(60)
                });
            if !already_fresh {
                let fingerprint = hex::encode(&Sha256::digest(entry.key)[..4]);
                let inserted = self
                    .relay_dialing
                    .lock()
                    .expect("relay dialing lock")
                    .insert(entry.key);
                if !inserted {
                    continue;
                }
                debug!(fingerprint, "dialing repeater directory peer");
                let node = Arc::clone(self);
                let dialer = dialer.clone();
                let target = entry.key;
                tokio::spawn(async move {
                    let connected = node
                        .dial(
                            Route::Tunnel(Arc::new(RepeaterOpener { dialer, target })),
                            None,
                        )
                        .await;
                    node.relay_dialing
                        .lock()
                        .expect("relay dialing lock")
                        .remove(&target);
                    debug!(fingerprint, connected, "repeater directory dial completed");
                });
            } else {
                debug!(
                    fingerprint = hex::encode(&Sha256::digest(entry.key)[..4]),
                    "skipping fresh entangled repeater peer"
                );
            }
        }
        Ok(())
    }

    fn clear_repeater(&self) {
        *self.repeater.write().expect("repeater dialer lock") = None;
        self.relay_directory
            .lock()
            .expect("relay directory lock")
            .clear();
    }

    fn reconnect_delay(&self, failures: u32) -> Duration {
        let base = self.reconnect_base_ms.load(Ordering::Relaxed).max(1);
        let cap = self.reconnect_cap_ms.load(Ordering::Relaxed).max(base);
        let shift = failures.saturating_sub(1).min(31);
        let millis = base.saturating_mul(1_u64 << shift).min(cap);
        let entropy = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as i64;
        let jitter_per_mille = entropy.rem_euclid(401) - 200;
        let jittered = ((millis as i128) * (1000 + jitter_per_mille) as i128 / 1000).max(1) as u64;
        Duration::from_millis(jittered)
    }

    async fn wait_or_shutdown(
        &self,
        shutdown: &mut tokio::sync::watch::Receiver<bool>,
        duration: Duration,
    ) -> bool {
        tokio::select! {
            changed = shutdown.changed() => changed.is_ok() && !*shutdown.borrow(),
            _ = sleep(duration) => true,
        }
    }

    async fn dial_static_peers(&self) {
        if self.options.relay_only || self.keys.read().expect("key ring lock").groups.is_empty() {
            return;
        }
        for peer in &self.options.peer {
            if let Ok(addresses) = lookup_host(peer).await {
                for address in addresses {
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
                    self.dial(Route::Direct(address), None).await;
                }
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
        let groups = self.groups.read().expect("group store lock").clone();
        local["groups"] = json!(groups
            .iter()
            .map(|group| json!({"name": &group.meta.name, "group": &group.id}))
            .collect::<Vec<_>>());
        local["identity"] = json!(if self._identity.persistent {
            "persistent"
        } else {
            "ephemeral"
        });
        local["link_port_fallback"] = json!(self.link_port_fallback);
        let connected = self
            .repeater
            .read()
            .expect("repeater dialer lock")
            .as_ref()
            .is_some_and(|dialer| !dialer.is_closed());
        let relay_directory = self
            .relay_directory
            .lock()
            .expect("relay directory lock")
            .clone();
        local["repeater"] = json!({
            "configured": self.repeater_configured.load(Ordering::Relaxed),
            "connected": connected,
            "relay_only": self.options.relay_only,
        });
        if let Some(warning) = self.identity_warning() {
            local["warning"] = json!(warning);
        }
        let mut particles = {
            let field = self.field.read().expect("field lock");
            if relay_directory.is_empty() {
                field.view(context, include_unentangled)
            } else {
                field.view_with_relay_directory(context, include_unentangled, &relay_directory)
            }
        };
        for peer in &mut particles {
            let Some(particle_id) = peer.get("particle_id").and_then(Value::as_str) else {
                continue;
            };
            let static_key = self
                .field
                .read()
                .expect("field lock")
                .all()
                .into_iter()
                .find(|record| record.resonance.particle_id.as_str() == particle_id)
                .and_then(|record| record.static_key);
            let shared = static_key
                .map(|key| self.group_names_for_peer(particle_id, &key))
                .unwrap_or_default();
            peer["groups"] = json!(shared);
        }
        json!({"self": local, "particles": particles})
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
                    "group": item.group,
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
        if self.keys.read().expect("key ring lock").groups.is_empty() {
            return Err("the peer isn't a member of any shared group".into());
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
                return Err("the peer isn't a member of any shared group".into());
            }
            if matched.len() > 1 {
                return Err(format!("ambiguous particle ID: {peer_id}"));
            }
            matched.into_iter().next().unwrap()
        };
        let target_peer_id = peer.resonance.particle_id.clone();
        if peer.state != PeerState::Entangled
            || peer.static_key.is_none_or(|key| {
                self.group_names_for_peer(peer.resonance.particle_id.as_str(), &key)
                    .is_empty()
            })
        {
            return Err("the peer isn't a member of any shared group".into());
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
                .map_err(|e| format!("could not write outbox payload {}: {e}", path.display()))?;
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
        let (size, sha256) = hash_file(&path)
            .await
            .map_err(|error| format!("could not hash payload {}: {error}", path.display()))?;
        if size > target.max_payload_bytes {
            return Err(format!(
                "payload is {size} bytes, exceeding peer limit of {} bytes",
                target.max_payload_bytes
            ));
        }
        let remote_key = self
            .field
            .read()
            .map_err(|_| "peer field lock poisoned".to_owned())?
            .binding(&peer.resonance.particle_id)
            .filter(|bound| peer.static_key == Some(*bound))
            .ok_or_else(|| "peer has no authenticated static key".to_owned())?;
        let group_id = self
            .select_peer_group(&peer, &remote_key)
            .ok_or_else(|| "the peer isn't a member of any shared group".to_owned())?;
        let started = std::time::Instant::now();
        let direct_socket = if self.options.relay_only || peer.resonance.port == 0 {
            None
        } else {
            peer.resonance
                .addrs
                .iter()
                .find(|ip| !ip.is_loopback() && !ip.is_unspecified())
                .or_else(|| peer.resonance.addrs.iter().find(|ip| !ip.is_unspecified()))
                .copied()
                .map(|address| SocketAddr::new(address, peer.resonance.port))
        };
        let mut established = None;
        if let Some(socket) = direct_socket {
            match self
                .sync_handshake(&Route::Direct(socket), remote_key, group_id)
                .await
            {
                Ok(stream) => established = Some((stream, "direct")),
                Err(error) => debug!(%error, "direct Noise connection failed before sync offer"),
            }
        }
        if established.is_none() {
            let dialer = self
                .repeater
                .read()
                .expect("repeater dialer lock")
                .as_ref()
                .filter(|dialer| !dialer.is_closed())
                .cloned();
            let listed = self
                .relay_directory
                .lock()
                .expect("relay directory lock")
                .contains(&remote_key);
            if let Some(dialer) = dialer.filter(|_| listed) {
                let route = Route::Tunnel(Arc::new(RepeaterOpener {
                    dialer,
                    target: remote_key,
                }));
                match self.sync_handshake(&route, remote_key, group_id).await {
                    Ok(stream) => established = Some((stream, "repeater")),
                    Err(error) => {
                        debug!(%error, "repeater Noise connection failed before sync offer")
                    }
                }
            }
        }
        let Some((stream, link_path)) = established else {
            let hint = if self.repeater_configured.load(Ordering::Relaxed) {
                "configure and connect both peers to the repeater, then retry"
            } else {
                "configure a Quantum Repeater with `entangle repeater join` to enable relay fallback"
            };
            let reason = if direct_socket.is_none() {
                "peer has no usable direct address"
            } else {
                "peer could not be authenticated over a direct link"
            };
            return Err(format!("{reason}; {hint}"));
        };
        let label = args.get("label").and_then(Value::as_str).map(str::to_owned);
        let source = tokio::fs::File::open(&path)
            .await
            .map_err(|error| format!("could not open payload {}: {error}", path.display()))?;
        let result = entangle_link::offer_on(
            stream,
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
            "path": link_path,
            "elapsed_ms": started.elapsed().as_millis()
        }))
    }

    async fn sync_handshake(
        &self,
        route: &Route,
        expected_static: [u8; 32],
        group_id: [u8; 4],
    ) -> Result<SecureStream, String> {
        let stream = entangle_link::connect_secure(
            route,
            self.keys.clone(),
            group_id,
            Duration::from_secs(5),
        )
        .await
        .map_err(|error| error.to_string())?;
        if stream.remote_static() != expected_static {
            return Err("remote Noise static key did not match the bound peer key".into());
        }
        Ok(stream)
    }

    fn select_peer_group(&self, peer: &PeerRecord, static_key: &[u8; 32]) -> Option<[u8; 4]> {
        let groups = self.groups.read().expect("group store lock");
        let member_matches = |group: &&Group| {
            group.members.iter().any(|member| {
                member.particle_id == peer.resonance.particle_id.as_str()
                    && member.static_key == hex::encode(static_key)
            })
        };
        let advertised = !peer.resonance.groups.is_empty();
        groups
            .iter()
            .filter(member_matches)
            .find(|group| {
                if advertised {
                    peer.resonance.groups.contains(&group.id)
                } else {
                    peer.group_id == Some(groups::group_id_bytes(&group.key))
                        || peer.group_id.is_none()
                }
            })
            .map(|group| groups::group_id_bytes(&group.key))
    }

    async fn on_detected(&self, peer: Resonance) {
        if peer.particle_id == self.manifest.particle_id {
            return;
        }
        self.field
            .write()
            .expect("field lock")
            .resonate(peer.clone());
        let local_groups = self.groups.read().expect("group store lock").clone();
        if !local_groups
            .iter()
            .any(|group| peer.groups.contains(&group.id))
        {
            return;
        }
        for address in &peer.addrs {
            for attempt in 0..3 {
                if self
                    .dial(
                        Route::Direct(SocketAddr::new(*address, peer.port)),
                        Some(peer.clone()),
                    )
                    .await
                {
                    return;
                }
                sleep(Duration::from_millis(150 * (attempt + 1))).await;
            }
        }
    }

    async fn dial(&self, route: Route, discovery: Option<Resonance>) -> bool {
        let groups = self.groups.read().expect("group store lock").clone();
        let candidates = groups.into_iter().filter(|group| {
            if discovery
                .as_ref()
                .is_some_and(|peer| !peer.groups.contains(&group.id))
            {
                return false;
            }
            discovery.as_ref().is_none_or(|peer| {
                group
                    .members
                    .iter()
                    .any(|member| member.particle_id == peer.particle_id.as_str())
            })
        });
        for group in candidates {
            let group_id = groups::group_id_bytes(&group.key);
            match entangle_link::handshake_stream(
                &route,
                self.keys.clone(),
                group_id,
                &self.manifest,
                Duration::from_secs(5),
            )
            .await
            {
                Ok((manifest, remote_static, _stream)) if manifest.protocol == PROTOCOL_VERSION => {
                    if manifest.particle_id == self.manifest.particle_id {
                        return false;
                    }
                    let member = group.members.iter().any(|member| {
                        member.particle_id == manifest.particle_id.as_str()
                            && member.static_key == hex::encode(remote_static)
                    });
                    if !member {
                        debug!(
                            particle_id = %manifest.particle_id,
                            group = %group.meta.name,
                            "peer is not a member of the authenticated group"
                        );
                        continue;
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
                    let route_path = match &route {
                        Route::Direct(_) => LinkPath::Direct,
                        Route::Tunnel(_) => LinkPath::Repeater,
                    };
                    let mut resonance = discovery.clone().unwrap_or_else(|| match &route {
                        Route::Direct(address) => Resonance {
                            particle_id: manifest.particle_id.clone(),
                            name: manifest.name.clone(),
                            hostname: address.ip().to_string(),
                            addrs: vec![address.ip()],
                            port: manifest.link_port,
                            context: manifest.context.clone(),
                            groups: vec![group.id.clone()],
                            proto: manifest.protocol,
                        },
                        Route::Tunnel(_) => self
                            .field
                            .read()
                            .expect("field lock")
                            .by_id(&manifest.particle_id)
                            .map(|record| record.resonance.clone())
                            .unwrap_or_else(|| Resonance {
                                particle_id: manifest.particle_id.clone(),
                                name: manifest.name.clone(),
                                hostname: "via-repeater".into(),
                                addrs: vec![],
                                port: manifest.link_port,
                                context: manifest.context.clone(),
                                groups: vec![group.id.clone()],
                                proto: manifest.protocol,
                            }),
                    });
                    resonance.particle_id = manifest.particle_id.clone();
                    resonance.name = manifest.name.clone();
                    resonance.context = manifest.context.clone();
                    resonance.proto = manifest.protocol;
                    let newly_linked = self.field.write().expect("field lock").entangle_with_group(
                        resonance,
                        manifest.clone(),
                        remote_static,
                        Some(group_id),
                        Some(route_path),
                    );
                    if newly_linked {
                        info!(
                            "peer linked: {} ({})",
                            manifest.name,
                            manifest.particle_id.short()
                        );
                    }
                    return true;
                }
                Ok((manifest, _, _)) => {
                    debug!("peer protocol mismatch: {}", manifest.protocol);
                }
                Err(error) => {
                    let route_description = match &route {
                        Route::Direct(address) => address.to_string(),
                        Route::Tunnel(opener) => opener.describe(),
                    };
                    debug!(
                        "group {} handshake via {route_description} failed: {error}",
                        group.meta.name
                    );
                }
            }
        }
        false
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
            if !self.group_member(
                peer_info.group,
                offer.from.as_str(),
                &peer_info.remote_static,
            ) {
                return Err("sender is not a member of the authenticated group".into());
            }
            let peer = field.by_id(&offer.from);
            let peer = peer
                .filter(|peer| peer.state == PeerState::Entangled)
                .ok_or_else(|| "sender is not a member of a shared group".to_owned())?;
            if field.binding(&offer.from) != Some(peer_info.remote_static) {
                return Err("sender key does not match the entangled particle".into());
            }
            field.touch(&offer.from);
            peer
        };
        let Some(manifest) = peer.manifest else {
            return Err("sender is not a member of a shared group".into());
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
        tokio::fs::create_dir_all(&directory).await.map_err(|e| {
            format!(
                "could not create inbox directory {}: {e}",
                directory.display()
            )
        })?;
        let mut cleanup = PartialTransferGuard::new(directory.clone());
        let result: Result<String, String> = async {
            let path = directory.join(&name);
            let mut file = tokio::fs::File::create(&path).await.map_err(|error| {
                format!(
                    "could not create received payload {}: {error}",
                    path.display()
                )
            })?;
            let mut hasher = Sha256::new();
            let mut size = 0_u64;
            while let Some(chunk) = payload.next_chunk().await.map_err(|e| e.to_string())? {
                hasher.update(&chunk);
                size = size.saturating_add(chunk.len() as u64);
                file.write_all(&chunk).await.map_err(|error| {
                    format!(
                        "could not write received payload {}: {error}",
                        path.display()
                    )
                })?;
            }
            file.flush().await.map_err(|error| {
                format!(
                    "could not flush received payload {}: {error}",
                    path.display()
                )
            })?;
            drop(file);
            let hash = hex::encode(hasher.finalize());
            if size != offer.size || hash != offer.sha256 {
                return Err("received payload size or SHA-256 did not match the offer".into());
            }
            let (state, text) = match &offer.kind {
                StateKind::Json => {
                    let data = tokio::fs::read(&path).await.map_err(|e| {
                        format!("could not read received payload {}: {e}", path.display())
                    })?;
                    (
                        Some(
                            serde_json::from_slice(&data)
                                .map_err(|e| format!("invalid JSON payload: {e}"))?,
                        ),
                        None,
                    )
                }
                StateKind::File if size <= 64 * 1024 => {
                    let data = tokio::fs::read(&path).await.map_err(|e| {
                        format!("could not read received payload {}: {e}", path.display())
                    })?;
                    (None, String::from_utf8(data).ok())
                }
                StateKind::File => (None, None),
            };
            let group = self
                .groups
                .read()
                .expect("group store lock")
                .iter()
                .find(|group| groups::group_id_bytes(&group.key) == peer_info.group)
                .map(|group| group.meta.name.clone())
                .ok_or_else(|| "authenticated group is no longer available".to_owned())?;
            let item = InboxItem {
                group,
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
        if manifest.particle_id == self.manifest.particle_id {
            return Err(LinkError::Handler(
                "refusing a link to this particle itself".into(),
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
        if !self.group_member(
            peer.group,
            manifest.particle_id.as_str(),
            &peer.remote_static,
        ) {
            debug!(
                particle_id = %manifest.particle_id,
                group = %hex::encode(peer.group),
                "dropping Hello from a non-member"
            );
            return Err(LinkError::Handler(
                "Hello particle is not a member of the authenticated group".into(),
            ));
        }
        let mut field = self
            .field
            .write()
            .map_err(|_| LinkError::Handler("peer field lock poisoned".into()))?;
        if field
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
        let mut resonance = field
            .by_id(&manifest.particle_id)
            .map(|record| record.resonance.clone())
            .unwrap_or_else(|| Resonance {
                particle_id: manifest.particle_id.clone(),
                name: manifest.name.clone(),
                hostname: if peer.relayed {
                    "via-repeater".into()
                } else {
                    peer.addr.ip().to_string()
                },
                addrs: if peer.relayed {
                    vec![]
                } else {
                    vec![peer.addr.ip()]
                },
                port: manifest.link_port,
                context: manifest.context.clone(),
                groups: vec![hex::encode(peer.group)],
                proto: manifest.protocol,
            });
        resonance.particle_id = manifest.particle_id.clone();
        resonance.name = manifest.name.clone();
        resonance.port = manifest.link_port;
        resonance.context = manifest.context.clone();
        resonance.proto = manifest.protocol;
        let route_path = if peer.relayed {
            LinkPath::Repeater
        } else {
            LinkPath::Direct
        };
        if field.entangle_with_group(
            resonance,
            manifest.clone(),
            peer.remote_static,
            Some(peer.group),
            Some(route_path),
        ) {
            info!(
                "peer linked: {} ({})",
                manifest.name,
                manifest.particle_id.short()
            );
        }
        Ok(self.manifest.clone())
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
            if field.binding(&offer.from) != Some(peer_info.remote_static) {
                return Err("sender key does not match the entangled particle".into());
            }
            if !self.group_member(
                peer_info.group,
                offer.from.as_str(),
                &peer_info.remote_static,
            ) {
                return Err("sender is not a member of the authenticated group".into());
            }
            let peer = field
                .by_id(&offer.from)
                .filter(|peer| peer.state == PeerState::Entangled)
                .ok_or_else(|| "sender is not a member of a shared group".to_owned())?;
            if !peer_info.relayed {
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
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|error| anyhow!("could not open {} for hashing: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut size = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|error| anyhow!("could not read {} while hashing: {error}", path.display()))?;
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
    use crate::groups::Member;
    use entangle_core::ParticleId;
    use std::collections::HashMap;

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
            relay_only: false,
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

    fn canonical_temp_root(temp: &tempfile::TempDir) -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            temp.path().canonicalize().unwrap()
        }
        #[cfg(not(target_os = "macos"))]
        {
            temp.path().to_path_buf()
        }
    }

    fn port_other_than(other: u16) -> u16 {
        loop {
            let port = free_port();
            if port != other {
                return port;
            }
        }
    }

    fn saved_identity(root: &Path) -> (ParticleId, [u8; 32]) {
        let identity = identity::claim(root).unwrap();
        let result = (identity.id.clone(), identity.static_private);
        drop(identity);
        result
    }

    fn test_member(id: &ParticleId, name: &str, private: &[u8; 32], added_by: &str) -> Member {
        Member {
            particle_id: id.to_string(),
            name: name.into(),
            static_key: hex::encode(entangle_transport::public_key(private)),
            added_by: added_by.into(),
            added_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn insert_test_group(
        root: &Path,
        name: &str,
        key: [u8; 32],
        members: Vec<Member>,
        role: groups::Role,
    ) {
        groups::insert(
            root,
            key,
            groups::GroupMeta {
                version: 1,
                name: name.into(),
                role,
                created_at: chrono::Utc::now().to_rfc3339(),
            },
            members,
        )
        .unwrap();
    }

    fn prepare_group_pair(root_a: &Path, root_b: &Path, key: [u8; 32]) {
        let (id_a, private_a) = saved_identity(root_a);
        let (id_b, private_b) = saved_identity(root_b);
        let member_a = test_member(&id_a, "particle-a", &private_a, id_a.as_str());
        let member_b = test_member(&id_b, "particle-b", &private_b, id_a.as_str());
        insert_test_group(
            root_a,
            "test",
            key,
            vec![member_a.clone(), member_b.clone()],
            groups::Role::Admin,
        );
        insert_test_group(
            root_b,
            "test",
            key,
            vec![member_a, member_b],
            groups::Role::Member,
        );
    }

    async fn start_test_repeater(root: PathBuf, port: u16) -> (JoinHandle<()>, String, [u8; 32]) {
        let store = entangle_repeater::store::Store::new(&root);
        let private = store.key().unwrap();
        let public = entangle_transport::public_key(&private);
        let url = format!("ws://127.0.0.1:{port}/entangle");
        let server = tokio::spawn(async move {
            let _ = entangle_repeater::server::serve(entangle_repeater::server::ServerConfig {
                listen: SocketAddr::from(([127, 0, 0, 1], port)),
                path: "/entangle".into(),
                root,
                requests: true,
            })
            .await;
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        (server, url, public)
    }

    fn write_repeater_config(root: &Path, url: &str, public: [u8; 32]) {
        let path = root.join("repeater.json");
        let config = crate::repeater::RepeaterConfig {
            url: url.into(),
            repeater_public_key: hex::encode(public),
        };
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    async fn enroll_with_test_repeater(
        identity_root: &Path,
        repeater_root: &Path,
        url: &str,
        repeater_public: [u8; 32],
        invite_secret: [u8; 32],
    ) {
        let identity = identity::claim(identity_root).unwrap();
        let static_private = identity.static_private;
        drop(identity);
        let store = entangle_repeater::store::Store::new(repeater_root);
        let expires = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
        store.add_invite(invite_secret, expires, None).unwrap();
        entangle_repeater::client::enroll(
            url,
            static_private,
            repeater_public,
            invite_secret,
            None,
        )
        .await
        .unwrap();
    }

    async fn prepare_test_repeater_pair(
        root_a: &Path,
        root_b: &Path,
        repeater_root: &Path,
        port: u16,
    ) -> (JoinHandle<()>, String, [u8; 32]) {
        let (server, url, repeater_public) =
            start_test_repeater(repeater_root.to_path_buf(), port).await;
        prepare_group_pair(root_a, root_b, [0x41; 32]);
        enroll_with_test_repeater(root_a, repeater_root, &url, repeater_public, [0x51; 32]).await;
        enroll_with_test_repeater(root_b, repeater_root, &url, repeater_public, [0x52; 32]).await;
        write_repeater_config(root_a, &url, repeater_public);
        write_repeater_config(root_b, &url, repeater_public);
        (server, url, repeater_public)
    }

    async fn wait_for_repeater(a: &Particle, b: &Particle) {
        let a_key = entangle_transport::public_key(&a._identity.static_private);
        let b_key = entangle_transport::public_key(&b._identity.static_private);
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let a_connected =
                    a.find_particles(&json!({}))["self"]["repeater"]["connected"] == true;
                let b_connected =
                    b.find_particles(&json!({}))["self"]["repeater"]["connected"] == true;
                let a_lists_b = a
                    .relay_directory
                    .lock()
                    .expect("relay directory lock")
                    .contains(&b_key);
                let b_lists_a = b
                    .relay_directory
                    .lock()
                    .expect("relay directory lock")
                    .contains(&a_key);
                if a_connected && b_connected && a_lists_b && b_lists_a {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("both particles should connect and see each other in the repeater directory");
    }

    async fn wait_for_repeater_sessions(a: &Particle, b: &Particle) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let a_connected =
                    a.find_particles(&json!({}))["self"]["repeater"]["connected"] == true;
                let b_connected =
                    b.find_particles(&json!({}))["self"]["repeater"]["connected"] == true;
                if a_connected && b_connected {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("both particles should connect to the repeater");
    }

    async fn wait_for_group_pair(a: &Particle, b: &Particle) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let a_linked = a
                    .field
                    .read()
                    .unwrap()
                    .by_id(&b.manifest.particle_id)
                    .is_some_and(|peer| peer.state == PeerState::Entangled);
                let b_linked = b
                    .field
                    .read()
                    .unwrap()
                    .by_id(&a.manifest.particle_id)
                    .is_some_and(|peer| peer.state == PeerState::Entangled);
                if a_linked && b_linked {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("group members should link through the repeater");
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
    async fn groupless_particle_listens_but_does_not_dial() {
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

        assert!(particle.keys.read().unwrap().groups.is_empty());
        assert!(particle.field.read().unwrap().all().is_empty());
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
        assert!(matches!(
            target.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        let local = particle.find_particles(&json!({}))["self"].clone();
        assert!(local["groups"].as_array().unwrap().is_empty());
        particle.shutdown().await;
    }

    #[tokio::test]
    async fn mutual_group_members_link_sync_and_label_inbox_items() {
        let temp = tempfile::tempdir().unwrap();
        let root_a = temp.path().join("a");
        let root_b = temp.path().join("b");
        prepare_group_pair(&root_a, &root_b, [0x41; 32]);
        let a_port = free_port();
        let b_port = port_other_than(a_port);
        let (b, _) = Particle::start(options("particle-b", b_port, root_b, None), None)
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
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let linked = a
                    .field
                    .read()
                    .unwrap()
                    .by_id(&b.manifest.particle_id)
                    .is_some_and(|peer| peer.state == PeerState::Entangled);
                if linked {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("mutual group members should link");
        let result = a
            .sync_state(json!({
                "particle_id": b.manifest.particle_id.as_str(),
                "state": { "message": "grouped" },
                "timeout_secs": 60
            }))
            .await
            .unwrap();
        assert_eq!(result["delivered"], true);
        let observed = b.observe(&json!({ "limit": 20 })).await;
        assert_eq!(observed["states"][0]["group"], "test");
        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn static_peer_dial_uses_first_shared_group_by_name() {
        let temp = tempfile::tempdir().unwrap();
        let root_a = temp.path().join("a");
        let root_b = temp.path().join("b");
        let (id_a, private_a) = saved_identity(&root_a);
        let (id_b, private_b) = saved_identity(&root_b);
        let member_a = test_member(&id_a, "particle-a", &private_a, id_a.as_str());
        let member_b = test_member(&id_b, "particle-b", &private_b, id_a.as_str());
        insert_test_group(
            &root_a,
            "a",
            [0xa1; 32],
            vec![member_a.clone()],
            groups::Role::Admin,
        );
        insert_test_group(
            &root_a,
            "b",
            [0xb2; 32],
            vec![member_a.clone(), member_b.clone()],
            groups::Role::Member,
        );
        insert_test_group(
            &root_b,
            "b",
            [0xb2; 32],
            vec![member_a.clone(), member_b.clone()],
            groups::Role::Admin,
        );
        insert_test_group(
            &root_b,
            "c",
            [0xc3; 32],
            vec![member_b],
            groups::Role::Member,
        );
        let a_port = free_port();
        let b_port = port_other_than(a_port);
        let (b, _) = Particle::start(options("particle-b", b_port, root_b, None), None)
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
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if a.field
                    .read()
                    .unwrap()
                    .by_id(&b.manifest.particle_id)
                    .is_some_and(|peer| peer.state == PeerState::Entangled)
                {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("static peer should link using the shared group");
        assert_eq!(
            a.field
                .read()
                .unwrap()
                .by_id(&b.manifest.particle_id)
                .unwrap()
                .group_id,
            Some(groups::group_id_bytes(&[0xb2; 32]))
        );
        let result = a
            .sync_state(json!({
                "particle_id": b.manifest.particle_id.as_str(),
                "state": { "shared_group": "b" },
                "timeout_secs": 60
            }))
            .await
            .unwrap();
        assert_eq!(result["delivered"], true);
        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn group_membership_changes_redial_and_revoke_sync_access() {
        let temp = tempfile::tempdir().unwrap();
        let root_a = temp.path().join("a");
        let root_b = temp.path().join("b");
        let key = [0x52; 32];
        let (id_a, private_a) = saved_identity(&root_a);
        let (id_b, private_b) = saved_identity(&root_b);
        let member_a = test_member(&id_a, "particle-a", &private_a, id_a.as_str());
        let member_b = test_member(&id_b, "particle-b", &private_b, id_a.as_str());
        insert_test_group(
            &root_a,
            "test",
            key,
            vec![member_a.clone()],
            groups::Role::Admin,
        );
        insert_test_group(
            &root_b,
            "test",
            key,
            vec![member_a, member_b.clone()],
            groups::Role::Member,
        );
        let a_port = free_port();
        let b_port = port_other_than(a_port);
        let (b, _) = Particle::start(options("particle-b", b_port, root_b, None), None)
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
        assert!(a
            .field
            .read()
            .unwrap()
            .by_id(&b.manifest.particle_id)
            .is_none());
        assert!(a
            .sync_state(json!({
                "particle_id": b.manifest.particle_id.as_str(),
                "state": { "message": "before membership" }
            }))
            .await
            .unwrap_err()
            .contains("isn't a member of any shared group"));
        groups::add_member(&root_a, &groups::group_id(&key), member_b).unwrap();
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if a.field
                    .read()
                    .unwrap()
                    .by_id(&b.manifest.particle_id)
                    .is_some_and(|peer| peer.state == PeerState::Entangled)
                {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the group-store watcher should redial after membership is added");
        groups::leave(&root_a, "test").unwrap();
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if a.groups.read().unwrap().is_empty() {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the group-store watcher should observe leaving the group");
        assert!(a
            .sync_state(json!({
                "particle_id": b.manifest.particle_id.as_str(),
                "state": { "message": "after leave" }
            }))
            .await
            .unwrap_err()
            .contains("isn't a member of any shared group"));
        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn timed_out_partial_transfer_removes_payload_and_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let root_a = temp.path().join("a");
        let root_b = temp.path().join("b");
        prepare_group_pair(&root_a, &root_b, [0x41; 32]);
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
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let sync_id = "fedcba9876543210fedcba9876543210";
        let keys = a.keys.read().unwrap().clone();
        let mut stream = entangle_transport::connect(
            SocketAddr::from(([127, 0, 0, 1], b_port)),
            &keys,
            groups::group_id_bytes(&[0x41; 32]),
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
        assert!(!root.join("peers").exists());

        first.shutdown().await;
        second.shutdown().await;
    }

    #[tokio::test]
    async fn lost_peer_binding_rejects_hello_and_offer_from_another_key() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("node");
        let (local_id, local_private) = saved_identity(&root);
        let id = ParticleId::generate();
        let remote_private = [0x11; 32];
        insert_test_group(
            &root,
            "test",
            [0x41; 32],
            vec![
                test_member(&local_id, "receiver", &local_private, local_id.as_str()),
                test_member(&id, "peer", &remote_private, local_id.as_str()),
            ],
            groups::Role::Admin,
        );
        let (particle, _) = Particle::start(options("receiver", free_port(), root, None), None)
            .await
            .unwrap();
        let manifest = peer_manifest(id.clone());
        let resonance = Resonance {
            particle_id: id.clone(),
            name: manifest.name.clone(),
            hostname: "127.0.0.1".into(),
            addrs: vec!["127.0.0.1".parse().unwrap()],
            port: manifest.link_port,
            context: None,
            groups: vec![groups::group_id(&[0x41; 32])],
            proto: manifest.protocol,
        };
        assert!(particle.field.write().unwrap().entangle(
            resonance,
            manifest.clone(),
            entangle_transport::public_key(&remote_private)
        ));
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
            remote_static: entangle_transport::public_key(&remote_private),
            group: groups::group_id_bytes(&[0x41; 32]),
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
            Some(entangle_transport::public_key(&remote_private))
        );
        let hello_error = particle
            .on_hello(
                &PeerInfo {
                    addr: SocketAddr::from(([127, 0, 0, 1], 7337)),
                    remote_static: [0x22; 32],
                    group: groups::group_id_bytes(&[0x41; 32]),
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
                    group: groups::group_id_bytes(&[0x41; 32]),
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
    async fn unbound_static_key_cannot_receive_sync_offer_for_a_group_member() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("node");
        let (local_id, local_private) = saved_identity(&root);
        let trusted_id = ParticleId::generate();
        let trusted_private = [0x11; 32];
        let unbound_private = [0x22; 32];
        let group_key = [0x41; 32];
        let group_id = groups::group_id_bytes(&group_key);
        insert_test_group(
            &root,
            "test",
            group_key,
            vec![
                test_member(&local_id, "receiver", &local_private, local_id.as_str()),
                test_member(&trusted_id, "peer", &trusted_private, local_id.as_str()),
            ],
            groups::Role::Admin,
        );
        let (particle, _) = Particle::start(options("receiver", free_port(), root, None), None)
            .await
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let responder_keys = KeyRing {
            static_private: unbound_private,
            groups: HashMap::from([(group_id, groups::derive_psk(&group_key))]),
        };
        let accept_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            entangle_transport::accept_io(
                Box::new(stream),
                &responder_keys,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });
        let error = match particle
            .sync_handshake(
                &Route::Direct(address),
                entangle_transport::public_key(&trusted_private),
                group_id,
            )
            .await
        {
            Ok(_) => panic!("unbound static key must not complete the sync handshake"),
            Err(error) => error,
        };
        assert!(error.contains("remote Noise static key did not match"));
        accept_task.await.unwrap();
        particle.shutdown().await;
    }

    #[tokio::test]
    async fn relayed_hello_preserves_discovery_addresses_and_never_learns_placeholder() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("node");
        let (local_id, local_private) = saved_identity(&root);
        let id = ParticleId::generate();
        let remote_private = [0x33; 32];
        insert_test_group(
            &root,
            "test",
            [0x41; 32],
            vec![
                test_member(&local_id, "receiver", &local_private, local_id.as_str()),
                test_member(&id, "peer", &remote_private, local_id.as_str()),
            ],
            groups::Role::Admin,
        );
        let (particle, _) = Particle::start(options("receiver", free_port(), root, None), None)
            .await
            .unwrap();
        let mut manifest = peer_manifest(id.clone());
        manifest.link_port = 7338;
        let known_address = "192.0.2.42".parse().unwrap();
        particle.field.write().unwrap().resonate(Resonance {
            particle_id: id.clone(),
            name: manifest.name.clone(),
            hostname: "peer.local.".into(),
            addrs: vec![known_address],
            port: 7338,
            context: None,
            groups: vec![groups::group_id(&[0x41; 32])],
            proto: manifest.protocol,
        });

        particle
            .on_hello(
                &PeerInfo {
                    addr: RELAY_PLACEHOLDER,
                    remote_static: entangle_transport::public_key(&remote_private),
                    group: groups::group_id_bytes(&[0x41; 32]),
                    relayed: true,
                },
                manifest,
            )
            .await
            .unwrap();

        let record = particle.field.read().unwrap().by_id(&id).unwrap();
        assert_eq!(record.resonance.hostname, "peer.local.");
        assert_eq!(record.resonance.addrs, vec![known_address]);
        assert_eq!(record.resonance.port, 7338);
        assert_eq!(record.path, Some(LinkPath::Repeater));
        let view = particle.find_particles(&json!({"include_unentangled": true}));
        assert_eq!(view["particles"][0]["path"], "repeater");
        assert_eq!(view["particles"][0]["addrs"], json!(["192.0.2.42"]));
        assert!(!view.to_string().contains("0.0.0.0"));
        particle.shutdown().await;
    }

    #[tokio::test]
    async fn relay_only_self_reports_listener_and_repeater_state() {
        let temp = tempfile::tempdir().unwrap();
        let mut options = options("relay-only", 0, temp.path().join("node"), None);
        options.relay_only = true;
        options.peer.push("127.0.0.1:7337".into());
        let (particle, manifest) = Particle::start(options, None).await.unwrap();
        assert_eq!(manifest.link_port, 0);
        assert!(!particle.link_port_fallback);
        let view = particle.find_particles(&json!({}));
        assert_eq!(
            view["self"]["repeater"],
            json!({"configured": false, "connected": false, "relay_only": true})
        );
        assert_eq!(view["self"]["repeater"].as_object().unwrap().len(), 3);
        particle.shutdown().await;
    }

    #[tokio::test]
    async fn relay_only_particles_exchange_json_and_files_through_repeater() {
        let temp = tempfile::tempdir().unwrap();
        let temp_root = canonical_temp_root(&temp);
        let root_a = temp_root.join("a");
        let root_b = temp_root.join("b");
        let repeater_root = temp_root.join("repeater");
        let port = free_port();
        let (server, _, _) =
            prepare_test_repeater_pair(&root_a, &root_b, &repeater_root, port).await;
        let mut options_a = options("particle-a", 0, root_a.clone(), None);
        let mut options_b = options("particle-b", 0, root_b.clone(), None);
        options_a.relay_only = true;
        options_b.relay_only = true;
        let (a, _) = Particle::start(options_a, None).await.unwrap();
        let (b, _) = Particle::start(options_b, None).await.unwrap();
        wait_for_repeater(&a, &b).await;
        wait_for_group_pair(&a, &b).await;
        for particle in [&a, &b] {
            assert_eq!(
                particle.find_particles(&json!({}))["self"]["repeater"],
                json!({"configured": true, "connected": true, "relay_only": true})
            );
        }

        for (source, target, value) in [
            (&a, &b, json!({"from": "a"})),
            (&b, &a, json!({"from": "b"})),
        ] {
            let result = source
                .sync_state(json!({
                    "particle_id": target.manifest.particle_id.as_str(),
                    "state": value,
                    "timeout_secs": 60
                }))
                .await
                .unwrap();
            assert_eq!(result["path"], "repeater");
        }

        let bytes = (0..256 * 1024)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let expected_hash = hex::encode(Sha256::digest(&bytes));
        for (source, target, filename) in [(&a, &b, "a.bin"), (&b, &a, "b.bin")] {
            let path = temp.path().join(filename);
            tokio::fs::write(&path, &bytes).await.unwrap();
            let result = source
                .sync_state(json!({
                    "particle_id": target.manifest.particle_id.as_str(),
                    "file_path": path,
                    "timeout_secs": 60
                }))
                .await
                .unwrap();
            assert_eq!(result["path"], "repeater");
            assert_eq!(result["sha256"], expected_hash);
            let receiver_path = target
                .data_dir
                .join("inbox")
                .join(result["sync_id"].as_str().unwrap())
                .join(filename);
            assert_eq!(tokio::fs::read(receiver_path).await.unwrap(), bytes);
        }

        for (node, other) in [(&a, &b), (&b, &a)] {
            let view = node.find_particles(&json!({}));
            let peer = view["particles"]
                .as_array()
                .unwrap()
                .iter()
                .find(|peer| peer["particle_id"] == other.manifest.particle_id.as_str())
                .unwrap();
            assert_eq!(peer["state"], "linked");
            assert_eq!(peer["path"], "repeater");
            assert_eq!(peer["via_repeater"], true);
            assert_eq!(peer["addrs"], json!([]));
            assert!(!view.to_string().contains("0.0.0.0"));
        }

        a.shutdown().await;
        b.shutdown().await;
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn normal_particle_uses_repeater_for_relay_only_peer() {
        let temp = tempfile::tempdir().unwrap();
        let temp_root = canonical_temp_root(&temp);
        let root_a = temp_root.join("a");
        let root_b = temp_root.join("b");
        let repeater_root = temp_root.join("repeater");
        let (server, _, _) =
            prepare_test_repeater_pair(&root_a, &root_b, &repeater_root, free_port()).await;
        let options_a = options("particle-a", free_port(), root_a.clone(), None);
        let mut options_b = options("particle-b", 0, root_b.clone(), None);
        options_b.relay_only = true;
        let (a, _) = Particle::start(options_a, None).await.unwrap();
        let (b, _) = Particle::start(options_b, None).await.unwrap();
        wait_for_repeater(&a, &b).await;
        wait_for_group_pair(&a, &b).await;

        let result = a
            .sync_state(json!({
                "particle_id": b.manifest.particle_id.as_str(),
                "state": {"route": "repeater"},
                "timeout_secs": 60
            }))
            .await
            .unwrap();
        assert_eq!(result["path"], "repeater");
        let peer = a.find_particles(&json!({}))["particles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|peer| peer["particle_id"] == b.manifest.particle_id.as_str())
            .unwrap()
            .clone();
        assert_eq!(peer["path"], "repeater");
        assert_eq!(peer["addrs"], json!([]));

        a.shutdown().await;
        b.shutdown().await;
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn failed_direct_noise_handshake_falls_back_to_repeater_before_offer() {
        let temp = tempfile::tempdir().unwrap();
        let temp_root = canonical_temp_root(&temp);
        let root_a = temp_root.join("a");
        let root_b = temp_root.join("b");
        let repeater_root = temp_root.join("repeater");
        let (server, _, _) =
            prepare_test_repeater_pair(&root_a, &root_b, &repeater_root, free_port()).await;
        let options_a = options("particle-a", free_port(), root_a.clone(), None);
        let mut options_b = options("particle-b", 0, root_b.clone(), None);
        options_b.relay_only = true;
        let (a, _) = Particle::start(options_a, None).await.unwrap();
        let (b, _) = Particle::start(options_b, None).await.unwrap();
        wait_for_repeater(&a, &b).await;
        wait_for_group_pair(&a, &b).await;

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let dead_direct_addr = listener.local_addr().unwrap();
        let unrelated_listener = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let _ = socket.write_all(b"not a Noise response").await;
            }
        });
        let mut advertised = a
            .field
            .read()
            .unwrap()
            .by_id(&b.manifest.particle_id)
            .unwrap()
            .resonance;
        advertised.hostname = "127.0.0.1".into();
        advertised.addrs = vec![dead_direct_addr.ip()];
        advertised.port = dead_direct_addr.port();
        a.field.write().unwrap().resonate(advertised);

        let result = a
            .sync_state(json!({
                "particle_id": b.manifest.particle_id.as_str(),
                "state": {"route": "authenticated fallback"},
                "timeout_secs": 60
            }))
            .await
            .unwrap();
        assert_eq!(result["path"], "repeater");

        unrelated_listener.abort();
        a.shutdown().await;
        b.shutdown().await;
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn normal_particles_prefer_direct_route_with_repeater_available() {
        let temp = tempfile::tempdir().unwrap();
        let temp_root = canonical_temp_root(&temp);
        let root_a = temp_root.join("a");
        let root_b = temp_root.join("b");
        let repeater_root = temp_root.join("repeater");
        let repeater_port = free_port();
        let port_a = loop {
            let port = free_port();
            if port != repeater_port {
                break port;
            }
        };
        let port_b = loop {
            let port = free_port();
            if port != repeater_port && port != port_a {
                break port;
            }
        };
        let (server, _, _) =
            prepare_test_repeater_pair(&root_a, &root_b, &repeater_root, repeater_port).await;
        let options_a = options(
            "particle-a",
            port_a,
            root_a.clone(),
            Some(format!("127.0.0.1:{port_b}")),
        );
        let options_b = options(
            "particle-b",
            port_b,
            root_b.clone(),
            Some(format!("127.0.0.1:{port_a}")),
        );
        let (a, _) = Particle::start(options_a, None).await.unwrap();
        let (b, _) = Particle::start(options_b, None).await.unwrap();
        wait_for_repeater_sessions(&a, &b).await;
        wait_for_group_pair(&a, &b).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if a.field
                    .read()
                    .unwrap()
                    .by_id(&b.manifest.particle_id)
                    .is_some_and(|peer| !peer.resonance.addrs.is_empty())
                {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("direct Hello should preserve a usable TCP address");

        let result = a
            .sync_state(json!({
                "particle_id": b.manifest.particle_id.as_str(),
                "state": {"route": "direct"},
                "timeout_secs": 60
            }))
            .await
            .unwrap();
        assert_eq!(result["path"], "direct");

        a.shutdown().await;
        b.shutdown().await;
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn relay_only_particles_reconnect_after_repeater_restart() {
        let temp = tempfile::tempdir().unwrap();
        let temp_root = canonical_temp_root(&temp);
        let root_a = temp_root.join("a");
        let root_b = temp_root.join("b");
        let repeater_root = temp_root.join("repeater");
        let port = free_port();
        let (server, url, repeater_public) =
            prepare_test_repeater_pair(&root_a, &root_b, &repeater_root, port).await;
        let mut options_a = options("particle-a", 0, root_a.clone(), None);
        let mut options_b = options("particle-b", 0, root_b.clone(), None);
        options_a.relay_only = true;
        options_b.relay_only = true;
        let (a, _) = Particle::start(options_a, None).await.unwrap();
        let (b, _) = Particle::start(options_b, None).await.unwrap();
        for particle in [&a, &b] {
            particle.reconnect_base_ms.store(100, Ordering::Relaxed);
            particle.reconnect_cap_ms.store(400, Ordering::Relaxed);
            particle
                .repeater_directory_poll_ms
                .store(100, Ordering::Relaxed);
        }
        wait_for_repeater(&a, &b).await;
        wait_for_group_pair(&a, &b).await;

        server.abort();
        let _ = server.await;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let a_connected =
                    a.find_particles(&json!({}))["self"]["repeater"]["connected"] == true;
                let b_connected =
                    b.find_particles(&json!({}))["self"]["repeater"]["connected"] == true;
                if !a_connected && !b_connected {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("both nodes should observe the repeater disconnect");

        let (server, restarted_url, restarted_public) =
            start_test_repeater(repeater_root, port).await;
        assert_eq!(restarted_url, url);
        assert_eq!(restarted_public, repeater_public);
        wait_for_repeater(&a, &b).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let a_entangled = a
                    .field
                    .read()
                    .unwrap()
                    .by_id(&b.manifest.particle_id)
                    .is_some_and(|peer| peer.state == PeerState::Entangled);
                let b_entangled = b
                    .field
                    .read()
                    .unwrap()
                    .by_id(&a.manifest.particle_id)
                    .is_some_and(|peer| peer.state == PeerState::Entangled);
                if a_entangled && b_entangled {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("both peers should re-establish their approved link");
        let result = a
            .sync_state(json!({
                "particle_id": b.manifest.particle_id.as_str(),
                "state": {"after_restart": true},
                "timeout_secs": 60
            }))
            .await
            .unwrap();
        assert_eq!(result["path"], "repeater");

        a.shutdown().await;
        b.shutdown().await;
        server.abort();
        let _ = server.await;
    }
}
