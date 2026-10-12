//! Local mDNS resonance for finding Entangle particles on a LAN.
//!
//! This crate carries discovery metadata only and is independent of transport.

use entangle_core::{ParticleId, PROTOCOL_VERSION};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::IpAddr,
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::mpsc as tokio_mpsc;
use tracing::{debug, info};

/// mDNS service name used by all Entangle particles.
pub const SERVICE_TYPE: &str = "_entangle._tcp.local.";
/// mDNS service name used for short-lived group invites.
pub const INVITE_SERVICE_TYPE: &str = "_entangle-invite._tcp.local.";

/// Information published by a local particle.
#[derive(Clone, Debug)]
pub struct Advertisement {
    /// The advertising process identity.
    pub particle_id: ParticleId,
    /// Human-readable particle name.
    pub name: String,
    /// TCP control port.
    pub port: u16,
    /// Optional project context.
    pub context: Option<String>,
    /// Public group identifiers (never group keys).
    pub groups: Vec<String>,
    /// Entangle package version.
    pub version: String,
}

/// Discovery record for a remote particle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resonance {
    /// Remote process identity.
    pub particle_id: ParticleId,
    /// Human-readable display name.
    pub name: String,
    /// Advertised DNS host name.
    pub hostname: String,
    /// Candidate network addresses, ordered by likely usefulness.
    pub addrs: Vec<IpAddr>,
    /// Remote TCP control port.
    pub port: u16,
    /// Optional project context.
    pub context: Option<String>,
    /// Public group identifiers shared with this particle.
    pub groups: Vec<String>,
    /// Remote control protocol version.
    pub proto: u32,
}

/// A resolved invite rendezvous endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InviteCandidate {
    /// One-time code nameplate.
    pub nameplate: u8,
    /// Human-readable name of the inviting particle.
    pub name: String,
    /// Advertised DNS host name.
    pub hostname: String,
    /// Candidate addresses for the advertised host.
    pub addrs: Vec<IpAddr>,
    /// TCP invite port.
    pub port: u16,
}

/// Owns a short-lived invite advertisement, separate from particle discovery.
pub struct InviteAdvert {
    daemon: ServiceDaemon,
    fullname: String,
    addresses: Vec<IpAddr>,
}

impl InviteAdvert {
    /// Registers one nameplate on the local network.
    pub fn register(nameplate: u8, name: &str, port: u16) -> Result<Self, ResonanceError> {
        let properties = encode_invite_txt(nameplate, name)?;
        let mut random = [0; 2];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let instance = format!(
            "entangle-invite-{nameplate}-{:02x}{:02x}",
            random[0], random[1]
        );
        let host = local_hostname(&ParticleId::generate());
        let service = ServiceInfo::new(
            INVITE_SERVICE_TYPE,
            &instance,
            &host,
            "",
            port,
            properties.as_slice(),
        )?
        .enable_addr_auto();
        let fullname = service.get_fullname().to_owned();
        let mut addresses = service.get_addresses().iter().copied().collect::<Vec<_>>();
        addresses.sort_by_key(|address| address.to_string());
        let daemon = ServiceDaemon::new()?;
        daemon.register(service)?;
        Ok(Self {
            daemon,
            fullname,
            addresses,
        })
    }

    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// Unregisters this invite advertisement and shuts down its daemon.
    pub fn shutdown(self) -> Result<(), ResonanceError> {
        let _ = self.daemon.unregister(&self.fullname);
        self.daemon.shutdown()?;
        Ok(())
    }

    /// Browses for matching nameplates until the timeout expires.
    pub async fn browse(
        nameplate: u8,
        timeout: Duration,
    ) -> Result<Vec<InviteCandidate>, ResonanceError> {
        Ok(browse_invites(Some(nameplate), timeout)
            .await?
            .into_values()
            .collect())
    }

    /// Browses all currently visible invites for nameplate selection.
    pub async fn visible_nameplates(timeout: Duration) -> Result<Vec<u8>, ResonanceError> {
        let mut nameplates = browse_invites(None, timeout)
            .await?
            .into_values()
            .map(|candidate| candidate.nameplate)
            .collect::<Vec<_>>();
        nameplates.sort_unstable();
        nameplates.dedup();
        Ok(nameplates)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InviteTxt {
    nameplate: u8,
    name: String,
}

/// Change in the local discovery view.
#[derive(Clone, Debug)]
pub enum ResonanceEvent {
    /// A particle was discovered or its advertisement changed.
    Detected(Resonance),
    /// A previously discovered particle disappeared.
    Lost(ParticleId),
}

/// Errors produced by mDNS registration and browsing.
#[derive(Debug, Error)]
pub enum ResonanceError {
    /// The platform mDNS daemon rejected an operation.
    #[error("mDNS operation failed: {0}")]
    Mdns(#[from] mdns_sd::Error),
    /// A remote advertisement was missing or had malformed required fields.
    #[error("invalid Entangle TXT record: {0}")]
    InvalidTxt(String),
    /// Waiting for mDNS events failed.
    #[error("mDNS event stream stopped")]
    EventStreamStopped,
}

/// Owns one mDNS daemon that advertises this particle and browses its peers.
pub struct Resonator {
    daemon: ServiceDaemon,
    fullname: String,
    worker: Option<thread::JoinHandle<()>>,
}

impl Resonator {
    /// Advertises this particle and begins browsing, filtering out its own ID.
    pub fn start(
        ad: Advertisement,
    ) -> Result<(Self, tokio_mpsc::Receiver<ResonanceEvent>), ResonanceError> {
        let daemon = ServiceDaemon::new()?;
        let host = local_hostname(&ad.particle_id);
        let instance = format!("particle-{}", ad.particle_id.short());
        let mut properties = vec![
            ("id", ad.particle_id.to_string()),
            ("proto", PROTOCOL_VERSION.to_string()),
            ("name", ad.name.clone()),
            ("ver", ad.version.clone()),
        ];
        if let Some(context) = &ad.context {
            properties.push(("ctx", context.clone()));
        }
        let groups = encode_groups(&ad.groups)?;
        properties.push(("grp", groups));
        let service = ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &host,
            "",
            ad.port,
            properties.as_slice(),
        )?
        .enable_addr_auto();
        let fullname = service.get_fullname().to_owned();
        daemon.register(service)?;
        let events = daemon.browse(SERVICE_TYPE)?;
        let (tx, rx) = tokio_mpsc::channel(64);
        let own_id = ad.particle_id;
        let worker = thread::Builder::new()
            .name("entangle-resonance".into())
            .spawn(move || bridge_events(events, tx, own_id))
            .map_err(|e| ResonanceError::InvalidTxt(e.to_string()))?;
        Ok((
            Self {
                daemon,
                fullname,
                worker: Some(worker),
            },
            rx,
        ))
    }

    /// Unregisters this particle's advertisement and shuts down mDNS.
    pub fn shutdown(mut self) -> Result<(), ResonanceError> {
        let _ = self.daemon.unregister(&self.fullname);
        self.daemon.shutdown()?;
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        Ok(())
    }
}

async fn browse_invites(
    nameplate: Option<u8>,
    timeout: Duration,
) -> Result<HashMap<String, InviteCandidate>, ResonanceError> {
    let daemon = ServiceDaemon::new()?;
    let events = daemon.browse(INVITE_SERVICE_TYPE)?;
    let (tx, mut rx) = tokio_mpsc::channel(64);
    let worker = thread::spawn(move || bridge_invite_events(events, tx));
    let deadline = Instant::now() + timeout;
    let mut found = HashMap::<String, InviteCandidate>::new();
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some((fullname, Some(candidate)))) => {
                if nameplate.is_none_or(|expected| candidate.nameplate == expected) {
                    found.insert(fullname, candidate);
                }
            }
            Ok(Some((fullname, None))) => {
                found.remove(&fullname);
            }
            Ok(None) | Err(_) => break,
        }
    }
    daemon.shutdown()?;
    let _ = worker.join();
    Ok(found)
}

fn bridge_invite_events(
    events: mdns_sd::Receiver<ServiceEvent>,
    tx: tokio_mpsc::Sender<(String, Option<InviteCandidate>)>,
) {
    while let Ok(event) = events.recv() {
        let outgoing = match event {
            ServiceEvent::ServiceResolved(info) => decode_invite_service(&info)
                .ok()
                .map(|candidate| (info.get_fullname().to_owned(), Some(candidate))),
            ServiceEvent::ServiceRemoved(_, fullname) => Some((fullname, None)),
            _ => None,
        };
        if let Some(outgoing) = outgoing {
            if tx.blocking_send(outgoing).is_err() {
                break;
            }
        }
    }
}

fn decode_invite_service(
    info: &mdns_sd::ResolvedService,
) -> Result<InviteCandidate, ResonanceError> {
    let txt = decode_invite_txt(|key| info.get_property_val_str(key).map(str::to_owned))?;
    let mut addrs = info
        .get_addresses()
        .iter()
        .map(|address| address.to_ip_addr())
        .collect::<Vec<_>>();
    addrs.sort_by_key(|address| match address {
        IpAddr::V4(ip) if !ip.is_loopback() => (0, ip.to_string()),
        IpAddr::V6(ip) if !ip.is_loopback() => (1, ip.to_string()),
        IpAddr::V4(_) | IpAddr::V6(_) => (2, address.to_string()),
    });
    Ok(InviteCandidate {
        nameplate: txt.nameplate,
        name: txt.name,
        hostname: info.get_hostname().to_owned(),
        addrs,
        port: info.get_port(),
    })
}

fn encode_invite_txt(
    nameplate: u8,
    name: &str,
) -> Result<Vec<(&'static str, String)>, ResonanceError> {
    if !(1..=99).contains(&nameplate) || name.is_empty() || name.len() > 255 {
        return Err(ResonanceError::InvalidTxt("invalid invite fields".into()));
    }
    Ok(vec![
        ("np", nameplate.to_string()),
        ("proto", PROTOCOL_VERSION.to_string()),
        ("name", name.to_owned()),
    ])
}

fn decode_invite_txt(
    property: impl Fn(&str) -> Option<String>,
) -> Result<InviteTxt, ResonanceError> {
    let property =
        |key| property(key).ok_or_else(|| ResonanceError::InvalidTxt(format!("missing {key}")));
    let nameplate = property("np")?;
    if !nameplate.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ResonanceError::InvalidTxt("invalid np".into()));
    }
    let nameplate = nameplate
        .parse::<u8>()
        .ok()
        .filter(|number| (1..=99).contains(number))
        .ok_or_else(|| ResonanceError::InvalidTxt("invalid np".into()))?;
    let proto = property("proto")?
        .parse::<u32>()
        .map_err(|_| ResonanceError::InvalidTxt("invalid proto".into()))?;
    if proto != PROTOCOL_VERSION {
        return Err(ResonanceError::InvalidTxt("unsupported proto".into()));
    }
    let name = property("name")?;
    if name.is_empty() || name.len() > 255 {
        return Err(ResonanceError::InvalidTxt("invalid name".into()));
    }
    Ok(InviteTxt { nameplate, name })
}

/// Performs a one-shot browse for up to `timeout` and returns unique particles.
pub async fn scan(timeout: Duration) -> Result<Vec<Resonance>, ResonanceError> {
    let daemon = ServiceDaemon::new()?;
    let receiver = daemon.browse(SERVICE_TYPE)?;
    let (tx, mut rx) = tokio_mpsc::channel(128);
    let worker = thread::spawn(move || bridge_events(receiver, tx, ParticleId::generate()));
    let deadline = Instant::now() + timeout;
    let mut found = HashMap::<ParticleId, Resonance>::new();
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(ResonanceEvent::Detected(peer))) => {
                found.insert(peer.particle_id.clone(), peer);
            }
            Ok(Some(ResonanceEvent::Lost(id))) => {
                found.remove(&id);
            }
            Ok(None) | Err(_) => break,
        }
    }
    daemon.shutdown()?;
    let _ = worker.join();
    Ok(found.into_values().collect())
}

fn bridge_events(
    events: mdns_sd::Receiver<ServiceEvent>,
    tx: tokio_mpsc::Sender<ResonanceEvent>,
    own_id: ParticleId,
) {
    // mdns-sd exposes a blocking flume stream; isolate it so Tokio workers stay responsive.
    let mut fullnames = HashMap::<String, ParticleId>::new();
    while let Ok(event) = events.recv() {
        let outgoing = match event {
            ServiceEvent::ServiceResolved(info) => match decode_service(&info) {
                Ok(peer) if peer.particle_id != own_id => {
                    let previous =
                        fullnames.insert(info.fullname.clone(), peer.particle_id.clone());
                    if previous.as_ref() != Some(&peer.particle_id) {
                        info!(
                            "peer detected: {} ({})",
                            peer.name,
                            peer.particle_id.short()
                        );
                    } else {
                        debug!(
                            "peer detected: {} ({})",
                            peer.name,
                            peer.particle_id.short()
                        );
                    }
                    Some(ResonanceEvent::Detected(peer))
                }
                _ => None,
            },
            ServiceEvent::ServiceRemoved(_, fullname) => fullnames.remove(&fullname).map(|id| {
                info!("peer lost: {}", id.short());
                ResonanceEvent::Lost(id)
            }),
            _ => None,
        };
        if let Some(event) = outgoing {
            if tx.blocking_send(event).is_err() {
                break;
            }
        }
    }
}

fn decode_service(info: &mdns_sd::ResolvedService) -> Result<Resonance, ResonanceError> {
    decode_values(
        |key| info.get_property_val_str(key).map(str::to_owned),
        info.get_hostname().to_owned(),
        info.get_addresses()
            .iter()
            .map(|address| address.to_ip_addr())
            .collect(),
        info.get_port(),
    )
}

fn decode_values(
    property: impl Fn(&str) -> Option<String>,
    hostname: String,
    mut addrs: Vec<IpAddr>,
    port: u16,
) -> Result<Resonance, ResonanceError> {
    let property =
        |key| property(key).ok_or_else(|| ResonanceError::InvalidTxt(format!("missing {key}")));
    let id = ParticleId::parse(property("id")?)
        .map_err(|e| ResonanceError::InvalidTxt(e.to_string()))?;
    let proto = property("proto")?
        .parse()
        .map_err(|_| ResonanceError::InvalidTxt("invalid proto".into()))?;
    let groups = decode_groups(&property("grp").unwrap_or_default())?;
    addrs.sort_by_key(|address| match address {
        IpAddr::V4(ip) if !ip.is_loopback() => (0, ip.to_string()),
        IpAddr::V6(ip) if !ip.is_loopback() => (1, ip.to_string()),
        IpAddr::V4(_) | IpAddr::V6(_) => (2, address.to_string()),
    });
    Ok(Resonance {
        particle_id: id,
        name: property("name")?,
        hostname,
        addrs,
        port,
        context: property("ctx").ok(),
        groups,
        proto,
    })
}

fn encode_groups(groups: &[String]) -> Result<String, ResonanceError> {
    let mut groups = groups.to_vec();
    if groups.len() > 8 || groups.iter().any(|group| !valid_group_id(group)) {
        return Err(ResonanceError::InvalidTxt("invalid grp".into()));
    }
    groups.sort();
    groups.dedup();
    Ok(groups.join(","))
}

fn decode_groups(value: &str) -> Result<Vec<String>, ResonanceError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut groups = value.split(',').map(str::to_owned).collect::<Vec<_>>();
    if groups.len() > 8 || groups.iter().any(|group| !valid_group_id(group)) {
        return Err(ResonanceError::InvalidTxt("invalid grp".into()));
    }
    groups.sort();
    groups.dedup();
    Ok(groups)
}

fn valid_group_id(group: &str) -> bool {
    group.len() == 8
        && group
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn local_hostname(particle_id: &ParticleId) -> String {
    let hostname = gethostname::gethostname();
    let suffix = format!("-{}", particle_id.short());
    let max_host_len = 63 - suffix.len();
    let host = sanitize_dns_label(&hostname.to_string_lossy(), max_host_len);
    format!("{host}{suffix}.local.")
}

fn sanitize_dns_label(hostname: &str, max_len: usize) -> String {
    let max_len = max_len.clamp(1, 63);
    let mut label = String::with_capacity(max_len);
    for character in hostname.chars() {
        let character = character.to_ascii_lowercase();
        if character.is_ascii_alphanumeric() {
            label.push(character);
        } else if !label.is_empty() && !label.ends_with('-') {
            label.push('-');
        }
        if label.len() == max_len {
            break;
        }
    }
    let label = label.trim_matches('-');
    if label.is_empty() {
        "entangle".chars().take(max_len).collect()
    } else {
        label.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertisement_txt_roundtrip() {
        let id = ParticleId::generate();
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &format!("particle-{}", id.short()),
            "test.local.",
            "127.0.0.1",
            7337,
            &[
                ("id", id.to_string()),
                ("proto", PROTOCOL_VERSION.to_string()),
                ("name", "test node".into()),
                ("ctx", "sample".into()),
                ("grp", "a1b2c3d4".into()),
                ("ver", "0.1.0".into()),
            ][..],
        )
        .unwrap();
        let peer = decode_values(
            |key| info.get_property_val_str(key).map(str::to_owned),
            "test.local.".into(),
            info.get_addresses().iter().copied().collect(),
            info.get_port(),
        )
        .unwrap();
        assert_eq!(peer.particle_id, id);
        assert_eq!(peer.name, "test node");
        assert_eq!(peer.context.as_deref(), Some("sample"));
        assert_eq!(peer.groups, ["a1b2c3d4"]);
        assert_eq!(peer.proto, PROTOCOL_VERSION);
    }

    #[test]
    fn invite_advert_txt_roundtrip() {
        let properties = encode_invite_txt(7, "particle-a").unwrap();
        let txt = decode_invite_txt(|key| {
            properties
                .iter()
                .find(|(property, _)| *property == key)
                .map(|(_, value)| value.clone())
        })
        .unwrap();
        assert_eq!(
            txt,
            InviteTxt {
                nameplate: 7,
                name: "particle-a".into(),
            }
        );
        assert_eq!(
            properties
                .iter()
                .find(|(key, _)| *key == "proto")
                .unwrap()
                .1,
            "4"
        );
    }

    #[test]
    fn dns_labels_are_lowercase_safe_and_bounded() {
        assert_eq!(
            sanitize_dns_label("My_Workstation.local", 63),
            "my-workstation-local"
        );
        assert_eq!(sanitize_dns_label("---", 63), "entangle");
        let long_label = sanitize_dns_label(&"A".repeat(80), 54);
        assert_eq!(long_label.len(), 54);
        assert!(long_label
            .chars()
            .all(|character| character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '-'));
    }

    #[test]
    #[ignore = "mDNS multicast is frequently unavailable in CI and containers"]
    fn live_loopback_discovery() {
        let _ = Resonator::start(Advertisement {
            particle_id: ParticleId::generate(),
            name: "loopback-test".into(),
            port: 7337,
            context: None,
            groups: vec![],
            version: env!("CARGO_PKG_VERSION").into(),
        })
        .unwrap();
    }

    #[test]
    fn group_txt_roundtrips_zero_one_and_eight_ids() {
        for groups in [
            vec![],
            vec!["a1b2c3d4".to_owned()],
            (0..8).map(|value| format!("{value:08x}")).collect(),
        ] {
            let encoded = encode_groups(&groups).unwrap();
            let mut sorted = groups.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(decode_groups(&encoded).unwrap(), sorted);
        }
    }

    #[test]
    fn group_txt_rejects_nine_ids_and_malformed_ids() {
        let nine = (0..9)
            .map(|value| format!("{value:08x}"))
            .collect::<Vec<_>>();
        assert!(encode_groups(&nine).is_err());
        assert!(decode_groups(&nine.join(",")).is_err());
        assert!(decode_groups("ABCDEFGH").is_err());
        assert!(decode_groups("abcd").is_err());
    }
}
