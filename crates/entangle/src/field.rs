//! In-memory field of recently resonating and entangled particles.

use entangle_core::{Manifest, ParticleId};
use entangle_resonance::Resonance;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::Instant,
};

/// Relationship state stored for a peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerState {
    /// The peer was discovered but its Hello handshake has not completed.
    Seen,
    /// The peer exchanged compatible manifests.
    Entangled,
}

/// Route used by the most recent successful peer Hello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkPath {
    /// The peer link used a direct TCP connection.
    Direct,
    /// The peer link was carried through a Quantum Repeater.
    Repeater,
}

/// One peer record and its latest discovery and manifest data.
#[derive(Clone, Debug)]
pub struct PeerRecord {
    /// Last mDNS or direct-connection metadata.
    pub resonance: Resonance,
    /// Full manifest, populated after a successful handshake.
    pub manifest: Option<Manifest>,
    /// Noise static public key authenticated by that handshake.
    pub static_key: Option<[u8; 32]>,
    /// Current relationship state.
    pub state: PeerState,
    /// Group selected by the authenticated link.
    pub group_id: Option<[u8; 4]>,
    /// Route used by the most recent successful Hello, if known.
    pub path: Option<LinkPath>,
    /// Monotonic time at which this record was refreshed.
    pub last_seen: Instant,
}

/// Registry of local peer records.
#[derive(Default)]
pub struct Field {
    peers: HashMap<ParticleId, PeerRecord>,
    bindings: HashMap<ParticleId, [u8; 32]>,
}

impl Field {
    /// Adds or refreshes a discovered particle.
    pub fn resonate(&mut self, resonance: Resonance) {
        let record = self
            .peers
            .entry(resonance.particle_id.clone())
            .or_insert(PeerRecord {
                resonance: resonance.clone(),
                manifest: None,
                static_key: None,
                state: PeerState::Seen,
                group_id: None,
                path: None,
                last_seen: Instant::now(),
            });
        record.resonance = resonance;
        record.last_seen = Instant::now();
    }

    /// Stores a validated manifest and marks the peer entangled.
    #[must_use]
    #[cfg(test)]
    pub fn entangle(
        &mut self,
        resonance: Resonance,
        manifest: Manifest,
        static_key: [u8; 32],
    ) -> bool {
        self.entangle_with_group(
            resonance,
            manifest,
            static_key,
            None,
            Some(LinkPath::Direct),
        )
    }

    /// Stores a validated manifest, group, relationship state, and route.
    #[must_use]
    pub fn entangle_with_group(
        &mut self,
        mut resonance: Resonance,
        manifest: Manifest,
        static_key: [u8; 32],
        group_id: Option<[u8; 4]>,
        path: Option<LinkPath>,
    ) -> bool {
        let id = resonance.particle_id.clone();
        let newly_entangled = !self
            .peers
            .get(&id)
            .is_some_and(|existing| existing.state == PeerState::Entangled);
        self.bindings.insert(id.clone(), static_key);
        let path = if let Some(existing) = self.peers.get(&id) {
            for address in &existing.resonance.addrs {
                if !resonance.addrs.contains(address) {
                    resonance.addrs.push(*address);
                }
            }
            path.or(existing.path)
        } else {
            path
        };
        self.peers.insert(
            id,
            PeerRecord {
                resonance,
                manifest: Some(manifest),
                static_key: Some(static_key),
                state: PeerState::Entangled,
                group_id,
                path,
                last_seen: Instant::now(),
            },
        );
        newly_entangled
    }

    /// Removes a peer which disappeared from mDNS.
    pub fn remove(&mut self, id: &ParticleId) {
        self.peers.remove(id);
    }

    /// Returns the static key first authenticated for this particle ID.
    pub fn binding(&self, id: &ParticleId) -> Option<[u8; 32]> {
        self.bindings.get(id).copied()
    }

    /// Clears live peers and their process-lifetime static-key bindings.
    pub fn clear(&mut self) {
        self.peers.clear();
        self.bindings.clear();
    }

    /// Returns cloned peer records matching a full or short particle ID.
    pub fn resolve(&self, identifier: &str) -> Vec<PeerRecord> {
        self.peers
            .values()
            .filter(|record| {
                record.resonance.particle_id.as_str() == identifier
                    || record.resonance.particle_id.short() == identifier
            })
            .cloned()
            .collect()
    }

    /// Returns a peer record by its full particle identity.
    pub fn by_id(&self, id: &ParticleId) -> Option<PeerRecord> {
        self.peers.get(id).cloned()
    }

    /// Adds a source address learned from an inbound control connection.
    pub fn add_address(&mut self, id: &ParticleId, address: IpAddr) {
        if let Some(peer) = self.peers.get_mut(id) {
            if !peer.resonance.addrs.contains(&address) {
                peer.resonance.addrs.push(address);
            }
        }
    }

    /// Refreshes the last-seen time for a known peer.
    pub fn touch(&mut self, id: &ParticleId) -> bool {
        if let Some(peer) = self.peers.get_mut(id) {
            peer.last_seen = Instant::now();
            true
        } else {
            false
        }
    }

    /// Returns a serialized view, optionally including resonating peers.
    pub fn view(&self, context: Option<&str>, include_unentangled: bool) -> Vec<Value> {
        self.view_with_relay_directory(context, include_unentangled, &HashSet::new())
    }

    /// Returns a serialized view with live repeater-directory membership.
    pub fn view_with_relay_directory(
        &self,
        context: Option<&str>,
        include_unentangled: bool,
        relay_directory: &HashSet<[u8; 32]>,
    ) -> Vec<Value> {
        self.peers
            .values()
            .filter(|record| include_unentangled || record.state == PeerState::Entangled)
            .filter(|record| context.is_none_or(|value| record.resonance.context.as_deref() == Some(value)))
            .map(|record| {
                let key_fingerprint = record
                    .static_key
                    .map(|key| hex::encode(Sha256::digest(key))[..16].to_owned());
                let state = match record.state {
                    PeerState::Seen => "seen",
                    PeerState::Entangled => "linked",
                };
                let path = record.path.map(|path| match path {
                    LinkPath::Direct => "direct",
                    LinkPath::Repeater => "repeater",
                });
                let view = json!({
                    "particle_id": record.resonance.particle_id.as_str(),
                    "name": record.resonance.name,
                    "hostname": record.resonance.hostname,
                    "addrs": record.resonance.addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "port": record.resonance.port,
                    "context": record.resonance.context,
                    "key_fingerprint": key_fingerprint,
                    "state": state,
                    "path": path,
                    "via_repeater": record.static_key.is_some_and(|key| relay_directory.contains(&key)),
                    "manifest": record.manifest,
                    "last_seen_secs": record.last_seen.elapsed().as_secs()
                });
                view
            })
            .collect()
    }

    /// Returns a snapshot of all known peers.
    pub fn all(&self) -> Vec<PeerRecord> {
        self.peers.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entangle_core::{StateKind, PROTOCOL_VERSION};

    fn manifest(id: ParticleId) -> Manifest {
        Manifest {
            particle_id: id,
            name: "peer".into(),
            version: "0.1.0".into(),
            protocol: PROTOCOL_VERSION,
            link_port: 7337,
            context: None,
            tools: vec![],
            accepts: vec![StateKind::Json],
            max_payload_bytes: 1024,
        }
    }

    #[test]
    fn entangling_preserves_existing_addresses() {
        let id = ParticleId::generate();
        let mut field = Field::default();
        field.resonate(Resonance {
            particle_id: id.clone(),
            name: "peer".into(),
            hostname: "peer.local.".into(),
            addrs: vec!["192.0.2.1".parse().unwrap()],
            port: 7337,
            context: None,
            groups: vec![],
            proto: PROTOCOL_VERSION,
        });
        assert!(field.entangle(
            Resonance {
                particle_id: id.clone(),
                name: "peer".into(),
                hostname: "192.0.2.2".into(),
                addrs: vec!["192.0.2.2".parse().unwrap()],
                port: 7337,
                context: None,
                groups: vec![],
                proto: PROTOCOL_VERSION,
            },
            manifest(id.clone()),
            [0x42; 32],
        ));
        let peer = field.by_id(&id).unwrap();
        assert_eq!(peer.state, PeerState::Entangled);
        assert!(peer.resonance.addrs.contains(&"192.0.2.1".parse().unwrap()));
        assert!(peer.resonance.addrs.contains(&"192.0.2.2".parse().unwrap()));
        assert_eq!(
            field.view(None, false)[0]["key_fingerprint"],
            hex::encode(Sha256::digest([0x42; 32]))[..16]
        );
    }

    #[test]
    fn entangle_reports_only_state_transitions() {
        let id = ParticleId::generate();
        let mut field = Field::default();
        let resonance = || Resonance {
            particle_id: id.clone(),
            name: "peer".into(),
            hostname: "peer.local.".into(),
            addrs: vec!["192.0.2.1".parse().unwrap()],
            port: 7337,
            context: None,
            groups: vec![],
            proto: PROTOCOL_VERSION,
        };

        assert!(field.entangle(resonance(), manifest(id.clone()), [0x42; 32]));
        assert!(!field.entangle(resonance(), manifest(id.clone()), [0x42; 32]));

        field.remove(&id);
        field.resonate(resonance());
        assert!(field.entangle(resonance(), manifest(id.clone()), [0x42; 32]));
    }

    #[test]
    fn touch_refreshes_known_peers_only() {
        let id = ParticleId::generate();
        let unknown = ParticleId::generate();
        let mut field = Field::default();
        field.resonate(Resonance {
            particle_id: id.clone(),
            name: "peer".into(),
            hostname: "peer.local.".into(),
            addrs: vec!["192.0.2.1".parse().unwrap()],
            port: 7337,
            context: None,
            groups: vec![],
            proto: PROTOCOL_VERSION,
        });
        let previous = field.by_id(&id).unwrap().last_seen;
        std::thread::sleep(std::time::Duration::from_millis(2));

        assert!(field.touch(&id));
        assert!(field.by_id(&id).unwrap().last_seen > previous);
        assert!(!field.touch(&unknown));
    }
}
