//! In-memory field of recently resonating and entangled particles.

use entangle_core::{Manifest, ParticleId};
use entangle_resonance::Resonance;
use serde_json::{json, Value};
use std::{collections::HashMap, net::IpAddr, time::Instant};

/// Relationship state stored for a peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerState {
    /// The peer was discovered but its Hello handshake has not completed.
    Resonating,
    /// The peer exchanged compatible manifests.
    Entangled,
}

/// One peer record and its latest discovery and manifest data.
#[derive(Clone, Debug)]
pub struct PeerRecord {
    /// Last mDNS or direct-connection metadata.
    pub resonance: Resonance,
    /// Full manifest, populated after a successful handshake.
    pub manifest: Option<Manifest>,
    /// Current relationship state.
    pub state: PeerState,
    /// Monotonic time at which this record was refreshed.
    pub last_seen: Instant,
}

/// Registry of local peer records.
#[derive(Default)]
pub struct Field {
    peers: HashMap<ParticleId, PeerRecord>,
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
                state: PeerState::Resonating,
                last_seen: Instant::now(),
            });
        record.resonance = resonance;
        record.last_seen = Instant::now();
    }

    /// Stores a validated manifest and marks the peer entangled.
    pub fn entangle(&mut self, mut resonance: Resonance, manifest: Manifest) {
        let id = resonance.particle_id.clone();
        if let Some(existing) = self.peers.get(&id) {
            for address in &existing.resonance.addrs {
                if !resonance.addrs.contains(address) {
                    resonance.addrs.push(*address);
                }
            }
        }
        self.peers.insert(
            id,
            PeerRecord {
                resonance,
                manifest: Some(manifest),
                state: PeerState::Entangled,
                last_seen: Instant::now(),
            },
        );
    }

    /// Removes a peer which disappeared from mDNS.
    pub fn remove(&mut self, id: &ParticleId) {
        self.peers.remove(id);
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

    /// Returns a serialized view, optionally including resonating peers.
    pub fn view(&self, context: Option<&str>, include_unentangled: bool) -> Vec<Value> {
        self.peers
            .values()
            .filter(|record| include_unentangled || record.state == PeerState::Entangled)
            .filter(|record| context.map_or(true, |value| record.resonance.context.as_deref() == Some(value)))
            .map(|record| {
                json!({
                    "particle_id": record.resonance.particle_id.as_str(),
                    "name": record.resonance.name,
                    "hostname": record.resonance.hostname,
                    "addrs": record.resonance.addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "port": record.resonance.port,
                    "context": record.resonance.context,
                    "state": if record.state == PeerState::Entangled { "entangled" } else { "resonating" },
                    "manifest": record.manifest,
                    "last_seen_secs": record.last_seen.elapsed().as_secs()
                })
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
            proto: PROTOCOL_VERSION,
        });
        field.entangle(
            Resonance {
                particle_id: id.clone(),
                name: "peer".into(),
                hostname: "192.0.2.2".into(),
                addrs: vec!["192.0.2.2".parse().unwrap()],
                port: 7337,
                context: None,
                proto: PROTOCOL_VERSION,
            },
            manifest(id.clone()),
        );
        let peer = field.by_id(&id).unwrap();
        assert_eq!(peer.state, PeerState::Entangled);
        assert!(peer.resonance.addrs.contains(&"192.0.2.1".parse().unwrap()));
        assert!(peer.resonance.addrs.contains(&"192.0.2.2".parse().unwrap()));
    }
}
