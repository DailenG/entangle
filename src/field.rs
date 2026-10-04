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
    pub fn entangle(&mut self, resonance: Resonance, manifest: Manifest) {
        self.peers.insert(
            resonance.particle_id.clone(),
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

    /// Finds a particle by its network source address and returns its identity.
    pub fn by_addr(&self, address: IpAddr) -> Option<PeerRecord> {
        self.peers
            .values()
            .find(|peer| {
                peer.state == PeerState::Entangled && peer.resonance.addrs.contains(&address)
            })
            .cloned()
    }

    /// Returns a snapshot of all known peers.
    pub fn all(&self) -> Vec<PeerRecord> {
        self.peers.values().cloned().collect()
    }
}
