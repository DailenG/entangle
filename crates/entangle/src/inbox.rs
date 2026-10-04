//! Received state-sync index and inline data representation.

use entangle_core::StateKind;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

/// A verified payload received from an entangled particle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxItem {
    /// Unique transfer identifier.
    pub sync_id: String,
    /// Sending particle identity.
    pub from_particle_id: String,
    /// Sending particle name.
    pub from_name: String,
    /// Payload format.
    pub kind: StateKind,
    /// Optional sender label.
    pub label: Option<String>,
    /// RFC 3339 receive time.
    pub received_at: String,
    /// Verified payload size.
    pub bytes: u64,
    /// Verified lowercase SHA-256.
    pub sha256: String,
    /// Inline JSON value for JSON payloads.
    pub state: Option<Value>,
    /// Path to a received file.
    pub path: Option<PathBuf>,
    /// Optional inline UTF-8 file body.
    pub text: Option<String>,
}
