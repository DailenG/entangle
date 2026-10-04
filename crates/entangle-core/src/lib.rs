//! Shared, transport-independent types for Entangle particles and state syncs.

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{fmt, path::Path};

/// Current version of the Entangle control protocol.
pub const PROTOCOL_VERSION: u32 = 1;

/// A process-unique particle identity rendered as 32 lowercase hexadecimal digits.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ParticleId(String);

impl ParticleId {
    /// Creates a fresh identity using the operating system random number generator.
    pub fn generate() -> Self {
        // A process identity is never persisted: concurrently running copies must remain distinct.
        let mut bytes = [0_u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    /// Parses a 128-bit hexadecimal particle identity.
    pub fn parse(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        if value.len() != 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(IdError);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Returns the complete lowercase hexadecimal identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the first eight characters for display and discovery names.
    pub fn short(&self) -> &str {
        &self.0[..8]
    }
}

impl<'de> Deserialize<'de> for ParticleId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for ParticleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ParticleId").field(&self.0).finish()
    }
}

impl fmt::Display for ParticleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Error returned when a particle identity is not exactly 128 bits of hex.
#[derive(Debug, thiserror::Error)]
#[error("particle ID must be 32 hexadecimal characters")]
pub struct IdError;

/// Payload format accepted by a particle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StateKind {
    /// A JSON value.
    Json,
    /// One regular file.
    File,
}

/// Capability and addressing manifest exchanged during the Hello handshake.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    /// This process's particle identity.
    pub particle_id: ParticleId,
    /// Human-readable display name.
    pub name: String,
    /// Entangle package version.
    pub version: String,
    /// Control protocol version.
    pub protocol: u32,
    /// TCP port used by the link listener.
    pub link_port: u16,
    /// Optional project context identifier.
    pub context: Option<String>,
    /// Tool names exposed by this particle.
    pub tools: Vec<String>,
    /// Payload kinds accepted by this particle.
    pub accepts: Vec<StateKind>,
    /// Maximum accepted payload size in bytes.
    pub max_payload_bytes: u64,
}

/// Connection information for a local croc relay.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayTicket {
    /// Hostname or IP address reachable by the peer.
    pub host: String,
    /// Relay base port.
    pub port: u16,
    /// Relay password.
    pub password: String,
}

impl fmt::Debug for RelayTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayTicket")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Returns a safe single-component filename, rejecting traversal and control bytes.
pub fn sanitize_name(name: &str) -> Option<String> {
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.contains(['/', '\\', '\0'])
        || name.chars().any(char::is_control)
        || Path::new(name).file_name().and_then(|v| v.to_str()) != Some(name)
    {
        return None;
    }
    Some(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_and_ticket_roundtrip() {
        let id = ParticleId::generate();
        let manifest = Manifest {
            particle_id: id,
            name: "node".into(),
            version: "0.1.0".into(),
            protocol: PROTOCOL_VERSION,
            link_port: 7337,
            context: Some("project".into()),
            tools: vec!["sync_entangled_state".into()],
            accepts: vec![StateKind::Json, StateKind::File],
            max_payload_bytes: 1024,
        };
        let json = serde_json::to_string(&manifest).unwrap();
        assert_eq!(serde_json::from_str::<Manifest>(&json).unwrap(), manifest);
        let ticket = RelayTicket {
            host: "127.0.0.1".into(),
            port: 9109,
            password: "secret".into(),
        };
        assert_eq!(
            serde_json::from_str::<RelayTicket>(&serde_json::to_string(&ticket).unwrap()).unwrap(),
            ticket
        );
        assert!(!format!("{ticket:?}").contains("secret"));
    }

    #[test]
    fn ids_are_fresh_and_formatted() {
        let id = ParticleId::generate();
        assert_eq!(id.as_str().len(), 32);
        assert!(id
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_ne!(id, ParticleId::generate());
        assert_eq!(id.short().len(), 8);
    }

    #[test]
    fn deserialized_ids_are_validated_and_normalized() {
        assert_eq!(
            serde_json::from_str::<ParticleId>(&format!("\"{}\"", "AB".repeat(16)))
                .unwrap()
                .as_str(),
            "ab".repeat(16)
        );
        assert!(serde_json::from_str::<ParticleId>("\"not-an-id\"").is_err());
    }

    #[test]
    fn state_kind_is_lowercase() {
        assert_eq!(serde_json::to_string(&StateKind::Json).unwrap(), "\"json\"");
        assert_eq!(
            serde_json::from_str::<StateKind>("\"file\"").unwrap(),
            StateKind::File
        );
    }

    #[test]
    fn names_reject_traversal_and_invalid_components() {
        for name in ["", ".", "..", "../x", "/etc/passwd", "a\\b", "a\0b", "a\nb"] {
            assert!(sanitize_name(name).is_none(), "{name:?}");
        }
        assert_eq!(sanitize_name("report.txt").as_deref(), Some("report.txt"));
        assert!(sanitize_name(&"x".repeat(256)).is_none());
    }
}
