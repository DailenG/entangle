//! Persistent peer-verification state and human-managed trust decisions.

use chrono::{SecondsFormat, Utc};
use entangle_core::{
    sas::{self, Role, Sas},
    ParticleId,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};
use thiserror::Error;
use tracing::warn;

const STORE_VERSION: u32 = 1;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A locally approved particle and the SAS its operator verified.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Approval {
    /// Human-readable peer name at approval time.
    pub name: String,
    /// Lowercase hex Noise static public key.
    pub static_key: String,
    /// The verified short authentication string.
    pub sas: Sas,
    /// RFC 3339 approval time.
    pub approved_at: String,
}

/// A Noise static key explicitly denied by the local operator.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Denial {
    /// Particle ID claimed by the denied key.
    pub particle_id: ParticleId,
    /// Human-readable name claimed by the denied key.
    pub name: String,
    /// RFC 3339 denial time.
    pub denied_at: String,
    /// Human-readable reason for the denial.
    pub reason: String,
}

/// The trust decisions maintained by human-only CLI commands.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustStore {
    /// On-disk format version.
    pub version: u32,
    /// Approvals keyed by full particle ID.
    pub approved: BTreeMap<String, Approval>,
    /// Denials keyed by lowercase hex Noise static key.
    pub denied: BTreeMap<String, Denial>,
}

/// File metadata used to detect CLI trust-store updates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileStamp {
    /// Modification time, if the platform reports one.
    pub modified: Option<SystemTime>,
    /// File size in bytes.
    pub len: u64,
}

impl Default for TrustStore {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            approved: BTreeMap::new(),
            denied: BTreeMap::new(),
        }
    }
}

/// Persistent state for the commit/reveal exchange with one peer.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerificationRecord {
    /// On-disk format version.
    pub version: u32,
    /// Peer identity this record belongs to.
    pub particle_id: ParticleId,
    /// Most recently observed peer name.
    pub name: String,
    /// Lowercase hex local Noise static public key.
    pub local_key: String,
    /// Lowercase hex remote Noise static public key.
    pub remote_key: String,
    /// Local role derived from bytewise key ordering.
    pub role: Role,
    /// Locally generated nonce (committer nonce_c or revealer nonce_r).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Committer's lowercase hex commitment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    /// Remote nonce accepted for this commitment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_nonce: Option<String>,
    /// Committer nonce revealed by the local committer or verified by the revealer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reveal: Option<String>,
    /// Derived SAS after the commitment and both nonces are verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sas: Option<Sas>,
    /// RFC 3339 time this record was first created.
    pub first_seen: String,
    /// RFC 3339 time this record was most recently updated.
    pub updated: String,
}

impl VerificationRecord {
    /// Whether the local side has completed the commit/reveal exchange.
    pub fn is_complete(&self) -> bool {
        self.sas.is_some()
    }
}

/// Trust-store file, format, or verification-state failure.
#[derive(Debug, Error)]
pub enum TrustError {
    /// File-system operation failed.
    #[error("peer trust I/O failed: {0}")]
    Io(#[from] io::Error),
    /// JSON data is malformed.
    #[error("peer trust JSON is malformed: {0}")]
    Json(#[from] serde_json::Error),
    /// A trust-store path is a symlink or has an unexpected type.
    #[error("peer trust path is not a regular file or directory: {0}")]
    UnsafePath(PathBuf),
    /// The persisted data uses a newer or unsupported format.
    #[error("unsupported peer trust store version {0}")]
    UnsupportedVersion(u32),
    /// A record is internally inconsistent or contains invalid lowercase hex.
    #[error("invalid peer verification record: {0}")]
    InvalidRecord(String),
    /// Identical local and remote static keys cannot establish distinct roles.
    #[error("peer verification requires distinct Noise static keys")]
    EqualStaticKeys,
}

/// Loads the CLI-owned trust decisions; a missing store is empty.
pub fn load(data_root: &Path) -> Result<TrustStore, TrustError> {
    let peers = peers_dir(data_root);
    if !existing_directory(&peers)? {
        return Ok(TrustStore::default());
    }
    let Some(contents) = read_regular_file(&peers.join("trust.json"))? else {
        return Ok(TrustStore::default());
    };
    let store: TrustStore = serde_json::from_slice(&contents)?;
    if store.version != STORE_VERSION {
        return Err(TrustError::UnsupportedVersion(store.version));
    }
    for approval in store.approved.values() {
        decode_key(&approval.static_key)?;
    }
    for key in store.denied.keys() {
        decode_key(key)?;
    }
    Ok(store)
}

/// Atomically writes the human-managed trust decisions.
pub fn save(data_root: &Path, store: &TrustStore) -> Result<(), TrustError> {
    if store.version != STORE_VERSION {
        return Err(TrustError::UnsupportedVersion(store.version));
    }
    let peers = peers_dir(data_root);
    create_private_directory(&peers)?;
    let contents = serde_json::to_vec_pretty(store)?;
    atomic_write(&peers.join("trust.json"), &contents)?;
    Ok(())
}

/// Loads one node-owned verification record, if present.
pub fn load_verification(
    data_root: &Path,
    particle_id: &ParticleId,
) -> Result<Option<VerificationRecord>, TrustError> {
    let peers = peers_dir(data_root);
    if !existing_directory(&peers)? {
        return Ok(None);
    }
    let directory = verification_dir(data_root);
    if !existing_directory(&directory)? {
        return Ok(None);
    }
    let path = directory.join(format!("{particle_id}.json"));
    let Some(contents) = read_regular_file(&path)? else {
        return Ok(None);
    };
    let record: VerificationRecord = serde_json::from_slice(&contents)?;
    validate_verification(&record, particle_id)?;
    Ok(Some(record))
}

/// Loads all validly stored verification records in particle-ID order.
pub fn load_verifications(data_root: &Path) -> Result<Vec<VerificationRecord>, TrustError> {
    let peers = peers_dir(data_root);
    if !existing_directory(&peers)? {
        return Ok(Vec::new());
    }
    let directory = verification_dir(data_root);
    if !existing_directory(&directory)? {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    for entry in fs::read_dir(&directory)? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    paths
        .iter()
        .map(|path| {
            let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                return Err(TrustError::UnsafePath(path.clone()));
            };
            let id = ParticleId::parse(stem.to_owned())
                .map_err(|_| TrustError::InvalidRecord("invalid record filename".into()))?;
            let Some(contents) = read_regular_file(path)? else {
                return Err(TrustError::UnsafePath(path.clone()));
            };
            let record: VerificationRecord = serde_json::from_slice(&contents)?;
            validate_verification(&record, &id)?;
            Ok(record)
        })
        .collect()
}

/// Persists one node-owned verification record using a temporary file and rename.
pub fn save_verification(data_root: &Path, record: &VerificationRecord) -> Result<(), TrustError> {
    validate_verification(record, &record.particle_id)?;
    let directory = verification_dir(data_root);
    create_private_directory(&peers_dir(data_root))?;
    create_private_directory(&directory)?;
    let contents = serde_json::to_vec_pretty(record)?;
    atomic_write(
        &directory.join(format!("{}.json", record.particle_id)),
        &contents,
    )?;
    Ok(())
}

/// Removes one verification record.
pub fn remove_verification(data_root: &Path, particle_id: &ParticleId) -> Result<(), TrustError> {
    let peers = peers_dir(data_root);
    if !existing_directory(&peers)? {
        return Ok(());
    }
    let directory = verification_dir(data_root);
    if !existing_directory(&directory)? {
        return Ok(());
    }
    let path = directory.join(format!("{particle_id}.json"));
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => fs::remove_file(path)?,
        Ok(_) => return Err(TrustError::UnsafePath(path)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// Reads trust.json metadata without following a symlink.
pub fn file_stamp(data_root: &Path) -> Result<Option<FileStamp>, TrustError> {
    let peers = peers_dir(data_root);
    if !existing_directory(&peers)? {
        return Ok(None);
    }
    let path = peers.join("trust.json");
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(Some(FileStamp {
            modified: metadata.modified().ok(),
            len: metadata.len(),
        })),
        Ok(_) => Err(TrustError::UnsafePath(path)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Initializes a verification record with its local role and timestamps.
pub fn new_verification(
    particle_id: ParticleId,
    name: String,
    local_key: [u8; 32],
    remote_key: [u8; 32],
) -> Result<VerificationRecord, TrustError> {
    let role = sas::role(&local_key, &remote_key).ok_or(TrustError::EqualStaticKeys)?;
    let now = timestamp();
    Ok(VerificationRecord {
        version: STORE_VERSION,
        particle_id,
        name,
        local_key: hex::encode(local_key),
        remote_key: hex::encode(remote_key),
        role,
        nonce: None,
        commitment: None,
        peer_nonce: None,
        reveal: None,
        sas: None,
        first_seen: now.clone(),
        updated: now,
    })
}

/// Initializes a record's local exchange state before it is persisted.
pub fn initialize_exchange_state(record: &mut VerificationRecord) -> Result<(), TrustError> {
    ensure_local_state(record)?;
    record.updated = timestamp();
    Ok(())
}

/// Produces the local message as a pure function of persisted exchange state.
pub fn outgoing(record: &VerificationRecord) -> entangle_link::VerifyMessage {
    match record.role {
        Role::Committer => entangle_link::VerifyMessage {
            commitment: record.commitment.clone(),
            nonce: None,
            reveal: record.reveal.clone(),
        },
        Role::Revealer => entangle_link::VerifyMessage {
            commitment: None,
            nonce: record.nonce.clone().filter(|_| record.commitment.is_some()),
            reveal: None,
        },
    }
}

/// Ingests a peer message without reusing a nonce against a changed counterpart value.
pub fn ingest(
    record: &mut VerificationRecord,
    message: entangle_link::VerifyMessage,
) -> Result<(), TrustError> {
    let commitment = message
        .commitment
        .as_deref()
        .map(decode_key)
        .transpose()?
        .map(hex::encode);
    let nonce = message
        .nonce
        .as_deref()
        .map(decode_key)
        .transpose()?
        .map(hex::encode);
    let reveal = message
        .reveal
        .as_deref()
        .map(decode_key)
        .transpose()?
        .map(hex::encode);

    ensure_local_state(record)?;
    match record.role {
        Role::Revealer => {
            let changed_commitment = commitment
                .as_ref()
                .is_some_and(|incoming| record.commitment.as_ref() != Some(incoming));
            if changed_commitment {
                // Never reuse a revealer nonce or accepted reveal with a new commitment.
                record.nonce = None;
                record.peer_nonce = None;
                record.reveal = None;
                record.sas = None;
                record.commitment = commitment;
                ensure_local_state(record)?;
            } else if let Some(incoming_reveal) = reveal {
                let local_key = decode_key(&record.local_key)?;
                let remote_key = decode_key(&record.remote_key)?;
                let key_c = &remote_key;
                let key_r = &local_key;
                let valid = record
                    .commitment
                    .as_deref()
                    .map(decode_key)
                    .transpose()?
                    .is_some_and(|stored| {
                        sas::commitment(
                            &decode_key(&incoming_reveal).expect("validated reveal"),
                            key_c,
                            key_r,
                        ) == stored
                    });
                if valid {
                    record.reveal = Some(incoming_reveal.clone());
                    record.peer_nonce = Some(incoming_reveal);
                    recompute_sas(record)?;
                } else {
                    warn!("verification reveal did not match its commitment");
                }
            }
        }
        Role::Committer => {
            if let Some(incoming_nonce) = nonce {
                match record.peer_nonce.as_ref() {
                    Some(stored_nonce) if stored_nonce != &incoming_nonce => {
                        // A changed revealer nonce invalidates the old commitment and SAS.
                        // Drop this round's nonce so the replacement commitment is seen first.
                        record.nonce = None;
                        record.commitment = None;
                        record.peer_nonce = None;
                        record.reveal = None;
                        record.sas = None;
                        ensure_local_state(record)?;
                    }
                    None => {
                        record.peer_nonce = Some(incoming_nonce);
                        record.reveal = record.nonce.clone();
                        recompute_sas(record)?;
                    }
                    Some(_) => {}
                }
            }
        }
    }
    record.updated = timestamp();
    Ok(())
}

/// Returns whether a stored approval matches both the particle ID and static key.
pub fn is_approved(store: &TrustStore, particle_id: &ParticleId, key: &[u8; 32]) -> bool {
    store
        .approved
        .get(particle_id.as_str())
        .is_some_and(|approval| approval.static_key == hex::encode(key))
}

/// Returns whether the static key is in the operator's denial set.
pub fn is_denied(store: &TrustStore, key: &[u8; 32]) -> bool {
    store.denied.contains_key(&hex::encode(key))
}

/// Decodes exactly 32 bytes of lowercase hexadecimal.
pub fn decode_key(value: &str) -> Result<[u8; 32], TrustError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(TrustError::InvalidRecord(
            "keys, nonces, and commitments must be 64 lowercase hex characters".into(),
        ));
    }
    let bytes = hex::decode(value)
        .map_err(|_| TrustError::InvalidRecord("invalid lowercase hex".into()))?;
    bytes
        .try_into()
        .map_err(|_| TrustError::InvalidRecord("expected 32 bytes".into()))
}

fn ensure_local_state(record: &mut VerificationRecord) -> Result<(), TrustError> {
    match record.role {
        Role::Committer => {
            if record.nonce.is_none() {
                record.nonce = Some(random_nonce());
            }
            let key_c = decode_key(&record.local_key)?;
            let key_r = decode_key(&record.remote_key)?;
            let nonce = decode_key(record.nonce.as_deref().expect("committer nonce"))?;
            record.commitment = Some(hex::encode(sas::commitment(&nonce, &key_c, &key_r)));
        }
        Role::Revealer => {
            if record.commitment.is_some() && record.nonce.is_none() {
                record.nonce = Some(random_nonce());
            }
        }
    }
    Ok(())
}

fn recompute_sas(record: &mut VerificationRecord) -> Result<(), TrustError> {
    record.sas = match record.role {
        Role::Committer => match (&record.nonce, &record.peer_nonce) {
            (Some(nonce_c), Some(nonce_r)) => Some(sas::derive(
                &decode_key(&record.local_key)?,
                &decode_key(&record.remote_key)?,
                &decode_key(nonce_c)?,
                &decode_key(nonce_r)?,
            )),
            _ => None,
        },
        Role::Revealer => match (&record.reveal, &record.nonce, &record.commitment) {
            (Some(reveal), Some(nonce_r), Some(commitment)) => {
                let key_c = decode_key(&record.remote_key)?;
                let key_r = decode_key(&record.local_key)?;
                let nonce_c = decode_key(reveal)?;
                if sas::commitment(&nonce_c, &key_c, &key_r) == decode_key(commitment)? {
                    Some(sas::derive(&key_c, &key_r, &nonce_c, &decode_key(nonce_r)?))
                } else {
                    None
                }
            }
            _ => None,
        },
    };
    Ok(())
}

fn random_nonce() -> String {
    let mut nonce = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    hex::encode(nonce)
}

fn validate_verification(
    record: &VerificationRecord,
    particle_id: &ParticleId,
) -> Result<(), TrustError> {
    if record.version != STORE_VERSION {
        return Err(TrustError::UnsupportedVersion(record.version));
    }
    if &record.particle_id != particle_id {
        return Err(TrustError::InvalidRecord(
            "particle ID does not match its filename".into(),
        ));
    }
    let local = decode_key(&record.local_key)?;
    let remote = decode_key(&record.remote_key)?;
    if sas::role(&local, &remote) != Some(record.role) {
        return Err(TrustError::InvalidRecord(
            "role does not match the keys".into(),
        ));
    }
    for value in [
        record.nonce.as_deref(),
        record.commitment.as_deref(),
        record.peer_nonce.as_deref(),
        record.reveal.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        decode_key(value)?;
    }
    Ok(())
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn peers_dir(data_root: &Path) -> PathBuf {
    data_root.join("peers")
}

fn verification_dir(data_root: &Path) -> PathBuf {
    peers_dir(data_root).join("verify")
}

fn existing_directory(path: &Path) -> Result<bool, TrustError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => Err(TrustError::UnsafePath(path.to_owned())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn create_private_directory(path: &Path) -> Result<(), TrustError> {
    fs::create_dir_all(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            }
            Ok(())
        }
        _ => Err(TrustError::UnsafePath(path.to_owned())),
    }
}

fn read_regular_file(path: &Path) -> Result<Option<Vec<u8>>, TrustError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o777 != 0o600 {
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                }
            }
            Ok(Some(fs::read(path)?))
        }
        Ok(_) => Err(TrustError::UnsafePath(path.to_owned())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), TrustError> {
    let temporary = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        replace_file(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok(())
}

fn replace_file(temporary: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(windows)]
    if destination.exists() {
        fs::remove_file(destination)?;
    }
    fs::rename(temporary, destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn record(role: Role) -> VerificationRecord {
        let (local, remote) = match role {
            Role::Committer => ([1; 32], [2; 32]),
            Role::Revealer => ([2; 32], [1; 32]),
        };
        new_verification(ParticleId::generate(), "peer".into(), local, remote).unwrap()
    }

    #[test]
    fn verification_record_is_atomic_and_private() {
        let temp = tempdir().unwrap();
        let record = record(Role::Committer);
        save_verification(temp.path(), &record).unwrap();
        assert_eq!(
            load_verification(temp.path(), &record.particle_id)
                .unwrap()
                .unwrap()
                .local_key,
            record.local_key
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(temp.path().join("peers"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(
                    temp.path()
                        .join("peers")
                        .join("verify")
                        .join(format!("{}.json", record.particle_id))
                )
                .unwrap()
                .permissions()
                .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn revealer_restarts_nonce_and_discards_reveal_for_changed_commitment() {
        let mut record = record(Role::Revealer);
        let old_nonce = [0x33; 32];
        record.commitment = Some(hex::encode([0x44; 32]));
        record.nonce = Some(hex::encode(old_nonce));
        record.reveal = Some(hex::encode([0x55; 32]));
        record.peer_nonce = record.reveal.clone();
        record.sas = Some([1, 2, 3]);
        let new_commitment = hex::encode([0x66; 32]);

        ingest(
            &mut record,
            entangle_link::VerifyMessage {
                commitment: Some(new_commitment.clone()),
                nonce: None,
                reveal: Some(hex::encode([0x77; 32])),
            },
        )
        .unwrap();

        assert_eq!(record.commitment.as_deref(), Some(new_commitment.as_str()));
        assert_ne!(
            record.nonce.as_deref(),
            Some(hex::encode(old_nonce).as_str())
        );
        assert!(record.reveal.is_none());
        assert!(record.peer_nonce.is_none());
        assert!(record.sas.is_none());
    }

    #[test]
    fn committer_restarts_and_drops_changed_revealer_nonce_in_same_round() {
        let mut record = record(Role::Committer);
        initialize_exchange_state(&mut record).unwrap();
        let old_nonce = record.nonce.clone().unwrap();
        let old_commitment = record.commitment.clone().unwrap();
        record.peer_nonce = Some(hex::encode([0x44; 32]));
        record.sas = Some([1, 2, 3]);

        ingest(
            &mut record,
            entangle_link::VerifyMessage {
                commitment: None,
                nonce: Some(hex::encode([0x55; 32])),
                reveal: None,
            },
        )
        .unwrap();

        assert_ne!(record.nonce.as_deref(), Some(old_nonce.as_str()));
        assert_ne!(record.commitment.as_deref(), Some(old_commitment.as_str()));
        assert!(record.peer_nonce.is_none());
        assert!(record.reveal.is_none());
        assert!(record.sas.is_none());
        assert!(outgoing(&record).reveal.is_none());
    }

    #[test]
    fn bad_revealer_input_does_not_complete_sas() {
        let mut record = record(Role::Revealer);
        let nonce_c = [0x11; 32];
        let key_c = decode_key(&record.remote_key).unwrap();
        let key_r = decode_key(&record.local_key).unwrap();
        record.commitment = Some(hex::encode(sas::commitment(&nonce_c, &key_c, &key_r)));
        record.nonce = Some(hex::encode([0x22; 32]));

        ingest(
            &mut record,
            entangle_link::VerifyMessage {
                commitment: None,
                nonce: None,
                reveal: Some(hex::encode([0x33; 32])),
            },
        )
        .unwrap();

        assert!(record.reveal.is_none());
        assert!(record.sas.is_none());
    }

    #[test]
    fn a_verified_reveal_derives_the_same_sas_as_the_committer() {
        let mut committer = record(Role::Committer);
        initialize_exchange_state(&mut committer).unwrap();
        let commit_message = outgoing(&committer);
        let mut revealer = VerificationRecord {
            particle_id: committer.particle_id.clone(),
            name: committer.name.clone(),
            local_key: committer.remote_key.clone(),
            remote_key: committer.local_key.clone(),
            role: Role::Revealer,
            ..record(Role::Revealer)
        };
        ingest(&mut revealer, commit_message).unwrap();
        let revealer_message = outgoing(&revealer);
        ingest(&mut committer, revealer_message).unwrap();
        let reveal_message = outgoing(&committer);
        ingest(&mut revealer, reveal_message).unwrap();

        assert_eq!(committer.sas, revealer.sas);
        assert!(committer.is_complete());
        assert!(revealer.is_complete());
    }
}
