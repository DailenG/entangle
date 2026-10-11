//! Private, atomically replaced repeater state.

use crate::invite::secret_hash;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::SystemTime,
};
use thiserror::Error;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Errors from private repeater state access and persistence.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Filesystem access or atomic-write failure.
    #[error("repeater store I/O failed: {0}")]
    Io(#[from] io::Error),
    /// State-file serialization or parsing failure.
    #[error("repeater store JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    /// A state path is a symlink or has an unsafe file type.
    #[error("repeater store path is not a regular file or directory")]
    UnsafePath,
    /// The host's stored private key is malformed.
    #[error("invalid repeater key")]
    InvalidKey,
}

/// An enrolled repeater device.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Device {
    /// Optional operator-supplied enrollment label.
    pub label: Option<String>,
    /// RFC 3339 enrollment time.
    pub enrolled_at: String,
    /// Whether the repeater must refuse this device.
    pub revoked: bool,
}

/// Persistent repeater device allowlist.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Devices {
    /// Map from lowercase static-public-key hex to device metadata.
    pub devices: BTreeMap<String, Device>,
}

/// Persistent metadata for a single-use invitation.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InviteRecord {
    /// SHA-256 digest of the invitation secret; the secret itself is not stored.
    pub secret_sha256: String,
    /// RFC 3339 expiry time.
    pub expires_at: String,
    /// Whether this invitation has already been consumed.
    pub used: bool,
    /// Optional operator-supplied label transferred to the enrolled device.
    pub label: Option<String>,
}

/// Persistent list of invitations.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Invites {
    /// Available and previously consumed invitation records.
    pub invites: Vec<InviteRecord>,
}

/// Metadata used by the server to detect device-file changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileStamp {
    /// Last-modified time, if the filesystem reports one.
    pub modified: Option<SystemTime>,
    /// File length in bytes.
    pub len: u64,
}

/// Private, atomically persisted repeater host state.
pub struct Store {
    /// Directory containing the host key, devices, and invitations.
    pub root: PathBuf,
    invite_lock: Arc<Mutex<()>>,
}

impl Clone for Store {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            invite_lock: Arc::clone(&self.invite_lock),
        }
    }
}

impl Store {
    /// Opens or creates a repeater store rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            invite_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Loads the private host key, creating a mode-0600 key if absent.
    pub fn key(&self) -> Result<[u8; 32], StoreError> {
        let path = self.root.join("repeater.key");
        if let Some(bytes) = read_file(&path)? {
            let text = String::from_utf8(bytes).map_err(|_| StoreError::InvalidKey)?;
            let text = text.strip_suffix('\n').unwrap_or(&text);
            if text.len() != 64
                || !text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(StoreError::InvalidKey);
            }
            let decoded = hex::decode(text).map_err(|_| StoreError::InvalidKey)?;
            return decoded.try_into().map_err(|_| StoreError::InvalidKey);
        }
        let mut key = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        atomic_write(&path, format!("{}\n", hex::encode(key)).as_bytes())?;
        Ok(key)
    }

    /// Loads enrolled devices, or an empty allowlist if the file is absent.
    pub fn devices(&self) -> Result<Devices, StoreError> {
        load_json(&self.root.join("devices.json"))
    }

    /// Atomically writes the device allowlist with private permissions.
    pub fn save_devices(&self, value: &Devices) -> Result<(), StoreError> {
        atomic_write(
            &self.root.join("devices.json"),
            &serde_json::to_vec_pretty(value)?,
        )
    }

    /// Loads invitations, or an empty list if the file is absent.
    pub fn invites(&self) -> Result<Invites, StoreError> {
        load_json(&self.root.join("invites.json"))
    }

    /// Atomically writes invitation metadata with private permissions.
    pub fn save_invites(&self, value: &Invites) -> Result<(), StoreError> {
        atomic_write(
            &self.root.join("invites.json"),
            &serde_json::to_vec_pretty(value)?,
        )
    }

    /// Persists a single-use invitation by its secret hash, never its secret.
    pub fn add_invite(
        &self,
        secret: [u8; 32],
        expires_at: String,
        label: Option<String>,
    ) -> Result<(), StoreError> {
        let mut invites = self.invites()?;
        invites.invites.push(InviteRecord {
            secret_sha256: secret_hash(&secret),
            expires_at,
            used: false,
            label,
        });
        self.save_invites(&invites)
    }

    /// Atomically consumes an unused, unexpired invite and enrolls its key.
    pub fn consume_invite(
        &self,
        secret: &[u8; 32],
        key: [u8; 32],
        label: Option<String>,
    ) -> Result<bool, StoreError> {
        // Serialize validation and consumption so concurrent enroll handshakes
        // cannot both claim the same single-use invitation.
        let _guard = self
            .invite_lock
            .lock()
            .map_err(|_| StoreError::Io(io::Error::other("invite store lock poisoned")))?;
        let mut invites = self.invites()?;
        let hash = secret_hash(secret);
        let now = Utc::now();
        let Some(index) = invites.invites.iter().position(|v| v.secret_sha256 == hash) else {
            return Ok(false);
        };
        let invite_label = invites.invites[index].label.clone();
        let expiry = DateTime::parse_from_rfc3339(&invites.invites[index].expires_at)
            .map(|v| v.with_timezone(&Utc))
            .ok();
        if invites.invites[index].used || expiry.is_none_or(|v| v <= now) {
            return Ok(false);
        }
        invites.invites[index].used = true;
        self.save_invites(&invites)?;
        let enrollment = self.devices().and_then(|mut devices| {
            devices.devices.insert(
                hex::encode(key),
                Device {
                    label: label.or(invite_label),
                    enrolled_at: now.to_rfc3339(),
                    revoked: false,
                },
            );
            self.save_devices(&devices)
        });
        if let Err(error) = enrollment {
            invites.invites[index].used = false;
            return match self.save_invites(&invites) {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(StoreError::Io(io::Error::other(format!(
                    "enrollment failed ({error}); invite rollback failed ({rollback_error})"
                )))),
            };
        }
        Ok(true)
    }

    /// Returns whether the key is present in the allowlist and not revoked.
    pub fn device_allowed(&self, key: &[u8; 32]) -> Result<bool, StoreError> {
        Ok(self
            .devices()?
            .devices
            .get(&hex::encode(key))
            .is_some_and(|d| !d.revoked))
    }

    /// Returns the current stamp for `devices.json` for revocation polling.
    pub fn device_stamp(&self) -> Result<Option<FileStamp>, StoreError> {
        stamp(&self.root.join("devices.json"))
    }
}

fn load_json<T: DeserializeOwned + Default>(path: &Path) -> Result<T, StoreError> {
    let Some(bytes) = read_file(path)? else {
        return Ok(T::default());
    };
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_file(path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
    reject_symlink_components(path)?;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o777 != 0o600 {
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                }
            }
            Ok(Some(fs::read(path)?))
        }
        Ok(_) => Err(StoreError::UnsafePath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    reject_symlink_components(path)?;
    let parent = path.parent().ok_or(StoreError::UnsafePath)?;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => {}
        Ok(_) => return Err(StoreError::UnsafePath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    match fs::symlink_metadata(parent) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(_) => return Err(StoreError::UnsafePath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(parent)?,
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    // A same-directory private temporary file makes replacement atomic and
    // prevents a partial JSON/key file from becoming visible after a crash.
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
        file.write_all(bytes)?;
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
    fs::rename(temporary, destination)
}

fn stamp(path: &Path) -> Result<Option<FileStamp>, StoreError> {
    reject_symlink_components(path)?;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => Ok(Some(FileStamp {
            modified: meta.modified().ok(),
            len: meta.len(),
        })),
        Ok(_) => Err(StoreError::UnsafePath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn reject_symlink_components(path: &Path) -> Result<(), StoreError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => continue,
            Component::ParentDir => current.push(".."),
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                current.push(component.as_os_str())
            }
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StoreError::UnsafePath)
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root_path(path: &Path) -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            path.canonicalize().unwrap()
        }
        #[cfg(not(target_os = "macos"))]
        {
            path.to_path_buf()
        }
    }

    #[test]
    fn creates_private_host_key() {
        let root = tempfile::tempdir().unwrap();
        let root_path = test_root_path(root.path());
        let store = Store::new(&root_path);
        let key = store.key().unwrap();
        assert_eq!(store.key().unwrap(), key);
        let text = fs::read_to_string(root_path.join("repeater.key")).unwrap();
        assert_eq!(text.trim().len(), 64);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(root_path.join("repeater.key"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn atomic_store_write_replaces_existing_destination() {
        let root = tempfile::tempdir().unwrap();
        let root_path = test_root_path(root.path());
        let store = Store::new(&root_path);
        let first = Devices::default();
        store.save_devices(&first).unwrap();
        let mut second = Devices::default();
        second.devices.insert(
            "01".into(),
            Device {
                label: Some("device".into()),
                enrolled_at: "2026-01-01T00:00:00Z".into(),
                revoked: false,
            },
        );
        store.save_devices(&second).unwrap();
        assert_eq!(store.devices().unwrap().devices.len(), 1);
    }

    #[test]
    fn failed_device_persistence_restores_single_use_invite() {
        let root = tempfile::tempdir().unwrap();
        let root_path = test_root_path(root.path());
        let store = Store::new(&root_path);
        let secret = [9; 32];
        store
            .add_invite(
                secret,
                (Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                None,
            )
            .unwrap();
        fs::create_dir(root_path.join("devices.json")).unwrap();

        assert!(store.consume_invite(&secret, [7; 32], None).is_err());
        assert!(!store.invites().unwrap().invites[0].used);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_store_files_and_directories() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root_path = test_root_path(root.path());
        let outside_path = test_root_path(outside.path());
        fs::write(outside_path.join("devices.json"), b"{\"devices\":{}}").unwrap();
        symlink(
            outside_path.join("devices.json"),
            root_path.join("devices.json"),
        )
        .unwrap();
        assert!(matches!(
            Store::new(&root_path).devices(),
            Err(StoreError::UnsafePath)
        ));

        let link = root_path.join("linked-root");
        symlink(&outside_path, &link).unwrap();
        assert!(matches!(
            Store::new(link).devices(),
            Err(StoreError::UnsafePath)
        ));
    }
}
