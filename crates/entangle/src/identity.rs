//! Lock-backed identity persistence for a local Entangle data root.

use entangle_core::ParticleId;
use entangle_transport::generate_static;
use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Write},
    path::Path,
};
use tracing::{info, warn};

/// The identity claimed by this process and the lock keeping it exclusive.
pub struct Identity {
    pub id: ParticleId,
    pub persistent: bool,
    pub static_private: [u8; 32],
    _lock: Option<File>,
}

/// Claims the persistent identity for a data root, or generates an ephemeral one.
pub fn claim(root: &Path) -> std::io::Result<Identity> {
    if let Err(error) = fs::create_dir_all(root) {
        warn!(
            path = %root.display(),
            %error,
            "could not create identity data directory; using an ephemeral identity"
        );
        return Ok(ephemeral());
    }

    let lock_path = root.join("identity.lock");
    let lock = match OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
    {
        Ok(lock) => lock,
        Err(error) => {
            warn!(
                path = %lock_path.display(),
                %error,
                "could not open identity lock; using an ephemeral identity"
            );
            return Ok(ephemeral());
        }
    };

    if let Err(error) = lock.try_lock() {
        if matches!(error, std::fs::TryLockError::WouldBlock) {
            info!(
                path = %root.display(),
                "another Entangle process holds the identity; using an ephemeral identity"
            );
        } else {
            warn!(
                path = %lock_path.display(),
                error = ?error,
                "could not lock identity; using an ephemeral identity"
            );
        }
        return Ok(ephemeral());
    }

    let identity_path = root.join("identity");
    match fs::read(&identity_path) {
        Ok(contents) => {
            if let Some(id) = std::str::from_utf8(&contents)
                .ok()
                .and_then(|value| ParticleId::parse(value.trim().to_owned()).ok())
            {
                return persistent(id, lock, root);
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            warn!(
                path = %identity_path.display(),
                %error,
                "could not read identity; using an ephemeral identity"
            );
            return Ok(ephemeral());
        }
    }

    let id = ParticleId::generate();
    let temporary_path = root.join("identity.tmp");
    let write_result = (|| {
        let mut file = File::create(&temporary_path)?;
        writeln!(file, "{}", id.as_str())?;
        file.sync_all()?;
        fs::rename(&temporary_path, &identity_path)
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary_path);
        warn!(
            path = %identity_path.display(),
            %error,
            "could not persist identity; using an ephemeral identity"
        );
        return Ok(ephemeral());
    }

    persistent(id, lock, root)
}

fn persistent(id: ParticleId, lock: File, root: &Path) -> std::io::Result<Identity> {
    Ok(Identity {
        id,
        persistent: true,
        static_private: load_or_create_static(root)?,
        _lock: Some(lock),
    })
}

fn ephemeral() -> Identity {
    Identity {
        id: ParticleId::generate(),
        persistent: false,
        static_private: generate_static(),
        _lock: None,
    }
}

fn load_or_create_static(root: &Path) -> std::io::Result<[u8; 32]> {
    let path = root.join("noise_static.key");
    #[cfg(unix)]
    match fs::metadata(&path) {
        Ok(_) => repair_permissions(&path)?,
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match fs::read_to_string(&path) {
        Ok(contents) => {
            if contents.len() == 64
                && contents
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                if let Ok(bytes) = hex::decode(contents) {
                    if let Ok(key) = <[u8; 32]>::try_from(bytes) {
                        return Ok(key);
                    }
                }
            }
            warn!(
                path = %path.display(),
                "malformed Noise static key; generating a replacement"
            );
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            warn!(
                path = %path.display(),
                %error,
                "could not read Noise static key; generating a replacement"
            );
        }
    }

    let key = generate_static();
    if let Err(error) = persist_static(&path, &key) {
        warn!(
            path = %path.display(),
            %error,
            "could not persist Noise static key; using it for this process only"
        );
    }
    Ok(key)
}

#[cfg(unix)]
fn repair_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
        warn!(path = %path.display(), "repairing Noise static key permissions to 0600");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn persist_static(path: &Path, key: &[u8; 32]) -> std::io::Result<()> {
    let temporary = path.with_extension("key.tmp");
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(hex::encode(key).as_bytes())?;
    file.sync_all()?;
    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_persistent_across_claims() {
        let temp = tempfile::tempdir().unwrap();
        let first = claim(temp.path()).unwrap();
        assert!(first.persistent);
        let id = first.id.clone();
        assert_eq!(
            fs::read_to_string(temp.path().join("identity"))
                .unwrap()
                .trim(),
            id.as_str()
        );

        drop(first);
        let second = claim(temp.path()).unwrap();
        assert!(second.persistent);
        assert_eq!(second.id, id);
    }

    #[test]
    fn noise_static_key_persists_across_claims() {
        let temp = tempfile::tempdir().unwrap();
        let first = claim(temp.path()).unwrap();
        let key = first.static_private;
        let key_text = fs::read_to_string(temp.path().join("noise_static.key")).unwrap();
        assert_eq!(key_text.len(), 64);
        assert!(key_text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        drop(first);

        let second = claim(temp.path()).unwrap();
        assert_eq!(second.static_private, key);
    }

    #[cfg(unix)]
    #[test]
    fn noise_static_key_is_written_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let _identity = claim(temp.path()).unwrap();
        let mode = fs::metadata(temp.path().join("noise_static.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn loading_noise_static_key_repairs_permissive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let original = claim(temp.path()).unwrap();
        let key = original.static_private;
        drop(original);
        let path = temp.path().join("noise_static.key");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let loaded = claim(temp.path()).unwrap();
        assert_eq!(loaded.static_private, key);
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn malformed_noise_static_key_is_regenerated() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("noise_static.key"), "broken").unwrap();
        let identity = claim(temp.path()).unwrap();
        let persisted = fs::read_to_string(temp.path().join("noise_static.key")).unwrap();
        assert_eq!(persisted.len(), 64);
        assert_eq!(hex::decode(persisted).unwrap(), identity.static_private);
    }

    #[test]
    fn concurrent_claim_uses_an_ephemeral_identity_without_changing_file() {
        let temp = tempfile::tempdir().unwrap();
        let first = claim(temp.path()).unwrap();
        assert!(first.persistent);
        let identity_path = temp.path().join("identity");
        let original_contents = fs::read_to_string(&identity_path).unwrap();

        let second = claim(temp.path()).unwrap();
        assert!(!second.persistent);
        assert_ne!(second.id, first.id);
        assert_eq!(
            fs::read_to_string(identity_path).unwrap(),
            original_contents
        );
    }

    #[test]
    fn corrupt_identity_is_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let identity_path = temp.path().join("identity");
        fs::write(&identity_path, "nope").unwrap();

        let identity = claim(temp.path()).unwrap();
        assert!(identity.persistent);
        assert_ne!(identity.id.as_str(), "nope");
        assert_eq!(
            ParticleId::parse(fs::read_to_string(identity_path).unwrap().trim().to_owned())
                .unwrap(),
            identity.id
        );
    }
}
