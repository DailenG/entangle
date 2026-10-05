//! Lock-backed identity persistence for a local Entangle data root.

use entangle_core::ParticleId;
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
    _lock: Option<File>,
}

/// Claims the persistent identity for a data root, or generates an ephemeral one.
pub fn claim(root: &Path) -> Identity {
    if let Err(error) = fs::create_dir_all(root) {
        warn!(
            path = %root.display(),
            %error,
            "could not create identity data directory; using an ephemeral identity"
        );
        return ephemeral();
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
            return ephemeral();
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
        return ephemeral();
    }

    let identity_path = root.join("identity");
    match fs::read(&identity_path) {
        Ok(contents) => {
            if let Some(id) = std::str::from_utf8(&contents)
                .ok()
                .and_then(|value| ParticleId::parse(value.trim().to_owned()).ok())
            {
                return persistent(id, lock);
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            warn!(
                path = %identity_path.display(),
                %error,
                "could not read identity; using an ephemeral identity"
            );
            return ephemeral();
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
        return ephemeral();
    }

    persistent(id, lock)
}

fn persistent(id: ParticleId, lock: File) -> Identity {
    Identity {
        id,
        persistent: true,
        _lock: Some(lock),
    }
}

fn ephemeral() -> Identity {
    Identity {
        id: ParticleId::generate(),
        persistent: false,
        _lock: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_persistent_across_claims() {
        let temp = tempfile::tempdir().unwrap();
        let first = claim(temp.path());
        assert!(first.persistent);
        let id = first.id.clone();
        assert_eq!(
            fs::read_to_string(temp.path().join("identity"))
                .unwrap()
                .trim(),
            id.as_str()
        );

        drop(first);
        let second = claim(temp.path());
        assert!(second.persistent);
        assert_eq!(second.id, id);
    }

    #[test]
    fn concurrent_claim_uses_an_ephemeral_identity_without_changing_file() {
        let temp = tempfile::tempdir().unwrap();
        let first = claim(temp.path());
        assert!(first.persistent);
        let identity_path = temp.path().join("identity");
        let original_contents = fs::read_to_string(&identity_path).unwrap();

        let second = claim(temp.path());
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

        let identity = claim(temp.path());
        assert!(identity.persistent);
        assert_ne!(identity.id.as_str(), "nope");
        assert_eq!(
            ParticleId::parse(fs::read_to_string(identity_path).unwrap().trim().to_owned())
                .unwrap(),
            identity.id
        );
    }
}
