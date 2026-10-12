//! Private directories and atomic writes for persistent local state.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use thiserror::Error;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Error)]
pub enum PrivateFsError {
    #[error("unsafe private-state path: {0}")]
    UnsafePath(PathBuf),
    #[error("private-state I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl PrivateFsError {
    fn io(path: &Path, source: io::Error) -> Self {
        Self::Io {
            path: path.to_owned(),
            source,
        }
    }
}

pub fn create_private_directory(path: &Path) -> Result<(), PrivateFsError> {
    fs::create_dir_all(path).map_err(|error| PrivateFsError::io(path, error))?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .map_err(|error| PrivateFsError::io(path, error))?;
            }
            Ok(())
        }
        Ok(_) => Err(PrivateFsError::UnsafePath(path.to_owned())),
        Err(error) => Err(PrivateFsError::io(path, error)),
    }
}

pub fn read_regular_file(path: &Path) -> Result<Option<Vec<u8>>, PrivateFsError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o777 != 0o600 {
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                        .map_err(|error| PrivateFsError::io(path, error))?;
                }
            }
            fs::read(path)
                .map(Some)
                .map_err(|error| PrivateFsError::io(path, error))
        }
        Ok(_) => Err(PrivateFsError::UnsafePath(path.to_owned())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(PrivateFsError::io(path, error)),
    }
}

pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), PrivateFsError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    create_private_directory(parent)?;
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
        let mut file = options
            .open(&temporary)
            .map_err(|error| PrivateFsError::io(&temporary, error))?;
        file.write_all(contents)
            .map_err(|error| PrivateFsError::io(&temporary, error))?;
        file.sync_all()
            .map_err(|error| PrivateFsError::io(&temporary, error))?;
        fs::rename(&temporary, path).map_err(|error| PrivateFsError::io(path, error))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
