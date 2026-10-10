//! Pairing-code parsing, key derivation, and local pairing-key storage.

use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;
#[cfg(unix)]
use tracing::warn;

const GROUP_DOMAIN: &[u8] = b"entangle-pair-group-v1";
const PSK_DOMAIN: &[u8] = b"entangle-pair-psk-v1";

/// Pairing key storage or code-validation failure.
#[derive(Debug, Error)]
pub enum PairingError {
    /// File-system operation failed.
    #[error("pairing key I/O failed: {0}")]
    Io(#[from] io::Error),
    /// A code does not contain a valid ENT1 key.
    #[error("invalid pairing code")]
    InvalidCode,
    /// Pair initialization would replace an existing key.
    #[error("a pairing key already exists; use --force to replace it")]
    AlreadyPaired,
    /// A join code differs from the key already stored on this machine.
    #[error("this machine is paired with a different key; use --force to replace it")]
    DifferentKey,
    /// A pairing key file exists but does not contain a valid key.
    #[error("the pairing key file is malformed; use --force to replace it")]
    MalformedKey,
    /// The pairing key path is not a regular file.
    #[error("the pairing key path is not a regular file")]
    NotRegularFile,
    /// An operation requires a pairing key that is not present.
    #[error("this machine is not paired")]
    NotPaired,
}

/// Loads the pairing key, returning `None` when the machine is not paired.
pub fn load(data_root: &Path) -> Result<Option<[u8; 32]>, PairingError> {
    read_key(&key_path(data_root))
}

/// Creates and stores a fresh pairing key, unless one already exists without force.
pub fn initialize(data_root: &Path, force: bool) -> Result<[u8; 32], PairingError> {
    let path = key_path(data_root);
    if path.exists() && !force {
        return Err(PairingError::AlreadyPaired);
    }
    let mut key = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    write_key(&path, &key)?;
    Ok(key)
}

/// Joins an existing pairing group, replacing a different key only with force.
pub fn join(data_root: &Path, code: &str, force: bool) -> Result<[u8; 32], PairingError> {
    let key = parse_code(code)?;
    let path = key_path(data_root);
    match read_key(&path) {
        Ok(Some(existing)) if existing == key => return Ok(key),
        Ok(Some(_)) if !force => return Err(PairingError::DifferentKey),
        Err(PairingError::MalformedKey) if !force => return Err(PairingError::MalformedKey),
        Err(error) if !matches!(&error, PairingError::MalformedKey) => return Err(error),
        _ => {}
    }
    write_key(&path, &key)?;
    Ok(key)
}

/// Reads the stored pairing key or reports that it is absent.
pub fn require(data_root: &Path) -> Result<[u8; 32], PairingError> {
    load(data_root)?.ok_or(PairingError::NotPaired)
}

/// Formats a pairing key as an ENT1 code with four-character groups.
pub fn encode_code(key: &[u8; 32]) -> String {
    let encoded = data_encoding::BASE32_NOPAD.encode(key);
    let groups = encoded
        .as_bytes()
        .chunks(4)
        .map(|part| std::str::from_utf8(part).expect("base32 output is ASCII"))
        .collect::<Vec<_>>()
        .join("-");
    format!("ENT1-{groups}")
}

/// Parses an ENT1 code, ignoring ASCII whitespace and hyphens.
pub fn parse_code(code: &str) -> Result<[u8; 32], PairingError> {
    let compact = code
        .chars()
        .filter(|character| *character != '-' && !character.is_ascii_whitespace())
        .map(|character| character.to_ascii_uppercase())
        .collect::<String>();
    let encoded = compact
        .strip_prefix("ENT1")
        .ok_or(PairingError::InvalidCode)?;
    let bytes = data_encoding::BASE32_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| PairingError::InvalidCode)?;
    bytes.try_into().map_err(|_| PairingError::InvalidCode)
}

/// Returns the public eight-hex-character identifier for a pairing key.
pub fn group_id(key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(GROUP_DOMAIN);
    hasher.update(key);
    hex_prefix(&hasher.finalize(), 4)
}

/// Derives the Noise PSK from a pairing key.
pub fn derive_psk(key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PSK_DOMAIN);
    hasher.update(key);
    hasher.finalize().into()
}

fn key_path(data_root: &Path) -> PathBuf {
    data_root.join("pairing.key")
}

fn read_key(path: &Path) -> Result<Option<[u8; 32]>, PairingError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            #[cfg(unix)]
            repair_permissions(path)?;
        }
        Ok(_) => return Err(PairingError::NotRegularFile),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let contents = contents.trim_end_matches(['\r', '\n']);
    if contents.len() != 64 || !contents.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PairingError::MalformedKey);
    }
    let mut key = [0_u8; 32];
    for (index, pair) in contents.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        key[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Ok(Some(key))
}

#[cfg(unix)]
fn repair_permissions(path: &Path) -> Result<(), PairingError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(PairingError::NotRegularFile);
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        warn!(path = %path.display(), "repairing pairing key permissions to 0600");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn write_key(path: &Path, key: &[u8; 32]) -> Result<(), PairingError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(hex_encode(key).as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        replace_file(&temporary, path)?;
        Ok::<_, io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
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

fn hex_value(byte: u8) -> Result<u8, PairingError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(PairingError::MalformedKey),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 15) as usize] as char);
    }
    output
}

fn hex_prefix(bytes: &[u8], count: usize) -> String {
    hex_encode(&bytes[..count])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn pairing_code_roundtrips_with_case_whitespace_and_missing_hyphens() {
        let key = [0x52; 32];
        let code = encode_code(&key);
        assert_eq!(parse_code(&code).unwrap(), key);
        assert_eq!(parse_code(&code.to_lowercase()).unwrap(), key);
        assert_eq!(parse_code(&code.replace('-', " \n")).unwrap(), key);
        assert_eq!(parse_code(&code.replace('-', "")).unwrap(), key);
        assert_eq!(code.len(), 4 + 1 + 52 + 12);
    }

    #[test]
    fn bad_pairing_prefix_or_length_is_rejected() {
        let key = [0x31; 32];
        let code = encode_code(&key);
        assert!(matches!(
            parse_code(&code.replacen("ENT1", "BAD1", 1)),
            Err(PairingError::InvalidCode)
        ));
        assert!(matches!(
            parse_code("ENT1-AAAA"),
            Err(PairingError::InvalidCode)
        ));
    }

    #[test]
    fn init_and_join_enforce_overwrite_rules() {
        let directory = tempdir().unwrap();
        let first = initialize(directory.path(), false).unwrap();
        assert!(matches!(
            initialize(directory.path(), false),
            Err(PairingError::AlreadyPaired)
        ));
        let same = join(directory.path(), &encode_code(&first), false).unwrap();
        assert_eq!(same, first);

        let second = [0x77; 32];
        assert!(matches!(
            join(directory.path(), &encode_code(&second), false),
            Err(PairingError::DifferentKey)
        ));
        assert_eq!(
            join(directory.path(), &encode_code(&second), true).unwrap(),
            second
        );
        assert_eq!(load(directory.path()).unwrap(), Some(second));

        let forced = initialize(directory.path(), true).unwrap();
        assert_ne!(forced, second);
    }

    #[test]
    fn pairing_derivations_are_deterministic_and_domain_separated() {
        let key = [0x91; 32];
        let group = group_id(&key);
        let psk = derive_psk(&key);
        assert_eq!(group, group_id(&key));
        assert_eq!(psk, derive_psk(&key));
        assert_eq!(group.len(), 8);
        assert_ne!(psk, key);
        let key_hex = hex_encode(&key);
        let psk_hex = hex_encode(&psk);
        assert_ne!(group.as_str(), &key_hex[..8]);
        assert_ne!(psk_hex, key_hex);
        assert_ne!(group.as_str(), &psk_hex[..8]);
    }

    #[test]
    fn pairing_key_is_written_as_lowercase_hex_with_private_permissions() {
        let directory = tempdir().unwrap();
        let key = [0xab; 32];
        initialize(directory.path(), false).unwrap();
        write_key(&key_path(directory.path()), &key).unwrap();
        let content = fs::read_to_string(directory.path().join("pairing.key")).unwrap();
        assert_eq!(content.trim(), hex_encode(&key));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(directory.path().join("pairing.key"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn loading_pairing_key_repairs_permissive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().unwrap();
        let key = initialize(directory.path(), false).unwrap();
        let path = key_path(directory.path());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(load(directory.path()).unwrap(), Some(key));
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_pairing_key_is_rejected_without_changing_target_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempdir().unwrap();
        let target = directory.path().join("target.key");
        fs::write(&target, hex_encode(&[0x47; 32])).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&target, key_path(directory.path())).unwrap();

        assert!(matches!(
            load(directory.path()),
            Err(PairingError::NotRegularFile)
        ));
        assert_eq!(
            fs::metadata(target).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}
