//! Persistent group keys and membership lists.

use crate::{identity, private_fs};
use chrono::{SecondsFormat, Utc};
use entangle_core::ParticleId;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};
use thiserror::Error;

pub const MAX_GROUPS: usize = 8;
const GROUP_VERSION: u32 = 1;
const GROUP_DOMAIN: &[u8] = b"entangle-group-id-v1";
const PSK_DOMAIN: &[u8] = b"entangle-group-psk-v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Member,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupMeta {
    pub version: u32,
    pub name: String,
    pub role: Role,
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Member {
    pub particle_id: String,
    pub name: String,
    pub static_key: String,
    pub added_by: String,
    pub added_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Group {
    pub id: String,
    pub key: [u8; 32],
    pub meta: GroupMeta,
    pub members: Vec<Member>,
}

#[derive(Debug, Error)]
pub enum GroupError {
    #[error("invalid group name: {0}")]
    InvalidName(String),
    #[error("a group named {0} already exists")]
    NameTaken(String),
    #[error("particle {0} is already a group member")]
    AlreadyMember(String),
    #[error("this machine is already in {MAX_GROUPS} groups")]
    TooMany,
    #[error("group not found: {0}")]
    NotFound(String),
    #[error("group member key conflicts for particle {0}")]
    #[allow(dead_code)]
    KeyConflict(String),
    #[error(
        "this machine has no saved Entangle identity in {0} yet; start Entangle once (for example, open your MCP client) using the same data directory, then retry"
    )]
    MissingIdentity(PathBuf),
    #[error("malformed group data at {path}: {reason}")]
    Malformed { path: PathBuf, reason: String },
    #[error("unsafe group storage path: {0}")]
    UnsafePath(PathBuf),
    #[error("group storage I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl GroupError {
    fn io(path: &Path, source: io::Error) -> Self {
        Self::Io {
            path: path.to_owned(),
            source,
        }
    }

    fn malformed(path: &Path, reason: impl Into<String>) -> Self {
        Self::Malformed {
            path: path.to_owned(),
            reason: reason.into(),
        }
    }

    fn private_fs(error: private_fs::PrivateFsError) -> Self {
        match error {
            private_fs::PrivateFsError::UnsafePath(path) => Self::UnsafePath(path),
            private_fs::PrivateFsError::Io { path, source } => Self::Io { path, source },
        }
    }
}

pub fn group_id(key: &[u8; 32]) -> String {
    hex::encode(group_id_bytes(key))
}

pub fn group_id_bytes(key: &[u8; 32]) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(GROUP_DOMAIN);
    hasher.update(key);
    hasher.finalize()[..4]
        .try_into()
        .expect("four-byte group ID")
}

pub fn derive_psk(key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PSK_DOMAIN);
    hasher.update(key);
    hasher.finalize().into()
}

pub fn validate_name(name: &str) -> Result<(), GroupError> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 32
        || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return Err(GroupError::InvalidName(name.to_owned()));
    }
    Ok(())
}

pub fn list(root: &Path) -> Result<Vec<Group>, GroupError> {
    let _lock = lock_groups(root)?;
    let directory = groups_dir(root);
    let mut groups = Vec::new();
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(groups),
        Err(error) => return Err(GroupError::io(&directory, error)),
    };
    for entry in entries {
        let entry = entry.map_err(|error| GroupError::io(&directory, error))?;
        let path = entry.path();
        if entry.file_name() == ".lock" {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| GroupError::io(&path, error))?;
        if !metadata.file_type().is_dir() {
            return Err(GroupError::malformed(&path, "expected a group directory"));
        }
        let group = read_group(&path)?;
        groups.push(group);
    }
    groups.sort_by(|left, right| {
        left.meta
            .name
            .cmp(&right.meta.name)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(groups)
}

pub fn find(root: &Path, name_or_id: &str) -> Result<Option<Group>, GroupError> {
    Ok(list(root)?
        .into_iter()
        .find(|group| group.meta.name == name_or_id || group.id == name_or_id))
}

pub fn create(root: &Path, name: &str, self_member: Member) -> Result<Group, GroupError> {
    validate_name(name)?;
    let Some((identity_id, identity_key)) = identity::read_saved(root)
        .map_err(|error| GroupError::malformed(root, error.to_string()))?
    else {
        return Err(GroupError::MissingIdentity(root.to_owned()));
    };
    validate_member(&self_member, root)?;
    if self_member.particle_id != identity_id.as_str()
        || self_member.static_key != hex::encode(entangle_transport::public_key(&identity_key))
    {
        return Err(GroupError::malformed(
            root,
            "self member does not match this machine's saved identity",
        ));
    }
    let _lock = lock_groups(root)?;
    let existing = read_groups_unlocked(root)?;
    ensure_available(&existing, name)?;
    if existing.len() >= MAX_GROUPS {
        return Err(GroupError::TooMany);
    }
    let mut key = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let now = timestamp();
    let group = Group {
        id: group_id(&key),
        key,
        meta: GroupMeta {
            version: GROUP_VERSION,
            name: name.to_owned(),
            role: Role::Admin,
            created_at: now,
        },
        members: vec![self_member],
    };
    write_group(root, &group)?;
    Ok(group)
}

#[allow(dead_code)]
pub fn insert(
    root: &Path,
    key: [u8; 32],
    meta: GroupMeta,
    members: Vec<Member>,
) -> Result<Group, GroupError> {
    validate_meta(&meta, root)?;
    validate_members(&members, root)?;
    let _lock = lock_groups(root)?;
    let existing = read_groups_unlocked(root)?;
    ensure_available(&existing, &meta.name)?;
    if existing.len() >= MAX_GROUPS {
        return Err(GroupError::TooMany);
    }
    let id = group_id(&key);
    if existing.iter().any(|group| group.id == id) {
        return Err(GroupError::AlreadyMember(id));
    }
    let group = Group {
        id,
        key,
        meta,
        members,
    };
    write_group(root, &group)?;
    Ok(group)
}

#[allow(dead_code)]
pub fn add_member(root: &Path, group_id: &str, member: Member) -> Result<bool, GroupError> {
    validate_member(&member, root)?;
    if group_id.len() != 8
        || !group_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GroupError::NotFound(group_id.to_owned()));
    }
    let _lock = lock_groups(root)?;
    let path = group_path(root, group_id);
    let mut group = read_group(&path)?;
    if let Some(existing) = group
        .members
        .iter()
        .find(|existing| existing.particle_id == member.particle_id)
    {
        if existing.static_key == member.static_key {
            return Ok(false);
        }
        return Err(GroupError::KeyConflict(member.particle_id));
    }
    group.members.push(member);
    group
        .members
        .sort_by(|left, right| left.particle_id.cmp(&right.particle_id));
    write_group(root, &group)?;
    Ok(true)
}

pub fn leave(root: &Path, name_or_id: &str) -> Result<Group, GroupError> {
    let _lock = lock_groups(root)?;
    let group = read_groups_unlocked(root)?
        .into_iter()
        .find(|group| group.id == name_or_id || group.meta.name == name_or_id)
        .ok_or_else(|| GroupError::NotFound(name_or_id.to_owned()))?;
    let path = group_path(root, &group.id);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(GroupError::UnsafePath(path)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(GroupError::NotFound(name_or_id.to_owned()))
        }
        Err(error) => return Err(GroupError::io(&path, error)),
    }
    fs::remove_dir_all(&path).map_err(|error| GroupError::io(&path, error))?;
    Ok(group)
}

fn ensure_available(groups: &[Group], name: &str) -> Result<(), GroupError> {
    if groups.iter().any(|group| group.meta.name == name) {
        return Err(GroupError::NameTaken(name.to_owned()));
    }
    Ok(())
}

fn groups_dir(root: &Path) -> PathBuf {
    root.join("groups")
}

fn group_path(root: &Path, id: &str) -> PathBuf {
    groups_dir(root).join(id)
}

fn lock_groups(root: &Path) -> Result<File, GroupError> {
    let directory = groups_dir(root);
    private_fs::create_private_directory(&directory).map_err(GroupError::private_fs)?;
    let path = directory.join(".lock");
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => return Err(GroupError::UnsafePath(path)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(GroupError::io(&path, error)),
    }
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options
        .open(&path)
        .map_err(|error| GroupError::io(&path, error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = lock
            .metadata()
            .map_err(|error| GroupError::io(&path, error))?;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|error| GroupError::io(&path, error))?;
        }
    }
    lock.lock().map_err(|error| GroupError::io(&path, error))?;
    Ok(lock)
}

fn read_groups_unlocked(root: &Path) -> Result<Vec<Group>, GroupError> {
    let directory = groups_dir(root);
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(GroupError::io(&directory, error)),
    };
    let mut groups = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| GroupError::io(&directory, error))?;
        let path = entry.path();
        if entry.file_name() == ".lock" {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| GroupError::io(&path, error))?;
        if !metadata.file_type().is_dir() {
            return Err(GroupError::malformed(&path, "expected a group directory"));
        }
        groups.push(read_group(&path)?);
    }
    groups.sort_by(|left, right| {
        left.meta
            .name
            .cmp(&right.meta.name)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(groups)
}

fn read_group(path: &Path) -> Result<Group, GroupError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            GroupError::NotFound(path.display().to_string())
        } else {
            GroupError::io(path, error)
        }
    })?;
    if !metadata.file_type().is_dir() {
        return Err(GroupError::UnsafePath(path.to_owned()));
    }
    private_fs::create_private_directory(path).map_err(GroupError::private_fs)?;
    let key_path = path.join("key");
    let key_bytes = private_fs::read_regular_file(&key_path)
        .map_err(GroupError::private_fs)?
        .ok_or_else(|| GroupError::malformed(&key_path, "missing key"))?;
    let key_text = std::str::from_utf8(&key_bytes)
        .map_err(|error| GroupError::malformed(&key_path, error.to_string()))?
        .trim_end_matches(['\r', '\n']);
    if key_text.len() != 64
        || !key_text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GroupError::malformed(
            &key_path,
            "expected 64 hexadecimal characters",
        ));
    }
    let decoded = hex::decode(key_text)
        .map_err(|error| GroupError::malformed(&key_path, error.to_string()))?;
    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| GroupError::malformed(&key_path, "expected a 32-byte key"))?;

    let meta_path = path.join("meta.json");
    let meta_bytes = private_fs::read_regular_file(&meta_path)
        .map_err(GroupError::private_fs)?
        .ok_or_else(|| GroupError::malformed(&meta_path, "missing metadata"))?;
    let meta: GroupMeta = serde_json::from_slice(&meta_bytes)
        .map_err(|error| GroupError::malformed(&meta_path, error.to_string()))?;
    validate_meta(&meta, &meta_path)?;

    let members_path = path.join("members.json");
    let members_bytes = private_fs::read_regular_file(&members_path)
        .map_err(GroupError::private_fs)?
        .ok_or_else(|| GroupError::malformed(&members_path, "missing member list"))?;
    let members: Vec<Member> = serde_json::from_slice(&members_bytes)
        .map_err(|error| GroupError::malformed(&members_path, error.to_string()))?;
    validate_members(&members, &members_path)?;
    if members.is_empty() {
        return Err(GroupError::malformed(&members_path, "group has no members"));
    }

    let id = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| GroupError::malformed(path, "invalid group directory name"))?;
    if id != group_id(&key) {
        return Err(GroupError::malformed(
            path,
            "directory name does not match the key's group ID",
        ));
    }
    Ok(Group {
        id: id.to_owned(),
        key,
        meta,
        members,
    })
}

fn write_group(root: &Path, group: &Group) -> Result<(), GroupError> {
    let path = group_path(root, &group.id);
    private_fs::create_private_directory(&path).map_err(GroupError::private_fs)?;
    validate_meta(&group.meta, &path.join("meta.json"))?;
    validate_members(&group.members, &path.join("members.json"))?;
    if group.members.is_empty() {
        return Err(GroupError::malformed(
            &path.join("members.json"),
            "group has no members",
        ));
    }
    if group.id != group_id(&group.key) {
        return Err(GroupError::malformed(
            &path.join("key"),
            "group ID does not match the key",
        ));
    }
    let key = format!("{}\n", hex::encode(group.key));
    let meta = serde_json::to_vec_pretty(&group.meta)
        .map_err(|error| GroupError::malformed(&path.join("meta.json"), error.to_string()))?;
    let members = serde_json::to_vec_pretty(&group.members)
        .map_err(|error| GroupError::malformed(&path.join("members.json"), error.to_string()))?;
    private_fs::atomic_write(&path.join("key"), key.as_bytes()).map_err(GroupError::private_fs)?;
    private_fs::atomic_write(&path.join("meta.json"), &meta).map_err(GroupError::private_fs)?;
    private_fs::atomic_write(&path.join("members.json"), &members)
        .map_err(GroupError::private_fs)?;
    Ok(())
}

fn validate_meta(meta: &GroupMeta, path: &Path) -> Result<(), GroupError> {
    if meta.version != GROUP_VERSION {
        return Err(GroupError::malformed(
            path,
            format!("unsupported metadata version {}", meta.version),
        ));
    }
    validate_name(&meta.name).map_err(|error| GroupError::malformed(path, error.to_string()))?;
    chrono::DateTime::parse_from_rfc3339(&meta.created_at)
        .map_err(|error| GroupError::malformed(path, error.to_string()))?;
    Ok(())
}

fn validate_members(members: &[Member], path: &Path) -> Result<(), GroupError> {
    if members.is_empty() {
        return Err(GroupError::malformed(path, "group has no members"));
    }
    let mut ids = std::collections::HashSet::new();
    for member in members {
        validate_member(member, path)?;
        if !ids.insert(&member.particle_id) {
            return Err(GroupError::AlreadyMember(member.particle_id.clone()));
        }
    }
    Ok(())
}

fn validate_member(member: &Member, path: &Path) -> Result<(), GroupError> {
    for id in [&member.particle_id, &member.added_by] {
        ParticleId::parse(id.clone())
            .map_err(|error| GroupError::malformed(path, error.to_string()))?;
    }
    if member.static_key.len() != 64
        || !member
            .static_key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GroupError::malformed(
            path,
            "member static key must be 64 lowercase hexadecimal characters",
        ));
    }
    chrono::DateTime::parse_from_rfc3339(&member.added_at)
        .map_err(|error| GroupError::malformed(path, error.to_string()))?;
    Ok(())
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::{Arc, Mutex},
        thread,
    };
    use tempfile::tempdir;

    fn saved_identity(root: &Path) -> Member {
        let identity = identity::claim(root).unwrap();
        Member {
            particle_id: identity.id.to_string(),
            name: "workstation".into(),
            static_key: hex::encode(entangle_transport::public_key(&identity.static_private)),
            added_by: identity.id.to_string(),
            added_at: timestamp(),
        }
    }

    fn member(index: u8) -> Member {
        let id = format!("{index:032x}");
        Member {
            particle_id: id.clone(),
            name: format!("peer-{index}"),
            static_key: hex::encode([index; 32]),
            added_by: id,
            added_at: timestamp(),
        }
    }

    fn create_named(root: &Path, name: &str) -> Group {
        groups_create(root, name, saved_identity(root))
    }

    fn groups_create(root: &Path, name: &str, self_member: Member) -> Group {
        create(root, name, self_member).unwrap()
    }

    #[test]
    fn group_name_validation_accepts_and_rejects_the_required_names() {
        for name in ["work", "a", "home-lab-2", "default"] {
            assert!(validate_name(name).is_ok(), "{name}");
        }
        for name in ["", "Work", "-x", "a_b", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] {
            assert!(validate_name(name).is_err(), "{name}");
        }
    }

    #[test]
    fn create_list_and_find_by_name_or_id() {
        let root = tempdir().unwrap();
        let group = create_named(root.path(), "work");
        assert_eq!(list(root.path()).unwrap(), vec![group.clone()]);
        assert_eq!(find(root.path(), "work").unwrap(), Some(group.clone()));
        assert_eq!(find(root.path(), &group.id).unwrap(), Some(group));
        assert_eq!(find(root.path(), "missing").unwrap(), None);
    }

    #[test]
    fn duplicate_name_and_ninth_group_are_rejected() {
        let root = tempdir().unwrap();
        let self_member = saved_identity(root.path());
        create(root.path(), "work", self_member.clone()).unwrap();
        assert!(matches!(
            create(root.path(), "work", self_member.clone()),
            Err(GroupError::NameTaken(_))
        ));
        for index in 1..MAX_GROUPS {
            create(root.path(), &format!("group-{index}"), self_member.clone()).unwrap();
        }
        assert!(matches!(
            create(root.path(), "ninth", self_member),
            Err(GroupError::TooMany)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_lowercase_hex_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempdir().unwrap();
        let group = create_named(root.path(), "work");
        let key_path = root.path().join("groups").join(&group.id).join("key");
        let key = fs::read_to_string(&key_path).unwrap();
        assert_eq!(key, format!("{}\n", hex::encode(group.key)));
        assert_eq!(
            fs::metadata(key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_key_is_rejected_without_changing_its_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = tempdir().unwrap();
        let group = create_named(root.path(), "work");
        let directory = root.path().join("groups").join(&group.id);
        let key_path = directory.join("key");
        let target = root.path().join("outside-key");
        fs::write(&target, "00".repeat(32)).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        fs::remove_file(&key_path).unwrap();
        symlink(&target, &key_path).unwrap();

        assert!(matches!(list(root.path()), Err(GroupError::UnsafePath(_))));
        assert_eq!(
            fs::metadata(target).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn malformed_metadata_error_names_its_path() {
        let root = tempdir().unwrap();
        let group = create_named(root.path(), "work");
        let path = root.path().join("groups").join(&group.id).join("meta.json");
        fs::write(&path, b"{").unwrap();
        let error = list(root.path()).unwrap_err().to_string();
        assert!(error.contains(&path.display().to_string()), "{error}");
    }

    #[test]
    fn group_directory_name_must_match_key_id() {
        let root = tempdir().unwrap();
        let group = create_named(root.path(), "work");
        let original_path = root.path().join("groups").join(&group.id);
        let renamed_id = if group.id == "00000000" {
            "00000001"
        } else {
            "00000000"
        };
        let renamed_path = original_path.with_file_name(renamed_id);
        assert_eq!(renamed_id.len(), 8);
        fs::rename(&original_path, &renamed_path).unwrap();

        match list(root.path()).unwrap_err() {
            GroupError::Malformed { path, .. } => assert_eq!(path, renamed_path),
            error => panic!("expected malformed group data, got {error}"),
        }
    }

    #[test]
    fn add_member_is_idempotent_and_rejects_key_conflicts() {
        let root = tempdir().unwrap();
        let group = create_named(root.path(), "work");
        let peer = member(1);
        assert!(add_member(root.path(), &group.id, peer.clone()).unwrap());
        assert!(!add_member(root.path(), &group.id, peer.clone()).unwrap());
        let mut changed_key = peer.clone();
        changed_key.static_key = hex::encode([9; 32]);
        assert!(matches!(
            add_member(root.path(), &group.id, changed_key),
            Err(GroupError::KeyConflict(_))
        ));
    }

    #[test]
    fn add_member_rejects_group_id_path_traversal() {
        let root = tempdir().unwrap();
        let outside_root = root.path().join("outside");
        let outside_group = create_named(&outside_root, "outside");
        let path = format!("../outside/groups/{}", outside_group.id);
        let error = add_member(root.path(), &path, member(1)).unwrap_err();
        assert!(matches!(error, GroupError::NotFound(_)));
        assert_eq!(
            find(&outside_root, "outside")
                .unwrap()
                .unwrap()
                .members
                .len(),
            1
        );
    }

    #[test]
    fn leave_removes_the_directory_and_second_leave_is_not_found() {
        let root = tempdir().unwrap();
        let group = create_named(root.path(), "work");
        let path = root.path().join("groups").join(&group.id);
        assert_eq!(leave(root.path(), "work").unwrap(), group);
        assert!(!path.exists());
        assert!(matches!(
            leave(root.path(), "work"),
            Err(GroupError::NotFound(_))
        ));
    }

    #[test]
    fn derivations_are_deterministic_and_domain_separated() {
        let key = [7; 32];
        assert_eq!(group_id(&key), group_id(&key));
        assert_eq!(group_id(&key).len(), 8);
        assert_eq!(hex::encode(group_id_bytes(&key)), group_id(&key));
        let mut id_hasher = Sha256::new();
        id_hasher.update(b"entangle-group-id-v1");
        id_hasher.update(key);
        assert_eq!(group_id_bytes(&key), id_hasher.finalize()[..4]);
        let mut psk_hasher = Sha256::new();
        psk_hasher.update(b"entangle-group-psk-v1");
        psk_hasher.update(key);
        assert_eq!(derive_psk(&key), psk_hasher.finalize().as_slice());
        assert_ne!(group_id_bytes(&key), [0; 4]);
    }

    #[test]
    fn create_without_saved_identity_has_the_required_message() {
        let root = tempdir().unwrap();
        let error = create(root.path(), "work", member(1)).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "this machine has no saved Entangle identity in {} yet; start Entangle once (for example, open your MCP client) using the same data directory, then retry",
                root.path().display()
            )
        );
    }

    #[test]
    fn concurrent_member_updates_do_not_lose_members() {
        let root = tempdir().unwrap();
        let group = create_named(root.path(), "work");
        let root = Arc::new(root);
        let failures = Arc::new(Mutex::new(Vec::new()));
        let handles = (1..=16)
            .map(|index| {
                let root = Arc::clone(&root);
                let failures = Arc::clone(&failures);
                let id = group.id.clone();
                thread::spawn(move || {
                    if let Err(error) = add_member(root.path(), &id, member(index)) {
                        failures.lock().unwrap().push(error.to_string());
                    }
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().unwrap();
        }
        assert!(failures.lock().unwrap().is_empty());
        assert_eq!(
            find(root.path(), &group.id).unwrap().unwrap().members.len(),
            17
        );
    }
}
