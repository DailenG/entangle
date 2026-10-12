//! Persistent group keys and membership lists.

use crate::{identity, private_fs};
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
pub use entangle_core::Member;
use entangle_core::{GroupUpdate, ParticleId, Revocation, UpdateKind};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};
use thiserror::Error;

pub const MAX_GROUPS: usize = 8;
const GROUP_VERSION: u32 = 2;
const GROUP_DOMAIN: &[u8] = b"entangle-group-id-v1";
const PSK_DOMAIN: &[u8] = b"entangle-group-psk-v1";
const SIGN_DOMAIN: &[u8] = b"entangle-sign-v1";
const UPDATE_DOMAIN: &[u8] = b"entangle-group-update-v1\n";
const RETAINED_LIMIT: usize = 16;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
#[cfg(test)]
pub enum Role {
    Admin,
    Member,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupMeta {
    pub version: u32,
    pub name: String,
    pub created_at: String,
    pub epoch: u32,
    pub admin: String,
    pub admin_sign_key: String,
    pub revoked: Vec<Revocation>,
    #[serde(default)]
    pub leaving: bool,
}

impl GroupMeta {
    pub fn is_admin(&self, self_id: &str) -> bool {
        self.admin == self_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Group {
    pub id: String,
    pub key: [u8; 32],
    pub meta: GroupMeta,
    pub members: Vec<Member>,
    pub retained_keys: BTreeMap<u32, [u8; 32]>,
    pub updates: Vec<GroupUpdate>,
    pub outdated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyResult {
    pub epoch: u32,
    pub removed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupStatus {
    pub epoch: u32,
    pub op: String,
    pub confirmed: Vec<String>,
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
    #[error("group {name} was created by Entangle 0.6; run `entangle group leave {name}` and create it again")]
    Outdated { name: String },
    #[error("could not generate a unique group ID after 16 key attempts")]
    IdCollision,
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
    #[error("invalid signed group update: {0}")]
    InvalidUpdate(String),
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

pub fn id_bytes(id: &str) -> Option<[u8; 4]> {
    if !is_group_id(id) {
        return None;
    }
    hex::decode(id).ok()?.try_into().ok()
}

pub fn derive_psk(key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PSK_DOMAIN);
    hasher.update(key);
    hasher.finalize().into()
}

pub fn signing_key(static_private: &[u8; 32]) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(SIGN_DOMAIN);
    hasher.update(static_private);
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

pub fn signing_public_key(static_private: &[u8; 32]) -> String {
    hex::encode(signing_key(static_private).verifying_key().to_bytes())
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
    read_groups_unlocked(root)
}

pub fn find(root: &Path, name_or_id: &str) -> Result<Option<Group>, GroupError> {
    Ok(list(root)?
        .into_iter()
        .find(|group| group.meta.name == name_or_id || group.id == name_or_id))
}

pub fn create(root: &Path, name: &str, self_member: Member) -> Result<Group, GroupError> {
    create_with_key_source(root, name, self_member, |key| {
        rand::rngs::OsRng.fill_bytes(key);
    })
}

fn create_with_key_source(
    root: &Path,
    name: &str,
    self_member: Member,
    mut fill_key: impl FnMut(&mut [u8; 32]),
) -> Result<Group, GroupError> {
    validate_name(name)?;
    let Some((identity_id, identity_key)) = identity::read_saved(root)
        .map_err(|error| GroupError::malformed(root, error.to_string()))?
    else {
        return Err(GroupError::MissingIdentity(root.to_owned()));
    };
    validate_member(&self_member, root)?;
    if self_member.particle_id != identity_id.as_str()
        || self_member.static_key != hex::encode(entangle_transport::public_key(&identity_key))
        || self_member.sign_key != signing_public_key(&identity_key)
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
    let (key, id) = (0..16)
        .find_map(|_| {
            let mut key = [0_u8; 32];
            fill_key(&mut key);
            let id = group_id(&key);
            (!existing.iter().any(|group| group.id == id)).then_some((key, id))
        })
        .ok_or(GroupError::IdCollision)?;
    let now = timestamp();
    let group = Group {
        id,
        key,
        meta: GroupMeta {
            version: GROUP_VERSION,
            name: name.to_owned(),
            created_at: now,
            epoch: 0,
            admin: self_member.particle_id.clone(),
            admin_sign_key: self_member.sign_key.clone(),
            revoked: Vec::new(),
            leaving: false,
        },
        members: vec![self_member],
        retained_keys: BTreeMap::new(),
        updates: Vec::new(),
        outdated: false,
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
    insert_with_id(root, group_id(&key), key, meta, members)
}

pub fn insert_with_id(
    root: &Path,
    id: String,
    key: [u8; 32],
    meta: GroupMeta,
    members: Vec<Member>,
) -> Result<Group, GroupError> {
    validate_meta(&meta, root)?;
    validate_members(&members, root)?;
    validate_admin_member(&meta, &members, root)?;
    let _lock = lock_groups(root)?;
    let existing = read_groups_unlocked(root)?;
    ensure_available(&existing, &meta.name)?;
    if existing.len() >= MAX_GROUPS {
        return Err(GroupError::TooMany);
    }
    if !is_group_id(&id) {
        return Err(GroupError::malformed(
            Path::new("group ID"),
            "directory name is not an eight-character group ID",
        ));
    }
    if existing.iter().any(|group| group.id == id) {
        return Err(GroupError::AlreadyMember(id));
    }
    let group = Group {
        id,
        key,
        meta,
        members,
        retained_keys: BTreeMap::new(),
        updates: Vec::new(),
        outdated: false,
    };
    write_group(root, &group)?;
    Ok(group)
}

#[allow(dead_code)]
pub fn add_member(root: &Path, group_id: &str, member: Member) -> Result<bool, GroupError> {
    validate_member(&member, root)?;
    if !is_group_id(group_id) {
        return Err(GroupError::NotFound(group_id.to_owned()));
    }
    let _lock = lock_groups(root)?;
    cleanup_transaction_dirs(&groups_dir(root))?;
    let path = group_path(root, group_id);
    let mut group = read_group(&path)?;
    if group
        .meta
        .revoked
        .iter()
        .any(|revocation| revocation.particle_id == member.particle_id)
    {
        return Err(GroupError::InvalidUpdate(format!(
            "particle {} is revoked",
            member.particle_id
        )));
    }
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

pub fn remove_member(root: &Path, group_id: &str, particle_id: &str) -> Result<(), GroupError> {
    if !is_group_id(group_id) {
        return Err(GroupError::NotFound(group_id.to_owned()));
    }
    let _lock = lock_groups(root)?;
    cleanup_transaction_dirs(&groups_dir(root))?;
    let path = group_path(root, group_id);
    let mut group = read_group(&path)?;
    group
        .members
        .retain(|member| member.particle_id != particle_id);
    if group.members.is_empty() {
        fs::remove_dir_all(&path).map_err(|error| GroupError::io(&path, error))?;
    } else {
        write_group(root, &group)?;
    }
    Ok(())
}

pub fn set_leaving(root: &Path, group_id: &str, leaving: bool) -> Result<Group, GroupError> {
    if !is_group_id(group_id) {
        return Err(GroupError::NotFound(group_id.to_owned()));
    }
    let _lock = lock_groups(root)?;
    cleanup_transaction_dirs(&groups_dir(root))?;
    let path = group_path(root, group_id);
    let mut group = read_group(&path)?;
    group.meta.leaving = leaving;
    write_group(root, &group)?;
    Ok(group)
}

pub fn issue_update(
    root: &Path,
    group_id: &str,
    kind: UpdateKind,
    static_private: &[u8; 32],
) -> Result<Group, GroupError> {
    issue_update_with(root, group_id, kind, static_private, None)
}

pub fn issue_unrevoke_update(
    root: &Path,
    group_id: &str,
    particle_id: &str,
    static_private: &[u8; 32],
) -> Result<Group, GroupError> {
    issue_update_with(
        root,
        group_id,
        UpdateKind::Rekey,
        static_private,
        Some(particle_id),
    )
}

fn issue_update_with(
    root: &Path,
    group_id: &str,
    kind: UpdateKind,
    static_private: &[u8; 32],
    unrevoke: Option<&str>,
) -> Result<Group, GroupError> {
    let Some((self_id, saved_private)) = identity::read_saved(root)
        .map_err(|error| GroupError::malformed(root, error.to_string()))?
    else {
        return Err(GroupError::MissingIdentity(root.to_owned()));
    };
    if &saved_private != static_private {
        return Err(GroupError::InvalidUpdate(
            "signing identity does not match the saved identity".into(),
        ));
    }
    let _lock = lock_groups(root)?;
    cleanup_transaction_dirs(&groups_dir(root))?;
    let path = group_path(root, group_id);
    let mut group = read_group(&path)?;
    if !group.meta.is_admin(self_id.as_str())
        || group.meta.admin_sign_key != signing_public_key(static_private)
    {
        return Err(GroupError::InvalidUpdate(format!(
            "only group admin {} may issue updates",
            group.meta.admin
        )));
    }
    let issued_by = self_id.to_string();
    let mut new_key = group.key;
    let mut new_admin = group.meta.admin.clone();
    let mut new_admin_sign_key = group.meta.admin_sign_key.clone();
    let mut revoked = group.meta.revoked.clone();
    if let Some(particle_id) = unrevoke {
        revoked.retain(|revocation| revocation.particle_id != particle_id);
    }
    match &kind {
        UpdateKind::Remove { particle_id } => {
            if particle_id == &issued_by {
                return Err(GroupError::InvalidUpdate(
                    "the admin cannot remove itself".into(),
                ));
            }
            let member = group
                .members
                .iter()
                .find(|member| member.particle_id == *particle_id)
                .ok_or_else(|| GroupError::InvalidUpdate(format!("no member {particle_id}")))?;
            let revocation = Revocation {
                particle_id: member.particle_id.clone(),
                static_key: member.static_key.clone(),
            };
            if !revoked.iter().any(|existing| existing == &revocation) {
                revoked.push(revocation);
            }
            group
                .members
                .retain(|member| member.particle_id != *particle_id);
            rand::rngs::OsRng.fill_bytes(&mut new_key);
        }
        UpdateKind::Rekey => {
            if unrevoke.is_none() {
                rand::rngs::OsRng.fill_bytes(&mut new_key);
            }
        }
        UpdateKind::AdminHandoff { to } => {
            if to == &issued_by {
                return Err(GroupError::InvalidUpdate(
                    "the group is already administered by this particle".into(),
                ));
            }
            let member = group
                .members
                .iter()
                .find(|member| member.particle_id == *to)
                .ok_or_else(|| GroupError::InvalidUpdate(format!("no member {to}")))?;
            new_admin = member.particle_id.clone();
            new_admin_sign_key = member.sign_key.clone();
        }
    }
    let epoch = group
        .meta
        .epoch
        .checked_add(1)
        .ok_or_else(|| GroupError::InvalidUpdate("group epoch overflow".into()))?;
    revoked.sort_by(|left, right| left.particle_id.cmp(&right.particle_id));
    let mut update = GroupUpdate {
        group_id: group.id.clone(),
        epoch,
        key_hex: hex::encode(new_key),
        admin: new_admin.clone(),
        admin_sign_key: new_admin_sign_key.clone(),
        revoked: revoked.clone(),
        kind,
        issued_by,
        issued_at: timestamp(),
        signature: String::new(),
    };
    let message = update_signing_bytes(&update)?;
    update.signature = hex::encode(signing_key(static_private).sign(&message).to_bytes());
    group.retained_keys.insert(group.meta.epoch, group.key);
    trim_oldest(&mut group.retained_keys);
    group.key = new_key;
    group.meta.epoch = epoch;
    group.meta.admin = new_admin;
    group.meta.admin_sign_key = new_admin_sign_key;
    group.meta.revoked = revoked;
    group.updates.push(update);
    if group.updates.len() > RETAINED_LIMIT {
        group.updates.drain(..group.updates.len() - RETAINED_LIMIT);
    }
    write_group(root, &group)?;
    Ok(group)
}

pub fn apply_updates(
    root: &Path,
    group_id: &str,
    updates: &[GroupUpdate],
    _via: Option<&Member>,
) -> Result<ApplyResult, GroupError> {
    if !is_group_id(group_id) {
        return Err(GroupError::NotFound(group_id.to_owned()));
    }
    let Some((self_id, _)) = identity::read_saved(root)
        .map_err(|error| GroupError::malformed(root, error.to_string()))?
    else {
        return Err(GroupError::MissingIdentity(root.to_owned()));
    };
    let _lock = lock_groups(root)?;
    cleanup_transaction_dirs(&groups_dir(root))?;
    let path = group_path(root, group_id);
    let mut group = read_group(&path)?;
    let mut ordered = updates.to_vec();
    ordered.sort_by_key(|update| update.epoch);
    for update in ordered {
        if update.epoch <= group.meta.epoch {
            continue;
        }
        validate_update(&group, &update)?;
        let new_key = decode_key(&update.key_hex, &path.join("updates.json"))?;
        group.retained_keys.insert(group.meta.epoch, group.key);
        trim_oldest(&mut group.retained_keys);
        group.key = new_key;
        group.meta.epoch = update.epoch;
        group.meta.admin = update.admin.clone();
        group.meta.admin_sign_key = update.admin_sign_key.clone();
        group.meta.revoked = update.revoked.clone();
        if let UpdateKind::Remove { particle_id } = &update.kind {
            group
                .members
                .retain(|member| member.particle_id != *particle_id);
        }
        group.members.retain(|member| {
            !group
                .meta
                .revoked
                .iter()
                .any(|revocation| revocation.particle_id == member.particle_id)
        });
        group.updates.push(update);
        if group.updates.len() > RETAINED_LIMIT {
            group.updates.drain(..group.updates.len() - RETAINED_LIMIT);
        }
        let self_revoked = group
            .meta
            .revoked
            .iter()
            .any(|revocation| revocation.particle_id == self_id.as_str());
        if self_revoked {
            fs::remove_dir_all(&path).map_err(|error| GroupError::io(&path, error))?;
            tracing::info!("removed from group {} by its admin", group.meta.name);
            return Ok(ApplyResult {
                epoch: group.meta.epoch,
                removed: true,
            });
        }
        write_group(root, &group)?;
    }
    Ok(ApplyResult {
        epoch: group.meta.epoch,
        removed: false,
    })
}

fn validate_update(group: &Group, update: &GroupUpdate) -> Result<(), GroupError> {
    if update.group_id != group.id {
        return Err(GroupError::InvalidUpdate("group ID mismatch".into()));
    }
    if update.epoch != group.meta.epoch.saturating_add(1) {
        return Err(GroupError::InvalidUpdate(format!(
            "expected epoch {}, received {}",
            group.meta.epoch.saturating_add(1),
            update.epoch
        )));
    }
    if update.issued_by != group.meta.admin {
        return Err(GroupError::InvalidUpdate(
            "update issuer is not the current admin".into(),
        ));
    }
    if update.admin != group.meta.admin {
        let member = group
            .members
            .iter()
            .find(|member| member.particle_id == update.admin)
            .ok_or_else(|| GroupError::InvalidUpdate("new admin is not a current member".into()))?;
        if update.admin_sign_key != member.sign_key {
            return Err(GroupError::InvalidUpdate(
                "new admin signing key does not match its member record".into(),
            ));
        }
    } else if update.admin_sign_key != group.meta.admin_sign_key {
        return Err(GroupError::InvalidUpdate(
            "admin signing key changed without a handoff".into(),
        ));
    }
    let verifying_key_bytes = hex::decode(&group.meta.admin_sign_key)
        .map_err(|error| GroupError::InvalidUpdate(error.to_string()))?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| GroupError::InvalidUpdate("invalid admin signing key length".into()))?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|error| GroupError::InvalidUpdate(error.to_string()))?;
    let signature_bytes = hex::decode(&update.signature)
        .map_err(|error| GroupError::InvalidUpdate(error.to_string()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|error| GroupError::InvalidUpdate(error.to_string()))?;
    verifying_key
        .verify(&update_signing_bytes(update)?, &signature)
        .map_err(|error| GroupError::InvalidUpdate(error.to_string()))?;
    decode_key(&update.key_hex, Path::new("updates.json"))?;
    Ok(())
}

fn update_signing_bytes(update: &GroupUpdate) -> Result<Vec<u8>, GroupError> {
    let mut unsigned = update.clone();
    unsigned.signature.clear();
    let bytes = serde_json::to_vec(&unsigned)
        .map_err(|error| GroupError::InvalidUpdate(error.to_string()))?;
    let mut message = UPDATE_DOMAIN.to_vec();
    message.extend_from_slice(&bytes);
    Ok(message)
}

fn decode_key(value: &str, path: &Path) -> Result<[u8; 32], GroupError> {
    let decoded =
        hex::decode(value).map_err(|error| GroupError::malformed(path, error.to_string()))?;
    decoded
        .try_into()
        .map_err(|_| GroupError::malformed(path, "expected a 32-byte key"))
}

fn trim_oldest<K: Ord, V>(map: &mut BTreeMap<K, V>) {
    while map.len() > RETAINED_LIMIT {
        map.pop_first();
    }
}

pub fn updates_since(group: &Group, epoch: u32) -> Option<Vec<GroupUpdate>> {
    if epoch >= group.meta.epoch {
        return Some(Vec::new());
    }
    let updates = group
        .updates
        .iter()
        .filter(|update| update.epoch > epoch)
        .cloned()
        .collect::<Vec<_>>();
    let mut expected = epoch.checked_add(1)?;
    for update in &updates {
        if update.epoch != expected {
            return None;
        }
        expected = expected.checked_add(1)?;
    }
    (expected == group.meta.epoch.checked_add(1)?).then_some(updates)
}

pub fn write_status(root: &Path, group_id: &str, status: &GroupStatus) -> Result<(), GroupError> {
    if !is_group_id(group_id) {
        return Err(GroupError::NotFound(group_id.to_owned()));
    }
    let directory = groups_dir(root).join(".status");
    private_fs::create_private_directory(&directory).map_err(GroupError::private_fs)?;
    let path = directory.join(format!("{group_id}.json"));
    let bytes = serde_json::to_vec_pretty(status)
        .map_err(|error| GroupError::malformed(&path, error.to_string()))?;
    private_fs::atomic_write(&path, &bytes).map_err(GroupError::private_fs)
}

pub fn read_status(root: &Path, group_id: &str) -> Result<Option<GroupStatus>, GroupError> {
    if !is_group_id(group_id) {
        return Ok(None);
    }
    let path = groups_dir(root)
        .join(".status")
        .join(format!("{group_id}.json"));
    let Some(bytes) = private_fs::read_regular_file(&path).map_err(GroupError::private_fs)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| GroupError::malformed(&path, error.to_string()))
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
    cleanup_transaction_dirs(&directory)?;
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(GroupError::io(&directory, error)),
    };
    let mut groups = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| GroupError::io(&directory, error))?;
        let path = entry.path();
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| GroupError::io(&path, error))?;
        if !metadata.file_type().is_dir() {
            return Err(GroupError::malformed(&path, "expected a group directory"));
        }
        match read_group(&path) {
            Ok(group) => groups.push(group),
            Err(GroupError::Outdated { name }) => {
                groups.push(read_outdated_group(&path, name)?);
            }
            Err(error) => return Err(error),
        }
    }
    groups.sort_by(|left, right| {
        left.meta
            .name
            .cmp(&right.meta.name)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(groups)
}

fn read_outdated_group(path: &Path, name: String) -> Result<Group, GroupError> {
    let key_path = path.join("key");
    let key_bytes = private_fs::read_regular_file(&key_path)
        .map_err(GroupError::private_fs)?
        .ok_or_else(|| GroupError::malformed(&key_path, "missing key"))?;
    let key_text = std::str::from_utf8(&key_bytes)
        .map_err(|error| GroupError::malformed(&key_path, error.to_string()))?
        .trim_end_matches(['\r', '\n']);
    let decoded = hex::decode(key_text)
        .map_err(|error| GroupError::malformed(&key_path, error.to_string()))?;
    let key = decoded
        .try_into()
        .map_err(|_| GroupError::malformed(&key_path, "expected a 32-byte key"))?;
    let id = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|id| is_group_id(id))
        .ok_or_else(|| GroupError::malformed(path, "invalid group directory name"))?;
    Ok(Group {
        id: id.to_owned(),
        key,
        meta: GroupMeta {
            version: 1,
            name,
            created_at: String::new(),
            epoch: 0,
            admin: String::new(),
            admin_sign_key: String::new(),
            revoked: Vec::new(),
            leaving: false,
        },
        members: Vec::new(),
        retained_keys: BTreeMap::new(),
        updates: Vec::new(),
        outdated: true,
    })
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
    let meta_value: serde_json::Value = serde_json::from_slice(&meta_bytes)
        .map_err(|error| GroupError::malformed(&meta_path, error.to_string()))?;
    if meta_value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        == Some(1)
    {
        let name = meta_value
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| GroupError::malformed(&meta_path, "missing group name"))?;
        return Err(GroupError::Outdated {
            name: name.to_owned(),
        });
    }
    let meta: GroupMeta = serde_json::from_value(meta_value)
        .map_err(|error| GroupError::malformed(&meta_path, error.to_string()))?;
    validate_meta(&meta, &meta_path)?;

    let members_path = path.join("members.json");
    let members_bytes = private_fs::read_regular_file(&members_path)
        .map_err(GroupError::private_fs)?
        .ok_or_else(|| GroupError::malformed(&members_path, "missing member list"))?;
    let members: Vec<Member> = serde_json::from_slice(&members_bytes)
        .map_err(|error| GroupError::malformed(&members_path, error.to_string()))?;
    validate_members(&members, &members_path)?;
    validate_admin_member(&meta, &members, &members_path)?;
    if members.is_empty() {
        return Err(GroupError::malformed(&members_path, "group has no members"));
    }

    let id = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| GroupError::malformed(path, "invalid group directory name"))?;
    if !is_group_id(id) {
        return Err(GroupError::malformed(
            path,
            "directory name is not an eight-character group ID",
        ));
    }
    let retained_path = path.join("keys.json");
    let retained_bytes = private_fs::read_regular_file(&retained_path)
        .map_err(GroupError::private_fs)?
        .ok_or_else(|| GroupError::malformed(&retained_path, "missing retained key list"))?;
    let retained_hex: BTreeMap<u32, String> = serde_json::from_slice(&retained_bytes)
        .map_err(|error| GroupError::malformed(&retained_path, error.to_string()))?;
    let mut retained_keys = BTreeMap::new();
    for (epoch, key_hex) in retained_hex {
        let bytes = hex::decode(&key_hex)
            .map_err(|error| GroupError::malformed(&retained_path, error.to_string()))?;
        let retained_key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| GroupError::malformed(&retained_path, "expected 32-byte keys"))?;
        if epoch >= meta.epoch {
            return Err(GroupError::malformed(
                &retained_path,
                "retained key epoch must be older than the current epoch",
            ));
        }
        retained_keys.insert(epoch, retained_key);
    }
    if retained_keys.len() > RETAINED_LIMIT {
        return Err(GroupError::malformed(
            &retained_path,
            "too many retained group keys",
        ));
    }

    let updates_path = path.join("updates.json");
    let updates_bytes = private_fs::read_regular_file(&updates_path)
        .map_err(GroupError::private_fs)?
        .ok_or_else(|| GroupError::malformed(&updates_path, "missing update log"))?;
    let updates: Vec<GroupUpdate> = serde_json::from_slice(&updates_bytes)
        .map_err(|error| GroupError::malformed(&updates_path, error.to_string()))?;
    if updates.len() > RETAINED_LIMIT {
        return Err(GroupError::malformed(
            &updates_path,
            "too many retained group updates",
        ));
    }
    Ok(Group {
        id: id.to_owned(),
        key,
        meta,
        members,
        retained_keys,
        updates,
        outdated: false,
    })
}

fn write_group(root: &Path, group: &Group) -> Result<(), GroupError> {
    let path = group_path(root, &group.id);
    if group.outdated {
        return Err(GroupError::Outdated {
            name: group.meta.name.clone(),
        });
    }
    if !is_group_id(&group.id) {
        return Err(GroupError::malformed(
            &path,
            "directory name is not an eight-character group ID",
        ));
    }
    validate_meta(&group.meta, &path.join("meta.json"))?;
    validate_members(&group.members, &path.join("members.json"))?;
    validate_admin_member(&group.meta, &group.members, &path.join("members.json"))?;
    if group.members.is_empty() {
        return Err(GroupError::malformed(
            &path.join("members.json"),
            "group has no members",
        ));
    }
    let key = format!("{}\n", hex::encode(group.key));
    let meta = serde_json::to_vec_pretty(&group.meta)
        .map_err(|error| GroupError::malformed(&path.join("meta.json"), error.to_string()))?;
    let members = serde_json::to_vec_pretty(&group.members)
        .map_err(|error| GroupError::malformed(&path.join("members.json"), error.to_string()))?;
    let retained = group
        .retained_keys
        .iter()
        .map(|(epoch, key)| (*epoch, hex::encode(key)))
        .collect::<BTreeMap<_, _>>();
    let retained = serde_json::to_vec_pretty(&retained)
        .map_err(|error| GroupError::malformed(&path.join("keys.json"), error.to_string()))?;
    let updates = serde_json::to_vec_pretty(&group.updates)
        .map_err(|error| GroupError::malformed(&path.join("updates.json"), error.to_string()))?;

    let replace_existing = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            read_group(&path)?;
            true
        }
        Ok(_) => return Err(GroupError::UnsafePath(path)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(GroupError::io(&path, error)),
    };
    let staging = create_staging_directory(root, &group.id)?;
    let write_result = (|| {
        private_fs::atomic_write(&staging.join("key"), key.as_bytes())
            .map_err(GroupError::private_fs)?;
        private_fs::atomic_write(&staging.join("meta.json"), &meta)
            .map_err(GroupError::private_fs)?;
        private_fs::atomic_write(&staging.join("members.json"), &members)
            .map_err(GroupError::private_fs)?;
        private_fs::atomic_write(&staging.join("keys.json"), &retained)
            .map_err(GroupError::private_fs)?;
        private_fs::atomic_write(&staging.join("updates.json"), &updates)
            .map_err(GroupError::private_fs)?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = remove_transaction_entry(&staging);
        return Err(error);
    }

    if replace_existing {
        let old = unused_transaction_path(root, "old", &group.id)?;
        fs::rename(&path, &old).map_err(|error| GroupError::io(&path, error))?;
        if let Err(error) = fs::rename(&staging, &path) {
            let restore = fs::rename(&old, &path);
            let _ = remove_transaction_entry(&staging);
            if let Err(restore_error) = restore {
                return Err(GroupError::malformed(
                    &path,
                    format!("replacement failed ({error}); restoring the old group failed ({restore_error})"),
                ));
            }
            return Err(GroupError::io(&path, error));
        }
        remove_transaction_entry(&old)?;
    } else if let Err(error) = fs::rename(&staging, &path) {
        let _ = remove_transaction_entry(&staging);
        return Err(GroupError::io(&path, error));
    }
    Ok(())
}

fn create_staging_directory(root: &Path, id: &str) -> Result<PathBuf, GroupError> {
    for _ in 0..16 {
        let path = random_transaction_path(root, "staging", id);
        match private_fs::create_private_directory_exclusive(&path)
            .map_err(GroupError::private_fs)?
        {
            true => return Ok(path),
            false => continue,
        }
    }
    let path = groups_dir(root);
    Err(GroupError::io(
        &path,
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique group staging directory",
        ),
    ))
}

fn unused_transaction_path(root: &Path, kind: &str, id: &str) -> Result<PathBuf, GroupError> {
    for _ in 0..16 {
        let path = random_transaction_path(root, kind, id);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(path),
            Ok(_) => continue,
            Err(error) => return Err(GroupError::io(&path, error)),
        }
    }
    let path = groups_dir(root);
    Err(GroupError::io(
        &path,
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique group transaction path",
        ),
    ))
}

fn random_transaction_path(root: &Path, kind: &str, id: &str) -> PathBuf {
    let mut suffix = [0_u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    groups_dir(root).join(format!(".{kind}-{id}-{}", hex::encode(suffix)))
}

fn cleanup_transaction_dirs(directory: &Path) -> Result<(), GroupError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(GroupError::io(directory, error)),
    };
    let mut candidates = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| GroupError::io(directory, error))?;
        candidates.push((entry.file_name(), entry.path()));
    }
    let mut staging = Vec::new();
    let mut old: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for (entry_name, path) in candidates {
        let Some(name) = entry_name.to_str() else {
            continue;
        };
        if name.starts_with(".staging-") {
            staging.push(path);
        } else if let Some(remainder) = name.strip_prefix(".old-") {
            if let Some((id, suffix)) = remainder.split_once('-') {
                if is_group_id(id) && !suffix.is_empty() {
                    old.entry(id.to_owned()).or_default().push(path);
                } else {
                    remove_transaction_entry(&path)?;
                }
            } else {
                remove_transaction_entry(&path)?;
            }
        }
    }
    for path in staging {
        remove_transaction_entry(&path)?;
    }
    for (id, mut old_paths) in old {
        old_paths.sort();
        let target = directory.join(&id);
        match fs::symlink_metadata(&target) {
            Ok(_) => {
                for path in old_paths {
                    remove_transaction_entry(&path)?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let restore = old_paths.remove(0);
                fs::rename(&restore, &target).map_err(|error| GroupError::io(&target, error))?;
                for path in old_paths {
                    remove_transaction_entry(&path)?;
                }
            }
            Err(error) => return Err(GroupError::io(&target, error)),
        }
    }
    Ok(())
}

fn remove_transaction_entry(path: &Path) -> Result<(), GroupError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            fs::remove_dir_all(path).map_err(|error| GroupError::io(path, error))
        }
        Ok(_) => fs::remove_file(path).map_err(|error| GroupError::io(path, error)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(GroupError::io(path, error)),
    }
}

fn is_group_id(id: &str) -> bool {
    id.len() == 8
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    ParticleId::parse(meta.admin.clone())
        .map_err(|error| GroupError::malformed(path, error.to_string()))?;
    validate_hex_key(&meta.admin_sign_key, path, "admin signing key")?;
    for revocation in &meta.revoked {
        ParticleId::parse(revocation.particle_id.clone())
            .map_err(|error| GroupError::malformed(path, error.to_string()))?;
        validate_hex_key(&revocation.static_key, path, "revoked static key")?;
    }
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

fn validate_admin_member(
    meta: &GroupMeta,
    members: &[Member],
    path: &Path,
) -> Result<(), GroupError> {
    let admin = members
        .iter()
        .find(|member| member.particle_id == meta.admin)
        .ok_or_else(|| GroupError::malformed(path, "admin is not a current group member"))?;
    if admin.sign_key != meta.admin_sign_key {
        return Err(GroupError::malformed(
            path,
            "admin signing key does not match its member record",
        ));
    }
    Ok(())
}

fn validate_member(member: &Member, path: &Path) -> Result<(), GroupError> {
    for id in [&member.particle_id, &member.added_by] {
        ParticleId::parse(id.clone())
            .map_err(|error| GroupError::malformed(path, error.to_string()))?;
    }
    validate_hex_key(&member.static_key, path, "member static key")?;
    validate_hex_key(&member.sign_key, path, "member signing key")?;
    chrono::DateTime::parse_from_rfc3339(&member.added_at)
        .map_err(|error| GroupError::malformed(path, error.to_string()))?;
    Ok(())
}

fn validate_hex_key(value: &str, path: &Path, label: &str) -> Result<(), GroupError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GroupError::malformed(
            path,
            format!("{label} must be 64 lowercase hexadecimal characters"),
        ));
    }
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
            sign_key: signing_public_key(&identity.static_private),
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
            sign_key: signing_public_key(&[index; 32]),
            added_by: id,
            added_at: timestamp(),
        }
    }

    fn group_meta(name: &str, admin: &Member) -> GroupMeta {
        GroupMeta {
            version: GROUP_VERSION,
            name: name.into(),
            created_at: timestamp(),
            epoch: 0,
            admin: admin.particle_id.clone(),
            admin_sign_key: admin.sign_key.clone(),
            revoked: Vec::new(),
            leaving: false,
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
        let self_member = &group.members[0];
        assert_eq!(group.meta.epoch, 0);
        assert_eq!(group.meta.admin, self_member.particle_id);
        assert_eq!(group.meta.admin_sign_key, self_member.sign_key);
        assert_eq!(
            group.meta.admin_sign_key,
            signing_public_key(&identity::read_saved(root.path()).unwrap().unwrap().1)
        );
        assert_eq!(list(root.path()).unwrap(), vec![group.clone()]);
        assert_eq!(find(root.path(), "work").unwrap(), Some(group.clone()));
        assert_eq!(find(root.path(), &group.id).unwrap(), Some(group));
        assert_eq!(find(root.path(), "missing").unwrap(), None);
    }

    #[test]
    fn version_one_group_is_reported_as_outdated() {
        let root = tempdir().unwrap();
        let path = root.path().join("groups").join("deadbeef");
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("key"), format!("{}\n", hex::encode([0x44; 32]))).unwrap();
        fs::write(
            path.join("meta.json"),
            br#"{"version":1,"name":"legacy","created_at":"2026-01-01T00:00:00Z","role":"admin"}"#,
        )
        .unwrap();
        assert!(matches!(
            read_group(&path),
            Err(GroupError::Outdated { name }) if name == "legacy"
        ));
        let listed = list(root.path()).unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].outdated);
        assert_eq!(listed[0].meta.name, "legacy");
    }

    #[test]
    fn remove_rotates_key_records_revocation_and_retains_the_update() {
        let admin_root = tempdir().unwrap();
        let admin = saved_identity(admin_root.path());
        let group = insert(
            admin_root.path(),
            [0x41; 32],
            group_meta("work", &admin),
            vec![admin.clone(), member(1)],
        )
        .unwrap();
        let updated = issue_update(
            admin_root.path(),
            &group.id,
            UpdateKind::Remove {
                particle_id: member(1).particle_id,
            },
            &identity::read_saved(admin_root.path()).unwrap().unwrap().1,
        )
        .unwrap();
        assert_eq!(updated.meta.epoch, 1);
        assert_ne!(updated.key, group.key);
        assert_eq!(updated.members.len(), 1);
        assert_eq!(updated.meta.revoked.len(), 1);
        assert_eq!(updated.retained_keys.get(&0), Some(&group.key));
        assert_eq!(updated.updates.len(), 1);
        let stored = find(admin_root.path(), &group.id).unwrap().unwrap();
        assert_eq!(stored, updated);
    }

    #[test]
    fn re_invitation_unrevokes_without_rotating_the_key() {
        let root = tempdir().unwrap();
        let admin = saved_identity(root.path());
        let target = member(3);
        let group = insert(
            root.path(),
            [0x47; 32],
            group_meta("work", &admin),
            vec![admin.clone(), target.clone()],
        )
        .unwrap();
        let private = identity::read_saved(root.path()).unwrap().unwrap().1;
        let removed = issue_update(
            root.path(),
            &group.id,
            UpdateKind::Remove {
                particle_id: target.particle_id.clone(),
            },
            &private,
        )
        .unwrap();
        let restored =
            issue_unrevoke_update(root.path(), &group.id, &target.particle_id, &private).unwrap();
        assert_eq!(restored.meta.epoch, removed.meta.epoch + 1);
        assert_eq!(restored.key, removed.key);
        assert!(restored.meta.revoked.is_empty());
    }

    #[test]
    fn valid_update_chain_applies_and_replays_are_ignored() {
        let admin_root = tempdir().unwrap();
        let peer_root = tempdir().unwrap();
        let admin = saved_identity(admin_root.path());
        let peer = saved_identity(peer_root.path());
        let group = insert(
            admin_root.path(),
            [0x42; 32],
            group_meta("work", &admin),
            vec![admin.clone(), peer.clone()],
        )
        .unwrap();
        insert_with_id(
            peer_root.path(),
            group.id.clone(),
            group.key,
            group.meta.clone(),
            group.members.clone(),
        )
        .unwrap();
        let private = identity::read_saved(admin_root.path()).unwrap().unwrap().1;
        let first =
            issue_update(admin_root.path(), &group.id, UpdateKind::Rekey, &private).unwrap();
        let second =
            issue_update(admin_root.path(), &group.id, UpdateKind::Rekey, &private).unwrap();
        let updates = vec![first.updates[0].clone(), second.updates[1].clone()];
        let applied = apply_updates(peer_root.path(), &group.id, &updates, Some(&admin)).unwrap();
        assert_eq!(applied.epoch, 2);
        assert!(!applied.removed);
        let stored = find(peer_root.path(), &group.id).unwrap().unwrap();
        assert_eq!(stored.key, second.key);
        assert_eq!(stored.updates.len(), 2);
        assert_eq!(
            apply_updates(peer_root.path(), &group.id, &updates, None)
                .unwrap()
                .epoch,
            2
        );
    }

    #[test]
    fn update_chain_rejects_invalid_signature_issuer_epoch_and_group() {
        let admin_root = tempdir().unwrap();
        let peer_root = tempdir().unwrap();
        let admin = saved_identity(admin_root.path());
        let peer = saved_identity(peer_root.path());
        let group = insert(
            admin_root.path(),
            [0x43; 32],
            group_meta("work", &admin),
            vec![admin.clone(), peer],
        )
        .unwrap();
        let private = identity::read_saved(admin_root.path()).unwrap().unwrap().1;
        let update = issue_update(admin_root.path(), &group.id, UpdateKind::Rekey, &private)
            .unwrap()
            .updates[0]
            .clone();
        let reject = |mutated: GroupUpdate| {
            let root = tempdir().unwrap();
            let self_member = saved_identity(root.path());
            insert_with_id(
                root.path(),
                group.id.clone(),
                group.key,
                group.meta.clone(),
                vec![admin.clone(), self_member],
            )
            .unwrap();
            assert!(apply_updates(root.path(), &group.id, &[mutated], None).is_err());
        };
        let mut bad_signature = update.clone();
        bad_signature.signature = "00".repeat(64);
        reject(bad_signature);
        let mut wrong_issuer = update.clone();
        wrong_issuer.issued_by = member(7).particle_id;
        reject(wrong_issuer);
        let mut gap = update.clone();
        gap.epoch = 2;
        reject(gap);
        let mut wrong_group = update;
        wrong_group.group_id = "deadbeef".into();
        reject(wrong_group);
    }

    #[test]
    fn self_revocation_deletes_the_group_and_handoff_changes_the_signer() {
        let admin_root = tempdir().unwrap();
        let peer_root = tempdir().unwrap();
        let admin = saved_identity(admin_root.path());
        let peer = saved_identity(peer_root.path());
        let group = insert(
            admin_root.path(),
            [0x45; 32],
            group_meta("work", &admin),
            vec![admin.clone(), peer.clone()],
        )
        .unwrap();
        insert_with_id(
            peer_root.path(),
            group.id.clone(),
            group.key,
            group.meta.clone(),
            group.members.clone(),
        )
        .unwrap();
        let admin_private = identity::read_saved(admin_root.path()).unwrap().unwrap().1;
        let handoff = issue_update(
            admin_root.path(),
            &group.id,
            UpdateKind::AdminHandoff {
                to: peer.particle_id.clone(),
            },
            &admin_private,
        )
        .unwrap();
        apply_updates(peer_root.path(), &group.id, &handoff.updates, Some(&admin)).unwrap();
        let peer_private = identity::read_saved(peer_root.path()).unwrap().unwrap().1;
        let peer_update = issue_update(
            peer_root.path(),
            &group.id,
            UpdateKind::Rekey,
            &peer_private,
        )
        .unwrap();
        assert_eq!(peer_update.meta.admin, peer.particle_id);
        let mut old_admin_update = peer_update.updates[1].clone();
        old_admin_update.epoch += 1;
        old_admin_update.issued_by = admin.particle_id.clone();
        old_admin_update.signature = hex::encode(
            signing_key(&admin_private)
                .sign(&update_signing_bytes(&old_admin_update).unwrap())
                .to_bytes(),
        );
        assert!(apply_updates(
            peer_root.path(),
            &group.id,
            &[old_admin_update],
            Some(&admin)
        )
        .is_err());

        let revoke_admin = issue_update(
            peer_root.path(),
            &group.id,
            UpdateKind::Remove {
                particle_id: admin.particle_id.clone(),
            },
            &peer_private,
        )
        .unwrap();
        let revoked = apply_updates(
            admin_root.path(),
            &group.id,
            &revoke_admin.updates,
            Some(&peer),
        )
        .unwrap();
        assert!(revoked.removed);
        assert!(find(admin_root.path(), &group.id).unwrap().is_none());
    }

    #[test]
    fn retained_keys_and_updates_are_capped_at_sixteen() {
        let root = tempdir().unwrap();
        let admin = saved_identity(root.path());
        let group = insert(
            root.path(),
            [0x46; 32],
            group_meta("work", &admin),
            vec![admin],
        )
        .unwrap();
        let private = identity::read_saved(root.path()).unwrap().unwrap().1;
        for _ in 0..20 {
            issue_update(root.path(), &group.id, UpdateKind::Rekey, &private).unwrap();
        }
        let stored = find(root.path(), &group.id).unwrap().unwrap();
        assert_eq!(stored.retained_keys.len(), 16);
        assert_eq!(stored.updates.len(), 16);
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

    #[test]
    fn create_retries_a_colliding_group_id_without_replacing_the_existing_group() {
        let root = tempdir().unwrap();
        let self_member = saved_identity(root.path());
        let existing_key = [0x21; 32];
        let existing = insert(
            root.path(),
            existing_key,
            group_meta("existing", &self_member),
            vec![self_member.clone()],
        )
        .unwrap();
        let replacement_key = (0_u8..=u8::MAX)
            .map(|byte| [byte; 32])
            .find(|key| group_id(key) != existing.id)
            .unwrap();
        let mut attempts = 0;

        let created = create_with_key_source(root.path(), "new", self_member.clone(), |key| {
            attempts += 1;
            *key = if attempts == 1 {
                existing_key
            } else {
                replacement_key
            };
        })
        .unwrap();

        assert_eq!(attempts, 2);
        assert_ne!(created.id, existing.id);
        assert_eq!(created.key, replacement_key);
        assert_eq!(find(root.path(), &existing.id).unwrap(), Some(existing));

        let mut attempts = 0;
        assert!(matches!(
            create_with_key_source(root.path(), "collision", self_member, |key| {
                attempts += 1;
                *key = existing_key;
            }),
            Err(GroupError::IdCollision)
        ));
        assert_eq!(attempts, 16);
        assert_eq!(
            find(root.path(), "existing").unwrap().unwrap().key,
            existing_key
        );
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
    fn stable_group_id_does_not_change_with_the_current_key() {
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

        let mut groups = list(root.path()).unwrap();
        let renamed = groups.remove(0);
        assert_eq!(renamed.id, renamed_id);
        assert_eq!(renamed.key, group.key);
    }

    #[test]
    fn list_ignores_and_cleans_leftover_staging_directories() {
        let root = tempdir().unwrap();
        let group = create_named(root.path(), "work");
        let staging = root
            .path()
            .join("groups")
            .join(format!(".staging-{}-deadbeef", group.id));
        fs::create_dir(&staging).unwrap();

        assert_eq!(list(root.path()).unwrap(), vec![group]);
        assert!(!staging.exists());
    }

    #[test]
    fn list_restores_a_group_after_crash_between_directory_renames() {
        let root = tempdir().unwrap();
        let group = create_named(root.path(), "work");
        let path = root.path().join("groups").join(&group.id);
        let old = root
            .path()
            .join("groups")
            .join(format!(".old-{}-x", group.id));
        fs::rename(&path, &old).unwrap();

        assert_eq!(list(root.path()).unwrap(), vec![group.clone()]);
        assert!(path.is_dir());
        assert!(!old.exists());
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
