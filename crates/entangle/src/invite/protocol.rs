use crate::{
    groups::{self, Group, GroupError, GroupMeta, Member, Role},
    identity,
    invite::code::InviteCode,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use chrono::{SecondsFormat, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{watch, Mutex, Semaphore},
    time::{timeout, Instant},
};

const MAX_FRAME_BYTES: usize = 64 * 1024;
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const SPAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SESSIONS: usize = 8;
const DEFAULT_TTL: Duration = Duration::from_secs(10 * 60);
const ID_INVITER: &[u8] = b"entangle-invite-inviter";
const ID_JOINER: &[u8] = b"entangle-invite-joiner";
const CONFIRM_JOINER: &[u8] = b"entangle-invite-confirm-joiner";
const CONFIRM_INVITER: &[u8] = b"entangle-invite-confirm-inviter";
const ENCRYPT_JOINER: &[u8] = b"entangle-invite-enc-joiner";
const ENCRYPT_INVITER: &[u8] = b"entangle-invite-enc-inviter";
const FRAME_SPAKE: u8 = 1;
const FRAME_CONFIRM: u8 = 2;

#[derive(Debug, Error)]
pub enum InviteError {
    #[error(transparent)]
    Group(#[from] GroupError),
    #[error("invite I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("invite frame exceeds {MAX_FRAME_BYTES} bytes")]
    Oversize,
    #[error("invalid invite frame")]
    InvalidFrame,
    #[error("invite session timed out")]
    Timeout,
    #[error("invite has reached its concurrent session limit")]
    Busy,
    #[error("that code was wrong")]
    WrongCode,
    #[error("the join did not complete")]
    Incomplete,
    #[error("invite is closed")]
    Closed,
    #[error("invite has no remaining capacity")]
    Full,
    #[error("invite count must be between 1 and 20")]
    InvalidCount,
    #[error("invalid invite message: {0}")]
    Message(String),
    #[error("the inviter declined this join: {reason}")]
    Declined {
        reason: String,
        group_name: Option<String>,
    },
    #[error("invite encryption failed")]
    Encryption,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InviteEnd {
    Complete,
    Expired,
    Cancelled,
    WrongCode,
    Failed,
}

struct Capacity {
    complete: u8,
    pending: u8,
}

/// Shared lifetime and capacity state for one advertised invitation.
pub struct InviteState {
    count: u8,
    expires_at: Instant,
    capacity: Mutex<Capacity>,
    terminal: watch::Sender<Option<InviteEnd>>,
}

impl InviteState {
    pub fn new(count: u8, ttl: Duration) -> Result<Self, InviteError> {
        if !(1..=20).contains(&count) {
            return Err(InviteError::InvalidCount);
        }
        let (terminal, _) = watch::channel(None);
        Ok(Self {
            count,
            expires_at: Instant::now() + ttl,
            capacity: Mutex::new(Capacity {
                complete: 0,
                pending: 0,
            }),
            terminal,
        })
    }

    pub fn default_ttl() -> Duration {
        DEFAULT_TTL
    }

    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    pub fn subscribe(&self) -> watch::Receiver<Option<InviteEnd>> {
        self.terminal.subscribe()
    }

    pub fn end(&self, reason: InviteEnd) {
        if self.terminal.borrow().is_none() {
            self.terminal.send_replace(Some(reason));
        }
    }

    pub fn end_if_expired(&self) {
        if Instant::now() >= self.expires_at {
            self.end(InviteEnd::Expired);
        }
    }

    pub async fn terminal(&self) -> Option<InviteEnd> {
        self.end_if_expired();
        *self.terminal.borrow()
    }

    pub async fn counts(&self) -> (u8, u8) {
        let capacity = self.capacity.lock().await;
        (capacity.complete, self.count)
    }

    async fn reserve(&self) -> Result<(), InviteError> {
        self.end_if_expired();
        let mut capacity = self.capacity.lock().await;
        if capacity.complete.saturating_add(capacity.pending) >= self.count {
            return Err(InviteError::Full);
        }
        capacity.pending += 1;
        Ok(())
    }

    async fn release(&self) {
        let mut capacity = self.capacity.lock().await;
        capacity.pending = capacity.pending.saturating_sub(1);
    }

    async fn completed(&self) {
        let mut capacity = self.capacity.lock().await;
        capacity.pending = capacity.pending.saturating_sub(1);
        capacity.complete += 1;
        let finished = capacity.complete >= self.count;
        drop(capacity);
        if finished {
            self.end(InviteEnd::Complete);
        }
    }
}

/// An inviter-side protocol endpoint backed by the persistent group store.
#[derive(Clone)]
pub struct InviteServer {
    root: PathBuf,
    group_id: String,
    inviter_id: String,
    inviter_name: String,
    code: InviteCode,
    state: std::sync::Arc<InviteState>,
    sessions: std::sync::Arc<Semaphore>,
}

impl InviteServer {
    pub fn new(
        root: impl Into<PathBuf>,
        group_id: String,
        inviter_name: String,
        code: InviteCode,
        count: u8,
        ttl: Duration,
    ) -> Result<Self, InviteError> {
        let root = root.into();
        let Some((id, _)) = identity::read_saved(&root).map_err(|error| GroupError::Malformed {
            path: root.clone(),
            reason: error.to_string(),
        })?
        else {
            return Err(GroupError::MissingIdentity(root).into());
        };
        groups::find(&root, &group_id)?.ok_or_else(|| GroupError::NotFound(group_id.clone()))?;
        Ok(Self {
            root,
            group_id,
            inviter_id: id.to_string(),
            inviter_name,
            code,
            state: std::sync::Arc::new(InviteState::new(count, ttl)?),
            sessions: std::sync::Arc::new(Semaphore::new(MAX_SESSIONS)),
        })
    }

    pub fn state(&self) -> &std::sync::Arc<InviteState> {
        &self.state
    }

    /// Serves one concurrent join attempt.
    pub async fn handle<S>(&self, stream: S) -> Result<Option<String>, InviteError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.handle_with_policy(stream, SESSION_TIMEOUT, SPAKE_TIMEOUT, true)
            .await
    }

    async fn handle_with_policy<S>(
        &self,
        mut stream: S,
        session_timeout: Duration,
        spake_timeout: Duration,
        send_committed: bool,
    ) -> Result<Option<String>, InviteError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let _permit = self
            .sessions
            .clone()
            .try_acquire_owned()
            .map_err(|_| InviteError::Busy)?;
        if self.state.terminal().await.is_some() {
            return Err(InviteError::Closed);
        }
        let mut joiner_message_received = false;
        let mut confirmed = false;
        let mut reserved = false;
        let result = timeout(
            session_timeout,
            self.handle_inner(
                &mut stream,
                &mut joiner_message_received,
                &mut confirmed,
                &mut reserved,
                spake_timeout,
                send_committed,
            ),
        )
        .await
        .map_err(|_| InviteError::Timeout)
        .and_then(|result| result);
        if reserved && result.is_err() {
            self.state.release().await;
        }
        if joiner_message_received && !confirmed && result.is_err() {
            self.state.end(match &result {
                Err(InviteError::WrongCode) => InviteEnd::WrongCode,
                _ => InviteEnd::Failed,
            });
        }
        result
    }

    async fn handle_inner<S>(
        &self,
        stream: &mut S,
        joiner_message_received: &mut bool,
        confirmed: &mut bool,
        reserved: &mut bool,
        spake_timeout: Duration,
        send_committed: bool,
    ) -> Result<Option<String>, InviteError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let password = self.password();
        let (spake, local_msg) = Spake2::<Ed25519Group>::start_a(
            &Password::new(password.as_bytes()),
            &Identity::new(ID_INVITER),
            &Identity::new(ID_JOINER),
        );
        write_tagged_frame(stream, FRAME_SPAKE, &local_msg).await?;
        let mut terminal = self.state.subscribe();
        let peer_msg = read_before_terminal_timeout(stream, &mut terminal, spake_timeout).await?;
        let peer_msg = tagged_body(&peer_msg, FRAME_SPAKE)?;
        *joiner_message_received = true;
        let shared = spake.finish(peer_msg).map_err(|_| InviteError::WrongCode)?;
        let keys = DerivedKeys::new(&shared);
        let got_confirmation = read_before_terminal(stream, &mut terminal).await?;
        let got_confirmation = tagged_body(&got_confirmation, FRAME_CONFIRM)?;
        if !bool::from(keys.confirm_joiner.ct_eq(got_confirmation)) {
            self.state.end(InviteEnd::WrongCode);
            return Err(InviteError::WrongCode);
        }
        *confirmed = true;
        write_tagged_frame(stream, FRAME_CONFIRM, &keys.confirm_inviter).await?;
        let mut sender = SecureJson::new(keys.enc_inviter);
        let mut receiver = SecureJson::new(keys.enc_joiner);
        let group = groups::find(&self.root, &self.group_id)?
            .ok_or_else(|| GroupError::NotFound(self.group_id.clone()))?;
        sender
            .send(
                stream,
                &Message::GroupInfo {
                    name: group.meta.name,
                    group_id: group.id,
                    inviter_name: self.inviter_name.clone(),
                },
            )
            .await?;
        let request = match receiver.receive::<_, Message>(stream).await? {
            Message::Decline { reason } => {
                return Err(InviteError::Declined {
                    reason: reason.as_str().to_owned(),
                    group_name: None,
                });
            }
            Message::JoinRequest {
                particle_id,
                name,
                static_key,
            } => Member {
                particle_id,
                name,
                static_key,
                added_by: self.inviter_id.clone(),
                added_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            },
            message => {
                return Err(InviteError::Message(format!(
                    "expected join request, got {message:?}"
                )))
            }
        };
        let joined_name = request.name.clone();
        self.state.reserve().await?;
        *reserved = true;
        let mut proposed = groups::find(&self.root, &self.group_id)?
            .ok_or_else(|| GroupError::NotFound(self.group_id.clone()))?;
        if let Some(existing) = proposed
            .members
            .iter()
            .find(|member| member.particle_id == request.particle_id)
        {
            if existing.static_key != request.static_key {
                return Err(GroupError::KeyConflict(request.particle_id).into());
            }
        } else {
            proposed.members.push(request.clone());
            proposed
                .members
                .sort_by(|left, right| left.particle_id.cmp(&right.particle_id));
        }
        sender
            .send(
                stream,
                &Message::JoinGrant {
                    name: proposed.meta.name,
                    key_hex: hex::encode(proposed.key),
                    created_at: proposed.meta.created_at,
                    members: proposed.members,
                },
            )
            .await?;
        if receiver.receive::<_, Message>(stream).await? != Message::Done {
            return Err(InviteError::Message("expected Done".into()));
        }
        groups::add_member(&self.root, &self.group_id, request)?;
        if send_committed {
            sender.send(stream, &Message::Committed).await?;
        } else {
            return Err(InviteError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "simulated missing commit confirmation",
            )));
        }
        self.state.completed().await;
        *reserved = false;
        Ok(Some(joined_name))
    }

    fn password(&self) -> String {
        self.code.to_string()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Message {
    GroupInfo {
        name: String,
        group_id: String,
        inviter_name: String,
    },
    Decline {
        reason: DeclineReason,
    },
    JoinRequest {
        particle_id: String,
        name: String,
        static_key: String,
    },
    JoinGrant {
        name: String,
        key_hex: String,
        created_at: String,
        members: Vec<Member>,
    },
    Done,
    Committed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DeclineReason {
    AlreadyMember,
    NameTaken,
}

impl DeclineReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::AlreadyMember => "already_member",
            Self::NameTaken => "name_taken",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Joined {
    pub group: Group,
    pub inviter_name: String,
}

/// Joins an inviter over an arbitrary byte stream.
pub async fn join<S>(
    stream: S,
    root: &Path,
    code: InviteCode,
    local_name: Option<&str>,
    particle_name: &str,
) -> Result<Joined, InviteError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    join_with_timeout(
        stream,
        root,
        code,
        local_name,
        particle_name,
        SESSION_TIMEOUT,
    )
    .await
}

async fn join_with_timeout<S>(
    mut stream: S,
    root: &Path,
    code: InviteCode,
    local_name: Option<&str>,
    particle_name: &str,
    session_timeout: Duration,
) -> Result<Joined, InviteError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some((id, static_private)) =
        identity::read_saved(root).map_err(|error| GroupError::Malformed {
            path: root.to_owned(),
            reason: error.to_string(),
        })?
    else {
        return Err(GroupError::MissingIdentity(root.to_owned()).into());
    };
    let mut inserted_group = None;
    let result = timeout(
        session_timeout,
        join_inner(
            &mut stream,
            root,
            code,
            local_name,
            particle_name,
            (id, static_private),
            &mut inserted_group,
        ),
    )
    .await;
    let result = match result {
        Ok(result) => result,
        Err(_) => Err(InviteError::Timeout),
    };
    match result {
        Ok(joined) => Ok(joined),
        Err(error) => {
            if let Some(group_id) = inserted_group.take() {
                match groups::leave(root, &group_id) {
                    Ok(_) | Err(GroupError::NotFound(_)) => Err(InviteError::Incomplete),
                    Err(error) => Err(error.into()),
                }
            } else {
                Err(error)
            }
        }
    }
}

async fn join_inner<S>(
    stream: &mut S,
    root: &Path,
    code: InviteCode,
    local_name: Option<&str>,
    particle_name: &str,
    identity: (entangle_core::ParticleId, [u8; 32]),
    inserted_group: &mut Option<String>,
) -> Result<Joined, InviteError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (id, static_private) = identity;
    let (spake, local_msg) = Spake2::<Ed25519Group>::start_b(
        &Password::new(code.to_string().as_bytes()),
        &Identity::new(ID_INVITER),
        &Identity::new(ID_JOINER),
    );
    write_tagged_frame(stream, FRAME_SPAKE, &local_msg).await?;
    let peer_msg = read_frame(stream).await?;
    let peer_msg = tagged_body(&peer_msg, FRAME_SPAKE)?;
    let shared = spake.finish(peer_msg).map_err(|_| InviteError::WrongCode)?;
    let keys = DerivedKeys::new(&shared);
    write_tagged_frame(stream, FRAME_CONFIRM, &keys.confirm_joiner).await?;
    let confirm = match read_frame(stream).await {
        Ok(frame) => frame,
        Err(_) => return Err(InviteError::WrongCode),
    };
    let confirm = tagged_body(&confirm, FRAME_CONFIRM).map_err(|_| InviteError::WrongCode)?;
    if !bool::from(keys.confirm_inviter.ct_eq(confirm)) {
        return Err(InviteError::WrongCode);
    }

    let mut sender = SecureJson::new(keys.enc_joiner);
    let mut receiver = SecureJson::new(keys.enc_inviter);
    let (name, group_id, inviter_name) = match receiver.receive::<_, Message>(stream).await? {
        Message::GroupInfo {
            name,
            group_id,
            inviter_name,
        } => (name, group_id, inviter_name),
        message => {
            return Err(InviteError::Message(format!(
                "expected group info, got {message:?}"
            )))
        }
    };
    let local_group_name = local_name.unwrap_or(&name);
    groups::validate_name(local_group_name)?;
    let local_groups = groups::list(root)?;
    let decline = if local_groups.iter().any(|group| group.id == group_id) {
        Some(DeclineReason::AlreadyMember)
    } else if local_groups
        .iter()
        .any(|group| group.meta.name == local_group_name)
    {
        Some(DeclineReason::NameTaken)
    } else {
        None
    };
    if let Some(reason) = decline {
        let group_name = match reason {
            DeclineReason::AlreadyMember => &name,
            DeclineReason::NameTaken => local_group_name,
        };
        sender.send(stream, &Message::Decline { reason }).await?;
        return Err(InviteError::Declined {
            reason: match reason {
                DeclineReason::AlreadyMember => "already_member",
                DeclineReason::NameTaken => "name_taken",
            }
            .to_owned(),
            group_name: Some(group_name.to_owned()),
        });
    }
    sender
        .send(
            stream,
            &Message::JoinRequest {
                particle_id: id.to_string(),
                name: particle_name.to_owned(),
                static_key: hex::encode(entangle_transport::public_key(&static_private)),
            },
        )
        .await?;
    let grant = match receiver.receive::<_, Message>(stream).await? {
        Message::JoinGrant {
            name,
            key_hex,
            created_at,
            members,
        } => (name, key_hex, created_at, members),
        message => {
            return Err(InviteError::Message(format!(
                "expected join grant, got {message:?}"
            )))
        }
    };
    if grant.0 != name
        || grant.1.len() != 64
        || !grant
            .1
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(InviteError::Message("invalid join grant".into()));
    }
    let key: [u8; 32] = hex::decode(&grant.1)
        .map_err(|_| InviteError::Message("invalid group key".into()))?
        .try_into()
        .map_err(|_| InviteError::Message("invalid group key".into()))?;
    if groups::group_id(&key) != group_id {
        return Err(InviteError::Message(
            "group ID does not match the granted key".into(),
        ));
    }
    let group = groups::insert(
        root,
        key,
        GroupMeta {
            version: 1,
            name: local_group_name.to_owned(),
            role: Role::Member,
            created_at: grant.2,
        },
        grant.3,
    )?;
    *inserted_group = Some(group.id.clone());
    sender.send(stream, &Message::Done).await?;
    if receiver.receive::<_, Message>(stream).await? != Message::Committed {
        return Err(InviteError::Message("expected commit confirmation".into()));
    }
    *inserted_group = None;
    Ok(Joined {
        group,
        inviter_name,
    })
}

struct DerivedKeys {
    confirm_joiner: [u8; 32],
    confirm_inviter: [u8; 32],
    enc_joiner: [u8; 32],
    enc_inviter: [u8; 32],
}

impl DerivedKeys {
    fn new(shared: &[u8]) -> Self {
        Self {
            confirm_joiner: derive(CONFIRM_JOINER, shared),
            confirm_inviter: derive(CONFIRM_INVITER, shared),
            enc_joiner: derive(ENCRYPT_JOINER, shared),
            enc_inviter: derive(ENCRYPT_INVITER, shared),
        }
    }
}

fn derive(domain: &[u8], shared: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(shared);
    hash.finalize().into()
}

async fn write_tagged_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    tag: u8,
    body: &[u8],
) -> Result<(), InviteError> {
    let mut frame = Vec::with_capacity(body.len() + 1);
    frame.push(tag);
    frame.extend_from_slice(body);
    write_frame(writer, &frame).await
}

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> Result<(), InviteError> {
    if body.len() > MAX_FRAME_BYTES {
        return Err(InviteError::Oversize);
    }
    writer.write_u32(body.len() as u32).await?;
    writer.write_all(body).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, InviteError> {
    let length = reader.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(InviteError::Oversize);
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await?;
    Ok(body)
}

async fn read_before_terminal<R: AsyncRead + Unpin>(
    reader: &mut R,
    terminal: &mut watch::Receiver<Option<InviteEnd>>,
) -> Result<Vec<u8>, InviteError> {
    if terminal.borrow().is_some() {
        return Err(InviteError::Closed);
    }
    tokio::select! {
        result = read_frame(reader) => result,
        result = terminal.changed() => {
            let _ = result;
            Err(InviteError::Closed)
        }
    }
}

async fn read_before_terminal_timeout<R: AsyncRead + Unpin>(
    reader: &mut R,
    terminal: &mut watch::Receiver<Option<InviteEnd>>,
    duration: Duration,
) -> Result<Vec<u8>, InviteError> {
    timeout(duration, read_before_terminal(reader, terminal))
        .await
        .map_err(|_| InviteError::Timeout)?
}

fn tagged_body(frame: &[u8], expected: u8) -> Result<&[u8], InviteError> {
    if frame.first() == Some(&expected) && frame.len() > 1 {
        Ok(&frame[1..])
    } else {
        Err(InviteError::InvalidFrame)
    }
}

struct SecureJson {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl SecureJson {
    fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
            counter: 0,
        }
    }

    async fn send<S: AsyncWrite + Unpin, T: Serialize>(
        &mut self,
        stream: &mut S,
        message: &T,
    ) -> Result<(), InviteError> {
        let plaintext =
            serde_json::to_vec(message).map_err(|error| InviteError::Message(error.to_string()))?;
        let nonce = nonce(self.counter);
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &[],
                },
            )
            .map_err(|_| InviteError::Encryption)?;
        self.counter = self.counter.checked_add(1).ok_or(InviteError::Encryption)?;
        write_frame(stream, &ciphertext).await
    }

    async fn receive<S: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(
        &mut self,
        stream: &mut S,
    ) -> Result<T, InviteError> {
        let ciphertext = read_frame(stream).await?;
        let nonce = nonce(self.counter);
        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &[],
                },
            )
            .map_err(|_| InviteError::Encryption)?;
        self.counter = self.counter.checked_add(1).ok_or(InviteError::Encryption)?;
        serde_json::from_slice(&plaintext).map_err(|error| InviteError::Message(error.to_string()))
    }
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Selects a random currently-unused nameplate.
pub fn choose_nameplate(visible: &[u8]) -> Option<u8> {
    let available = (1..=99)
        .filter(|number| !visible.contains(number))
        .collect::<Vec<_>>();
    if available.is_empty() {
        return None;
    }
    let mut random = [0];
    rand::rngs::OsRng.fill_bytes(&mut random);
    Some(available[usize::from(random[0]) % available.len()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;
    use tokio::io::duplex;

    fn saved_member(root: &Path, name: &str) -> Member {
        let identity = identity::claim(root).unwrap();
        let id = identity.id.to_string();
        let member = Member {
            particle_id: id.clone(),
            name: name.into(),
            static_key: hex::encode(entangle_transport::public_key(&identity.static_private)),
            added_by: id,
            added_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        };
        drop(identity);
        member
    }

    fn setup_group(root: &Path) -> Group {
        let member = saved_member(root, "inviter");
        groups::insert(
            root,
            [0x42; 32],
            GroupMeta {
                version: 1,
                name: "work".into(),
                role: Role::Admin,
                created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            },
            vec![member],
        )
        .unwrap()
    }

    fn server(root: &Path, group: &Group, count: u8, ttl: Duration) -> InviteServer {
        InviteServer::new(root, group.id.clone(), "inviter".into(), code(), count, ttl).unwrap()
    }

    fn code() -> InviteCode {
        InviteCode::parse("7-amber-photon-quasar").unwrap()
    }

    async fn confirm_joiner<S>(stream: &mut S, code: InviteCode) -> (SecureJson, SecureJson)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (spake, local_msg) = Spake2::<Ed25519Group>::start_b(
            &Password::new(code.to_string().as_bytes()),
            &Identity::new(ID_INVITER),
            &Identity::new(ID_JOINER),
        );
        write_tagged_frame(stream, FRAME_SPAKE, &local_msg)
            .await
            .unwrap();
        let peer_msg = read_frame(stream).await.unwrap();
        let peer_msg = tagged_body(&peer_msg, FRAME_SPAKE).unwrap();
        let shared = spake.finish(peer_msg).unwrap();
        let keys = DerivedKeys::new(&shared);
        write_tagged_frame(stream, FRAME_CONFIRM, &keys.confirm_joiner)
            .await
            .unwrap();
        let confirmation = read_frame(stream).await.unwrap();
        let confirmation = tagged_body(&confirmation, FRAME_CONFIRM).unwrap();
        assert!(bool::from(keys.confirm_inviter.ct_eq(confirmation)));
        (
            SecureJson::new(keys.enc_joiner),
            SecureJson::new(keys.enc_inviter),
        )
    }

    async fn successful_join(
        server: &InviteServer,
        root: &Path,
        name: &str,
    ) -> Result<Joined, InviteError> {
        let (joiner, inviter) = duplex(1024 * 1024);
        let server = server.clone();
        let task = tokio::spawn(async move { server.handle(inviter).await });
        let result = join(joiner, root, code(), None, name).await;
        let server_result = task.await.unwrap();
        if result.is_ok() {
            let _ = server_result.unwrap();
        }
        result
    }

    #[tokio::test]
    async fn protocol_success_installs_full_roster_on_both_sides() {
        let inviter_root = tempfile::tempdir().unwrap();
        let group = setup_group(inviter_root.path());
        let server = server(inviter_root.path(), &group, 1, DEFAULT_TTL);
        let joiner_root = tempfile::tempdir().unwrap();
        let _member = saved_member(joiner_root.path(), "joiner");

        let joined = successful_join(&server, joiner_root.path(), "joiner")
            .await
            .unwrap();
        assert_eq!(joined.group.meta.role, Role::Member);
        assert_eq!(joined.group.members.len(), 2);
        assert!(joined
            .group
            .members
            .iter()
            .any(|member| member.name == "joiner"));
        let updated = groups::find(inviter_root.path(), &group.id)
            .unwrap()
            .unwrap();
        let joiner = updated
            .members
            .iter()
            .find(|member| member.name == "joiner")
            .unwrap();
        assert_eq!(joiner.added_by, group.members[0].particle_id);
        assert_eq!(server.state().counts().await, (1, 1));
    }

    #[tokio::test]
    async fn wrong_code_kills_invite_and_refuses_later_attempt() {
        let inviter_root = tempfile::tempdir().unwrap();
        let group = setup_group(inviter_root.path());
        let server = server(inviter_root.path(), &group, 1, DEFAULT_TTL);
        let joiner_root = tempfile::tempdir().unwrap();
        let _member = saved_member(joiner_root.path(), "joiner");
        let (joiner, inviter) = duplex(1024);
        let server_task = server.clone();
        let task = tokio::spawn(async move { server_task.handle(inviter).await });
        let wrong = InviteCode::parse("8-amber-photon-quasar").unwrap();
        assert!(matches!(
            join(joiner, joiner_root.path(), wrong, None, "joiner").await,
            Err(InviteError::WrongCode)
        ));
        let _ = task.await.unwrap();
        assert_eq!(server.state().terminal().await, Some(InviteEnd::WrongCode));
        let (joiner, inviter) = duplex(1024);
        let server_task = server.clone();
        let task = tokio::spawn(async move { server_task.handle(inviter).await });
        assert!(matches!(
            join(joiner, joiner_root.path(), code(), None, "joiner").await,
            Err(InviteError::WrongCode | InviteError::Io(_) | InviteError::Closed)
        ));
        let _ = task.await.unwrap();
    }

    #[tokio::test]
    async fn disconnect_after_spake_message_kills_invite() {
        let inviter_root = tempfile::tempdir().unwrap();
        let group = setup_group(inviter_root.path());
        let server = server(inviter_root.path(), &group, 1, DEFAULT_TTL);
        let (mut joiner, inviter) = duplex(1024);
        let server_task = server.clone();
        let task = tokio::spawn(async move { server_task.handle(inviter).await });
        let inviter_spake = read_frame(&mut joiner).await.unwrap();
        tagged_body(&inviter_spake, FRAME_SPAKE).unwrap();
        let (_spake, joiner_spake) = Spake2::<Ed25519Group>::start_b(
            &Password::new(code().to_string().as_bytes()),
            &Identity::new(ID_INVITER),
            &Identity::new(ID_JOINER),
        );
        write_tagged_frame(&mut joiner, FRAME_SPAKE, &joiner_spake)
            .await
            .unwrap();
        drop(joiner);
        let _ = task.await.unwrap();
        assert_eq!(server.state().terminal().await, Some(InviteEnd::Failed));
    }

    #[tokio::test]
    async fn spake_timeout_before_joiner_message_does_not_kill_invite() {
        let inviter_root = tempfile::tempdir().unwrap();
        let group = setup_group(inviter_root.path());
        let server = server(inviter_root.path(), &group, 1, DEFAULT_TTL);
        let (mut joiner, inviter) = duplex(1024);
        let server_task = server.clone();
        let task = tokio::spawn(async move {
            server_task
                .handle_with_policy(
                    inviter,
                    Duration::from_secs(1),
                    Duration::from_millis(10),
                    true,
                )
                .await
        });
        let spake = read_frame(&mut joiner).await.unwrap();
        tagged_body(&spake, FRAME_SPAKE).unwrap();
        assert!(matches!(task.await.unwrap(), Err(InviteError::Timeout)));
        assert_eq!(server.state().terminal().await, None);
        assert_eq!(server.state().counts().await, (0, 1));
    }

    #[tokio::test]
    async fn bad_done_does_not_commit_member_or_consume_slot() {
        let inviter_root = tempfile::tempdir().unwrap();
        let group = setup_group(inviter_root.path());
        let server = server(inviter_root.path(), &group, 1, DEFAULT_TTL);
        let joiner_root = tempfile::tempdir().unwrap();
        let _joiner_member = saved_member(joiner_root.path(), "joiner");
        let (mut joiner, inviter) = duplex(1024 * 1024);
        let server_task = server.clone();
        let task = tokio::spawn(async move { server_task.handle(inviter).await });
        let (mut sender, mut receiver) = confirm_joiner(&mut joiner, code()).await;
        assert!(matches!(
            receiver.receive::<_, Message>(&mut joiner).await.unwrap(),
            Message::GroupInfo { .. }
        ));
        let (joiner_id, joiner_private) =
            identity::read_saved(joiner_root.path()).unwrap().unwrap();
        sender
            .send(
                &mut joiner,
                &Message::JoinRequest {
                    particle_id: joiner_id.to_string(),
                    name: "joiner".into(),
                    static_key: hex::encode(entangle_transport::public_key(&joiner_private)),
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            receiver.receive::<_, Message>(&mut joiner).await.unwrap(),
            Message::JoinGrant { .. }
        ));
        sender
            .send(
                &mut joiner,
                &Message::Decline {
                    reason: DeclineReason::AlreadyMember,
                },
            )
            .await
            .unwrap();
        assert!(matches!(task.await.unwrap(), Err(InviteError::Message(_))));
        let unchanged = groups::find(inviter_root.path(), &group.id)
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.members.len(), 1);
        assert_eq!(server.state().counts().await, (0, 1));
        assert_eq!(server.state().terminal().await, None);

        successful_join(&server, joiner_root.path(), "joiner")
            .await
            .unwrap();
        assert_eq!(server.state().counts().await, (1, 1));
    }

    #[tokio::test]
    async fn missing_committed_rolls_back_joiner_but_allows_retry() {
        let inviter_root = tempfile::tempdir().unwrap();
        let group = setup_group(inviter_root.path());
        let server = server(inviter_root.path(), &group, 1, DEFAULT_TTL);
        let joiner_root = tempfile::tempdir().unwrap();
        let joiner_member = saved_member(joiner_root.path(), "joiner");
        let joiner_id = joiner_member.particle_id.clone();
        let (joiner, inviter) = duplex(1024 * 1024);
        let server_task = server.clone();
        let task = tokio::spawn(async move {
            server_task
                .handle_with_policy(inviter, SESSION_TIMEOUT, SPAKE_TIMEOUT, false)
                .await
        });
        assert!(matches!(
            join_with_timeout(
                joiner,
                joiner_root.path(),
                code(),
                None,
                "joiner",
                Duration::from_secs(1),
            )
            .await,
            Err(InviteError::Incomplete)
        ));
        assert!(task.await.unwrap().is_err());
        assert!(groups::list(joiner_root.path()).unwrap().is_empty());
        let inviter_group = groups::find(inviter_root.path(), &group.id)
            .unwrap()
            .unwrap();
        assert!(inviter_group
            .members
            .iter()
            .any(|member| member.particle_id == joiner_id));
        assert_eq!(server.state().counts().await, (0, 1));

        successful_join(&server, joiner_root.path(), "joiner")
            .await
            .unwrap();
        assert_eq!(server.state().counts().await, (1, 1));
    }

    #[tokio::test]
    async fn ninth_concurrent_session_is_refused_without_closing_invite() {
        let inviter_root = tempfile::tempdir().unwrap();
        let group = setup_group(inviter_root.path());
        let server = server(inviter_root.path(), &group, 1, DEFAULT_TTL);
        let mut clients = Vec::new();
        let mut tasks = Vec::new();
        for _ in 0..MAX_SESSIONS {
            let (mut client, inviter) = duplex(1024);
            let session = server.clone();
            tasks.push(tokio::spawn(async move { session.handle(inviter).await }));
            let frame = read_frame(&mut client).await.unwrap();
            tagged_body(&frame, FRAME_SPAKE).unwrap();
            clients.push(client);
        }

        let (mut ninth_client, ninth_inviter) = duplex(1024);
        assert!(matches!(
            server.handle(ninth_inviter).await,
            Err(InviteError::Busy)
        ));
        assert!(read_frame(&mut ninth_client).await.is_err());
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        drop(clients);
        assert_eq!(server.state().terminal().await, None);
        assert_eq!(server.state().counts().await, (0, 1));

        let joiner_root = tempfile::tempdir().unwrap();
        let _joiner_member = saved_member(joiner_root.path(), "joiner");
        successful_join(&server, joiner_root.path(), "joiner")
            .await
            .unwrap();
        assert_eq!(server.state().counts().await, (1, 1));
    }

    #[tokio::test]
    async fn confirmed_session_finishes_after_wrong_code_kills_invite() {
        let inviter_root = tempfile::tempdir().unwrap();
        let group = setup_group(inviter_root.path());
        let server = server(inviter_root.path(), &group, 1, DEFAULT_TTL);

        let good_root = tempfile::tempdir().unwrap();
        let _good_member = saved_member(good_root.path(), "good-joiner");
        let (mut good_stream, good_server_stream) = duplex(1024 * 1024);
        let good_server = server.clone();
        let good_task = tokio::spawn(async move { good_server.handle(good_server_stream).await });
        let (mut sender, mut receiver) = confirm_joiner(&mut good_stream, code()).await;
        assert!(matches!(
            receiver
                .receive::<_, Message>(&mut good_stream)
                .await
                .unwrap(),
            Message::GroupInfo { .. }
        ));

        let wrong_root = tempfile::tempdir().unwrap();
        let _wrong_member = saved_member(wrong_root.path(), "wrong-joiner");
        let (wrong_stream, wrong_server_stream) = duplex(1024 * 1024);
        let wrong_server = server.clone();
        let wrong_task =
            tokio::spawn(async move { wrong_server.handle(wrong_server_stream).await });
        let wrong_code = InviteCode::parse("8-amber-photon-quasar").unwrap();
        assert!(matches!(
            join(
                wrong_stream,
                wrong_root.path(),
                wrong_code,
                None,
                "wrong-joiner"
            )
            .await,
            Err(InviteError::WrongCode)
        ));
        let _ = wrong_task.await.unwrap();
        assert_eq!(server.state().terminal().await, Some(InviteEnd::WrongCode));

        let (good_id, good_private) = identity::read_saved(good_root.path()).unwrap().unwrap();
        sender
            .send(
                &mut good_stream,
                &Message::JoinRequest {
                    particle_id: good_id.to_string(),
                    name: "good-joiner".into(),
                    static_key: hex::encode(entangle_transport::public_key(&good_private)),
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            receiver
                .receive::<_, Message>(&mut good_stream)
                .await
                .unwrap(),
            Message::JoinGrant { .. }
        ));
        sender.send(&mut good_stream, &Message::Done).await.unwrap();
        assert_eq!(
            good_task.await.unwrap().unwrap().as_deref(),
            Some("good-joiner")
        );
        assert_eq!(server.state().counts().await, (1, 1));
    }

    #[tokio::test]
    async fn count_limits_successful_joins_and_ttl_closes_invite() {
        let inviter_root = tempfile::tempdir().unwrap();
        let group = setup_group(inviter_root.path());
        let invite_server = server(inviter_root.path(), &group, 2, DEFAULT_TTL);
        let first_root = tempfile::tempdir().unwrap();
        let _first = saved_member(first_root.path(), "first");
        successful_join(&invite_server, first_root.path(), "first")
            .await
            .unwrap();
        let second_root = tempfile::tempdir().unwrap();
        let _second = saved_member(second_root.path(), "second");
        successful_join(&invite_server, second_root.path(), "second")
            .await
            .unwrap();
        assert_eq!(
            invite_server.state().terminal().await,
            Some(InviteEnd::Complete)
        );
        let third_root = tempfile::tempdir().unwrap();
        let _third = saved_member(third_root.path(), "third");
        assert!(successful_join(&invite_server, third_root.path(), "third")
            .await
            .is_err());

        let expired = InviteState::new(1, Duration::from_millis(1)).unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        expired.end_if_expired();
        assert_eq!(expired.terminal().await, Some(InviteEnd::Expired));

        let expired_server = server(inviter_root.path(), &group, 1, Duration::from_millis(1));
        tokio::time::sleep(Duration::from_millis(5)).await;
        let (_joiner, inviter) = duplex(128);
        assert!(matches!(
            expired_server.handle(inviter).await,
            Err(InviteError::Closed)
        ));
    }

    #[tokio::test]
    async fn declines_do_not_consume_a_slot_and_name_override_is_used() {
        let inviter_root = tempfile::tempdir().unwrap();
        let group = setup_group(inviter_root.path());
        let server = server(inviter_root.path(), &group, 1, DEFAULT_TTL);

        let already_root = tempfile::tempdir().unwrap();
        let already_member = saved_member(already_root.path(), "already");
        groups::insert(
            already_root.path(),
            group.key,
            GroupMeta {
                version: 1,
                name: "work".into(),
                role: Role::Member,
                created_at: group.meta.created_at.clone(),
            },
            vec![already_member],
        )
        .unwrap();
        assert!(matches!(
            successful_join(&server, already_root.path(), "already").await,
            Err(InviteError::Declined { reason, .. }) if reason == "already_member"
        ));
        assert_eq!(server.state().counts().await, (0, 1));
        assert_eq!(server.state().terminal().await, None);

        let taken_root = tempfile::tempdir().unwrap();
        let _taken = saved_member(taken_root.path(), "taken");
        groups::insert(
            taken_root.path(),
            [0x11; 32],
            GroupMeta {
                version: 1,
                name: "work".into(),
                role: Role::Admin,
                created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            },
            vec![_taken],
        )
        .unwrap();
        assert!(matches!(
            successful_join(&server, taken_root.path(), "taken").await,
            Err(InviteError::Declined { reason, .. }) if reason == "name_taken"
        ));
        assert_eq!(server.state().counts().await, (0, 1));

        let renamed_root = tempfile::tempdir().unwrap();
        let _renamed = saved_member(renamed_root.path(), "renamed");
        let (joiner, inviter) = duplex(1024 * 1024);
        let server_task = server.clone();
        let task = tokio::spawn(async move { server_task.handle(inviter).await });
        let renamed = join(joiner, renamed_root.path(), code(), Some("home"), "renamed")
            .await
            .unwrap();
        let _ = task.await.unwrap().unwrap();
        assert_eq!(renamed.group.meta.name, "home");
    }

    #[tokio::test]
    async fn missing_saved_identity_returns_the_standard_message() {
        let root = tempfile::tempdir().unwrap();
        let (joiner, _inviter) = duplex(128);
        let error = join(joiner, root.path(), code(), None, "missing")
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            format!(
                "this machine has no saved Entangle identity in {} yet; start Entangle once (for example, open your MCP client) using the same data directory, then retry",
                root.path().display()
            )
        );
    }
}
