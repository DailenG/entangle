//! Host and device administration for the Quantum Repeater.

use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;
use crossterm::{
    event::{read, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use entangle_repeater::{client, invite, server, store::Store};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    fs::{self, OpenOptions},
    io::{self, IsTerminal, Write},
    path::{Component, Path, PathBuf},
    time::Duration,
};

static CONFIG_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KeyOutcome {
    Pick(u8),
    Cancel,
    Invalid,
    Ignore,
}

#[derive(Debug, PartialEq, Eq)]
enum YesNo {
    Yes,
    No,
    Cancel,
    Invalid,
    Ignore,
}

fn classify_key(code: KeyCode, modifiers: KeyModifiers) -> KeyOutcome {
    match code {
        KeyCode::Esc => KeyOutcome::Cancel,
        KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => KeyOutcome::Cancel,
        KeyCode::Char(value @ '1'..='9') => KeyOutcome::Pick(value as u8 - b'0'),
        _ => KeyOutcome::Invalid,
    }
}

fn classify_event(event: Event) -> KeyOutcome {
    match event {
        Event::Key(key) if key.kind == KeyEventKind::Press => classify_key(key.code, key.modifiers),
        _ => KeyOutcome::Ignore,
    }
}

struct RawModeGuard;

impl RawModeGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

fn read_approval_key(max: u8) -> Result<KeyOutcome> {
    let _raw_mode = RawModeGuard::enter()?;
    loop {
        match classify_event(read()?) {
            KeyOutcome::Ignore => continue,
            KeyOutcome::Pick(value) if value > max => return Ok(KeyOutcome::Invalid),
            outcome => return Ok(outcome),
        }
    }
}

fn classify_yes_no(code: KeyCode, modifiers: KeyModifiers) -> YesNo {
    match code {
        KeyCode::Char('y' | 'Y') => YesNo::Yes,
        KeyCode::Char('n' | 'N') => YesNo::No,
        KeyCode::Esc | KeyCode::Char('q' | 'Q') => YesNo::Cancel,
        KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => YesNo::Cancel,
        KeyCode::Modifier(_) => YesNo::Ignore,
        _ => YesNo::Invalid,
    }
}

fn read_yes_no_key() -> Result<YesNo> {
    let _raw_mode = RawModeGuard::enter()?;
    loop {
        let outcome = match read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                classify_yes_no(key.code, key.modifiers)
            }
            _ => YesNo::Ignore,
        };
        if outcome != YesNo::Ignore {
            return Ok(outcome);
        }
    }
}

fn cancel_approval(output: &mut dyn Write) -> Result<i32> {
    writeln!(output, "\r\nCancelled; nothing was approved or denied.")?;
    Ok(1)
}

#[derive(Debug, Subcommand)]
pub enum RepeaterCommand {
    Serve {
        #[arg(long)]
        listen: std::net::SocketAddr,
        #[arg(long, default_value = "/entangle")]
        path: String,
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long)]
        no_requests: bool,
    },
    Invite {
        #[arg(long)]
        url: String,
        #[arg(long, default_value = "15m")]
        ttl: String,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        root: Option<PathBuf>,
    },
    Devices {
        #[arg(long)]
        root: Option<PathBuf>,
    },
    Revoke {
        fingerprint: String,
        #[arg(long)]
        root: Option<PathBuf>,
    },
    Join {
        code: String,
        #[arg(long)]
        label: Option<String>,
    },
    Approve {
        #[arg(long)]
        root: Option<PathBuf>,
    },
    Status,
    Leave,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RepeaterConfig {
    pub(crate) url: String,
    pub(crate) repeater_public_key: String,
}

fn human_only(command: &RepeaterCommand) -> bool {
    matches!(
        command,
        RepeaterCommand::Invite { .. }
            | RepeaterCommand::Revoke { .. }
            | RepeaterCommand::Join { .. }
            | RepeaterCommand::Approve { .. }
            | RepeaterCommand::Leave
    )
}

fn repeater_root(options: &crate::config::Options, root: Option<PathBuf>) -> PathBuf {
    root.unwrap_or_else(|| options.data_root().join("entangle-repeater"))
}

fn parse_ttl(value: &str) -> Result<Duration> {
    let minutes: u64 = value
        .strip_suffix('m')
        .ok_or_else(|| anyhow!("TTL must use minutes, for example 15m"))?
        .parse()?;
    Ok(Duration::from_secs(minutes.saturating_mul(60)))
}

fn validate_label(label: Option<&str>) -> Result<()> {
    if label.is_some_and(|value| value.len() > 64 || value.chars().any(char::is_control)) {
        bail!("label must be at most 64 bytes and contain no control characters");
    }
    Ok(())
}

pub(crate) fn websocket_host(url: &str) -> Result<&str> {
    let (scheme, remainder) = url
        .split_once("://")
        .ok_or_else(|| anyhow!("URL must use ws:// or wss://"))?;
    if !matches!(scheme, "ws" | "wss") {
        bail!("URL must use ws:// or wss://");
    }
    let authority = remainder.split('/').next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        bail!("URL must include a host and must not include credentials");
    }
    let host = if let Some(ipv6) = authority.strip_prefix('[') {
        ipv6.split_once(']')
            .map(|(host, _)| host)
            .ok_or_else(|| anyhow!("invalid IPv6 repeater URL"))?
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    if host.is_empty() {
        bail!("URL must include a host");
    }
    Ok(host)
}

fn short_fingerprint(public: &[u8; 32]) -> String {
    hex::encode(sha2::Sha256::digest(public))[..8].to_owned()
}

fn long_fingerprint(public: &[u8; 32]) -> String {
    let fingerprint = hex::encode(sha2::Sha256::digest(public));
    format!(
        "{} {} {} {}",
        &fingerprint[..4],
        &fingerprint[4..8],
        &fingerprint[8..12],
        &fingerprint[12..16]
    )
}

fn request_waiting_message(
    host: &str,
    repeater_public: &[u8; 32],
    device_public: &[u8; 32],
) -> String {
    format!(
        "Asked the Quantum Repeater at {host} to enroll this device (repeater fingerprint {}).\nThis device's fingerprint: {}\nRepeater fingerprint: {}\nOn the host, run `entangle repeater approve` and check that it shows the same two fingerprints.\nWaiting for the host to decide (up to 10 minutes; Ctrl+C cancels)...",
        short_fingerprint(repeater_public),
        long_fingerprint(device_public),
        long_fingerprint(repeater_public)
    )
}

fn join_summary(host: &str, repeater_public: &[u8; 32], device_public: &[u8; 32]) -> String {
    format!(
        "Joined the Quantum Repeater at {host} (repeater fingerprint {}).\nThis device's fingerprint: {} (listed by `entangle repeater devices` on the host).\nA running Entangle node connects within 30 seconds; check with `entangle repeater status`.",
        short_fingerprint(repeater_public),
        short_fingerprint(device_public)
    )
}

fn leave_summary(removed: bool) -> &'static str {
    if removed {
        "Left the Quantum Repeater: removed this device's saved configuration. The host keeps this device enrolled until it is revoked there."
    } else {
        "This device has not joined a Quantum Repeater; nothing to remove."
    }
}

pub(crate) fn read_config(path: &Path) -> Result<Option<RepeaterConfig>> {
    let Some(bytes) = read_regular_file(path)? else {
        return Ok(None);
    };
    let config: RepeaterConfig = serde_json::from_slice(&bytes)?;
    websocket_host(&config.url)?;
    let public: [u8; 32] = hex::decode(&config.repeater_public_key)?
        .try_into()
        .map_err(|_| anyhow!("invalid repeater configuration"))?;
    let _ = public;
    Ok(Some(config))
}

pub async fn run(
    command: RepeaterCommand,
    options: &crate::config::Options,
    output: &mut dyn Write,
) -> Result<i32> {
    if human_only(&command) && !(io::stdin().is_terminal() && io::stdout().is_terminal()) {
        writeln!(
            output,
            "This command is for the human operator and needs an interactive terminal."
        )?;
        return Ok(2);
    }
    match command {
        RepeaterCommand::Serve {
            listen,
            path,
            root,
            no_requests,
        } => {
            let store = Store::new(repeater_root(options, root));
            let key = store.key()?;
            let public = entangle_transport::public_key(&key);
            writeln!(
                output,
                "repeater key fingerprint: {}",
                short_fingerprint(&public)
            )?;
            output.flush()?;
            server::serve(server::ServerConfig {
                listen,
                path,
                root: store.root,
                requests: !no_requests,
            })
            .await?;
        }
        RepeaterCommand::Invite {
            url,
            ttl,
            label,
            root,
        } => {
            websocket_host(&url)?;
            validate_label(label.as_deref())?;
            let store = Store::new(repeater_root(options, root));
            let private = store.key()?;
            let mut secret = [0; 32];
            rand::rngs::OsRng.fill_bytes(&mut secret);
            let expires = chrono::Utc::now()
                .checked_add_signed(chrono::Duration::from_std(parse_ttl(&ttl)?)?)
                .ok_or_else(|| anyhow!("TTL overflow"))?
                .to_rfc3339();
            store.add_invite(secret, expires, label)?;
            let code = invite::encode(&invite::Invite {
                repeater_public_key: entangle_transport::public_key(&private),
                secret,
                url,
            })?;
            writeln!(output, "{code}")?;
        }
        RepeaterCommand::Devices { root } => {
            let store = Store::new(repeater_root(options, root));
            let devices = store.devices()?;
            for (key, device) in devices.devices {
                let public: [u8; 32] = hex::decode(key)?
                    .try_into()
                    .map_err(|_| anyhow!("invalid device key"))?;
                writeln!(
                    output,
                    "{} {} {}",
                    short_fingerprint(&public),
                    device.label.unwrap_or_default(),
                    if device.denied {
                        "denied"
                    } else if device.revoked {
                        "revoked"
                    } else {
                        "active"
                    }
                )?;
            }
            for request in store.requests()? {
                let public: [u8; 32] = hex::decode(request.key)?
                    .try_into()
                    .map_err(|_| anyhow!("invalid request key"))?;
                writeln!(
                    output,
                    "{} {} pending (from {})",
                    short_fingerprint(&public),
                    request.label.as_deref().unwrap_or("(unnamed)"),
                    request.source
                )?;
            }
        }
        RepeaterCommand::Revoke { fingerprint, root } => {
            if fingerprint.is_empty()
                || fingerprint.len() > 8
                || !fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                bail!("fingerprint must be a 1-8 character lowercase hex prefix");
            }
            let store = Store::new(repeater_root(options, root));
            store.revoke_device(&fingerprint)?;
        }
        RepeaterCommand::Join { code, label } => {
            if code.starts_with("ws://") || code.starts_with("wss://") {
                return request_join(code, label, options, output).await;
            }
            let parsed = invite::decode(&code)?;
            validate_label(label.as_deref())?;
            let host = websocket_host(&parsed.url)?.to_owned();
            let root = options.data_root();
            let static_private = match crate::identity::read_saved(&root)? {
                Some((_, static_private)) => static_private,
                None => {
                    let identity = crate::identity::claim(&root)?;
                    if !identity.persistent {
                        bail!("a persistent particle identity is required to join a repeater");
                    }
                    identity.static_private
                }
            };
            let device_public = entangle_transport::public_key(&static_private);
            client::enroll(
                &parsed.url,
                static_private,
                parsed.repeater_public_key,
                parsed.secret,
                label.as_deref(),
            )
            .await
            .with_context(|| format!("could not join the Quantum Repeater at {host}"))?;
            let config = RepeaterConfig {
                url: parsed.url,
                repeater_public_key: hex::encode(parsed.repeater_public_key),
            };
            write_private_json(&options.data_root().join("repeater.json"), &config)
                .with_context(|| format!("could not join the Quantum Repeater at {host}"))?;
            writeln!(
                output,
                "{}",
                join_summary(&host, &parsed.repeater_public_key, &device_public)
            )?;
        }
        RepeaterCommand::Approve { root } => {
            return approve_request(repeater_root(options, root), output);
        }
        RepeaterCommand::Status => {
            let path = options.data_root().join("repeater.json");
            if let Some(bytes) = read_regular_file(&path)? {
                let config: RepeaterConfig = serde_json::from_slice(&bytes)?;
                let public: [u8; 32] = hex::decode(config.repeater_public_key)?
                    .try_into()
                    .map_err(|_| anyhow!("invalid repeater configuration"))?;
                writeln!(output, "configured: yes")?;
                writeln!(output, "url host: {}", websocket_host(&config.url)?)?;
                writeln!(
                    output,
                    "repeater fingerprint: {}",
                    short_fingerprint(&public)
                )?;
            } else {
                writeln!(output, "configured: no")?;
            }
        }
        RepeaterCommand::Leave => {
            let path = options.data_root().join("repeater.json");
            reject_symlink_components(&path)?;
            let summary = match fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_file() => {
                    fs::remove_file(path)?;
                    leave_summary(true)
                }
                Ok(_) => bail!("repeater configuration is not a regular file"),
                Err(error) if error.kind() == io::ErrorKind::NotFound => leave_summary(false),
                Err(error) => return Err(error.into()),
            };
            writeln!(output, "{summary}")?;
        }
    }
    Ok(0)
}

fn truncate_label(mut label: String) -> String {
    if label.len() <= 64 {
        return label;
    }
    let mut end = 64;
    while !label.is_char_boundary(end) {
        end -= 1;
    }
    label.truncate(end);
    label
}

async fn request_join(
    url: String,
    label: Option<String>,
    options: &crate::config::Options,
    output: &mut dyn Write,
) -> Result<i32> {
    let host = websocket_host(&url)?.to_owned();
    validate_label(label.as_deref())?;
    let root = options.data_root();
    let static_private = match crate::identity::read_saved(&root)? {
        Some((_, private)) => private,
        None => {
            let identity = crate::identity::claim(&root)?;
            if !identity.persistent {
                bail!("a persistent particle identity is required to request repeater enrollment");
            }
            identity.static_private
        }
    };
    let device_public = entangle_transport::public_key(&static_private);
    let label = label.map(truncate_label).or_else(|| {
        crate::identity::read_saved(&root)
            .ok()
            .flatten()
            .map(|(id, _)| truncate_label(options.particle_name(&id)))
    });
    validate_label(label.as_deref())?;
    let (sas_tx, mut sas_rx) = tokio::sync::oneshot::channel();
    let request_url = url.clone();
    let request = client::request(
        &request_url,
        static_private,
        label.as_deref(),
        move |public, sas| {
            let _ = sas_tx.send((public, sas));
        },
    );
    tokio::pin!(request);
    let mut printed = false;
    let mut sas_closed = false;
    let outcome = loop {
        tokio::select! {
            biased;
            received = &mut sas_rx, if !printed && !sas_closed => {
                match received {
                    Ok((public, _sas)) => {
                        writeln!(
                            output,
                            "{}",
                            request_waiting_message(&host, &public, &device_public)
                        )?;
                        output.flush()?;
                        printed = true;
                    }
                    Err(_) => sas_closed = true,
                }
            }
            result = &mut request => break result,
        }
    };
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(client::ClientError::Busy) => bail!("the repeater has too many pending requests; try again shortly"),
        Err(error) => {
            return Err(anyhow!(error).context(format!(
                "could not ask the Quantum Repeater at {host} to enroll this device; it may be older than 0.5.0 or started with --no-requests; ask its operator for an invite code instead"
            )))
        }
    };
    match outcome {
        client::RequestOutcome::Denied => {
            writeln!(output, "The host denied this request. Nothing was saved.")?;
            Ok(1)
        }
        client::RequestOutcome::Approved { repeater_public } => {
            let config = RepeaterConfig {
                url,
                repeater_public_key: hex::encode(repeater_public),
            };
            write_private_json(&options.data_root().join("repeater.json"), &config).with_context(
                || format!("could not ask the Quantum Repeater at {host} to enroll this device"),
            )?;
            writeln!(
                output,
                "{}",
                join_summary(&host, &repeater_public, &device_public)
            )?;
            Ok(0)
        }
    }
}

fn request_age(requested_at: &str) -> String {
    let seconds = chrono::DateTime::parse_from_rfc3339(requested_at)
        .ok()
        .map(|time| {
            (chrono::Utc::now() - time.with_timezone(&chrono::Utc))
                .num_seconds()
                .max(0)
        })
        .unwrap_or(0);
    if seconds < 60 {
        format!("{seconds}s")
    } else {
        format!("{}m", seconds / 60)
    }
}

fn approval_prompt(
    request: &entangle_repeater::store::EnrollmentRequest,
    age: &str,
    repeater_public: &[u8; 32],
) -> Result<String> {
    let public: [u8; 32] = hex::decode(&request.key)?
        .try_into()
        .map_err(|_| anyhow!("invalid request key"))?;
    let label = request.label.as_deref().unwrap_or("(unnamed)");
    let device = request.label.as_deref().unwrap_or("this device");
    Ok(format!(
        "{label} from {}, {age} ago\nDevice fingerprint: {}\nRepeater fingerprint: {}\nDoes `entangle repeater join` on {device} show these two fingerprints? Approve? [y/n] ",
        request.source,
        long_fingerprint(&public),
        long_fingerprint(repeater_public)
    ))
}

fn approve_request(root: PathBuf, output: &mut dyn Write) -> Result<i32> {
    let store = Store::new(root);
    let now = chrono::Utc::now();
    let requests = store
        .requests()?
        .into_iter()
        .filter(|request| {
            chrono::DateTime::parse_from_rfc3339(&request.requested_at)
                .map(|time| {
                    now.signed_duration_since(time.with_timezone(&chrono::Utc))
                        .num_seconds()
                        <= 600
                })
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    if requests.is_empty() {
        writeln!(output, "No enrollment requests are waiting.")?;
        return Ok(1);
    }
    let request = if requests.len() == 1 {
        requests[0].clone()
    } else {
        for (index, request) in requests.iter().enumerate() {
            let public: [u8; 32] = hex::decode(&request.key)?
                .try_into()
                .map_err(|_| anyhow!("invalid request key"))?;
            writeln!(
                output,
                "{}) {} {} from {}, {} ago",
                index + 1,
                request.label.as_deref().unwrap_or("(unnamed)"),
                short_fingerprint(&public),
                request.source,
                request_age(&request.requested_at)
            )?;
        }
        let mut invalid = 0;
        loop {
            write!(output, "Press 1-{}: ", requests.len())?;
            output.flush()?;
            match read_approval_key(requests.len() as u8)? {
                KeyOutcome::Pick(value) => {
                    writeln!(output, "{value}")?;
                    break requests[usize::from(value - 1)].clone();
                }
                KeyOutcome::Cancel => return cancel_approval(output),
                KeyOutcome::Invalid => {
                    invalid += 1;
                    writeln!(output, "\r\nPress a number from 1 to {}.", requests.len())?;
                    if invalid == 3 {
                        return cancel_approval(output);
                    }
                }
                KeyOutcome::Ignore => unreachable!(),
            }
        }
    };
    let repeater_public = entangle_transport::public_key(&store.key()?);
    let mut invalid = 0;
    let approved = loop {
        let prompt = approval_prompt(
            &request,
            &request_age(&request.requested_at),
            &repeater_public,
        )?;
        output.write_all(prompt.as_bytes())?;
        output.flush()?;
        match read_yes_no_key()? {
            YesNo::Yes => {
                writeln!(output, "y")?;
                break true;
            }
            YesNo::No => {
                writeln!(output, "n")?;
                break false;
            }
            YesNo::Cancel => return cancel_approval(output),
            YesNo::Invalid => {
                invalid += 1;
                writeln!(
                    output,
                    "\r\nPress y to approve, n to deny, or Esc to cancel."
                )?;
                if invalid == 3 {
                    return cancel_approval(output);
                }
            }
            YesNo::Ignore => unreachable!(),
        }
    };
    let still_pending = store.requests()?.contains(&request)
        && chrono::DateTime::parse_from_rfc3339(&request.requested_at)
            .map(|time| {
                chrono::Utc::now()
                    .signed_duration_since(time.with_timezone(&chrono::Utc))
                    .num_seconds()
                    <= 600
            })
            .unwrap_or(false);
    if !still_pending {
        writeln!(output, "This enrollment request expired or was cancelled.")?;
        return Ok(1);
    }
    let key: [u8; 32] = hex::decode(&request.key)?
        .try_into()
        .map_err(|_| anyhow!("invalid request key"))?;
    store.decide_device(key, request.label.clone(), approved)?;
    let public: [u8; 32] = key;
    if approved {
        writeln!(
            output,
            "Approved {} ({}). It is enrolled now.",
            request.label.as_deref().unwrap_or("(unnamed)"),
            short_fingerprint(&public)
        )?;
        Ok(0)
    } else {
        writeln!(
            output,
            "Denied {} ({}).",
            request.label.as_deref().unwrap_or("(unnamed)"),
            short_fingerprint(&public)
        )?;
        Ok(1)
    }
}

fn write_private_json<T: Serialize>(path: &std::path::Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("missing configuration parent"))?;
    reject_symlink_components(path)?;
    fs::create_dir_all(parent)?;
    reject_symlink_components(path)?;
    match fs::symlink_metadata(parent) {
        Ok(meta) if meta.file_type().is_dir() => {}
        _ => bail!("repeater configuration directory is not a regular directory"),
    }
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => {}
        Ok(_) => bail!("repeater configuration path is not a regular file"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let temporary = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        CONFIG_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
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
        file.write_all(&serde_json::to_vec_pretty(value)?)?;
        file.sync_all()?;
        replace_private_file(&temporary, path)?;
        Ok::<_, anyhow::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn replace_private_file(
    temporary: &std::path::Path,
    destination: &std::path::Path,
) -> io::Result<()> {
    fs::rename(temporary, destination)
}

fn read_regular_file(path: &std::path::Path) -> Result<Option<Vec<u8>>> {
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
        Ok(_) => bail!("repeater configuration path is not a regular file"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn reject_symlink_components(path: &Path) -> Result<()> {
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
                bail!("repeater configuration path contains a symlink");
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
    use super::{
        approval_prompt, classify_yes_no, join_summary, leave_summary, long_fingerprint,
        request_waiting_message, short_fingerprint, YesNo,
    };
    use crossterm::event::{KeyCode, KeyModifiers, ModifierKeyCode};
    use entangle_repeater::store::EnrollmentRequest;

    #[test]
    fn repeater_short_fingerprint_matches_known_sha256() {
        assert_eq!(short_fingerprint(&[0; 32]), "66687aad");
    }

    #[test]
    fn repeater_long_fingerprint_matches_known_sha256() {
        assert_eq!(long_fingerprint(&[0; 32]), "6668 7aad f862 bd77");
    }

    #[test]
    fn request_waiting_message_shows_device_fingerprint() {
        assert_eq!(
            request_waiting_message("relay.example", &[1; 32], &[0; 32]),
            "Asked the Quantum Repeater at relay.example to enroll this device (repeater fingerprint 72cd6e84).\nThis device's fingerprint: 6668 7aad f862 bd77\nRepeater fingerprint: 72cd 6e84 22c4 07fb\nOn the host, run `entangle repeater approve` and check that it shows the same two fingerprints.\nWaiting for the host to decide (up to 10 minutes; Ctrl+C cancels)..."
        );
    }

    fn request(label: Option<&str>) -> EnrollmentRequest {
        EnrollmentRequest {
            key: hex::encode([0; 32]),
            label: label.map(str::to_owned),
            source: "192.0.2.7".to_owned(),
            requested_at: "2025-01-01T00:00:00Z".to_owned(),
            sas: [1, 2, 3],
        }
    }

    #[test]
    fn approval_prompt_shows_label_source_and_fingerprint() {
        assert_eq!(
            approval_prompt(&request(Some("alice")), "3s", &[1; 32]).unwrap(),
            "alice from 192.0.2.7, 3s ago\nDevice fingerprint: 6668 7aad f862 bd77\nRepeater fingerprint: 72cd 6e84 22c4 07fb\nDoes `entangle repeater join` on alice show these two fingerprints? Approve? [y/n] "
        );
    }

    #[test]
    fn approval_prompt_uses_device_for_unlabelled_request() {
        assert_eq!(
            approval_prompt(&request(None), "4s", &[1; 32]).unwrap(),
            "(unnamed) from 192.0.2.7, 4s ago\nDevice fingerprint: 6668 7aad f862 bd77\nRepeater fingerprint: 72cd 6e84 22c4 07fb\nDoes `entangle repeater join` on this device show these two fingerprints? Approve? [y/n] "
        );
    }

    #[test]
    fn yes_no_classification_handles_approval_denial_and_cancellation() {
        assert_eq!(
            classify_yes_no(KeyCode::Char('y'), KeyModifiers::NONE),
            YesNo::Yes
        );
        assert_eq!(
            classify_yes_no(KeyCode::Char('Y'), KeyModifiers::NONE),
            YesNo::Yes
        );
        assert_eq!(
            classify_yes_no(KeyCode::Char('n'), KeyModifiers::NONE),
            YesNo::No
        );
        assert_eq!(
            classify_yes_no(KeyCode::Char('N'), KeyModifiers::NONE),
            YesNo::No
        );
        assert_eq!(
            classify_yes_no(KeyCode::Esc, KeyModifiers::NONE),
            YesNo::Cancel
        );
        assert_eq!(
            classify_yes_no(KeyCode::Char('q'), KeyModifiers::NONE),
            YesNo::Cancel
        );
        assert_eq!(
            classify_yes_no(KeyCode::Char('Q'), KeyModifiers::NONE),
            YesNo::Cancel
        );
        assert_eq!(
            classify_yes_no(KeyCode::Char('c'), KeyModifiers::CONTROL),
            YesNo::Cancel
        );
        assert_eq!(
            classify_yes_no(KeyCode::Char('x'), KeyModifiers::NONE),
            YesNo::Invalid
        );
        assert_eq!(
            classify_yes_no(KeyCode::Enter, KeyModifiers::NONE),
            YesNo::Invalid
        );
        assert_eq!(
            classify_yes_no(
                KeyCode::Modifier(ModifierKeyCode::LeftShift),
                KeyModifiers::NONE
            ),
            YesNo::Ignore
        );
    }

    #[test]
    fn repeater_join_summary_reports_both_fingerprints() {
        let repeater_public = [0; 32];
        let device_public = [1; 32];
        let repeater_fingerprint = short_fingerprint(&repeater_public);
        let device_fingerprint = short_fingerprint(&device_public);

        let summary = join_summary("relay.example", &repeater_public, &device_public);
        assert_eq!(
            summary,
            format!(
                "Joined the Quantum Repeater at relay.example (repeater fingerprint {repeater_fingerprint}).\nThis device's fingerprint: {device_fingerprint} (listed by `entangle repeater devices` on the host).\nA running Entangle node connects within 30 seconds; check with `entangle repeater status`."
            )
        );
        assert_eq!(
            summary,
            "Joined the Quantum Repeater at relay.example (repeater fingerprint 66687aad).\nThis device's fingerprint: 72cd6e84 (listed by `entangle repeater devices` on the host).\nA running Entangle node connects within 30 seconds; check with `entangle repeater status`."
        );
    }

    #[test]
    fn repeater_leave_summary_covers_removed_and_missing_config() {
        assert_eq!(
            leave_summary(true),
            "Left the Quantum Repeater: removed this device's saved configuration. The host keeps this device enrolled until it is revoked there."
        );
        assert_eq!(
            leave_summary(false),
            "This device has not joined a Quantum Repeater; nothing to remove."
        );
    }
}
