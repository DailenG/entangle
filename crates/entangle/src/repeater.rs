//! Host and device administration for the Quantum Repeater.

use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;
use entangle_core::sas;
use entangle_repeater::{client, invite, server, store::Store};
use rand::seq::SliceRandom;
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
            let mut devices = store.devices()?;
            let matches = devices
                .devices
                .keys()
                .filter(|key| {
                    hex::decode(key)
                        .ok()
                        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                        .is_some_and(|public| short_fingerprint(&public).starts_with(&fingerprint))
                })
                .cloned()
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                bail!("fingerprint must match exactly one device");
            }
            devices.devices.get_mut(&matches[0]).unwrap().revoked = true;
            store.save_devices(&devices)?;
        }
        RepeaterCommand::Join { code, label } => {
            if code.starts_with("ws://") || code.starts_with("wss://") {
                return request_join(code, label, options, output).await;
            }
            let parsed = invite::decode(&code)?;
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
                None,
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
                    Ok((public, sas)) => {
                        writeln!(output, "Asked the Quantum Repeater at {host} to enroll this device (repeater fingerprint {}).", short_fingerprint(&public))?;
                        writeln!(output, "On the host, run `entangle repeater approve` and pick:")?;
                        writeln!(output, "{}", sas::render(sas))?;
                        writeln!(output, "Waiting for the host to decide (up to 10 minutes; Ctrl+C cancels)...")?;
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
            match crate::peer::read_approval_key(requests.len() as u8)? {
                crate::peer::KeyOutcome::Pick(value) => {
                    break requests[usize::from(value - 1)].clone()
                }
                crate::peer::KeyOutcome::Cancel => return crate::peer::cancel_approval(output),
                crate::peer::KeyOutcome::Invalid => {
                    invalid += 1;
                    writeln!(output, "\r\nPress a number from 1 to {}.", requests.len())?;
                    if invalid == 3 {
                        return crate::peer::cancel_approval(output);
                    }
                }
                crate::peer::KeyOutcome::Ignore => unreachable!(),
            }
        }
    };
    writeln!(
        output,
        "On {}, which set does `entangle repeater join` show?",
        request.label.as_deref().unwrap_or("(unnamed)")
    )?;
    let real = request.sas;
    let mut sets = sas::decoys(real, &mut rand::thread_rng())
        .into_iter()
        .collect::<Vec<_>>();
    sets.push(real);
    sets.shuffle(&mut rand::thread_rng());
    for (index, set) in sets.iter().enumerate() {
        writeln!(output, "{}) {}", index + 1, sas::render(*set))?;
    }
    writeln!(output, "5) none of these")?;
    let mut invalid = 0;
    let choice = loop {
        write!(output, "Press 1-5: ")?;
        output.flush()?;
        match crate::peer::read_approval_key(5)? {
            crate::peer::KeyOutcome::Pick(value) => break usize::from(value),
            crate::peer::KeyOutcome::Cancel => return crate::peer::cancel_approval(output),
            _ => {
                invalid += 1;
                writeln!(output, "\r\nPress a number from 1 to 5.")?;
                if invalid == 3 {
                    return crate::peer::cancel_approval(output);
                }
            }
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
    let approved = choice != 5 && sets[choice - 1] == real;
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
    use super::{join_summary, leave_summary, short_fingerprint};

    #[test]
    fn repeater_short_fingerprint_matches_known_sha256() {
        assert_eq!(short_fingerprint(&[0; 32]), "66687aad");
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
