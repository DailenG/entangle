//! Host and device administration for the Quantum Repeater.

use anyhow::{anyhow, bail, Result};
use clap::Subcommand;
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

#[derive(Debug, Subcommand)]
pub enum RepeaterCommand {
    Serve {
        #[arg(long)]
        listen: std::net::SocketAddr,
        #[arg(long, default_value = "/entangle")]
        path: String,
        #[arg(long)]
        root: Option<PathBuf>,
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
    },
    Status,
    Leave,
}

#[derive(Debug, Deserialize, Serialize)]
struct RepeaterConfig {
    url: String,
    repeater_public_key: String,
}

fn human_only(command: &RepeaterCommand) -> bool {
    matches!(
        command,
        RepeaterCommand::Invite { .. }
            | RepeaterCommand::Revoke { .. }
            | RepeaterCommand::Join { .. }
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

fn websocket_host(url: &str) -> Result<&str> {
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
        RepeaterCommand::Serve { listen, path, root } => {
            let store = Store::new(repeater_root(options, root));
            let key = store.key()?;
            let public = entangle_transport::public_key(&key);
            writeln!(
                output,
                "repeater key fingerprint: {}",
                hex::encode(sha2::Sha256::digest(public))[..8].to_owned()
            )?;
            output.flush()?;
            server::serve(server::ServerConfig {
                listen,
                path,
                root: store.root,
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
            let devices = Store::new(repeater_root(options, root)).devices()?;
            for (key, device) in devices.devices {
                let public: [u8; 32] = hex::decode(key)?
                    .try_into()
                    .map_err(|_| anyhow!("invalid device key"))?;
                writeln!(
                    output,
                    "{} {} {}",
                    hex::encode(sha2::Sha256::digest(public))[..8].to_owned(),
                    device.label.unwrap_or_default(),
                    if device.revoked { "revoked" } else { "active" }
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
                        .map(|bytes| {
                            hex::encode(sha2::Sha256::digest(bytes))[..8].starts_with(&fingerprint)
                        })
                        .unwrap_or(false)
                })
                .cloned()
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                bail!("fingerprint must match exactly one device");
            }
            devices.devices.get_mut(&matches[0]).unwrap().revoked = true;
            store.save_devices(&devices)?;
        }
        RepeaterCommand::Join { code } => {
            let parsed = invite::decode(&code)?;
            websocket_host(&parsed.url)?;
            let identity = crate::identity::claim(&options.data_root())?;
            if !identity.persistent {
                bail!("a persistent particle identity is required to join a repeater");
            }
            client::enroll(
                &parsed.url,
                identity.static_private,
                parsed.repeater_public_key,
                parsed.secret,
                None,
            )
            .await?;
            let config = RepeaterConfig {
                url: parsed.url,
                repeater_public_key: hex::encode(parsed.repeater_public_key),
            };
            write_private_json(&options.data_root().join("repeater.json"), &config)?;
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
                    hex::encode(sha2::Sha256::digest(public))[..8].to_owned()
                )?;
            } else {
                writeln!(output, "configured: no")?;
            }
        }
        RepeaterCommand::Leave => {
            let path = options.data_root().join("repeater.json");
            reject_symlink_components(&path)?;
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_file() => fs::remove_file(path)?,
                Ok(_) => bail!("repeater configuration is not a regular file"),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(0)
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
    #[cfg(windows)]
    if destination.exists() {
        fs::remove_file(destination)?;
    }
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
