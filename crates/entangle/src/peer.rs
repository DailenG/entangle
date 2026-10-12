//! Agent-safe inspection of known group members.

use crate::{groups, identity};
use anyhow::Result;
use crossterm::{
    event::{read, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Write, path::Path};

#[derive(Debug, clap::Subcommand)]
pub enum PeerCommand {
    /// List members of this machine's groups.
    List {
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
}

struct RawModeGuard;

impl RawModeGuard {
    fn enter() -> std::io::Result<Self> {
        enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

pub(crate) fn read_confirmation_key() -> Result<bool> {
    let _raw_mode = RawModeGuard::enter()?;
    loop {
        if let Event::Key(key) = read()? {
            if key.kind == KeyEventKind::Press {
                return Ok(matches!(key.code, KeyCode::Char('y' | 'Y')));
            }
        }
    }
}

#[derive(Serialize)]
struct PeerLine {
    name: String,
    id: String,
    state: &'static str,
    groups: Vec<String>,
    fingerprint: String,
}

pub fn run(command: PeerCommand, data_root: &Path, output: &mut dyn Write) -> Result<i32> {
    match command {
        PeerCommand::List { json } => list(data_root, json, output)?,
    }
    Ok(0)
}

fn list(data_root: &Path, json: bool, output: &mut dyn Write) -> Result<()> {
    let local_id = identity::read_saved(data_root)?.map(|(id, _)| id.to_string());
    let mut peers = BTreeMap::<String, PeerLine>::new();
    for group in groups::list(data_root)? {
        for member in group.members {
            if local_id.as_deref() == Some(&member.particle_id) {
                continue;
            }
            let peer = peers.entry(member.particle_id.clone()).or_insert_with(|| {
                let key = hex::decode(&member.static_key).unwrap_or_default();
                let fingerprint = if key.len() == 32 {
                    hex::encode(&Sha256::digest(&key)[..4])
                } else {
                    "invalid".into()
                };
                PeerLine {
                    name: member.name.clone(),
                    id: member.particle_id.clone(),
                    state: "seen",
                    groups: Vec::new(),
                    fingerprint,
                }
            });
            peer.groups.push(group.meta.name.clone());
        }
    }
    let peers = peers.into_values().collect::<Vec<_>>();
    if json {
        writeln!(output, "{}", serde_json::to_string_pretty(&peers)?)?;
    } else if peers.is_empty() {
        writeln!(output, "No peers are known.")?;
    } else {
        writeln!(output, "NAME  PARTICLE  STATE  GROUPS  FINGERPRINT")?;
        for peer in peers {
            writeln!(
                output,
                "{}  {}  {}  {}  {}",
                peer.name,
                short_id(&peer.id),
                peer.state,
                peer.groups.join(","),
                peer.fingerprint
            )?;
        }
    }
    Ok(())
}

fn short_id(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}
