//! Human-operated peer approval and agent-safe peer inspection commands.

use crate::{identity, trust};
use anyhow::{anyhow, bail, Result};
use chrono::{SecondsFormat, Utc};
use clap::Subcommand;
use entangle_core::sas;
use rand::seq::SliceRandom;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{self, IsTerminal, Write},
    path::Path,
};

#[derive(Debug, Subcommand)]
pub enum PeerCommand {
    /// List approved and pending peers without revealing SAS values.
    List {
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show this machine's verification card.
    Verify { peer: Option<String> },
    /// Approve a peer after comparing the verification card.
    Approve { peer: Option<String> },
    /// Deny a pending peer.
    Deny { peer: String },
    /// Revoke an existing approval.
    Revoke { peer: String },
    /// Forget all saved state for a peer.
    Forget { peer: String },
    /// Print the versioned SAS emoji table.
    Emoji,
}

#[derive(Serialize)]
struct PeerLine {
    name: String,
    id: String,
    status: String,
    key_fingerprint: String,
}

fn human_only(command: &PeerCommand) -> bool {
    matches!(
        command,
        PeerCommand::Verify { .. }
            | PeerCommand::Approve { .. }
            | PeerCommand::Deny { .. }
            | PeerCommand::Revoke { .. }
            | PeerCommand::Forget { .. }
    )
}

pub fn run(command: PeerCommand, data_root: &Path, local_name: Option<&str>) -> Result<i32> {
    if human_only(&command) && !(io::stdin().is_terminal() && io::stdout().is_terminal()) {
        println!("This command is for the human operator and needs an interactive terminal.");
        return Ok(2);
    }
    if !matches!(command, PeerCommand::Emoji) && identity::read_saved(data_root)?.is_none() {
        if matches!(command, PeerCommand::List { .. }) {
            if matches!(command, PeerCommand::List { json: true }) {
                println!("[]");
            } else {
                println!("No peers are known.");
            }
            return Ok(0);
        }
        bail!("peer approval is unavailable while running on a temporary identity");
    }
    match command {
        PeerCommand::Emoji => {
            println!("index glyph name");
            for (index, (glyph, name)) in sas::EMOJI.iter().enumerate() {
                println!("{index} {glyph} {name}");
            }
        }
        PeerCommand::List { json } => list(data_root, json)?,
        PeerCommand::Verify { peer } => return verify(data_root, peer.as_deref(), local_name),
        PeerCommand::Approve { peer } => return approve(data_root, peer.as_deref(), local_name),
        PeerCommand::Deny { peer } => deny(data_root, &peer)?,
        PeerCommand::Revoke { peer } => revoke(data_root, &peer)?,
        PeerCommand::Forget { peer } => forget(data_root, &peer)?,
    }
    Ok(0)
}

fn records(data_root: &Path) -> Result<Vec<trust::VerificationRecord>> {
    let Some((_, local_private)) = identity::read_saved(data_root)? else {
        return Ok(Vec::new());
    };
    let local_key = hex::encode(entangle_transport::public_key(&local_private));
    Ok(trust::load_verifications(data_root)?
        .into_iter()
        .filter(|record| record.local_key == local_key)
        .collect())
}

fn list(data_root: &Path, json: bool) -> Result<()> {
    let store = trust::load(data_root)?;
    let mut lines = BTreeMap::new();
    for record in records(data_root)? {
        let key = hex::decode(&record.remote_key)?;
        let key: [u8; 32] = key.try_into().map_err(|_| anyhow!("invalid stored key"))?;
        let key_hex = hex::encode(key);
        let status = if store
            .approved
            .get(record.particle_id.as_str())
            .is_some_and(|approval| approval.static_key == key_hex)
        {
            "approved"
        } else if store.denied.contains_key(&key_hex) {
            "denied"
        } else if record.is_complete() {
            "pending"
        } else {
            "verifying"
        };
        lines.insert(
            record.particle_id.to_string(),
            PeerLine {
                name: record.name,
                id: record.particle_id.short().to_owned(),
                status: status.to_owned(),
                key_fingerprint: hex::encode(Sha256::digest(key))[..16].to_owned(),
            },
        );
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&lines.values().collect::<Vec<_>>())?
        );
    } else if lines.is_empty() {
        println!("No peers are known.");
    } else {
        println!(
            "{:<24} {:<8} {:<10} KEY FINGERPRINT",
            "NAME", "ID", "STATUS"
        );
        for peer in lines.values() {
            println!(
                "{:<24} {:<8} {:<10} {}",
                peer.name, peer.id, peer.status, peer.key_fingerprint
            );
        }
    }
    Ok(())
}

fn choose_record(
    data_root: &Path,
    query: Option<&str>,
    include_approved: bool,
) -> Result<trust::VerificationRecord> {
    let store = trust::load(data_root)?;
    let all = records(data_root)?;
    let candidates: Vec<_> = all
        .into_iter()
        .filter(|record| {
            include_approved
                || !store
                    .approved
                    .get(record.particle_id.as_str())
                    .is_some_and(|approval| approval.static_key == record.remote_key)
        })
        .collect();
    let matching = match query {
        Some(query) => candidates
            .into_iter()
            .filter(|record| {
                record.particle_id.as_str() == query
                    || record.particle_id.short() == query
                    || record.name == query
            })
            .collect::<Vec<_>>(),
        None => candidates,
    };
    match matching.as_slice() {
        [record] => Ok(record.clone()),
        [] => bail!("no matching peer is available"),
        many => {
            let choices = many
                .iter()
                .map(|record| format!("{} ({})", record.name, record.particle_id.short()))
                .collect::<Vec<_>>()
                .join(", ");
            bail!("peer is ambiguous; candidates: {choices}")
        }
    }
}

fn verify(data_root: &Path, query: Option<&str>, local_name: Option<&str>) -> Result<i32> {
    let record = choose_record(data_root, query, true)?;
    let Some(sas) = record.sas else {
        println!(
            "Still verifying with {}; keep Entangle running on both machines and retry in a few seconds.",
            record.name
        );
        return Ok(1);
    };
    let local_name = local_name
        .map(str::to_owned)
        .or_else(|| {
            identity::read_saved(data_root)
                .ok()
                .flatten()
                .map(|(id, _)| id.short().to_owned())
        })
        .unwrap_or_else(|| "this machine".into());
    println!("This machine ({local_name}) sees {} as:", record.name);
    println!("{}", sas::render(sas));
    println!(
        "On {}, run `entangle peer approve` and pick this set.",
        record.name
    );
    Ok(0)
}

fn approve(data_root: &Path, query: Option<&str>, local_name: Option<&str>) -> Result<i32> {
    let store = trust::load(data_root)?;
    let mut pending = records(data_root)?
        .into_iter()
        .filter(|record| {
            !store
                .approved
                .get(record.particle_id.as_str())
                .is_some_and(|approval| approval.static_key == record.remote_key)
                && !store.denied.contains_key(&record.remote_key)
        })
        .collect::<Vec<_>>();
    if let Some(query) = query {
        pending.retain(|record| {
            record.particle_id.as_str() == query
                || record.particle_id.short() == query
                || record.name == query
        });
    } else if pending.len() > 1 {
        println!(
            "Several machines are waiting for approval. If you only expected one, deny the others."
        );
        for record in &pending {
            println!("{} ({})", record.name, record.particle_id.short());
        }
        bail!("specify a peer by ID or exact name");
    }
    if pending.len() > 1 {
        let choices = pending
            .iter()
            .map(|record| format!("{} ({})", record.name, record.particle_id.short()))
            .collect::<Vec<_>>()
            .join(", ");
        bail!("peer is ambiguous; candidates: {choices}");
    }
    if pending.len() != 1 {
        bail!("peer is ambiguous or not waiting for approval");
    }
    let record = pending.remove(0);
    let Some(real) = record.sas else {
        println!(
            "Still verifying with {}; keep Entangle running on both machines and retry in a few seconds.",
            record.name
        );
        return Ok(1);
    };
    println!(
        "On {}, run `entangle peer verify` (or look at its approve output). Which set does it show?",
        record.name
    );
    let mut options = sas::decoys(real, &mut rand::thread_rng())
        .into_iter()
        .collect::<Vec<_>>();
    options.push(real);
    options.shuffle(&mut rand::thread_rng());
    for (index, option) in options.iter().enumerate() {
        println!("{}) {}", index + 1, sas::render(*option));
    }
    println!("5) none of these");
    let mut input = String::new();
    let mut choice = None;
    for _ in 0..3 {
        print!("Choose 1-5: ");
        io::stdout().flush()?;
        input.clear();
        io::stdin().read_line(&mut input)?;
        match input.trim().parse::<usize>() {
            Ok(value @ 1..=5) => {
                choice = Some(value);
                break;
            }
            _ => println!("Please enter a number from 1 to 5."),
        }
    }
    let Some(choice) = choice else {
        bail!("too many invalid selections");
    };
    let key: [u8; 32] = hex::decode(&record.remote_key)?
        .try_into()
        .map_err(|_| anyhow!("invalid stored key"))?;
    let mut store = trust::load(data_root)?;
    if choice == 5 || options[choice - 1] != real {
        let reason = if choice == 5 {
            "no match"
        } else {
            "wrong pick"
        };
        store.denied.insert(
            record.remote_key.clone(),
            trust::Denial {
                particle_id: record.particle_id.clone(),
                name: record.name.clone(),
                denied_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                reason: reason.into(),
            },
        );
        trust::save(data_root, &store)?;
        println!("Denied {}.", record.name);
        println!(
            "If that was a mistake, run `entangle peer forget {}` here and verify again.",
            record.particle_id.short()
        );
        return Ok(1);
    }
    store.approved.insert(
        record.particle_id.to_string(),
        trust::Approval {
            name: record.name.clone(),
            static_key: hex::encode(key),
            sas: real,
            approved_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        },
    );
    trust::save(data_root, &store)?;
    println!("Approved {}.", record.name);
    let local = local_name.unwrap_or("this machine");
    println!("{local} sees {} as:", record.name);
    println!("{}", sas::render(real));
    println!(
        "If {} hasn't approved this machine yet, run `entangle peer approve` there and pick:",
        record.name
    );
    println!("{}", sas::render(real));
    Ok(0)
}

fn deny(data_root: &Path, query: &str) -> Result<()> {
    let record = choose_record(data_root, Some(query), false)?;
    let mut store = trust::load(data_root)?;
    store.denied.insert(
        record.remote_key.clone(),
        trust::Denial {
            particle_id: record.particle_id.clone(),
            name: record.name.clone(),
            denied_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            reason: "denied by operator".into(),
        },
    );
    trust::save(data_root, &store)?;
    println!("Denied {}.", record.name);
    Ok(())
}

fn revoke(data_root: &Path, query: &str) -> Result<()> {
    let record = choose_record(data_root, Some(query), true)?;
    let mut store = trust::load(data_root)?;
    store.approved.remove(record.particle_id.as_str());
    store.denied.insert(
        record.remote_key.clone(),
        trust::Denial {
            particle_id: record.particle_id.clone(),
            name: record.name.clone(),
            denied_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            reason: "revoked".into(),
        },
    );
    trust::save(data_root, &store)?;
    println!("Revoked {}.", record.name);
    Ok(())
}

fn forget(data_root: &Path, query: &str) -> Result<()> {
    let record = choose_record(data_root, Some(query), true)?;
    let mut store = trust::load(data_root)?;
    store.approved.remove(record.particle_id.as_str());
    store.denied.remove(&record.remote_key);
    trust::save(data_root, &store)?;
    trust::remove_verification(data_root, &record.particle_id)?;
    println!("Forgot {}.", record.name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_records_are_scoped_to_the_saved_identity_key() {
        let root = tempfile::tempdir().unwrap();
        let local = identity::claim(root.path()).unwrap();
        let remote = entangle_transport::generate_static();
        let record = trust::new_verification(
            entangle_core::ParticleId::generate(),
            "peer".into(),
            entangle_transport::public_key(&local.static_private),
            entangle_transport::public_key(&remote),
        )
        .unwrap();
        trust::save_verification(root.path(), &record).unwrap();
        assert_eq!(records(root.path()).unwrap().len(), 1);

        let stale_local = entangle_transport::generate_static();
        let stale_record = trust::new_verification(
            record.particle_id.clone(),
            record.name.clone(),
            entangle_transport::public_key(&stale_local),
            entangle_transport::public_key(&remote),
        )
        .unwrap();
        trust::save_verification(root.path(), &stale_record).unwrap();
        assert!(records(root.path()).unwrap().is_empty());
    }
}
