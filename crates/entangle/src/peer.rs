//! Human-operated peer approval and agent-safe peer inspection commands.

use crate::{identity, trust};
use anyhow::{anyhow, bail, Result};
use chrono::{SecondsFormat, Utc};
use clap::Subcommand;
use crossterm::{
    event::{read, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode},
};
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

#[derive(Debug, PartialEq, Eq)]
enum KeyOutcome {
    Pick(u8),
    Cancel,
    Invalid,
    Ignore,
}

fn classify_key(code: KeyCode, modifiers: KeyModifiers) -> KeyOutcome {
    match code {
        KeyCode::Esc => KeyOutcome::Cancel,
        KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => KeyOutcome::Cancel,
        KeyCode::Char('1') => KeyOutcome::Pick(1),
        KeyCode::Char('2') => KeyOutcome::Pick(2),
        KeyCode::Char('3') => KeyOutcome::Pick(3),
        KeyCode::Char('4') => KeyOutcome::Pick(4),
        KeyCode::Char('5') => KeyOutcome::Pick(5),
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

fn read_approval_key() -> Result<KeyOutcome> {
    let _raw_mode = RawModeGuard::enter()?;
    loop {
        match classify_event(read()?) {
            KeyOutcome::Ignore => continue,
            outcome => return Ok(outcome),
        }
    }
}

fn cancel_approval(output: &mut dyn Write) -> Result<i32> {
    writeln!(output, "\r\nCancelled; nothing was approved or denied.")?;
    Ok(1)
}

pub fn run(
    command: PeerCommand,
    data_root: &Path,
    local_name: Option<&str>,
    output: &mut dyn Write,
) -> Result<i32> {
    if human_only(&command) && !(io::stdin().is_terminal() && io::stdout().is_terminal()) {
        writeln!(
            output,
            "This command is for the human operator and needs an interactive terminal."
        )?;
        return Ok(2);
    }
    if !matches!(command, PeerCommand::Emoji) && identity::read_saved(data_root)?.is_none() {
        if matches!(command, PeerCommand::List { .. }) {
            if matches!(command, PeerCommand::List { json: true }) {
                writeln!(output, "[]")?;
            } else {
                writeln!(output, "No peers are known.")?;
            }
            return Ok(0);
        }
        bail!("peer approval is unavailable while running on a temporary identity");
    }
    match command {
        PeerCommand::Emoji => {
            writeln!(output, "index glyph name")?;
            for (index, (glyph, name)) in sas::EMOJI.iter().enumerate() {
                writeln!(output, "{index} {glyph} {name}")?;
            }
        }
        PeerCommand::List { json } => list(data_root, json, output)?,
        PeerCommand::Verify { peer } => {
            return verify(data_root, peer.as_deref(), local_name, output)
        }
        PeerCommand::Approve { peer } => {
            return approve(data_root, peer.as_deref(), local_name, output)
        }
        PeerCommand::Deny { peer } => deny(data_root, &peer, output)?,
        PeerCommand::Revoke { peer } => revoke(data_root, &peer, output)?,
        PeerCommand::Forget { peer } => forget(data_root, &peer, output)?,
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

fn list(data_root: &Path, json: bool, output: &mut dyn Write) -> Result<()> {
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
        writeln!(
            output,
            "{}",
            serde_json::to_string_pretty(&lines.values().collect::<Vec<_>>())?
        )?;
    } else if lines.is_empty() {
        writeln!(output, "No peers are known.")?;
    } else {
        writeln!(
            output,
            "{:<24} {:<8} {:<10} KEY FINGERPRINT",
            "NAME", "ID", "STATUS"
        )?;
        for peer in lines.values() {
            writeln!(
                output,
                "{:<24} {:<8} {:<10} {}",
                peer.name, peer.id, peer.status, peer.key_fingerprint
            )?;
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

fn verify(
    data_root: &Path,
    query: Option<&str>,
    local_name: Option<&str>,
    output: &mut dyn Write,
) -> Result<i32> {
    let record = choose_record(data_root, query, true)?;
    let Some(sas) = record.sas else {
        writeln!(
            output,
            "Still verifying with {}; keep Entangle running on both machines and retry in a few seconds.",
            record.name
        )?;
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
    writeln!(
        output,
        "This machine ({local_name}) sees {} as:",
        record.name
    )?;
    writeln!(output, "{}", sas::render(sas))?;
    writeln!(
        output,
        "On {}, run `entangle peer approve` and pick this set.",
        record.name
    )?;
    Ok(0)
}

fn approve(
    data_root: &Path,
    query: Option<&str>,
    local_name: Option<&str>,
    output: &mut dyn Write,
) -> Result<i32> {
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
        writeln!(
            output,
            "Several machines are waiting for approval. If you only expected one, deny the others."
        )?;
        for record in &pending {
            writeln!(output, "{} ({})", record.name, record.particle_id.short())?;
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
        writeln!(
            output,
            "Still verifying with {}; keep Entangle running on both machines and retry in a few seconds.",
            record.name
        )?;
        return Ok(1);
    };
    writeln!(
        output,
        "On {}, run `entangle peer verify` (or look at its approve output). Which set does it show?",
        record.name
    )?;
    let mut options = sas::decoys(real, &mut rand::thread_rng())
        .into_iter()
        .collect::<Vec<_>>();
    options.push(real);
    options.shuffle(&mut rand::thread_rng());
    for (index, option) in options.iter().enumerate() {
        writeln!(output, "{}) {}", index + 1, sas::render(*option))?;
    }
    writeln!(output, "5) none of these")?;
    let mut invalid_keys = 0;
    let choice = loop {
        write!(output, "Press 1-5: ")?;
        output.flush()?;
        match read_approval_key()? {
            KeyOutcome::Pick(value) => {
                writeln!(output, "{value}")?;
                break usize::from(value);
            }
            KeyOutcome::Cancel => return cancel_approval(output),
            KeyOutcome::Invalid => {
                invalid_keys += 1;
                writeln!(output, "\r\nPress a number from 1 to 5.")?;
                if invalid_keys == 3 {
                    return cancel_approval(output);
                }
            }
            KeyOutcome::Ignore => unreachable!("ignored events are filtered by read_approval_key"),
        }
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
        writeln!(output, "Denied {}.", record.name)?;
        writeln!(
            output,
            "If that was a mistake, run `entangle peer forget {}` here and verify again.",
            record.particle_id.short()
        )?;
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
    writeln!(output, "Approved {}.", record.name)?;
    let local = local_name.unwrap_or("this machine");
    writeln!(output, "{local} sees {} as:", record.name)?;
    writeln!(output, "{}", sas::render(real))?;
    writeln!(
        output,
        "If {} hasn't approved this machine yet, run `entangle peer approve` there and pick:",
        record.name
    )?;
    writeln!(output, "{}", sas::render(real))?;
    Ok(0)
}

fn deny(data_root: &Path, query: &str, output: &mut dyn Write) -> Result<()> {
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
    writeln!(output, "Denied {}.", record.name)?;
    Ok(())
}

fn revoke(data_root: &Path, query: &str, output: &mut dyn Write) -> Result<()> {
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
    writeln!(output, "Revoked {}.", record.name)?;
    Ok(())
}

fn forget(data_root: &Path, query: &str, output: &mut dyn Write) -> Result<()> {
    let record = choose_record(data_root, Some(query), true)?;
    let mut store = trust::load(data_root)?;
    store.approved.remove(record.particle_id.as_str());
    store.denied.remove(&record.remote_key);
    trust::save(data_root, &store)?;
    trust::remove_verification(data_root, &record.particle_id)?;
    writeln!(output, "Forgot {}.", record.name)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_keypresses_select_digits_one_through_five() {
        for (code, selection) in [
            (KeyCode::Char('1'), 1),
            (KeyCode::Char('2'), 2),
            (KeyCode::Char('3'), 3),
            (KeyCode::Char('4'), 4),
            (KeyCode::Char('5'), 5),
        ] {
            assert_eq!(
                classify_key(code, KeyModifiers::NONE),
                KeyOutcome::Pick(selection)
            );
        }
    }

    #[test]
    fn approval_keypresses_cancel_or_reject_other_keys() {
        assert_eq!(
            classify_key(KeyCode::Esc, KeyModifiers::NONE),
            KeyOutcome::Cancel
        );
        assert_eq!(
            classify_key(KeyCode::Char('c'), KeyModifiers::CONTROL),
            KeyOutcome::Cancel
        );
        for code in [
            KeyCode::Char('0'),
            KeyCode::Char('6'),
            KeyCode::Char('a'),
            KeyCode::Char('c'),
            KeyCode::Char('z'),
            KeyCode::Enter,
        ] {
            assert_eq!(classify_key(code, KeyModifiers::NONE), KeyOutcome::Invalid);
        }
    }

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
