//! Entangle binary entry point: particle orchestration, MCP, and CLI commands.

mod config;
mod field;
mod groups;
mod identity;
mod inbox;
mod node;
mod peer;
mod private_fs;
mod repeater;
mod tools;

use anyhow::Result;
use chrono::{SecondsFormat, Utc};
use clap::{Parser, Subcommand};
use config::Options;
use groups::{Member, Role};
use sha2::Digest;
use std::{
    io::{self, IsTerminal, Write},
    process::ExitCode,
    time::Duration,
};
use tracing_subscriber::EnvFilter;

/// Entangle local agent collaboration server.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Command to run; omitting it starts `serve`.
    #[command(subcommand)]
    command: Option<Command>,
    /// Common particle and network settings.
    #[command(flatten)]
    options: Options,
}

/// Supported Entangle commands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Run a particle node with MCP over stdio (the default).
    Serve,
    /// Run a node without MCP for diagnostics.
    Node,
    /// Browse for particles once and print the results.
    Scan {
        /// Seconds to browse for.
        #[arg(long, default_value_t = 3)]
        timeout_secs: u64,
        /// Print JSON instead of a text table.
        #[arg(long)]
        json: bool,
    },
    /// Manage this machine's groups.
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
    /// Inspect known group members.
    Peer {
        #[command(subcommand)]
        command: peer::PeerCommand,
    },
    /// Manage Quantum Repeater host and device enrollment.
    Repeater {
        #[command(subcommand)]
        command: repeater::RepeaterCommand,
    },
}

/// Group operations.
#[derive(Debug, Subcommand)]
enum GroupCommand {
    /// Create a group for this machine.
    Create { name: String },
    /// List this machine's groups.
    List {
        #[arg(long)]
        json: bool,
    },
    /// List members of a group.
    Members {
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// Leave a group.
    Leave { name: String },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if is_broken_pipe(&error) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:?}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_new(&cli.options.log_level).unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    if cli.options.relay_port.is_some()
        || cli.options.advertise_ip.is_some()
        || cli.options.legacy_transfer_path.is_some()
    {
        tracing::warn!("{}", concat!("ignored since 0.2: cr", "oc was removed"));
    }
    match cli.command.unwrap_or(Command::Serve) {
        Command::Scan { timeout_secs, json } => {
            let peers = entangle_resonance::scan(Duration::from_secs(timeout_secs)).await?;
            let mut output = io::stdout().lock();
            if json {
                writeln!(output, "{}", serde_json::to_string_pretty(&peers)?)?;
            } else if peers.is_empty() {
                writeln!(output, "No particles found.")?;
            } else {
                writeln!(
                    output,
                    "{:<10} {:<24} {:<40} PORT  GROUP     CONTEXT",
                    "PARTICLE", "NAME", "ADDRESSES"
                )?;
                for peer in peers {
                    let addresses = peer
                        .addrs
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",");
                    writeln!(
                        output,
                        "{:<10} {:<24} {:<40} {:<5} {:<20} {}",
                        peer.particle_id.short(),
                        peer.name,
                        addresses,
                        peer.port,
                        peer.groups.join(","),
                        peer.context.unwrap_or_default()
                    )?;
                }
            }
        }
        Command::Group { command } => {
            let mut output = io::stdout().lock();
            let code = run_group(command, &cli.options, &mut output)?;
            if code != 0 {
                std::process::exit(code);
            }
        }
        Command::Peer { command } => {
            let data_root = cli.options.data_root();
            let mut output = io::stdout().lock();
            let exit_code = peer::run(command, &data_root, &mut output)?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }
        Command::Repeater { command } => {
            let mut output = io::stdout().lock();
            let exit_code = repeater::run(command, &cli.options, &mut output).await?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }
        Command::Node => {
            let (node, _) = node::Particle::start(cli.options, None).await?;
            node.wait_for_shutdown().await;
            node.shutdown().await;
        }
        Command::Serve => {
            let (notify_tx, notify_rx) = tokio::sync::mpsc::channel(64);
            let (node, _) = node::Particle::start(cli.options, Some(notify_tx)).await?;
            let backend = tools::ParticleTools::new(node.clone());
            let server = entangle_mcp::Server::new(std::sync::Arc::new(backend), notify_rx);
            tokio::select! {
                _ = server.serve(tokio::io::stdin(), tokio::io::stdout()) => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            node.shutdown().await;
        }
    }
    Ok(())
}

fn is_broken_pipe(error: &anyhow::Error) -> bool {
    error.chain().last().is_some_and(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == io::ErrorKind::BrokenPipe)
    })
}

fn run_group(command: GroupCommand, options: &Options, output: &mut dyn Write) -> Result<i32> {
    let data_root = options.data_root();
    if matches!(
        &command,
        GroupCommand::Create { .. } | GroupCommand::Leave { .. }
    ) && !(io::stdin().is_terminal() && io::stdout().is_terminal())
    {
        writeln!(
            output,
            "This is a human-only command and requires an interactive terminal."
        )?;
        return Ok(2);
    }
    match command {
        GroupCommand::Create { name } => {
            let Some((id, static_private)) = identity::read_saved(&data_root)? else {
                return Err(groups::GroupError::MissingIdentity(data_root).into());
            };
            let particle_id = id.to_string();
            let particle_name = options.particle_name(&id);
            let member = Member {
                particle_id: particle_id.clone(),
                name: particle_name,
                static_key: hex::encode(entangle_transport::public_key(&static_private)),
                added_by: particle_id,
                added_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            };
            let group = groups::create(&data_root, &name, member)?;
            writeln!(
                output,
                "Created group {} ({}). You are its admin.",
                group.meta.name, group.id
            )?;
            writeln!(
                output,
                "Next: run `entangle group invite {}` here, then `entangle group join <code>` on each other device.",
                group.meta.name
            )?;
        }
        GroupCommand::List { json } => {
            let groups = groups::list(&data_root)?;
            if json {
                let rows = groups
                    .iter()
                    .map(|group| {
                        serde_json::json!({
                            "name": &group.meta.name,
                            "group": &group.id,
                            "role": role_name(&group.meta.role),
                            "members": group.members.len(),
                        })
                    })
                    .collect::<Vec<_>>();
                writeln!(output, "{}", serde_json::to_string_pretty(&rows)?)?;
            } else if groups.is_empty() {
                writeln!(output, "This machine isn't in any group yet. Run `entangle group create <name>` or `entangle group join <code>`.")?;
            } else {
                writeln!(output, "NAME  GROUP  ROLE  MEMBERS")?;
                for group in groups {
                    writeln!(
                        output,
                        "{}  {}  {}  {}",
                        group.meta.name,
                        group.id,
                        role_name(&group.meta.role),
                        group.members.len()
                    )?;
                }
            }
        }
        GroupCommand::Members { name, json } => {
            let group = groups::find(&data_root, &name)?
                .ok_or_else(|| groups::GroupError::NotFound(name.clone()))?;
            let self_id = identity::read_saved(&data_root)?.map(|(id, _)| id.to_string());
            let rows = group.members.iter().map(|member| {
                let key = hex::decode(&member.static_key).unwrap_or_default();
                let fingerprint = if key.len() == 32 {
                    hex::encode(&sha2::Sha256::digest(&key)[..4])
                } else {
                    "invalid".into()
                };
                let is_self = self_id.as_deref() == Some(&member.particle_id);
                serde_json::json!({
                    "name": if is_self { format!("{} (this machine)", member.name) } else { member.name.clone() },
                    "particle_id": &member.particle_id,
                    "fingerprint": fingerprint,
                    "added_by": &member.added_by,
                    "this_machine": is_self,
                })
            }).collect::<Vec<_>>();
            if json {
                writeln!(output, "{}", serde_json::to_string_pretty(&rows)?)?;
            } else {
                writeln!(output, "NAME  PARTICLE(short)  FINGERPRINT  ADDED BY")?;
                for (row, member) in rows.iter().zip(&group.members) {
                    let name = row["name"].as_str().unwrap_or_default();
                    writeln!(
                        output,
                        "{}  {}  {}  {}",
                        name,
                        short_particle_id(&member.particle_id),
                        row["fingerprint"].as_str().unwrap_or_default(),
                        short_particle_id(row["added_by"].as_str().unwrap_or_default())
                    )?;
                }
            }
        }
        GroupCommand::Leave { name } => {
            let group = groups::find(&data_root, &name)?
                .ok_or_else(|| groups::GroupError::NotFound(name.clone()))?;
            write!(
                output,
                "Leave group {} ({})? This deletes its key from this machine. [y/N] ",
                group.meta.name, group.id
            )?;
            output.flush()?;
            if peer::read_confirmation_key()? {
                groups::leave(&data_root, &name)?;
                writeln!(output, "Left group {}.", group.meta.name)?;
            } else {
                writeln!(output, "Cancelled; still in {}.", group.meta.name)?;
            }
        }
    }
    Ok(0)
}

fn role_name(role: &Role) -> &'static str {
    match role {
        Role::Admin => "admin",
        Role::Member => "member",
    }
}

fn short_particle_id(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(data_root: &std::path::Path) -> Options {
        Options {
            name: Some("local".into()),
            context: None,
            link_port: 7337,
            relay_port: None,
            advertise_ip: None,
            peer: Vec::new(),
            data_dir: Some(data_root.to_path_buf()),
            legacy_transfer_path: None,
            max_payload_mb: 512,
            no_mdns: true,
            relay_only: false,
            log_level: "warn".into(),
        }
    }

    #[test]
    fn detects_broken_pipe_root_cause() {
        let error = anyhow::Error::new(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
        assert!(is_broken_pipe(&error));
    }

    #[test]
    fn group_list_and_members_render_text_and_json() {
        let temp = tempfile::tempdir().unwrap();
        let options = options(temp.path());
        let identity = identity::claim(temp.path()).unwrap();
        let local_id = identity.id.to_string();
        let local_key = identity.static_private;
        drop(identity);
        let remote_id = entangle_core::ParticleId::generate().to_string();
        let members = vec![
            Member {
                particle_id: local_id.clone(),
                name: "local".into(),
                static_key: hex::encode(entangle_transport::public_key(&local_key)),
                added_by: local_id,
                added_at: "2026-10-12T00:00:00Z".into(),
            },
            Member {
                particle_id: remote_id.clone(),
                name: "remote".into(),
                static_key: hex::encode(entangle_transport::public_key(&[0x42; 32])),
                added_by: remote_id,
                added_at: "2026-10-12T00:00:00Z".into(),
            },
        ];
        groups::insert(
            temp.path(),
            [0x24; 32],
            groups::GroupMeta {
                version: 1,
                name: "work".into(),
                role: Role::Admin,
                created_at: "2026-10-12T00:00:00Z".into(),
            },
            members,
        )
        .unwrap();

        let mut text = Vec::new();
        assert_eq!(
            run_group(GroupCommand::List { json: false }, &options, &mut text).unwrap(),
            0
        );
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("NAME  GROUP  ROLE  MEMBERS"));
        assert!(text.contains("work"));
        assert!(text.contains("admin"));

        let mut json = Vec::new();
        run_group(GroupCommand::List { json: true }, &options, &mut json).unwrap();
        let rows: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(rows[0]["name"], "work");
        assert_eq!(rows[0]["members"], 2);
        assert!(rows[0].get("key").is_none());

        let mut text = Vec::new();
        run_group(
            GroupCommand::Members {
                name: "work".into(),
                json: false,
            },
            &options,
            &mut text,
        )
        .unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("PARTICLE(short)"));
        assert!(text.contains("local (this machine)"));
        assert!(text.contains("remote"));

        let mut json = Vec::new();
        run_group(
            GroupCommand::Members {
                name: "work".into(),
                json: true,
            },
            &options,
            &mut json,
        )
        .unwrap();
        let rows: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 2);
        assert_eq!(
            rows.as_array()
                .unwrap()
                .iter()
                .find(|row| row["this_machine"] == true)
                .unwrap()["name"],
            "local (this machine)"
        );
        assert!(rows.to_string().find("key").is_none());
    }

    #[test]
    fn group_create_and_leave_refuse_non_interactive_use() {
        let temp = tempfile::tempdir().unwrap();
        let options = options(temp.path());
        for command in [
            GroupCommand::Create {
                name: "work".into(),
            },
            GroupCommand::Leave {
                name: "work".into(),
            },
        ] {
            let mut output = Vec::new();
            assert_eq!(run_group(command, &options, &mut output).unwrap(), 2);
            assert!(String::from_utf8(output)
                .unwrap()
                .contains("human-only command"));
        }
    }
}
