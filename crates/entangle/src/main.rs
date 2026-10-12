//! Entangle binary entry point: particle orchestration, MCP, and CLI commands.

mod config;
mod field;
mod groups;
mod identity;
mod inbox;
mod invite;
mod node;
mod peer;
mod private_fs;
mod repeater;
mod tools;

use anyhow::Result;
use chrono::{SecondsFormat, Utc};
use clap::{Parser, Subcommand};
use config::Options;
use groups::Member;
use invite::{
    code::InviteCode,
    protocol::{self, InviteEnd, InviteError, InviteServer, InviteState},
};
use sha2::Digest;
use std::{
    future::Future,
    io::{self, IsTerminal, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::ExitCode,
    time::Duration,
};
use tokio::{net::TcpListener, task::JoinSet};
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
    Create {
        #[arg(id = "group_name", value_name = "NAME")]
        name: String,
        /// Start an invite for 1–20 additional machines.
        #[arg(long)]
        invite: Option<u8>,
    },
    /// Invite devices to join a group.
    Invite {
        #[arg(id = "group_name", value_name = "NAME")]
        name: String,
        #[arg(long, default_value_t = 1)]
        count: u8,
    },
    /// Join a group with a one-time invite code.
    Join {
        code: String,
        /// Local group name to use instead of the inviter's name.
        #[arg(long = "as")]
        local_name: Option<String>,
        /// Connect directly instead of using mDNS.
        #[arg(long)]
        via: Option<String>,
    },
    /// List this machine's groups.
    List {
        #[arg(long)]
        json: bool,
    },
    /// List members of a group.
    Members {
        #[arg(id = "group_name", value_name = "NAME")]
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// Leave a group.
    Leave {
        #[arg(id = "group_name", value_name = "NAME")]
        name: String,
    },
    /// Remove a member and rotate the group's key.
    Remove {
        #[arg(id = "group_name", value_name = "NAME")]
        name: String,
        member: String,
    },
    /// Rotate the group's key.
    Rekey {
        #[arg(id = "group_name", value_name = "NAME")]
        name: String,
    },
    /// Transfer group administration to a member.
    Admin {
        #[arg(id = "group_name", value_name = "NAME")]
        name: String,
        member: String,
    },
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
            let code = run_group(command, &cli.options, &mut output).await?;
            if code != 0 {
                output.flush()?;
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

async fn run_group(
    command: GroupCommand,
    options: &Options,
    output: &mut dyn Write,
) -> Result<i32> {
    let data_root = options.data_root();
    if matches!(
        &command,
        GroupCommand::Create { .. }
            | GroupCommand::Invite { .. }
            | GroupCommand::Join { .. }
            | GroupCommand::Leave { .. }
            | GroupCommand::Remove { .. }
            | GroupCommand::Rekey { .. }
            | GroupCommand::Admin { .. }
    ) && !(io::stdin().is_terminal() && io::stdout().is_terminal())
    {
        writeln!(
            output,
            "This is a human-only command and requires an interactive terminal."
        )?;
        return Ok(2);
    }
    match command {
        GroupCommand::Create { name, invite } => {
            if let Some(count) = invite {
                InviteState::new(count, InviteState::default_ttl())?;
            }
            let Some((id, static_private)) = identity::read_saved(&data_root)? else {
                return Err(groups::GroupError::MissingIdentity(data_root).into());
            };
            let particle_id = id.to_string();
            let particle_name = options.particle_name(&id);
            let member = Member {
                particle_id: particle_id.clone(),
                name: particle_name,
                static_key: hex::encode(entangle_transport::public_key(&static_private)),
                sign_key: groups::signing_public_key(&static_private),
                added_by: particle_id,
                added_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            };
            let group = groups::create(&data_root, &name, member)?;
            writeln!(
                output,
                "Created group {} ({}). You are its admin.",
                group.meta.name, group.id
            )?;
            if let Some(count) = invite {
                run_invite(&data_root, &group.meta.name, count, options, output).await?;
            } else {
                writeln!(
                    output,
                    "Next: run `entangle group invite {}` here, then `entangle group join <code>` on each other device.",
                    group.meta.name
                )?;
            }
        }
        GroupCommand::Invite { name, count } => {
            run_invite(&data_root, &name, count, options, output).await?;
        }
        GroupCommand::Join {
            code,
            local_name,
            via,
        } => {
            run_join(
                &data_root,
                &code,
                local_name.as_deref(),
                via.as_deref(),
                options,
                output,
            )
            .await?;
        }
        GroupCommand::List { json } => {
            let groups = groups::list(&data_root)?;
            if json {
                let self_id = identity::read_saved(&data_root)?.map(|(id, _)| id.to_string());
                let rows = groups
                    .iter()
                    .map(|group| {
                        serde_json::json!({
                            "name": &group.meta.name,
                            "group": &group.id,
                            "role": role_name(
                                !group.outdated
                                    && self_id
                                        .as_deref()
                                        .is_some_and(|id| group.meta.is_admin(id))
                            ),
                            "members": group.members.len(),
                            "admin": group.members.iter()
                                .find(|member| member.particle_id == group.meta.admin)
                                .map(|member| member.name.clone()),
                            "epoch": group.meta.epoch,
                            "outdated": group.outdated,
                            "hint": group.outdated.then(|| format!(
                                "group {} was created by Entangle 0.6; run `entangle group leave {}` and create it again",
                                group.meta.name, group.meta.name
                            )),
                        })
                    })
                    .collect::<Vec<_>>();
                writeln!(output, "{}", serde_json::to_string_pretty(&rows)?)?;
            } else if groups.is_empty() {
                writeln!(output, "This machine isn't in any group yet. Run `entangle group create <name>` or `entangle group join <code>`.")?;
            } else {
                writeln!(output, "NAME  GROUP  ROLE  MEMBERS")?;
                let self_id = identity::read_saved(&data_root)?.map(|(id, _)| id.to_string());
                for group in groups {
                    if group.outdated {
                        writeln!(
                            output,
                            "{}  {}  outdated  --  group {} was created by Entangle 0.6; run `entangle group leave {}` and create it again",
                            group.meta.name, group.id, group.meta.name, group.meta.name
                        )?;
                    } else {
                        let is_admin = self_id.as_deref().is_some_and(|id| group.meta.is_admin(id));
                        writeln!(
                            output,
                            "{}  {}  {}  {}",
                            group.meta.name,
                            group.id,
                            role_name(is_admin),
                            group.members.len()
                        )?;
                    }
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
                    "role": role_name(group.meta.is_admin(&member.particle_id)),
                    "this_machine": is_self,
                })
            }).collect::<Vec<_>>();
            if json {
                writeln!(output, "{}", serde_json::to_string_pretty(&rows)?)?;
            } else {
                writeln!(output, "NAME  PARTICLE(short)  FINGERPRINT  ADDED BY  ROLE")?;
                for (row, member) in rows.iter().zip(&group.members) {
                    let name = row["name"].as_str().unwrap_or_default();
                    writeln!(
                        output,
                        "{}  {}  {}  {}  {}",
                        name,
                        short_particle_id(&member.particle_id),
                        row["fingerprint"].as_str().unwrap_or_default(),
                        short_particle_id(row["added_by"].as_str().unwrap_or_default()),
                        row["role"].as_str().unwrap_or_default()
                    )?;
                }
            }
        }
        GroupCommand::Remove { name, member } => {
            let group = groups::find(&data_root, &name)?
                .ok_or_else(|| groups::GroupError::NotFound(name.clone()))?;
            let static_private = require_admin(&data_root, &group)?;
            let target = resolve_group_member(&group, &member)?;
            let self_id = identity::read_saved(&data_root)?
                .map(|(id, _)| id.to_string())
                .unwrap_or_default();
            if target.particle_id == self_id {
                anyhow::bail!("you cannot remove yourself from {}", group.meta.name);
            }
            write!(
                output,
                "Remove {} from {} and rotate the group key? [y/N] ",
                target.name, group.meta.name
            )?;
            output.flush()?;
            if !peer::read_confirmation_key()? {
                writeln!(output, "Cancelled; still in {}.", group.meta.name)?;
                return Ok(0);
            }
            let next_epoch = group
                .meta
                .epoch
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("group epoch exhausted"))?;
            write_update_status(&data_root, &group.id, next_epoch)?;
            let updated = groups::issue_update(
                &data_root,
                &group.id,
                entangle_core::UpdateKind::Remove {
                    particle_id: target.particle_id.clone(),
                },
                &static_private,
            )?;
            let line = update_outcome(
                &data_root,
                &updated,
                &format!("Removed {} from {}", target.name, group.meta.name),
                "New key",
                identity::is_running(&data_root),
                updated.members.len().saturating_sub(1),
                Duration::from_secs(20),
            )
            .await?;
            writeln!(output, "{line}")?;
        }
        GroupCommand::Rekey { name } => {
            let group = groups::find(&data_root, &name)?
                .ok_or_else(|| groups::GroupError::NotFound(name.clone()))?;
            let static_private = require_admin(&data_root, &group)?;
            write!(output, "Rotate the key for {}? [y/N] ", group.meta.name)?;
            output.flush()?;
            if !peer::read_confirmation_key()? {
                writeln!(output, "Cancelled; still in {}.", group.meta.name)?;
                return Ok(0);
            }
            let next_epoch = group
                .meta
                .epoch
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("group epoch exhausted"))?;
            write_update_status(&data_root, &group.id, next_epoch)?;
            let updated = groups::issue_update(
                &data_root,
                &group.id,
                entangle_core::UpdateKind::Rekey,
                &static_private,
            )?;
            let line = update_outcome(
                &data_root,
                &updated,
                &format!("Rekeyed {}", group.meta.name),
                "New key",
                identity::is_running(&data_root),
                group.members.len().saturating_sub(1),
                Duration::from_secs(20),
            )
            .await?;
            writeln!(output, "{line}")?;
        }
        GroupCommand::Admin { name, member } => {
            let group = groups::find(&data_root, &name)?
                .ok_or_else(|| groups::GroupError::NotFound(name.clone()))?;
            let static_private = require_admin(&data_root, &group)?;
            let target = resolve_group_member(&group, &member)?;
            if target.particle_id == group.meta.admin {
                anyhow::bail!(
                    "{} is already the admin of {}",
                    target.name,
                    group.meta.name
                );
            }
            write!(
                output,
                "Make {} the admin of {}? [y/N] ",
                target.name, group.meta.name
            )?;
            output.flush()?;
            if !peer::read_confirmation_key()? {
                writeln!(output, "Cancelled; still in {}.", group.meta.name)?;
                return Ok(0);
            }
            let next_epoch = group
                .meta
                .epoch
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("group epoch exhausted"))?;
            write_update_status(&data_root, &group.id, next_epoch)?;
            let updated = groups::issue_update(
                &data_root,
                &group.id,
                entangle_core::UpdateKind::AdminHandoff {
                    to: target.particle_id,
                },
                &static_private,
            )?;
            let line = update_outcome(
                &data_root,
                &updated,
                &format!("{} is now the admin of {}", target.name, group.meta.name),
                "Notified",
                identity::is_running(&data_root),
                group.members.len().saturating_sub(1),
                Duration::from_secs(20),
            )
            .await?;
            writeln!(output, "{line}")?;
        }
        GroupCommand::Leave { name } => {
            let group = groups::find(&data_root, &name)?
                .ok_or_else(|| groups::GroupError::NotFound(name.clone()))?;
            let self_id = identity::read_saved(&data_root)?
                .map(|(id, _)| id.to_string())
                .unwrap_or_default();
            if group.meta.is_admin(&self_id) && group.members.len() > 1 {
                let member = group
                    .members
                    .iter()
                    .find(|member| member.particle_id != self_id)
                    .map(|member| member.name.as_str())
                    .unwrap_or("<member>");
                anyhow::bail!(
                    "You're the admin of {}. Hand it off first: entangle group admin {} {}",
                    group.meta.name,
                    group.meta.name,
                    member
                );
            }
            write!(
                output,
                "Leave group {} ({})? [y/N] ",
                group.meta.name, group.id
            )?;
            output.flush()?;
            if peer::read_confirmation_key()? {
                if group.outdated {
                    groups::leave(&data_root, &name)?;
                    writeln!(output, "Left {}.", group.meta.name)?;
                } else if identity::is_running(&data_root) {
                    groups::write_status(
                        &data_root,
                        &group.id,
                        &groups::GroupStatus {
                            epoch: group.meta.epoch,
                            op: "leave".into(),
                            confirmed: Vec::new(),
                        },
                    )?;
                    groups::set_leaving(&data_root, &group.id, true)?;
                    let status = wait_for_status(
                        &data_root,
                        &group.id,
                        group.meta.epoch,
                        "leave",
                        group.members.len().saturating_sub(1),
                        Duration::from_secs(60),
                    )
                    .await;
                    writeln!(
                        output,
                        "Left {}. Told {} of {} members.",
                        group.meta.name,
                        status.confirmed.len(),
                        group.members.len().saturating_sub(1)
                    )?;
                } else {
                    groups::leave(&data_root, &name)?;
                    writeln!(output, "Left {}.", group.meta.name)?;
                }
            } else {
                writeln!(output, "Cancelled; still in {}.", group.meta.name)?;
            }
        }
    }
    Ok(0)
}

struct GroupMemberTarget {
    particle_id: String,
    name: String,
}

fn require_admin(root: &std::path::Path, group: &groups::Group) -> Result<[u8; 32]> {
    let saved = identity::read_saved(root)?;
    let Some((self_id, private)) = saved else {
        return Err(groups::GroupError::MissingIdentity(root.to_owned()).into());
    };
    if !group.meta.is_admin(self_id.as_str()) {
        let admin_name = group
            .members
            .iter()
            .find(|member| member.particle_id == group.meta.admin)
            .map_or(group.meta.admin.as_str(), |member| member.name.as_str());
        anyhow::bail!(
            "Only the admin of {} ({}) can do this.",
            group.meta.name,
            admin_name
        );
    }
    Ok(private)
}

fn resolve_group_member(group: &groups::Group, selector: &str) -> Result<GroupMemberTarget> {
    let matches = group
        .members
        .iter()
        .filter(|member| member.name == selector || member.particle_id.starts_with(selector))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => anyhow::bail!("no member matches {selector} in {}", group.meta.name),
        [member] => Ok(GroupMemberTarget {
            particle_id: member.particle_id.clone(),
            name: member.name.clone(),
        }),
        _ => anyhow::bail!("ambiguous member: {selector}"),
    }
}

fn write_update_status(root: &std::path::Path, group_id: &str, epoch: u32) -> Result<()> {
    groups::write_status(
        root,
        group_id,
        &groups::GroupStatus {
            epoch,
            op: "update".into(),
            confirmed: Vec::new(),
        },
    )?;
    Ok(())
}

async fn wait_for_status(
    root: &std::path::Path,
    group_id: &str,
    epoch: u32,
    op: &str,
    expected: usize,
    duration: Duration,
) -> groups::GroupStatus {
    let deadline = std::time::Instant::now() + duration;
    let mut latest = None;
    loop {
        if let Ok(Some(status)) = groups::read_status(root, group_id) {
            if status.epoch >= epoch && status.op == op {
                if status.confirmed.len() >= expected {
                    return status;
                }
                latest = Some(status);
            }
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    latest.unwrap_or_else(|| groups::GroupStatus {
        epoch,
        op: op.into(),
        confirmed: Vec::new(),
    })
}

async fn update_outcome(
    root: &std::path::Path,
    group: &groups::Group,
    action: &str,
    delivery_label: &str,
    running: bool,
    total: usize,
    timeout: Duration,
) -> Result<String> {
    if !running {
        return Ok(format!(
            "{action}. Entangle isn't running here, so the change goes out the next time it starts."
        ));
    }
    let status = wait_for_status(root, &group.id, group.meta.epoch, "update", total, timeout).await;
    let self_id = identity::read_saved(root)
        .ok()
        .flatten()
        .map(|(id, _)| id.to_string());
    let delivered_members = group
        .members
        .iter()
        .filter(|member| {
            self_id.as_deref() != Some(member.particle_id.as_str())
                && status.confirmed.contains(&member.particle_id)
        })
        .collect::<Vec<_>>();
    let delivered = delivered_members.len().min(total);
    if delivered >= total {
        if delivery_label == "Notified" {
            Ok(format!(
                "{action}. Notified {delivered} of {total} other members."
            ))
        } else {
            Ok(format!(
                "{action}. {delivery_label} delivered to {delivered} of {total} other members."
            ))
        }
    } else {
        let confirmed = delivered_members
            .iter()
            .map(|member| member.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let missing = group
            .members
            .iter()
            .filter(|member| {
                self_id.as_deref() != Some(member.particle_id.as_str())
                    && !status.confirmed.contains(&member.particle_id)
            })
            .map(|member| member.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        Ok(format!(
            "{action}. Delivered to {delivered} of {total} members so far ({confirmed}); {missing} gets it the next time it connects to any member."
        ))
    }
}

async fn run_invite(
    data_root: &std::path::Path,
    name: &str,
    count: u8,
    options: &Options,
    output: &mut dyn Write,
) -> Result<()> {
    let group = groups::find(data_root, name)?
        .ok_or_else(|| groups::GroupError::NotFound(name.to_owned()))?;
    let Some((id, _)) = identity::read_saved(data_root)? else {
        return Err(groups::GroupError::MissingIdentity(data_root.to_owned()).into());
    };
    let visible = if options.no_mdns {
        Vec::new()
    } else {
        entangle_resonance::InviteAdvert::visible_nameplates(Duration::from_secs(1))
            .await
            .unwrap_or_default()
    };
    let nameplate = protocol::choose_nameplate(&visible)
        .ok_or_else(|| anyhow::anyhow!("no invite nameplates are available on this network"))?;
    let code = InviteCode::generate(nameplate);
    let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await?;
    let port = listener.local_addr()?.port();
    let ttl = InviteState::default_ttl();
    let server = InviteServer::new(
        data_root,
        group.id.clone(),
        options.particle_name(&id),
        code,
        count,
        ttl,
    )?;
    let advert = if options.no_mdns {
        None
    } else {
        match entangle_resonance::InviteAdvert::register(
            nameplate,
            &options.particle_name(&id),
            port,
        ) {
            Ok(advert) => Some(advert),
            Err(error) => {
                tracing::warn!(%error, "invite mDNS registration failed; use --via");
                None
            }
        }
    };
    let ip = advert
        .as_ref()
        .and_then(|advert| {
            advert
                .addresses()
                .iter()
                .find(|address| matches!(address, IpAddr::V4(ip) if !ip.is_loopback()))
                .copied()
        })
        .or_else(local_ipv4)
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    writeln!(output, "Invite code for {}: {}", group.meta.name, code)?;
    writeln!(output, "On each device run: entangle group join {}", code)?;
    writeln!(
        output,
        "Waiting for {count} devices (closes in 10 minutes; press Esc to cancel). If a device can't find it: add --via {ip}:{port}"
    )?;
    output.flush()?;

    let (mut cancel, cancel_guard) = peer::start_cancel_key_listener()?;
    let mut terminal = server.state().subscribe();
    let mut sessions = JoinSet::new();
    let mut reported = 0_u8;
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = result?;
                let session = server.clone();
                sessions.spawn(async move { session.handle(stream).await });
            }
            result = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Ok(Ok(Some(joined_name)))) = result {
                    reported = reported.saturating_add(1);
                    writeln!(output, "{joined_name} joined ({reported}/{count}).")?;
                    output.flush()?;
                }
            }
            _ = tokio::time::sleep_until(server.state().expires_at()) => {
                server.state().end(InviteEnd::Expired);
            }
            _ = cancel.recv() => {
                server.state().end(InviteEnd::Cancelled);
            }
            changed = terminal.changed() => {
                if changed.is_err() || terminal.borrow().is_some() {
                    break;
                }
            }
        }
        if server.state().terminal().await.is_some() {
            break;
        }
    }
    drop(cancel_guard);
    drop(listener);
    if let Some(advert) = advert {
        let _ = advert.shutdown();
    }
    while let Some(result) = sessions.join_next().await {
        if let Ok(Ok(Some(joined_name))) = result {
            reported = reported.saturating_add(1);
            writeln!(output, "{joined_name} joined ({reported}/{count}).")?;
        }
    }
    let (joined, total) = server.state().counts().await;
    match server.state().terminal().await.unwrap_or(InviteEnd::Expired) {
        InviteEnd::Complete => writeln!(output, "{total} of {total} joined; invite closed.")?,
        InviteEnd::Expired => writeln!(output, "Invite expired; {joined} of {total} joined.")?,
        InviteEnd::Cancelled => writeln!(output, "Cancelled; {joined} of {total} joined.")?,
        InviteEnd::WrongCode => writeln!(
            output,
            "A device entered a wrong code; invite closed ({joined} of {total} joined). Run `entangle group invite {}` again for a new code.",
            group.meta.name
        )?,
        InviteEnd::Failed => writeln!(
            output,
            "A device failed to confirm; invite closed ({joined} of {total} joined). Run `entangle group invite {}` again for a new code.",
            group.meta.name
        )?,
    }
    Ok(())
}

async fn run_join(
    data_root: &std::path::Path,
    value: &str,
    local_name: Option<&str>,
    via: Option<&str>,
    options: &Options,
    output: &mut dyn Write,
) -> Result<i32> {
    let code = match InviteCode::parse(value) {
        Ok(code) => code,
        Err(error) => {
            writeln!(output, "Invalid invite code: {error}")?;
            return Ok(1);
        }
    };
    let Some((particle_id, _)) = identity::read_saved(data_root)? else {
        let error = groups::GroupError::MissingIdentity(data_root.to_owned());
        writeln!(output, "{error}")?;
        return Ok(1);
    };
    let particle_name = options.particle_name(&particle_id);
    let mut last_error = None;
    if let Some(via) = via {
        let addresses = tokio::net::lookup_host(via).await?;
        for address in addresses {
            match tokio::net::TcpStream::connect(address).await {
                Ok(stream) => {
                    match protocol::join(stream, data_root, code, local_name, &particle_name).await
                    {
                        Ok(joined) => {
                            write_join_success(output, joined)?;
                            return Ok(0);
                        }
                        Err(error) if is_terminal_join_error(&error) => {
                            return write_join_failure(output, error);
                        }
                        Err(error) => last_error = Some(error),
                    }
                }
                Err(error) => last_error = Some(error.into()),
            }
        }
    } else {
        let candidates = if options.no_mdns {
            Vec::new()
        } else {
            entangle_resonance::InviteAdvert::browse(code.nameplate, Duration::from_secs(15))
                .await
                .unwrap_or_default()
        };
        match try_join_candidates(candidates, |candidate| {
            let particle_name = particle_name.clone();
            async move {
                let mut wrong_code = false;
                let mut candidate_error = None;
                for address in candidate.addrs {
                    let target = SocketAddr::new(address, candidate.port);
                    match tokio::net::TcpStream::connect(target).await {
                        Ok(stream) => {
                            match protocol::join(
                                stream,
                                data_root,
                                code,
                                local_name,
                                &particle_name,
                            )
                            .await
                            {
                                Ok(joined) => return Ok(joined),
                                Err(InviteError::WrongCode) => wrong_code = true,
                                Err(error) if is_terminal_join_error(&error) => return Err(error),
                                Err(error) => candidate_error = Some(error),
                            }
                        }
                        Err(error) => candidate_error = Some(error.into()),
                    }
                }
                if wrong_code {
                    Err(InviteError::WrongCode)
                } else {
                    Err(candidate_error.unwrap_or(InviteError::Closed))
                }
            }
        })
        .await
        {
            Ok(joined) => {
                write_join_success(output, joined)?;
                return Ok(0);
            }
            Err(CandidateJoinFailure::WrongCode) => {
                return write_join_failure(output, InviteError::WrongCode);
            }
            Err(CandidateJoinFailure::Terminal(error)) => {
                return write_join_failure(output, error);
            }
            Err(CandidateJoinFailure::Other) => {}
        }
    }
    let _ = last_error;
    writeln!(
        output,
        "No invite {} found on this network. Check the code and that `entangle group invite` is still running; or add --via <host:port>.",
        code.nameplate
    )?;
    Ok(1)
}

#[derive(Debug)]
enum CandidateJoinFailure {
    WrongCode,
    Terminal(InviteError),
    Other,
}

async fn try_join_candidates<C, T, F, Fut>(
    candidates: impl IntoIterator<Item = C>,
    mut attempt: F,
) -> std::result::Result<T, CandidateJoinFailure>
where
    F: FnMut(C) -> Fut,
    Fut: Future<Output = std::result::Result<T, InviteError>>,
{
    let mut total = 0;
    let mut wrong_code = 0;
    for candidate in candidates {
        total += 1;
        match attempt(candidate).await {
            Ok(value) => return Ok(value),
            Err(InviteError::WrongCode) => wrong_code += 1,
            Err(error) if is_terminal_join_error(&error) => {
                return Err(CandidateJoinFailure::Terminal(error))
            }
            Err(_) => {}
        }
    }
    if total > 0 && wrong_code == total {
        Err(CandidateJoinFailure::WrongCode)
    } else {
        Err(CandidateJoinFailure::Other)
    }
}

fn is_terminal_join_error(error: &InviteError) -> bool {
    matches!(
        error,
        InviteError::WrongCode
            | InviteError::Declined { .. }
            | InviteError::Incomplete
            | InviteError::Group(groups::GroupError::MissingIdentity(_))
            | InviteError::Group(groups::GroupError::Conflict { .. })
    )
}

fn write_join_failure(output: &mut dyn Write, error: InviteError) -> Result<i32> {
    match error {
        InviteError::WrongCode => {
            writeln!(
                output,
                "That code was wrong; the invite is now closed. Ask for a new one."
            )?;
        }
        InviteError::Declined { reason, group_name } => match reason.as_str() {
            "already_member" => writeln!(
                output,
                "This machine is already in {}.",
                group_name.unwrap_or_else(|| "that group".into())
            )?,
            "name_taken" => writeln!(
                output,
                "A group named {} already exists here; rerun with --as <other>.",
                group_name.unwrap_or_else(|| "that group".into())
            )?,
            "removed" => writeln!(
                output,
                "This device was removed from {}; ask its admin to invite it.",
                group_name.unwrap_or_else(|| "that group".into())
            )?,
            _ => writeln!(output, "The inviter declined this join: {reason}.")?,
        },
        InviteError::Group(groups::GroupError::MissingIdentity(path)) => {
            let error = groups::GroupError::MissingIdentity(path);
            writeln!(output, "{error}")?;
        }
        InviteError::Group(groups::GroupError::Conflict { name }) => {
            writeln!(output, "{name} changed while joining; run the invite again")?;
        }
        InviteError::Incomplete => writeln!(
            output,
            "The join didn't complete; nothing was kept. Run the same command again while the invite is open."
        )?,
        other => writeln!(output, "Invite join failed: {other}")?,
    }
    Ok(1)
}

fn write_join_success(output: &mut dyn Write, joined: protocol::Joined) -> Result<()> {
    if joined.refreshed {
        writeln!(
            output,
            "Refreshed {}: this device was out of date and now has the current key.",
            joined.group.meta.name
        )?;
    } else {
        writeln!(
            output,
            "Joined {} ({}) via {}. {} members.",
            joined.group.meta.name,
            joined.group.id,
            joined.inviter_name,
            joined.group.members.len()
        )?;
    }
    Ok(())
}

fn local_ipv4() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    let address = socket.local_addr().ok()?.ip();
    (!address.is_loopback()).then_some(address)
}

fn role_name(is_admin: bool) -> &'static str {
    if is_admin {
        "admin"
    } else {
        "member"
    }
}

fn short_particle_id(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_cli_without_name_env(args: &[&str]) -> Cli {
        static ENTANGLE_NAME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _lock = ENTANGLE_NAME_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous_name = std::env::var_os("ENTANGLE_NAME");
        std::env::remove_var("ENTANGLE_NAME");
        let parsed = Cli::try_parse_from(args.iter().copied());
        if let Some(previous_name) = previous_name {
            std::env::set_var("ENTANGLE_NAME", previous_name);
        }
        parsed.unwrap()
    }

    fn group_command(cli: Cli) -> GroupCommand {
        match cli.command {
            Some(Command::Group { command }) => command,
            other => panic!("expected group command, got {other:?}"),
        }
    }

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
    fn group_create_keeps_particle_name_separate_from_group_name() {
        let cli =
            parse_cli_without_name_env(&["entangle", "--name", "pc-a", "group", "create", "work"]);
        assert_eq!(cli.options.name.as_deref(), Some("pc-a"));
        assert!(matches!(
            group_command(cli),
            GroupCommand::Create { name, .. } if name == "work"
        ));
    }

    #[test]
    fn group_create_without_particle_name_keeps_group_name() {
        let cli = parse_cli_without_name_env(&["entangle", "group", "create", "work"]);
        assert_eq!(cli.options.name, None);
        assert!(matches!(
            group_command(cli),
            GroupCommand::Create { name, .. } if name == "work"
        ));
    }

    #[test]
    fn group_invite_keeps_particle_name_separate_from_group_name() {
        let cli = parse_cli_without_name_env(&[
            "entangle", "--name", "pc-a", "group", "invite", "work", "--count", "2",
        ]);
        assert_eq!(cli.options.name.as_deref(), Some("pc-a"));
        assert!(matches!(
            group_command(cli),
            GroupCommand::Invite { name, count: 2 } if name == "work"
        ));
    }

    #[test]
    fn group_invite_without_particle_name_keeps_group_name() {
        let cli =
            parse_cli_without_name_env(&["entangle", "group", "invite", "work", "--count", "2"]);
        assert_eq!(cli.options.name, None);
        assert!(matches!(
            group_command(cli),
            GroupCommand::Invite { name, count: 2 } if name == "work"
        ));
    }

    #[test]
    fn group_members_keeps_particle_name_separate_from_group_name() {
        let cli =
            parse_cli_without_name_env(&["entangle", "--name", "pc-a", "group", "members", "work"]);
        assert_eq!(cli.options.name.as_deref(), Some("pc-a"));
        assert!(matches!(
            group_command(cli),
            GroupCommand::Members { name, .. } if name == "work"
        ));
    }

    #[test]
    fn group_remove_keeps_particle_name_separate_from_group_name() {
        let cli = parse_cli_without_name_env(&[
            "entangle", "--name", "pc-a", "group", "remove", "work", "pc-c",
        ]);
        assert_eq!(cli.options.name.as_deref(), Some("pc-a"));
        assert!(matches!(
            group_command(cli),
            GroupCommand::Remove { name, member } if name == "work" && member == "pc-c"
        ));
    }

    #[test]
    fn group_rekey_keeps_particle_name_separate_from_group_name() {
        let cli =
            parse_cli_without_name_env(&["entangle", "--name", "pc-a", "group", "rekey", "work"]);
        assert_eq!(cli.options.name.as_deref(), Some("pc-a"));
        assert!(matches!(
            group_command(cli),
            GroupCommand::Rekey { name } if name == "work"
        ));
    }

    #[test]
    fn group_admin_keeps_particle_name_separate_from_group_name() {
        let cli = parse_cli_without_name_env(&[
            "entangle", "--name", "pc-a", "group", "admin", "work", "pc-b",
        ]);
        assert_eq!(cli.options.name.as_deref(), Some("pc-a"));
        assert!(matches!(
            group_command(cli),
            GroupCommand::Admin { name, member } if name == "work" && member == "pc-b"
        ));
    }

    #[test]
    fn join_conflict_prints_the_retry_message_without_a_generic_prefix() {
        let mut output = Vec::new();
        assert_eq!(
            write_join_failure(
                &mut output,
                InviteError::Group(groups::GroupError::Conflict {
                    name: "work".into(),
                }),
            )
            .unwrap(),
            1
        );
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "work changed while joining; run the invite again\n"
        );
    }

    #[test]
    fn detects_broken_pipe_root_cause() {
        let error = anyhow::Error::new(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
        assert!(is_broken_pipe(&error));
    }

    #[tokio::test]
    async fn wrong_code_candidate_does_not_stop_the_join_loop() {
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let result = try_join_candidates([0, 1], {
            let attempts = std::sync::Arc::clone(&attempts);
            move |candidate| {
                let attempts = std::sync::Arc::clone(&attempts);
                async move {
                    attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if candidate == 0 {
                        Err(InviteError::WrongCode)
                    } else {
                        Ok(candidate)
                    }
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(result, 1);
        assert_eq!(attempts.load(std::sync::atomic::Ordering::Relaxed), 2);

        assert!(matches!(
            try_join_candidates([0, 1], |_| async {
                Err::<usize, InviteError>(InviteError::WrongCode)
            })
            .await,
            Err(CandidateJoinFailure::WrongCode)
        ));
        assert!(matches!(
            try_join_candidates([0, 1], |candidate| async move {
                if candidate == 0 {
                    Err::<usize, InviteError>(InviteError::WrongCode)
                } else {
                    Err(InviteError::Closed)
                }
            })
            .await,
            Err(CandidateJoinFailure::Other)
        ));
    }

    #[tokio::test]
    async fn join_preserves_configured_particle_name() {
        let inviter_root = tempfile::tempdir().unwrap();
        let identity = identity::claim(inviter_root.path()).unwrap();
        let inviter_id = identity.id.to_string();
        let inviter_member = Member {
            particle_id: inviter_id.clone(),
            name: "inviter".into(),
            static_key: hex::encode(entangle_transport::public_key(&identity.static_private)),
            sign_key: groups::signing_public_key(&identity.static_private),
            added_by: inviter_id.clone(),
            added_at: "2026-10-12T00:00:00Z".into(),
        };
        let inviter_sign_key = groups::signing_public_key(&identity.static_private);
        drop(identity);
        let group = groups::insert(
            inviter_root.path(),
            [0x42; 32],
            groups::GroupMeta {
                version: 2,
                name: "work".into(),
                created_at: "2026-10-12T00:00:00Z".into(),
                epoch: 0,
                admin: inviter_id.clone(),
                admin_sign_key: inviter_sign_key,
                revoked: vec![],
                leaving: false,
            },
            vec![inviter_member],
        )
        .unwrap();
        let invite = InviteServer::new(
            inviter_root.path(),
            group.id.clone(),
            "inviter".into(),
            InviteCode::parse("7-amber-photon-quasar").unwrap(),
            1,
            Duration::from_secs(30),
        )
        .unwrap();

        let joiner_root = tempfile::tempdir().unwrap();
        identity::claim(joiner_root.path()).unwrap();
        let mut options = options(joiner_root.path());
        options.name = Some("office-agent".into());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let via = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            invite.handle(stream).await
        });
        let mut output = Vec::new();
        assert_eq!(
            run_join(
                joiner_root.path(),
                "7-amber-photon-quasar",
                None,
                Some(&via),
                &options,
                &mut output,
            )
            .await
            .unwrap(),
            0
        );
        task.await.unwrap().unwrap();
        let updated = groups::find(inviter_root.path(), &group.id)
            .unwrap()
            .unwrap();
        assert!(updated
            .members
            .iter()
            .any(|member| member.name == "office-agent"));
    }

    #[tokio::test]
    async fn group_list_and_members_render_text_and_json() {
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
                sign_key: groups::signing_public_key(&local_key),
                added_by: local_id.clone(),
                added_at: "2026-10-12T00:00:00Z".into(),
            },
            Member {
                particle_id: remote_id.clone(),
                name: "remote".into(),
                static_key: hex::encode(entangle_transport::public_key(&[0x42; 32])),
                sign_key: groups::signing_public_key(&[0x42; 32]),
                added_by: remote_id,
                added_at: "2026-10-12T00:00:00Z".into(),
            },
        ];
        groups::insert(
            temp.path(),
            [0x24; 32],
            groups::GroupMeta {
                version: 2,
                name: "work".into(),
                created_at: "2026-10-12T00:00:00Z".into(),
                epoch: 0,
                admin: local_id.clone(),
                admin_sign_key: groups::signing_public_key(&local_key),
                revoked: vec![],
                leaving: false,
            },
            members,
        )
        .unwrap();

        let mut text = Vec::new();
        assert_eq!(
            run_group(GroupCommand::List { json: false }, &options, &mut text)
                .await
                .unwrap(),
            0
        );
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("NAME  GROUP  ROLE  MEMBERS"));
        assert!(text.contains("work"));
        assert!(text.contains("admin"));

        let mut json = Vec::new();
        run_group(GroupCommand::List { json: true }, &options, &mut json)
            .await
            .unwrap();
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
        .await
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
        .await
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

    #[tokio::test]
    async fn human_only_group_commands_refuse_non_interactive_use() {
        let temp = tempfile::tempdir().unwrap();
        let options = options(temp.path());
        for command in [
            GroupCommand::Create {
                name: "work".into(),
                invite: None,
            },
            GroupCommand::Invite {
                name: "work".into(),
                count: 1,
            },
            GroupCommand::Join {
                code: "7-amber-photon-quasar".into(),
                local_name: None,
                via: None,
            },
            GroupCommand::Leave {
                name: "work".into(),
            },
        ] {
            let mut output = Vec::new();
            assert_eq!(run_group(command, &options, &mut output).await.unwrap(), 2);
            assert!(String::from_utf8(output)
                .unwrap()
                .contains("human-only command"));
        }
    }
}
