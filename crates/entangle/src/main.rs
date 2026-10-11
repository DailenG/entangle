//! Entangle binary entry point: particle orchestration, MCP, and CLI commands.

mod config;
mod field;
mod identity;
mod inbox;
mod node;
mod pairing;
mod peer;
mod tools;
mod trust;

use anyhow::Result;
use clap::{Parser, Subcommand};
use config::Options;
use std::time::Duration;
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
    /// Manage this machine's pairing key.
    Pair {
        #[command(subcommand)]
        command: PairCommand,
    },
    /// Inspect and manage locally approved peers.
    Peer {
        #[command(subcommand)]
        command: peer::PeerCommand,
    },
}

/// Pairing key actions.
#[derive(Debug, Subcommand)]
enum PairCommand {
    /// Create a new pairing key and display its code.
    Init {
        /// Replace any existing pairing key.
        #[arg(long)]
        force: bool,
    },
    /// Join a pairing group using its code.
    Join {
        /// ENT1 pairing code supplied by the human.
        code: String,
        /// Replace a different existing pairing key.
        #[arg(long)]
        force: bool,
    },
    /// Display this machine's pairing code.
    Show,
    /// Report whether this machine is paired without revealing its code.
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
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
            if json {
                println!("{}", serde_json::to_string_pretty(&peers)?);
            } else if peers.is_empty() {
                println!("No particles found.");
            } else {
                println!(
                    "{:<10} {:<24} {:<40} PORT  GROUP     CONTEXT",
                    "PARTICLE", "NAME", "ADDRESSES"
                );
                for peer in peers {
                    let addresses = peer
                        .addrs
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",");
                    println!(
                        "{:<10} {:<24} {:<40} {:<5} {:<9} {}",
                        peer.particle_id.short(),
                        peer.name,
                        addresses,
                        peer.port,
                        peer.group.unwrap_or_default(),
                        peer.context.unwrap_or_default()
                    );
                }
            }
        }
        Command::Pair { command } => run_pairing(cli.options.data_root(), command)?,
        Command::Peer { command } => {
            let data_root = cli.options.data_root();
            let local_name = identity::read_saved(&data_root)
                .ok()
                .flatten()
                .map(|(id, _)| cli.options.particle_name(&id));
            let exit_code = peer::run(command, &data_root, local_name.as_deref())?;
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

fn run_pairing(data_root: std::path::PathBuf, command: PairCommand) -> Result<()> {
    match command {
        PairCommand::Init { force } => {
            let key = pairing::initialize(&data_root, force)?;
            eprintln!("WARNING: The pairing code is secret; share it only with the human on the other machine.");
            println!("code: {}", pairing::encode_code(&key));
            println!("group: {}", pairing::group_id(&key));
        }
        PairCommand::Join { code, force } => {
            let key = pairing::join(&data_root, &code, force)?;
            println!("paired with group: {}", pairing::group_id(&key));
        }
        PairCommand::Show => {
            let key = pairing::require(&data_root)?;
            eprintln!("WARNING: This pairing code is secret. Do not send it to an agent or include it in logs.");
            println!("{}", pairing::encode_code(&key));
        }
        PairCommand::Status => match pairing::load(&data_root)? {
            Some(key) => {
                println!("paired: yes");
                println!("group: {}", pairing::group_id(&key));
            }
            None => {
                println!("paired: no");
                println!("group: none");
            }
        },
    }
    Ok(())
}
