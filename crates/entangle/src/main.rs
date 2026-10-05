//! Entangle binary entry point: particle orchestration, MCP, and CLI commands.

mod config;
mod field;
mod identity;
mod inbox;
mod node;
mod tools;

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
    match cli.command.unwrap_or(Command::Serve) {
        Command::Scan { timeout_secs, json } => {
            let peers = entangle_resonance::scan(Duration::from_secs(timeout_secs)).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&peers)?);
            } else if peers.is_empty() {
                println!("No particles found.");
            } else {
                println!(
                    "{:<10} {:<24} {:<40} PORT  CONTEXT",
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
                        "{:<10} {:<24} {:<40} {:<5} {}",
                        peer.particle_id.short(),
                        peer.name,
                        addresses,
                        peer.port,
                        peer.context.unwrap_or_default()
                    );
                }
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
