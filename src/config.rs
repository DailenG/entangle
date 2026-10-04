//! CLI-derived configuration and platform-specific particle storage locations.

use clap::Args;
use std::path::PathBuf;

/// Common settings with environment-variable fallbacks for MCP clients.
#[derive(Clone, Debug, Args)]
pub struct Options {
    /// Human-readable name for this particle.
    #[arg(long, global = true, env = "ENTANGLE_NAME")]
    pub name: Option<String>,
    /// Optional project context identifier.
    #[arg(long, global = true, env = "ENTANGLE_CONTEXT")]
    pub context: Option<String>,
    /// TCP port for the control link.
    #[arg(
        long,
        global = true,
        env = "ENTANGLE_LINK_PORT",
        default_value_t = 7337
    )]
    pub link_port: u16,
    /// Base port for the process-local croc relay.
    #[arg(
        long,
        global = true,
        env = "ENTANGLE_RELAY_PORT",
        default_value_t = 9109
    )]
    pub relay_port: u16,
    /// IP address advertised to remote peers for relay access.
    #[arg(long, global = true, env = "ENTANGLE_ADVERTISE_IP")]
    pub advertise_ip: Option<String>,
    /// Static host:port peers to dial when multicast is unavailable.
    #[arg(long, global = true, env = "ENTANGLE_PEER")]
    pub peer: Vec<String>,
    /// Base data directory (a particle-specific subdirectory is created).
    #[arg(long, global = true, env = "ENTANGLE_DATA_DIR")]
    pub data_dir: Option<PathBuf>,
    /// Explicit croc executable path.
    #[arg(long, global = true, env = "ENTANGLE_CROC")]
    pub croc: Option<PathBuf>,
    /// Maximum accepted payload size in mebibytes.
    #[arg(
        long,
        global = true,
        env = "ENTANGLE_MAX_PAYLOAD_MB",
        default_value_t = 512
    )]
    pub max_payload_mb: u64,
    /// Disable mDNS browsing and advertisement.
    #[arg(long, global = true, env = "ENTANGLE_NO_MDNS")]
    pub no_mdns: bool,
    /// Logging filter; all logs go to stderr.
    #[arg(
        long,
        global = true,
        env = "ENTANGLE_LOG_LEVEL",
        default_value = "info"
    )]
    pub log_level: String,
}

impl Options {
    /// Returns a stable base path; the caller adds a fresh particle identifier.
    pub fn data_root(&self) -> PathBuf {
        self.data_dir.clone().unwrap_or_else(|| {
            dirs::data_dir()
                .or_else(dirs::home_dir)
                .unwrap_or_else(|| PathBuf::from("."))
                .join("entangle")
        })
    }

    /// Resolves an empty particle name to the operating-system hostname.
    pub fn particle_name(&self) -> String {
        self.name
            .clone()
            .filter(|name| !name.trim().is_empty())
            .or_else(|| {
                std::env::var("HOSTNAME")
                    .or_else(|_| std::env::var("COMPUTERNAME"))
                    .ok()
            })
            .unwrap_or_else(|| "entangle-particle".into())
    }
}
