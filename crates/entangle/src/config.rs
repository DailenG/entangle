//! CLI-derived configuration and platform-specific particle storage locations.

use clap::Args;
use entangle_core::ParticleId;
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
    /// Static host:port peers to dial when multicast is unavailable; comma-separated in ENTANGLE_PEER.
    #[arg(long, global = true, env = "ENTANGLE_PEER", value_delimiter = ',')]
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
    /// Returns the base path used for the persistent identity and particle data.
    pub fn data_root(&self) -> PathBuf {
        self.data_dir.clone().unwrap_or_else(|| {
            dirs::data_dir()
                .or_else(dirs::home_dir)
                .unwrap_or_else(|| PathBuf::from("."))
                .join("entangle")
        })
    }

    /// Resolves an empty particle name to the hostname and identity prefix.
    pub fn particle_name(&self, id: &ParticleId) -> String {
        self.name
            .clone()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| {
                let hostname = gethostname::gethostname();
                let hostname = hostname.to_string_lossy().trim().to_lowercase();
                let host = if hostname.is_empty() {
                    "entangle-particle"
                } else {
                    &hostname
                };
                format!("{host}-{}", &id.as_str()[..4])
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn options(name: Option<String>) -> Options {
        Options {
            name,
            context: None,
            link_port: 7337,
            relay_port: 9109,
            advertise_ip: None,
            peer: vec![],
            data_dir: None,
            croc: None,
            max_payload_mb: 512,
            no_mdns: true,
            log_level: "info".into(),
        }
    }

    #[test]
    fn default_particle_name_uses_hostname_and_id_prefix() {
        let options = options(None);
        let id = ParticleId::parse("0123456789abcdef0123456789abcdef").unwrap();
        let hostname = gethostname::gethostname()
            .to_string_lossy()
            .trim()
            .to_lowercase();
        let host = if hostname.is_empty() {
            "entangle-particle"
        } else {
            &hostname
        };
        assert_eq!(
            options.particle_name(&id),
            format!("{host}-{}", &id.as_str()[..4])
        );
    }

    #[test]
    fn explicit_particle_name_is_returned_verbatim() {
        let options = options(Some("  Workstation A  ".into()));
        let id = ParticleId::parse("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(options.particle_name(&id), "  Workstation A  ");
    }

    #[test]
    fn static_peers_split_comma_delimited_values() {
        #[derive(Parser)]
        struct TestCli {
            #[command(flatten)]
            options: Options,
        }

        let parsed = TestCli::try_parse_from(["entangle", "--peer", "a:7337,b:7337"]).unwrap();
        assert_eq!(parsed.options.peer, ["a:7337", "b:7337"]);
    }
}
