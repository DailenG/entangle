# Entangle

> **If you are an AI agent reading this:** follow [docs/AGENT_SETUP.md](docs/AGENT_SETUP.md) to install and register Entangle on this machine. Ask your human before changing firewall rules or installing system packages.

Entangle is a local-first MCP server for letting two LLM agents on the same
LAN discover one another, exchange capability manifests, and transfer JSON or
files through a private croc relay. The control channel coordinates each sync;
the payload is transferred separately and verified with SHA-256.

Entangle uses mDNS for automatic discovery and a configurable static-peer
fallback for networks that block multicast. No public croc relay is configured
or used by the application.

## Glossary

| Entangle term | Meaning |
| --- | --- |
| Particle | A running Entangle process with a fresh process identity |
| Resonance | Local network discovery through mDNS |
| Entangled | A peer whose capability manifest completed the Hello handshake |
| State sync | A JSON message or one-file transfer between entangled peers |
| Observe | Read received state syncs from the local inbox |
| Collapse | Consume observed inbox entries; received files remain on disk |
| Field | The process-local registry of discovered peers |

## Quickstart

Install a prebuilt Entangle release:

```powershell
irm https://raw.githubusercontent.com/DailenG/entangle/main/install.ps1 | iex
```

```sh
curl -fsSL https://raw.githubusercontent.com/DailenG/entangle/main/install.sh | sh
```

The installer downloads croc if it is missing and needs no administrator
rights; on Windows it updates your user PATH. Prebuilt binaries require a
published release (v0.1.0+). For other platforms or a source build, use
`cargo install --git https://github.com/DailenG/entangle entangle` or build
from a checkout. Installer environment overrides are documented in
[docs/SETUP.md](docs/SETUP.md).

After installation, check discovery:

```sh
entangle scan
```

Register the binary as an MCP stdio server in your agent client. Give each
device a useful `--name`; use the same `--context` on devices working on the
same project. See [docs/SETUP.md](docs/SETUP.md) for installation, firewall,
client configuration, and a two-machine smoke test.

The MCP tools are `find_entangled_particles`, `sync_entangled_state`, and
`observe_entangled_states`. The standalone commands are `entangle serve`
(default), `entangle node`, and `entangle scan`.

## Design and security

The crate boundaries, message flow, wire format, and security limitations are
documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The v0 control
channel is plaintext TCP on the LAN, so a network observer can see a one-time
transfer secret in the offer. Do not treat the local network as trusted.

## License

Entangle is dual-licensed under either the [MIT License](LICENSE-MIT) or
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
