# Entangle

> **If you are an AI agent reading this:** follow [docs/AGENT_SETUP.md](docs/AGENT_SETUP.md) to install and register Entangle on this machine. Ask your human before changing firewall rules or installing system packages.

> **Experimental.** Entangle is pre-1.0: commands, on-disk formats and the wire protocol can change between releases, and it has not had an external security review.

Entangle is a local-first MCP server for letting two LLM agents on the same
LAN discover one another, exchange capability manifests, and transfer JSON or
files through a group-authenticated Noise link. Control frames and payload
chunks are encrypted end-to-end and payloads are verified with SHA-256.

Entangle uses mDNS for automatic discovery and a configurable static-peer
fallback for networks that block multicast. Discovery metadata includes only
public group IDs, never group keys.

## Glossary

| Entangle term | Meaning |
| --- | --- |
| Particle | A running Entangle process with a persistent identity |
| Resonance | Local network discovery through mDNS |
| Linked | A group member authenticated by a group-bound Noise link |
| State sync | A JSON message or one-file transfer between linked peers |
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

It needs no administrator rights; on Windows it updates your user PATH.
Prebuilt binaries require a published release (v0.1.0+). For other platforms
or a source build, use
`cargo install --git https://github.com/DailenG/entangle entangle` or build
from a checkout. Installer environment overrides are documented in
[docs/SETUP.md](docs/SETUP.md).

After installation, check discovery:

```sh
entangle scan
```

Register the binary as an MCP stdio server in your agent client. The default
name is `<hostname>-<first 4 hex of the particle ID>`; the ID is saved in the
data directory and stays stable across restarts. `--name` is optional. Use the
same `--context` on devices working on the same project. Create a group with
`entangle group create <name>`, then run `entangle group invite <name>` on one
device and `entangle group join <code>` on each other device. Invitations
expire after ten minutes; `--count N` sets the number of successful joins, and
`--via <host:port>` provides a direct-connect fallback when multicast is
blocked. Use `--as <local-name>` on `group join` to choose a different local
group label without changing the particle name. A wrong code or failed
confirmation closes that invite. The inviter
should stay online briefly so existing members can learn about newly joined
devices through one-hop introductions. Use `entangle group list`,
`entangle group members <name>`, and `entangle group leave <name>` to inspect
or leave groups. A second Entangle server using the same data directory gets
a temporary ID while the first server is running. See
[docs/SETUP.md](docs/SETUP.md) for group setup, firewall, client configuration,
and a two-machine smoke test.

**Playbooks:** [Scenario guides](docs/playbooks/README.md).

The MCP tools are `find_entangled_particles`, `sync_entangled_state`, and
`observe_entangled_states`. `sync_entangled_state` can target one particle,
up to 32 selected particles, or every other member of a group; an optional
group pins a send to that group's authenticated link. Received inbox items
include their group name, and `observe_entangled_states` can filter by group.
The standalone commands are `entangle serve` (default), `entangle node`, and
`entangle scan`.

## Design and security

The crate boundaries, message flow, wire format, and security limitations are
documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Protocol version 4
uses group-bound Noise links; all devices must share a group to communicate.

## License

Entangle is dual-licensed under either the [MIT License](LICENSE-MIT) or
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
