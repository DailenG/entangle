# Setup and initialization

For step-by-step instructions written for an AI agent installing Entangle on
its own machine, see [AGENT_SETUP.md](AGENT_SETUP.md).

## Prerequisites

- A published Entangle release (v0.1.0+) for the prebuilt installers.
- An internet connection for downloading Entangle.
- Rust stable toolchain with Cargo only if building from source or using the
  Cargo-install fallback.
- A local network that permits the configured TCP ports; UDP multicast on
  5353 is needed for automatic mDNS resonance.

## Install Entangle

Install the prebuilt binary first:

```powershell
irm https://raw.githubusercontent.com/DailenG/entangle/main/install.ps1 | iex
```

```sh
curl -fsSL https://raw.githubusercontent.com/DailenG/entangle/main/install.sh | sh
```

The installer requires no administrator or `sudo` rights. macOS/Linux installs
into `$HOME/.local/bin` by default and prints a PATH hint if needed. Windows
installs into `%LOCALAPPDATA%\Programs\entangle\bin` and adds that directory
to the current user's PATH only. Prebuilt downloads support Linux x86_64 and
aarch64, macOS Intel and Apple silicon, and Windows x86_64.

Configure the installers with these environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `ENTANGLE_VERSION` | `latest` | Select `latest` or a release tag such as `v0.1.0`. |
| `ENTANGLE_INSTALL_DIR` | `$HOME/.local/bin` on Unix; `%LOCALAPPDATA%\Programs\entangle\bin` on Windows | User-writable installation directory. |
| `ENTANGLE_DOWNLOAD_BASE` | GitHub latest/download or the selected tag's download URL | Override the Entangle archive and `SHA256SUMS` base URL; intended for testing. |

The installers verify SHA-256 checksums before extracting binaries. To install
from Cargo instead, use:

```sh
cargo install --git https://github.com/DailenG/entangle entangle
```

Or build the current checkout from source:

```sh
git clone https://github.com/DailenG/entangle.git
cd entangle
cargo build --release
```

The executable is `target/release/entangle` (or `target/release/entangle.exe`
on Windows).

## Firewall

Allow inbound TCP 7337 for the encrypted link and UDP 5353 for mDNS if
automatic discovery is desired. If the configured link port is busy, Entangle
uses an ephemeral port; firewall rules and static peer entries must permit
that port.

On Ubuntu with UFW:

```sh
sudo ufw allow 7337/tcp
sudo ufw allow 5353/udp
```

On Windows PowerShell (run as Administrator):

```powershell
New-NetFirewallRule -DisplayName "Entangle link" -Direction Inbound -Protocol TCP -LocalPort 7337 -Action Allow
New-NetFirewallRule -DisplayName "Entangle mDNS" -Direction Inbound -Protocol UDP -LocalPort 5353 -Action Allow
```

On macOS, allow the Entangle executable to accept incoming connections in the
system firewall. Multicast behavior can also depend on the network interface
and router configuration.

## Pairing

Version 0.2 requires both devices to use the same pairing key and cannot
communicate with version 0.1.x peers. Upgrade both devices before pairing.
The pairing key is never advertised; mDNS publishes only its 8-character
group ID.
Migration: croc is no longer required by Entangle 0.2; remove an old
installation if it was installed only for Entangle.

On one device, a human runs:

```sh
entangle pair init
```

On each other device, a human enters the code directly into:

```sh
entangle pair join <code>
```

Treat the pairing code as a secret. Do not send it through Entangle, place it
in MCP configuration, or give it to an agent. Check the paired state and
public group ID with `entangle pair status`.
Pairing-key changes take effect within a few seconds without reloading the MCP
client; installing a new Entangle binary still requires a client reload.

## Register as an MCP server

Each device runs its own Entangle process. The default name is
`<hostname>-<first 4 hex of the particle ID>`; Entangle saves the ID in its
data directory so it stays stable across restarts. `--name` is optional.
Running a second Entangle server with the same data directory gives that
process a temporary ID while the first holds the identity lock. Use a matching
`--context` for agents working in the same project.
Configuration formats can vary by client version; check your client's docs
when the example does not match its current schema.
GUI clients often do not inherit your shell's `PATH`, so use the absolute path
to the `entangle` executable in their configuration.

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "entangle": {
      "command": "/ABSOLUTE/PATH/TO/entangle",
      "args": ["serve", "--context", "project-x"]
    }
  }
}
```

**Claude Code**:

```sh
claude mcp add entangle -- entangle serve --context project-x
```

**LM Studio** commonly uses an MCP server configuration such as `mcp.json`;
check the current LM Studio docs for the exact location and format:

```json
{
  "mcpServers": {
    "entangle": {
      "command": "/ABSOLUTE/PATH/TO/entangle",
      "args": ["serve", "--context", "project-x"]
    }
  }
}
```

For a generic stdio MCP client, launch `entangle serve --context project-x`,
send JSON-RPC lines to its stdin, and read JSON-RPC lines from stdout. Logs
are written separately to stderr.

## Two-machine smoke test

1. Start the configured MCP server on both devices and check that both
   processes stay running.
2. Run `entangle scan` on each device. The other particle should appear.
3. Ask agent A to call `find_entangled_particles`, then send a small JSON
   value or file with `sync_entangled_state`.
4. Ask agent B to call `observe_entangled_states`. Check the JSON value or
   received file path, then optionally set `collapse: true` to consume the
   inbox entry.

The response's `remaining` count is the number of items still in the inbox
after the call (after collapse, if requested).

Received items survive Entangle restarts and MCP client reloads until they are
collapsed. Collapsing removes the inbox entry; received files remain on disk.

## Troubleshooting

- **No peers appear:** check UDP 5353, multicast/VLAN policy, and Wi-Fi client
  isolation. Use `--peer host:7337` when multicast is blocked; `--peer` can be
  repeated and also accepts a resolvable hostname. For example,
  `ENTANGLE_PEER=host-a:7337,host-b:7337` provides a comma-separated list.
- **Peers do not entangle:** confirm both machines report `paired: yes` and
  the same pairing group. A pairing-key mismatch prevents the Noise handshake.
- **Port conflicts:** if the configured link port is occupied, Entangle listens
  on an ephemeral port. Static `--peer` entries for this machine and firewall
  rules must allow the port it selected.
- **Diagnostics:** logs are on stderr; use `--log-level debug` for more detail.
- **Inbox files:** files are stored below the platform data directory in
  `entangle/<particle-short-id>/inbox/<sync-id>/`. Override the base with
  `--data-dir`.
