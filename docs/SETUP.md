# Setup and initialization

For step-by-step instructions written for an AI agent installing Entangle on
its own machine, see [AGENT_SETUP.md](AGENT_SETUP.md).

## Prerequisites

- croc 10 or newer on each device. Install with `curl
  https://getcroc.schollz.com | bash` on Linux/macOS, `brew install croc` on
  macOS, or `scoop install croc` / `winget install schollz.croc` on Windows.
- Rust stable toolchain with Cargo if building from source.
- A local network that permits the configured TCP ports; UDP multicast on
  5353 is needed for automatic mDNS resonance.

## Install Entangle

Install the published Git package:

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
on Windows). Entangle locates croc on `PATH`; set `CROC_PATH` or pass
`--croc /path/to/croc` if it is installed elsewhere.

## Firewall

Allow inbound TCP 7337 for the control link and TCP 9109–9113 for the sender's
private croc relay. Allow UDP 5353 for mDNS if automatic discovery is desired.
Adjust these rules if you choose other link/relay ports.

On Ubuntu with UFW:

```sh
sudo ufw allow 7337/tcp
sudo ufw allow 9109:9113/tcp
sudo ufw allow 5353/udp
```

On Windows PowerShell (run as Administrator):

```powershell
New-NetFirewallRule -DisplayName "Entangle link" -Direction Inbound -Protocol TCP -LocalPort 7337 -Action Allow
New-NetFirewallRule -DisplayName "Entangle croc relay" -Direction Inbound -Protocol TCP -LocalPort 9109-9113 -Action Allow
New-NetFirewallRule -DisplayName "Entangle mDNS" -Direction Inbound -Protocol UDP -LocalPort 5353 -Action Allow
```

On macOS, allow the Entangle and croc executables to accept incoming
connections in the system firewall. Multicast behavior can also depend on the
network interface and router configuration.

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

## Troubleshooting

- **No peers appear:** check UDP 5353, multicast/VLAN policy, and Wi-Fi client
  isolation. Use `--peer host:7337` when multicast is blocked; `--peer` can be
  repeated and also accepts a resolvable hostname. For example,
  `ENTANGLE_PEER=host-a:7337,host-b:7337` provides a comma-separated list.
- **croc is not found:** install croc 10+ or configure `--croc` / `CROC_PATH`.
- **Port already in use:** change `--link-port` or `--relay-port`; the relay
  refuses to start if its base port is already occupied.
- **Diagnostics:** logs are on stderr; use `--log-level debug` for more detail.
- **Inbox files:** files are stored below the platform data directory in
  `entangle/<particle-short-id>/inbox/<sync-id>/`. Override the base with
  `--data-dir`.
