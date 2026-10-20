# Setup and initialization

For step-by-step instructions written for an AI agent installing Entangle on
its own machine, see [AGENT_SETUP.md](AGENT_SETUP.md).
For scenario walkthroughs, see the [playbooks](playbooks/README.md).

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

The encrypted link uses TCP 7337 by default and mDNS discovery uses UDP 5353.
If the configured link port is busy, Entangle falls back to an ephemeral port.
Group invites use a separate random ephemeral TCP port that is open only while
the invite runs; do not guess a fixed port to open. `--via` bypasses mDNS
discovery, not a firewall.

On Linux, check UFW and run the allow commands only when `sudo ufw status`
reports active. These fixed-port rules cover the default link and optional
mDNS discovery, not the random invite listener:

```sh
sudo ufw status
sudo ufw allow 7337/tcp
sudo ufw allow 5353/udp
```

On Windows, run this in an elevated PowerShell. Set `<abs-path>` to the
executable path printed by the installer:

```powershell
New-NetFirewallRule -DisplayName "Entangle" -Direction Inbound -Program "<abs-path>" -Action Allow -Profile Private
```

Keep an existing UDP 5353 mDNS rule. If discovery needs it and no rule exists,
the human can add one in elevated PowerShell:

```powershell
New-NetFirewallRule -DisplayName "Entangle mDNS" -Direction Inbound -Protocol UDP -LocalPort 5353 -Action Allow -Profile Private
```

On macOS, ask the human to allow incoming connections for Entangle in the
system firewall. If an active firewall blocks an invite, the human must choose
an appropriate policy for its random listener; do not suggest a fixed port.
Multicast behavior can also depend on the network interface and router
configuration.

An agent following [AGENT_SETUP.md](AGENT_SETUP.md) may apply these rules for
you, but only through an operating-system consent prompt you answer (UAC on
Windows, the `pkexec` password dialog on a Linux desktop). It never uses
`sudo`, cached credentials or stored passwords, and on SSH or headless
machines it asks you to run the commands yourself.

## Groups

Trust is based on membership in a shared group. Each device can belong to up
to eight groups, and group keys are never advertised; mDNS publishes only
public group IDs. Group-bound Noise links encrypt control frames and payloads.
Every machine in a group must use Entangle 0.7.x. Groups created with 0.6 are
outdated and remain only on each machine's local disk. To replace one, the
human upgrades every machine to 0.7, quits and reloads the MCP clients, then
runs `entangle group leave <name>` on each machine. On one machine only, the
human runs `entangle group create <name> --invite <N>`; every other machine
runs `entangle group join <code>`. Leaving the outdated group deletes only
that machine's local copy; only one machine recreates the group.

To create a group and invite three other devices from the first machine, run
this in an interactive terminal. `<N>` is the number of other machines, from
1 to 20. The command remains open until all requested devices join or the
invite expires:

```sh
entangle group create work --invite 3
```

On each other device, a human runs `entangle group join <code>` in that
machine's terminal. For an existing group, any member can run
`entangle group invite work`; the human joins with the code on the new device.
Never send invite codes through an agent.

Use `--as <local-name>` on `group join` to choose a different local group label;
it does not change the particle name advertised by this device.

Inspect groups and members with `entangle group list` and
`entangle group members work`; leave a group with `entangle group leave work`.
`--count N` requests that many successful joins (default 1, maximum 20).
Invites close after ten minutes. Use `--via <host:port>` on `group join` if
mDNS does not find the invite; the inviter prints a direct address. A wrong
code or failed key confirmation closes the invite, so ask for a fresh one.
Signed membership updates are relayed by any member, allowing offline devices
to catch up from any member.

Group membership administration is human-only. The group admin can use
`entangle group remove <group> <member>` to remove a member and rotate the key,
`entangle group rekey <group>` to rotate the key without changing membership,
and `entangle group admin <group> <member>` to hand administration to a
current member. An admin must hand off administration before leaving a group
with other members. See [playbook 10](playbooks/10-leave-remove-rekey.md).

## Register as an MCP server

Each device runs its own Entangle process. The default name is
`<hostname>-<first 4 hex of the particle ID>`; Entangle saves the ID in its
data directory so it stays stable across restarts. `--name` is optional.
Running a second Entangle server with the same data directory gives that
process a temporary ID while the first holds the identity lock. Use a matching
`--context` for agents working in the same project.
Configuration formats can vary by client version; check your client's docs
when the example does not match its current schema.
The installers print the absolute executable path as `Entangle MCP executable:
<path>` on Unix or `Entangle executable: <path>` on Windows. If the output is
unavailable, use `$HOME/.local/bin/entangle` or
`$env:LOCALAPPDATA\Programs\entangle\bin\entangle.exe` (PowerShell; expand it fully in config files), respectively. Use that
absolute path for all version/help checks and MCP registrations; GUI clients
often do not inherit your shell's `PATH`. If using a custom `--data-dir`, pass
the same directory to the MCP server, agent-run read-only CLI commands, and
human-run group commands.

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
claude mcp add --scope user entangle -- <abs-path> serve
claude mcp list
```

Restart Claude Code to load the registered server.

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

For a generic stdio MCP client, launch `<abs-path> serve` (add
`--data-dir <directory>` first if configured), send JSON-RPC lines to its
stdin, and read JSON-RPC lines from stdout. Logs are written separately to
stderr.

## Two-machine smoke test

1. Start the configured MCP server on both devices and check that both
   processes stay running.
2. Run `entangle scan` on each device. The other particle should appear.
3. Ensure both devices are members of the same group.
4. Ask agent A to call `find_entangled_particles`, then send a small JSON
   value or file with `sync_entangled_state`.
5. Ask agent B to call `observe_entangled_states`. Check the JSON value or
   received file path, then optionally set `collapse: true` to consume the
   inbox entry.

The response's `remaining` count is the number of items still in the inbox
after the call (after collapse, if requested).

`entangle peer list` shows known members and their shared groups.

Received items survive Entangle restarts and MCP client reloads until they are
collapsed. Collapsing removes the inbox entry; received files remain on disk.

## Using a repeater

A Quantum Repeater can carry end-to-end encrypted links when devices cannot
connect directly. Run a repeater on a host reachable by both devices. Keep
its state directory private and leave the server running.

Using `ws://` is sufficient for confidentiality because device links are
end-to-end Noise-encrypted; `wss`/TLS support via a reverse proxy is planned.

On the host, choose an address reachable by the devices and start the relay.
The host prints a short public-key fingerprint:

```sh
entangle repeater serve --listen 0.0.0.0:7338
```

To keep it running across reboots, see [Run the repeater as a service](#run-the-repeater-as-a-service).

In a human terminal on the host, create a single-use invitation. Share the
resulting code with the device operator through a trusted human channel; the
code contains the secret that authorizes enrollment:

```sh
entangle repeater invite --url ws://HOST:7338/entangle
```

On each device, a human enters the invitation in a terminal; this enrolls the
device's persistent Noise identity and saves the repeater URL and pinned
public key. Run `join` while Entangle (`omp`) keeps running; the node picks up
the configuration within 30 seconds:

```sh
entangle repeater join <code>
entangle repeater status
```

On success, `join` prints the repeater host, both fingerprints, and a reminder
that the node connects within 30 seconds; the host can confirm enrollment with
`entangle repeater devices`.

### Join without an invite code

On the device, run:

```sh
entangle repeater join ws://HOST:7338/entangle
```

The device's `join` command prints its fingerprint. On the host, run
`entangle repeater approve` and compare the device fingerprint shown there with
the one printed on the device. Press `y` to approve; `n` denies, and Esc
cancels. The operator can disable request enrollment with
`entangle repeater serve --no-requests`; invitation enrollment remains
available.

The host can inspect enrolled device fingerprints with
`entangle repeater devices` and revoke a device by fingerprint prefix with
`entangle repeater revoke <fingerprint>`. On a device,
`entangle repeater leave` removes its saved repeater configuration but does
not revoke the host-side enrollment. `invite`, `join`, `approve`, `revoke`, and
`leave` are human-only; agents may run only `repeater devices` and
`repeater status`.

For a device that must never accept a direct TCP link, start Entangle with
`--relay-only` (or set `ENTANGLE_RELAY_ONLY=1`). This disables the TCP listener
and mDNS and ignores static `--peer` entries. Relay-only mode can start before
the repeater is configured; it connects after a human runs `join`. Check the
local state with:

```sh
entangle repeater status
```

The repeater forwards the end-to-end encrypted link bytes and cannot read
sync content, group keys, or repeater-enrollment SAS values. It does learn
enrolled static public keys, declared group IDs, connection timing, and traffic
sizes.

### Run the repeater as a service

#### systemd (Linux)

Create the service account and install Entangle:

```sh
sudo useradd --system --create-home --home-dir /var/lib/entangle --shell /usr/sbin/nologin entangle
curl -fsSL https://raw.githubusercontent.com/DailenG/entangle/main/install.sh | sh
```

Run the installer as your normal user, not with `sudo`; this is why the
binary is in your own `~/.local/bin`. Install it in a system path:

```sh
sudo install -m 0755 ~/.local/bin/entangle /usr/local/bin/entangle
```

System services should not run binaries from a home directory; on SELinux
systems such as Oracle Linux, systemd can refuse them with `203/EXEC`.

Install and start the unit:

```sh
sudo curl -fsSL https://raw.githubusercontent.com/DailenG/entangle/main/deploy/systemd/entangle-repeater.service -o /etc/systemd/system/entangle-repeater.service
sudo systemctl daemon-reload
sudo systemctl enable --now entangle-repeater
```

Allow TCP 7338 in the host firewall (for example,
`sudo ufw allow 7338/tcp`) and in the cloud provider's firewall or security
group. Check the repeater fingerprint with
`sudo journalctl -u entangle-repeater`.

Run host-side enrollment commands as the service account:

```sh
sudo -u entangle env HOME=/var/lib/entangle /usr/local/bin/entangle repeater invite --url ws://HOST:7338/entangle
sudo -u entangle env HOME=/var/lib/entangle /usr/local/bin/entangle repeater devices
sudo -u entangle env HOME=/var/lib/entangle /usr/local/bin/entangle repeater revoke <fingerprint>
```

#### Docker

Build from the repository root and run with a persistent named volume:

```sh
docker build -t entangle-repeater .
docker run -d --name entangle-repeater --restart unless-stopped -p 7338:7338 -v entangle-repeater:/var/lib/entangle entangle-repeater
```

Create host invitations with:

```sh
docker exec -it entangle-repeater entangle repeater invite --url ws://HOST:7338/entangle
```

The `entangle-repeater` volume contains the repeater's private key and
enrollments; back it up and keep it private.

## Troubleshooting

- **No peers appear:** check UDP 5353, multicast/VLAN policy, and Wi-Fi client
  isolation. Use `--peer host:7337` when multicast is blocked; `--peer` can be
  repeated and also accepts a resolvable hostname. For example,
  `ENTANGLE_PEER=host-a:7337,host-b:7337` provides a comma-separated list.
- **Peers do not link:** confirm both machines are members of a shared group.
  A group-key mismatch prevents the Noise handshake.
- **Port conflicts:** if the configured link port is occupied, Entangle listens
  on an ephemeral port. Static `--peer` entries for this machine and firewall
  rules must allow the port it selected.
- **Diagnostics:** logs are on stderr; use `--log-level debug` for more detail.
- **Inbox files:** files are stored below the platform data directory in
  `entangle/<particle-short-id>/inbox/<sync-id>/`. Override the base with
  `--data-dir`.
