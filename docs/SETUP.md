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

## Groups

Trust is based on membership in a shared group. Each device can belong to up
to eight groups, and group keys are never advertised; mDNS publishes only
public group IDs. Group-bound Noise links encrypt control frames and payloads.

Create a group in an interactive terminal, then invite one device and join
each other device with the displayed one-time code:

```sh
entangle group create work
entangle group invite work --count 3
entangle group join 7-amber-photon-quasar
```

Inspect groups and members with `entangle group list` and
`entangle group members work`; leave a group with `entangle group leave work`.
`--count N` requests that many successful joins (default 1, maximum 20).
Invites close after ten minutes. Use `--via <host:port>` on `group join` if
multicast discovery is blocked; the inviter prints a direct address. A wrong
code or failed key confirmation closes the invite, so ask for a fresh one.
The inviter should stay online briefly after onboarding: existing group
members learn about newcomers when the inviter next links to them, using
one-hop member introductions.

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

On the host, run `entangle repeater approve` and choose the matching emoji set.
The emoji check protects against interception. The operator can disable
request enrollment with `entangle repeater serve --no-requests`; invitation
enrollment remains available.

The host can inspect enrolled device fingerprints with
`entangle repeater devices` and revoke a device by fingerprint prefix with
`entangle repeater revoke <fingerprint>`. On a device,
`entangle repeater leave` removes its saved repeater configuration but does
not revoke the host-side enrollment. `invite`, `join`, `approve`, `revoke`, and `leave`
are human-only; agents may run only `repeater devices` and `repeater status`.

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
