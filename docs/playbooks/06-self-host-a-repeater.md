# 06. Self-host a repeater

Use this when devices on different networks need a common relay for their encrypted links.

## You'll need

- Entangle 0.6.0 or later on the host and every device.
- A host with a reachable TCP port, defaulting to 7338 in these commands, and
  a persistent private data volume.
- An interactive terminal for human-only enrollment and device-management
  commands.
- A trusted channel for sharing a one-time repeater invite code.
- Human-only repeater commands: `invite`, `join`, `approve`, `revoke`, and
  `leave`. Agents may run `devices` and `status`.

## Steps

1. **On the repeater host (your terminal):** Start the server. `0.0.0.0`
   listens on all IPv4 interfaces; replace it with a suitable bind address if
   needed.

   ```sh
   entangle repeater serve --listen 0.0.0.0:7338
   ```

   Keep the process running, keep its data directory private, and allow TCP
   7338 through the host and cloud firewalls.

2. **On the repeater host (your terminal):** Create a human-only invite code.
   `<host>` is the repeater's DNS name or address reachable by the devices.

   ```sh
   entangle repeater invite --url ws://<host>:7338/entangle
   ```

   The default invite TTL is 15 minutes. Share the code securely; it contains
   the enrollment secret.

3. **On each device (the operator's terminal):** Ensure Entangle has run once
   so the device has a persistent particle identity, then join using the code.
   This is human-only. `<repeater-code>` is the full code printed by the host's
   invite command.

   ```sh
   entangle repeater join <repeater-code>
   ```

4. **On the repeater host (your terminal):** Inspect enrolled devices. Agents
   may run this read-only command.

   ```sh
   entangle repeater devices
   ```

   Revoke a device by its 1–8 character lowercase hexadecimal fingerprint
   prefix. This is human-only.

   ```sh
   entangle repeater revoke <fingerprint-prefix>
   ```

5. **On the repeater host (Linux, systemd):** Install Entangle, install the
   supplied unit, and start the service. The unit runs as the `entangle`
   service account and listens on TCP 7338.

   ```sh
   sudo useradd --system --create-home --home-dir /var/lib/entangle --shell /usr/sbin/nologin entangle
   curl -fsSL https://raw.githubusercontent.com/DailenG/entangle/main/install.sh | sh
   sudo install -m 0755 ~/.local/bin/entangle /usr/local/bin/entangle
   sudo curl -fsSL https://raw.githubusercontent.com/DailenG/entangle/main/deploy/systemd/entangle-repeater.service -o /etc/systemd/system/entangle-repeater.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now entangle-repeater
   ```

   A person must create host invites and revoke devices as the service account
   so those commands use the service's saved repeater key. Agents may inspect
   devices:

   ```sh
   sudo -u entangle env HOME=/var/lib/entangle /usr/local/bin/entangle repeater invite --url ws://<host>:7338/entangle
   sudo -u entangle env HOME=/var/lib/entangle /usr/local/bin/entangle repeater devices
   sudo -u entangle env HOME=/var/lib/entangle /usr/local/bin/entangle repeater revoke <fingerprint-prefix>
   ```

6. **On the repeater host (Docker):** Build and run the image with a persistent
   named volume. The image starts `repeater serve` on port 7338.

   ```sh
   docker build -t entangle-repeater .
   docker run -d --name entangle-repeater --restart unless-stopped -p 7338:7338 -v entangle-repeater:/var/lib/entangle entangle-repeater
   ```

   A person must run the invite and revoke commands interactively. Agents may
   inspect devices:

   ```sh
   docker exec -it entangle-repeater entangle repeater invite --url ws://<host>:7338/entangle
   docker exec -it entangle-repeater entangle repeater devices
   docker exec -it entangle-repeater entangle repeater revoke <fingerprint-prefix>
   ```

7. **On a device and the repeater host:** If you cannot share an invite code,
   use URL-request enrollment instead. The device command is human-only; the
   host operator then compares the displayed symbol set and runs the
   human-only approval command.

   ```sh
   entangle repeater join ws://<host>:7338/entangle
   entangle repeater approve
   ```

   The server accepts requests by default. `entangle repeater serve
   --no-requests` disables URL-request enrollment but still permits invite-code
   enrollment.

8. **On the enrolled device (the operator's terminal):** `leave` removes only
   this device's saved repeater configuration. It does not revoke the
   host-side enrollment. This is human-only.

   ```sh
   entangle repeater leave
   ```

## It worked if

These lines were captured during the local loopback invite-code run:

```text
repeater key fingerprint: a252e657
Joined the Quantum Repeater at 127.0.0.1 (repeater fingerprint a252e657).
704755eb playbook-device active
configured: yes
url host: 127.0.0.1
repeater fingerprint: a252e657
```

## If something goes wrong

| Symptom | Cause | Fix |
| --- | --- | --- |
| `configured: no` | This device has no saved repeater configuration. | Have a person run `entangle repeater join <repeater-code>` or complete URL-request enrollment. |
| `could not ask the Quantum Repeater at <host> to enroll this device; it may be older than 0.5.0 or started with --no-requests; ask its operator for an invite code instead` | The host is unreachable, too old for requests, or started with `--no-requests`. | Check the URL and TCP port. Use an invite code if request enrollment is disabled. |
| `fingerprint must be a 1-8 character lowercase hex prefix` | The revoke argument is not a valid fingerprint prefix. | Copy the lowercase prefix from `entangle repeater devices`; revocation is human-only. |

## Next

- [Different networks](05-different-networks.md)
- [Laptop away from home](07-laptop-away-from-home.md)
- [Troubleshooting](11-troubleshooting.md)
