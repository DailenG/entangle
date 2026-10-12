# 05. Different networks

Use this when multicast is blocked or devices cannot open direct links across their networks.

## You'll need

- Entangle 0.6.0 or later on each device and an interactive terminal for human-only
  group commands.
- A saved persistent particle identity on each device.
- For direct joining, TCP reachability to the inviter's printed invite address.
- For static peer discovery, TCP reachability to an Entangle node's link
  listener; the default port is 7337.
- A reachable repeater host if direct TCP cannot cross the network boundary.

## Steps

1. **On the inviter (your terminal):** Create or select the shared group and
   start its human-only invite.

   ```sh
   entangle group invite work
   ```

   Share the one-time code and the printed `<host:port>` address through a
   trusted human channel.

2. **On the joining device (the operator's terminal):** Skip invite mDNS and
   connect to the inviter's address with the human-only join command.

   ```sh
   entangle group join <code> --via <host:port>
   ```

3. **On a device that needs to find a peer without multicast (your terminal):**
   Configure a static peer when starting its MCP server. `<peer-host:port>` is
   the other Entangle node's reachable link address, not the invite address.
   Ensure the peer's listener and firewall permit that TCP port.

   ```sh
   entangle serve --peer <peer-host:port>
   ```

   `--peer` can be repeated or supplied as a comma-separated list. If the
   configured `--link-port` is occupied, the node may select an ephemeral
   port; use a reachable address and port.

4. **On both devices:** If neither direct links nor static peers can traverse
   the network boundary, use a reachable repeater and enroll each device
   through [Self-host a repeater](06-self-host-a-repeater.md).

5. **On each device (your terminal):** Check local group membership and known
   peers.

   ```sh
   entangle group list
   entangle peer list
   ```

## It worked if

For direct invite joining, the CLI's source-defined success format is:
`<group>` is the local group name, `<group-id>` its identifier, `<inviter>`
the inviter's name, and `<member-count>` the resulting roster size.

```text
Joined <group> (<group-id>) via <inviter>. <member-count> members.
```

The format comes from the join-success renderer. This playbook was not run on
a real multicast-blocked or cross-network LAN.

## If something goes wrong

`<nameplate>` means the number at the start of the invite code.

| Symptom | Cause | Fix |
| --- | --- | --- |
| `No invite <nameplate> found on this network. Check the code and that \`entangle group invite\` is still running; or add --via <host:port>.` | Invite discovery did not find an advert, or the invite is no longer running. | Use the printed invite address with `group join --via`. |
| No peer appears in `entangle peer list`. | Multicast discovery is blocked, or no static peer is configured. | Add `--peer <peer-host:port>` to the server that should dial the peer. |
| The peer is reachable only through a firewall or NAT boundary. | A direct TCP link cannot be opened between the devices. | Enroll both devices with a repeater as described in [Playbook 06](06-self-host-a-repeater.md). |

## Next

- [Self-host a repeater](06-self-host-a-repeater.md)
- [Laptop away from home](07-laptop-away-from-home.md)
- [Troubleshooting](11-troubleshooting.md)
