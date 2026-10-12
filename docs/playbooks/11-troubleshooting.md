# 11. Troubleshooting

Use this when a group invite, peer link, discovery path, or repeater does not work.

## You'll need

- Entangle 0.6.0 or later on each affected device.
- Access to the relevant device's terminal and, for repeater issues, the host.
- The group name, invite code if still open, and reachable host/port details.
- A human operator for group invite/join and repeater enrollment or
  administration.

## Steps

1. **On each affected device (your terminal):** Check local groups and
   members. `<group-name>` is the local group label shown by `group list`.

   ```sh
   entangle group list
   entangle group members <group-name>
   ```

2. **On devices that cannot discover each other:** Check UDP 5353 and multicast
   policy. `<code>` is the current group invite code; `<host:port>` is the
   invite address printed by its inviter. For a group invite, use that address
   with the human-only command:

   ```sh
   entangle group join <code> --via <host:port>
   ```

3. **On a device that should dial a known peer:** Add the peer's reachable
   link address to its MCP server command. `<peer-host:port>` is the Entangle
   link listener, not the group-invite listener.

   ```sh
   entangle serve --peer <peer-host:port>
   ```

4. **On devices behind NAT or a network boundary:** Follow
   [Self-host a repeater](06-self-host-a-repeater.md), then check the saved
   repeater configuration and live node status separately.

   ```sh
   entangle repeater status
   ```

5. **On the relevant host or device:** Use debug logging for additional
   diagnostics. The global option defaults to `info`.

   ```sh
   entangle serve --log-level debug
   ```

## It worked if

The captured local multi-group listing showed both memberships:

```text
NAME  GROUP  ROLE  MEMBERS
home  07d1da89  member  2
work  50af4383  member  2
```

The local loopback join transcript printed this line:
`<group>` is the group name, `<group-id>` its identifier, `<inviter>` the
inviter's name, and `<member-count>` the resulting roster size.

```text
Joined <group> (<group-id>) via <inviter>. <member-count> members.
```

The cross-network paths were not tested on a real LAN.

## If something goes wrong

`<nameplate>` means the number at the start of the invite code.

| Symptom | Cause | Fix |
| --- | --- | --- |
| `group not found: <group-name>` | The local name is wrong or the device has left that group. | Check `entangle group list` and use the exact local name. |
| `No invite <nameplate> found on this network. Check the code and that \`entangle group invite\` is still running; or add --via <host:port>.` | The invite is closed, the nameplate is wrong, or mDNS did not find the advert. | Check the code and invite status; retry with the printed `--via` address. |
| `That code was wrong; the invite is now closed. Ask for a new one.` | The code did not authenticate; the inviter closes that invite on a wrong code. | Ask for a new invite code. |
| `configured: no` | This device has not saved repeater enrollment in the data directory used by the current process. | Have a person complete repeater enrollment in that same data directory. |
| Members are not linked even though both devices list the group. | Membership does not make a blocked route reachable. | Check the link TCP port, static `--peer` address, and repeater enrollment. |

## Next

- [First group](01-first-group.md)
- [Different networks](05-different-networks.md)
- [Self-host a repeater](06-self-host-a-repeater.md)
- [Laptop away from home](07-laptop-away-from-home.md)
