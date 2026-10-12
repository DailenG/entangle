# 01. First group

Use this when you are connecting your first two devices in one group.

## You'll need

- Entangle 0.6.0 or later on both devices.
- A saved persistent particle identity on each device; start each configured
  Entangle server once if that identity has not been created yet.
- An interactive terminal on each device for the human-only group commands.
- A LAN that permits mDNS multicast on UDP 5353 and incoming TCP connections.
  The invite listener uses an ephemeral TCP port; the running node uses TCP
  7337 by default.

## Steps

1. **On device A (your terminal):** Create a group. `work` is the group name.
   This is a human-only command.

   ```sh
   entangle group create work
   ```

2. **On device A (your terminal):** Start an invite. This is human-only. The
   default is one successful join; invites expire after 10 minutes.

   ```sh
   entangle group invite work
   ```

   Keep this command running. It prints a one-time `<code>` and an address.
   Use the printed `<host:port>` if discovery is blocked; it is the invite
   listener's LAN address and ephemeral port.

3. **On device B (your terminal):** Enter the code from device A. This is
   human-only. The joiner browses for up to 15 seconds; use `--via` to skip
   mDNS and connect to the printed address directly.

   ```sh
   entangle group join <code>
   ```

4. **On both devices:** Start or reload the configured Entangle MCP server.
   Both devices now share the group; they do not need to use the same particle
   name.

## It worked if

These lines were captured during the local two-device run:

```text
Created group work (d8a1da2a). You are its admin.
Joined work (d8a1da2a) via work. 2 members.
1 of 1 joined; invite closed.
```

## If something goes wrong

`<nameplate>` means the number at the start of the invite code.

| Symptom | Cause | Fix |
| --- | --- | --- |
| `No invite <nameplate> found on this network. Check the code and that \`entangle group invite\` is still running; or add --via <host:port>.` | The invite was not discovered, has closed, or its nameplate does not match. | Check the code and that the inviter is still waiting. Retry with the exact printed address: `entangle group join <code> --via <host:port>`. |
| `That code was wrong; the invite is now closed. Ask for a new one.` | The entered code did not authenticate. A wrong code closes that invite. | Ask the inviter to start a new invite and use its new code. |

## Next

- [Many devices at once](02-many-devices-at-once.md)
- [Add a device later](03-add-a-device-later.md)
- [Troubleshooting](11-troubleshooting.md)
