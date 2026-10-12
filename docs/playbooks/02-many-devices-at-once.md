# 02. Many devices at once

Use this when several devices should join the same group during one onboarding session.

## You'll need

- Entangle 0.6.0 or later on the inviter and every joiner.
- A saved persistent particle identity on the inviter and every joiner.
- One interactive terminal per human-operated invite or join command.
- A network that permits invite TCP connections; mDNS is optional when joiners
  use the address printed by the inviter.
- A count from 1 to 20. `--count` defaults to 1, and the invite expires after
  10 minutes.

## Steps

1. **On device A (your terminal):** Create the group if it does not exist.
   `work` is the group name. This is human-only.

   ```sh
   entangle group create work
   ```

2. **On device A (your terminal):** Start one invite for three successful
   joins. This is human-only.

   ```sh
   entangle group invite work --count 3
   ```

   Keep it running and give each device operator the same one-time code
   securely. If multicast does not work, also give them the printed
   `<host:port>` address.

3. **On each other device (the operator's terminal):** Join with the shared
   code. This is human-only. Each device needs its own saved Entangle
   identity and data directory.

   ```sh
   entangle group join <code>
   ```

   When using the printed direct address instead of mDNS:

   ```sh
   entangle group join <code> --via <host:port>
   ```

4. **On device A (your terminal):** Leave the invite running until all three
   joins finish. It closes at the requested count; it does not remain open for
   later devices.

## It worked if

These lines were captured during the local run with three joiners:

```text
Joined work (4f41e624) via work. 2 members.
Joined work (4f41e624) via work. 3 members.
Joined work (4f41e624) via work. 4 members.
3 of 3 joined; invite closed.
```

## If something goes wrong

`<nameplate>` means the number at the start of the invite code.

| Symptom | Cause | Fix |
| --- | --- | --- |
| `A device entered a wrong code; invite closed (<joined-count> of 3 joined). Run \`entangle group invite work\` again for a new code.` | A joiner entered a wrong code; that invite is dead. `<joined-count>` is the number that had already completed. | Start a new invite with the desired `--count` and share its code with every remaining joiner. |
| `Invite expired; 2 of 3 joined.` | The 10-minute TTL elapsed before the count was reached. | Start another invite for the remaining devices. |
| `The join didn't complete; nothing was kept. Run the same command again while the invite is open.` | The joiner did not receive the final confirmation. | Retry the same `group join` command while the inviter's invite is still open. |

## Next

- [Add a device later](03-add-a-device-later.md)
- [Several groups](04-several-groups.md)
- [Troubleshooting](11-troubleshooting.md)
