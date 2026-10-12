# 03. Add a device later

Use this when a group already exists and you want to enroll one more device.

## You'll need

- Entangle 0.7.x on every machine.
- A saved persistent particle identity on both devices.
- The current member's group name and an interactive terminal on both devices.
- A network that allows the invite TCP connection, or a direct address to use
  with `--via`.
- Time for the current member to reconnect to existing group members after
  enrollment so it can vouch for the newcomer.

## Steps

1. **On the current member (your terminal):** Start a fresh invite for the
   existing group. Do not create the group again. `work` is the group name.
   This is human-only; the default count is one.

   ```sh
   entangle group invite work
   ```

2. **On the new device (the operator's terminal):** Join using the new
   one-time code. This is human-only.

   ```sh
   entangle group join <code>
   ```

   If multicast is blocked, use the inviter's printed address:

   ```sh
   entangle group join <code> --via <host:port>
   ```

3. **On the current member:** Keep its Entangle node online briefly. Member
   introductions are one-hop: the current member shares members it added
   when it next links to other group members. Those devices can then link to
   the newcomer.

4. **On the new device (your terminal):** Confirm the local membership.

   ```sh
   entangle group list
   entangle group members work
   ```

## It worked if

The initial and later join transcripts contained:

```text
Joined work (53e3e217) via pc-a. 2 members.
Joined work (53e3e217) via pc-a. 3 members.
```

Each inviter transcript contained:

```text
1 of 1 joined; invite closed.
```

## If something goes wrong

| Symptom | Cause | Fix |
| --- | --- | --- |
| `group not found: work` | The inviter's local group name is not `work`, or that device has left the group. | Check `entangle group list` on the inviter and invite the exact existing name. |
| `This machine is already in work.` | This device is already a member of that group. | Check `entangle group list`; do not create a duplicate group. |
| The newcomer joined, but an existing member has not learned about it. | Introductions are one-hop and the member who added the newcomer has not linked to that existing member since the invite. | Keep the inviter online until it reconnects to existing members. |

## Next

- [Many devices at once](02-many-devices-at-once.md)
- [Several groups](04-several-groups.md)
- [Leaving a group, removing a device, rekeying](README.md#scenario-playbooks)
