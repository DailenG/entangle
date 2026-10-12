# 10. Leave, remove, rekey, and hand off

Use this when a member leaves, an admin removes a device, rotates a group key,
or transfers administration to another member.

## You'll need

- Entangle 0.6.0 or later on each device.
- The group already joined on each device.
- A human operator for all membership and key-administration commands.
- The admin's node online to propagate a removal, rekey, or handoff promptly.

## Steps

1. **On the current admin's device (your terminal):** Check the group roster and
   identify the exact member to remove or promote.

   ```sh
   entangle group members work
   ```

2. **On the admin's device:** Remove a departed or untrusted member. Confirm the
   prompt with `y`; this rotates the key and distributes the signed update to
   reachable members.

   ```sh
   entangle group remove work pc-c
   ```

3. **On the admin's device:** Rotate a key without changing membership when a
   group credential may have been exposed.

   ```sh
   entangle group rekey work
   ```

4. **On the admin's device:** Before the admin leaves a group that still has
   other members, transfer administration to a current member.

   ```sh
   entangle group admin work pc-b
   ```

5. **On a member's device:** Leave the group. When its node is running, it
   notifies reachable members before removing its local group; when stopped,
   the CLI removes the local group immediately.

   ```sh
   entangle group leave work
   ```

Membership changes are human-only. Agents may inspect the roster, but must
never run `group remove`, `group rekey`, `group admin`, or `group leave`.

## It worked if

These lines were captured during a local run with separate data directories
and nodes on this machine:

```text
Removed pc-c from work. Delivered to 1 of 2 members so far (pc-a); pc-d gets it the next time it connects to any member.
pc-a is now the admin of work. Delivered to 1 of 2 members so far (pc-a); pc-d gets it the next time it connects to any member.
Left work. Told 2 of 2 members.
```

## If something goes wrong

- If an update is delivered to only some members, those members can relay its
  signed update chain when they next link to another current member.
- A device that is too far out of date must be invited again by the admin. On
  joining, it refreshes the existing local group to the current key while
  keeping its local group name. The join command prints:
  `Refreshed <name>: this device was out of date and now has the current key.`
- A removed device must ask the admin to invite it again; a non-admin cannot
  restore its membership.

## Next

- [Troubleshooting](11-troubleshooting.md)
- [First group](01-first-group.md)
