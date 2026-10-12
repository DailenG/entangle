# 04. Several groups

Use this when the same device needs separate group memberships, such as work and home.

## You'll need

- Entangle 0.7.x on every machine and a separate saved identity for each device.
- An interactive terminal for each human-operated create, invite, and join.
- A network that permits invite TCP connections, or the inviter's direct
  address for `--via`.
- A distinct invite for each group; group names and membership are local to
  each device.

## Steps

1. **On device A (your terminal):** Create each group that this device should
   administer. These are human-only commands.

   ```sh
   entangle group create work
   entangle group create home
   ```

2. **On device A (your terminal):** Start a human-only invite for `work`. It
   stays open in A's terminal while B joins in step 3. The one-time
   `<work-code>` is the code printed by this command.

   ```sh
   entangle group invite work
   ```

3. **On device B (the operator's terminal):** While A's `work` invite is still
   open, join using `<work-code>`. This is human-only. Add `--via <host:port>`
   if multicast discovery is blocked; `<host:port>` is the invite address
   printed in A's terminal.

   ```sh
   entangle group join <work-code>
   ```

4. **On device A (your terminal):** After the `work` invite finishes, start a
   human-only invite for `home`. It stays open in A's terminal while B joins
   in step 5. The one-time `<home-code>` is the code printed by this command.

   ```sh
   entangle group invite home
   ```

5. **On device B (the operator's terminal):** While A's `home` invite is still
   open, join using `<home-code>`. This is human-only.

   ```sh
   entangle group join <home-code>
   ```

   Use `--as <local-name>` only if this device needs a different local label
   for a group; it does not change the particle name.

6. **On device B (your terminal):** Check that it has both groups.

   ```sh
   entangle group list
   entangle group members work
   entangle group members home
   ```

## It worked if

The local two-group run printed these group-list rows:

```text
home  07d1da89  member  2
work  50af4383  member  2
```

## If something goes wrong

| Symptom | Cause | Fix |
| --- | --- | --- |
| `A group named work already exists here; rerun with --as <other>.` | The receiving device already has a local group with that name. | Choose a different local label with `--as <other>`; do not replace the particle's `--name`. |
| `This machine is already in work.` | The join was attempted again for a group this device already joined. | Check `entangle group list` and use the code for the other group. |
| A device joined `work` but not `home`. | Each group uses its own invite and count. | Invite and join that device to `home` separately. |

## Next

- [Add a device later](03-add-a-device-later.md)
- [Different networks](05-different-networks.md)
- [Troubleshooting](11-troubleshooting.md)
