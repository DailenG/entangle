# 07. Laptop away from home

Use this when a laptop must keep reaching group members after it leaves the home LAN.

## You'll need

- Entangle 0.7.x on every machine.
- A repeater reachable from the laptop's current network.
- The laptop enrolled with that repeater and all communicating devices sharing
  the same Entangle group.
- An interactive terminal for human-only repeater enrollment.

## Steps

1. **On a network where the repeater is reachable (the operator's terminal):**
   Enroll the laptop with a human-operated invite or URL request. Follow
   [Self-host a repeater](06-self-host-a-repeater.md).

2. **On the laptop's MCP client:** Start the server normally if you want
   Entangle to try direct links first and use the repeater when needed. If the
   laptop must not open a direct TCP listener, add `--relay-only` to its
   server arguments:

   ```sh
   entangle serve --relay-only
   ```

   Alternatively set the environment variable `ENTANGLE_RELAY_ONLY=1` for the
   MCP server process. Relay-only mode also disables mDNS and ignores static
   `--peer` entries; it can start before repeater enrollment is complete.

3. **On the laptop (your terminal):** Check the saved repeater configuration.

   ```sh
   entangle repeater status
   ```

   This reports saved configuration, host, and fingerprint. It does not
   report whether the live node tunnel is currently connected. The running
   node connects within 30 seconds after enrollment; use the
   `self.repeater.connected` field from `find_entangled_particles` to inspect
   its live state.

4. **On the laptop and other devices:** Ensure the peers share a group, then
   send a small test state in that group and observe it on the other device.

## It worked if

The local enrolled-device transcript showed:

```text
configured: yes
url host: 127.0.0.1
repeater fingerprint: a252e657
```

The source-defined join confirmation says:

```text
A running Entangle node connects within 30 seconds; check with `entangle repeater status`.
```

The live off-LAN route was not tested on this machine.

## If something goes wrong

| Symptom | Cause | Fix |
| --- | --- | --- |
| `configured: no` | The repeater join was not completed or this process uses a different data directory. | Have a person join the repeater, then check status using the same `--data-dir` as the MCP server. |
| Status is configured, but the live node is not connected. | The repeater URL may be unreachable from the current network, or the node has not refreshed its configuration yet. | Check TCP reachability and the `self.repeater.connected` field; allow up to 30 seconds after enrollment. |
| The laptop cannot reach peers directly away from home. | The network blocks direct TCP or mDNS. | Use the repeater. Use `--relay-only` only when the laptop must not accept direct links. |

## Next

- [Self-host a repeater](06-self-host-a-repeater.md)
- [Different networks](05-different-networks.md)
- [Troubleshooting](11-troubleshooting.md)
