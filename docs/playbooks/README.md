# Scenario playbooks

Use these walkthroughs for common group, network, repeater, and client setups.

| # | Playbook | Use it when | Machines involved |
| --- | --- | --- | --- |
| 01 | [First group](01-first-group.md) | You are connecting two devices for the first time | Two devices |
| 02 | [Many devices at once](02-many-devices-at-once.md) | Several devices should join one group together | One inviter and up to 20 joiners |
| 03 | [Add a device later](03-add-a-device-later.md) | An existing group needs another device | One current member and one new device |
| 04 | [Several groups](04-several-groups.md) | A device needs separate work and home groups | The members of each group |
| 05 | [Different networks](05-different-networks.md) | Multicast is blocked or direct links cannot cross networks | Group devices; a repeater if needed |
| 06 | [Self-host a repeater](06-self-host-a-repeater.md) | You need a relay reachable by devices on different networks | Repeater host and enrolled devices |
| 07 | [Laptop away from home](07-laptop-away-from-home.md) | A configured laptop must connect while off its home LAN | Laptop and reachable repeater |
| 08 | [Agents coordinating a test across machines](08-agents-coordinating-a-test-across-machines.md) | Agents need to coordinate a multi-machine test | Agents on two or more devices |
| 09 | [Windows with omp](09-windows-omp.md) | You are installing and configuring Entangle on Windows with omp | Windows device and its group peers |
| 10 | Leaving a group, removing a device, rekeying — coming with member removal | Membership administration is available | Group members |
| 11 | [Troubleshooting](11-troubleshooting.md) | Discovery, linking, invitations, or repeater enrollment fails | The affected device and relevant peers |

Playbook 08 is maintained separately and is linked here, but is not part of
this set of changes.
