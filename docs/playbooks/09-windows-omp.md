# 09. Windows with omp

Use this when you install Entangle on Windows and register it with omp.

## You'll need

- 64-bit Windows; the prebuilt `install.ps1` installer downloads the x64
  executable.
- An interactive PowerShell terminal and omp with an MCP `mcp.json`.
- A human operator to approve installation and config/firewall edits, reload
  omp, and run all human-only group commands.

## Steps

1. **On the Windows device (PowerShell):** Review and run the user-level
   installer. It does not require Administrator rights.

   ```powershell
   irm https://raw.githubusercontent.com/DailenG/entangle/main/install.ps1 | iex
   ```

   By default the executable is installed under
   `%LOCALAPPDATA%\Programs\entangle\bin`; the installer prints
   `Entangle executable: <path>`. Record that absolute path for all later
   verification and registration steps. If the installer output is
   unavailable, use `$env:LOCALAPPDATA\Programs\entangle\bin\entangle.exe` (PowerShell; expand it fully in config files).
   Restart the terminal if the installer adds its directory to PATH.

2. **On the Windows device (PowerShell, only if required):** If Windows
   Firewall blocks discovery or incoming links, add a program rule for the
   installer's absolute executable path. An agent follows
   [AGENT_SETUP step 4](../AGENT_SETUP.md#4-network): it shows the human the
   rule script, then launches it through the UAC prompt, which the human
   approves. It never uses stored credentials and does not retry if the
   prompt is declined. A human can instead run this in an elevated
   PowerShell, with `<abs-path>` replaced by the executable path:

   ```powershell
   New-NetFirewallRule -DisplayName "Entangle" -Direction Inbound -Program "<abs-path>" -Action Allow -Profile Private
   ```

   Keep an existing UDP 5353 rule for mDNS. If discovery needs it and no rule
   exists, add one the same way:

   ```powershell
   New-NetFirewallRule -DisplayName "Entangle mDNS" -Direction Inbound -Protocol UDP -LocalPort 5353 -Action Allow -Profile Private
   ```

   Group invitations use a random ephemeral TCP port. Do not add a guessed
   port rule; if a firewall blocks it, the human must choose an appropriate
   policy. `--via` bypasses mDNS, not the firewall.

3. **In omp's MCP config:** Add an Entangle server entry in
   `$env:USERPROFILE\.omp\agent\mcp.json`. The executable path must be
   absolute; keep other existing server entries. The default Entangle data
   directory is `$env:APPDATA\entangle`. (PowerShell syntax; write fully
   expanded paths into config files.)

   ```json
   {
     "mcpServers": {
       "entangle": {
         "command": "<abs-path>",
         "args": ["serve"]
       }
     }
   }
   ```

   Copy the exact installer path into `command` and JSON-escape its
   backslashes. Ask the human to reload omp with `/mcp reload`; omp keeps the
   current conversation through this reload. Its first server start creates
   the saved identity required by group commands. If a custom data directory
   is configured, pass it to the server, agent-run read-only CLI commands,
   and human group commands.

4. **On the Windows device (PowerShell):** Confirm the command is available
   and inspect its flags.

   ```powershell
   & "<abs-path>" --version
   & "<abs-path>" --help
   ```

   Use the absolute path recorded in step 1. Add `--data-dir <directory>`
   after the executable path and before `--version` or `--help` when configured.

5. **On the group devices (each operator's terminal):** For a new group, a
   person runs `entangle group create <name> --invite <N>` on the first device,
   where `<N>` is the number of other devices (1–20). For an existing group, any
   member runs `entangle group invite <name>`. A person runs
   `entangle group join <code>` on each other device, or adds
   `--via <host:port>` using the inviter's output if mDNS cannot find the
   invite. All group-changing commands are human-only; never ask a person to
   share an invite code with the agent.

## It worked if

The installer source prints this fixed confirmation after installation:

```text
Reload or restart your MCP client so it runs this version.
```

The Windows setup and firewall path was not run locally; the executable
path and installer message are defined in `install.ps1`.

## If something goes wrong

| Symptom | Cause | Fix |
| --- | --- | --- |
| `LOCALAPPDATA is unavailable; set ENTANGLE_INSTALL_DIR to a user-writable directory.` | The installer cannot determine its default install directory. | Set `ENTANGLE_INSTALL_DIR` to a user-writable absolute directory and rerun it. |
| `This is a human-only command and requires an interactive terminal.` | A group invite, join, create, or leave command was started without a terminal. | Have a person run it in their terminal. |
| omp cannot start Entangle. | The MCP `command` path is not absolute or points to a different executable. | Use the exact executable path printed by the installer and reload omp. |

## Next

- [First group](01-first-group.md)
- [Different networks](05-different-networks.md)
- [Troubleshooting](11-troubleshooting.md)
