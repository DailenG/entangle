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
   `%LOCALAPPDATA%\Programs\entangle\bin`; the installer prints the executable
   path. Restart the terminal if the installer adds its directory to PATH.

2. **On the Windows device (PowerShell, only if required):** If Windows
   Firewall blocks discovery or incoming links, ask the human before changing
   firewall rules. The following commands require an elevated PowerShell
   session:

   ```powershell
   New-NetFirewallRule -DisplayName "Entangle link" -Direction Inbound -Protocol TCP -LocalPort 7337 -Action Allow
   New-NetFirewallRule -DisplayName "Entangle mDNS" -Direction Inbound -Protocol UDP -LocalPort 5353 -Action Allow
   ```

   If an agent runs these commands, it must first write them to a temporary
   `.ps1`, then run `powershell.exe -NoProfile -ExecutionPolicy Bypass -File
   <path>` (`<path>` is the temporary script's full path) and delete the
   script. Do not pass inline `-Command` strings.

3. **In omp's MCP config:** Add an Entangle server entry in
   `%USERPROFILE%\.omp\agent\mcp.json` and replace `<user>` with the Windows
   account folder. The executable path must be absolute; keep other existing
   server entries. The default Entangle data directory is
   `%APPDATA%\entangle`.

   ```json
   {
     "mcpServers": {
       "entangle": {
         "command": "C:\\Users\\<user>\\AppData\\Local\\Programs\\entangle\\bin\\entangle.exe",
         "args": ["serve"]
       }
     }
   }
   ```

   Ask the human to reload omp with `/mcp reload`. Its first server start
   creates the saved identity required by group commands. If a custom data
   directory is configured, the human must use the same directory for group
   commands.

4. **On the Windows device (PowerShell):** Confirm the command is available
   and inspect its flags.

   ```powershell
   entangle --version
   entangle --help
   ```

5. **On the group devices (each operator's terminal):** For a new group, a
   person runs `entangle group create <name> --invite <N>` on the first device,
   where `<N>` is the number of other devices. For an existing group, any
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
