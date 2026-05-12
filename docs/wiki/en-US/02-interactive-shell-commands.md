# Interactive Shell Commands

**Language:** English (en-US). **pt-BR:** [../pt-BR/02-shell-interativo-comandos.md](../pt-BR/02-shell-interativo-comandos.md)

## Command Reference

| Command | Purpose |
|---------|---------|
| `use <module>` | Load a module by path |
| `back` | Leave the current module context |
| `show options` | List module options |
| `show info` | Show module metadata |
| `show devices` | List known devices / catalog view |
| `set <option> <value>` | Set a module-local option |
| `setg <option> <value>` | Set a global option (persists across modules) |
| `unset <option>` | Clear a module-local option |
| `unsetg <option>` | Clear a global option |
| `check` | Run a module-specific availability check |
| `run` / `exploit` | Execute the loaded module |
| `search <term>` | Search modules by keyword, CVE, or vendor |
| `discover [subnet] [--timing T0-T5] [--fresh]` | Discover and fingerprint targets on a subnet |
| `sessions <subcommand>` | Manage persistent scan history |
| `help` | Built-in help |
| `exit` | Quit the shell |

## Example Session

```text
EmbedXPL-Forge > use exploits/routers/dlink/dir_300_600_rce
EmbedXPL-Forge (dir_300_600_rce) > show options
EmbedXPL-Forge (dir_300_600_rce) > set target 192.168.0.1
EmbedXPL-Forge (dir_300_600_rce) > check
EmbedXPL-Forge (dir_300_600_rce) > run
```

## Network Discovery

The `discover` command performs multi-phase network scanning to identify known devices:

```text
# Scan the current default subnet (auto-detected from active interfaces)
EmbedXPL-Forge > discover

# Scan a specific subnet with T4 (aggressive) timing
EmbedXPL-Forge > discover 192.168.1.0/24 --timing T4

# Scan a single host
EmbedXPL-Forge > discover 192.168.1.1

# Ignore session history and run a full fresh scan
EmbedXPL-Forge > discover --fresh
```

### Timing Profiles (T0–T5)

| Profile | Inter-probe delay | Use case |
|---------|-------------------|----------|
| `T0` | paranoid — 300 s | Extreme IDS evasion |
| `T1` | sneaky — 15 s | Quiet audits |
| `T2` | polite — 2 s | Minimal network impact |
| `T3` | normal — 0.5 s | **Default** |
| `T4` | aggressive — 0.1 s | Fast LAN scans |
| `T5` | insane — 0 s | CTF / isolated lab only |

Discovery pipeline: **ARP sweep → Nmap (multi-method host probes) → Scapy → TCP connect fallback**.

OUI vendor resolution uses the [IEEE OUI database](https://standards-oui.ieee.org/oui/oui.txt) with online-first lookup and local `embedxpl/data/oui.txt` fallback.

When a discovered host exposes wireless capabilities, EmbedXPL-Forge will display a recommendation to use [WirelessXPL-Forge](https://github.com/mrhenrike/WirelessXPL-Forge) for WiFi-specific attacks.

## Session Management

Sessions persist scan history per unique host (keyed by SHA-256 of IP + MAC). On re-discovery of a known host, previously tested modules appear as `[Tested]` and are skipped by default.

Sessions are stored in `~/.exf_sessions/`.

```text
# List all known hosts with scan history
EmbedXPL-Forge > sessions list

# Show full history for a host: modules tested, findings, timestamps
EmbedXPL-Forge > sessions show 192.168.1.1

# Export session to JSON file
EmbedXPL-Forge > sessions export 192.168.1.1

# Delete session for one host
EmbedXPL-Forge > sessions delete 192.168.1.1

# Delete all sessions
EmbedXPL-Forge > sessions purge
```

## Tab Completion

Tab completion is available for commands and module paths where the readline layer is active.


[Wiki hub](../README.md)
