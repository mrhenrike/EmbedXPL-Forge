# Scanners and AutoPwn

**Language:** English (en-US). **pt-BR:** [../pt-BR/07-scanners-e-autopwn.md](../pt-BR/07-scanners-e-autopwn.md)

## `scanners/routers/router_scan`

Broad `generic + routers` orchestration entry point.

```text
use scanners/routers/router_scan
set target 192.168.1.1
run
```

## `scanners/autopwn`

Parallel scan with credential and exploit checks; **timing templates** similar to Nmap `T0`–`T5`.

### Key options

| Option | Description |
|--------|-------------|
| `target` | IP |
| `target_device_class` | `multi`, `router`, `switch`, `tap`, `fw`, `ngfw`, `isp_cpe` — see `routerxpl/resources/catalogs/module_target_scope.json` |
| `vendor` | Filter when supported |
| `timing_template` | `t0`..`t5` or aliases `paranoid` … `insane` |
| `check_exploits` / `check_creds` | Enable/disable classes of tests |
| HTTP/FTP/SSH/SFTP/Telnet/SNMP/TCP/UDP | `*_use`, ports, SSL flags |
| `threads`, `verify_positive_twice`, `module_timeout_s` | Performance / reliability |

### Optional ML advisor (`show advanced`)

**Off by default.** Reorders exploit/credential module queues and can suggest or apply a `timing_template` using a lightweight linear head (feature vector + JSON weights). Actual CPU/RAM cost of this layer is small; high `threads` and network I/O dominate.

| Option | Description |
|--------|-------------|
| `ml_advisor` | Set `true` to enable; prints warnings. |
| `ml_auto_timing` | With `ml_advisor true`, **overwrites** `timing_template` with the advisor suggestion. |
| `ml_use_gpu` | If PyTorch+CUDA is installed (optional extra `pip install .[ml-gpu]`), runs timing logits on GPU — marginal benefit. HTTP/SSH checks remain I/O bound. |

For heavy crypto (e.g. WPA/PMKID), use external tools such as hashcat, not this advisor.

### Example

```text
use scanners/autopwn
set target 192.168.50.1
set timing_template polite
set target_device_class router
run
```

Use `show advanced` for the full set.

## Perimeter / NGFW scanners

SSL-VPN and FortiGate-oriented recon modules live in [**FirewallXPL-Forge**](https://github.com/mrhenrike/FirewallXPL-Forge) after the repository split (authorized testing only).

## `scanners/routers/hootoo_scan`

HooToo-focused AutoPwn-style scanner.

## `scanners/misc/soho_exploit_catalog_server`

Serves the bundled **SOHO exploit catalog** (static HTML/JS under `routerxpl/resources/arsenal/pocs/soho_exploit_catalog/`) on **`127.0.0.1:8765`** by default. Lab-only; use `open_browser true` to launch the default browser.

---

[Wiki hub](../README.md)
