# Troubleshooting

**Language:** English (en-US) | **pt-BR:** [../pt-BR/11-troubleshooting.md](../pt-BR/11-troubleshooting.md)

---

## Quick diagnostics

Before filing a bug, run the environment doctor:

```bash
python tools/env_doctor.py
```

And the compatibility smoke check:

```bash
python tools/compat_smoke.py
```

---

## Startup issues

### `ImportError` or `ModuleNotFoundError` on launch

```
ModuleNotFoundError: No module named 'embedxpl'
```

**Cause:** Package not installed or wrong Python environment active.

```bash
# Install from source
pip install -e .

# Or install from PyPI
pip install embedxpl

# Reinstall all dependencies
pip install -r requirements.txt

# Verify environment
python tools/env_doctor.py
```

Confirm you are using the correct Python executable:

```bash
which python        # Linux/macOS
where python        # Windows
python --version    # must be >= 3.8
```

---

### `stdin is not a TTY` error

```
[-] stdin is not a TTY. Ensure `stdin_open` and `tty` are set
```

**Cause:** EmbedXPL-Forge's interactive shell requires a real TTY. This error appears when stdin is piped, redirected, or running inside a non-interactive Docker container without TTY allocation.

**Fix options:**

```bash
# Option 1 — non-interactive mode (no TTY required)
python -m embedxpl -m exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224 \
    -s "target 192.168.1.1" -s "port 80"

# Option 2 — Docker: allocate a pseudo-TTY
docker run -it --rm embedxpl-forge embedxpl

# Option 3 — SSH: request a TTY
ssh -t user@host 'embedxpl'
```

---

### Module not found after `use <module>`

```
[-] Unknown module: 'exploits/routers/tplink/nonexistent'
```

**Cause:** Module path is incorrect, module file is missing, or you are not running from the repository root.

```bash
# Verify module exists
ls embedxpl/modules/exploits/routers/tplink/

# Re-index modules
python -c "from embedxpl.core.exploit.utils import index_modules; print(len(index_modules()), 'modules')"

# Search for partial name
exf> search tplink
```

---

### `EmbedXPL stopped` on `Ctrl+C`

```
[-] Use Ctrl+D to exit
```

This is expected behavior. `Ctrl+C` cancels the current operation. To exit the shell cleanly, use `Ctrl+D` or type `exit`.

---

## Python version issues

### Python 3.13+ — `telnetlib` removed

```
ModuleNotFoundError: No module named 'telnetlib'
```

`telnetlib` was removed in Python 3.13. EmbedXPL-Forge ships `telnetlib3` as a drop-in replacement:

```bash
pip install telnetlib3
# or
pip install embedxpl[all]
```

---

### Python 3.8 minimum requirement

```
SyntaxError: ...
```

Most modules use f-strings, walrus operators, and `dataclasses` which require Python 3.8+. Check:

```bash
python --version
# Expected: Python 3.8.x or higher (3.10+ recommended)
```

---

### `readline` not available (Windows)

```
[WARN] readline not available — tab completion disabled
```

This is a non-critical warning on Windows. The interpreter uses a shim that disables tab completion but all commands work normally. To enable tab completion on Windows, install `pyreadline3`:

```bash
pip install pyreadline3
```

---

## Protocol-specific issues

### SSH — `No existing session` / `Authentication failed`

```
[-] Authentication failed for 192.168.1.1:22
```

**Common causes and fixes:**

| Cause | Fix |
|-------|-----|
| Wrong credentials | Use `set username admin` and `set password admin` |
| SSH key type mismatch | Add `set ssh_key_type rsa-sha2-256` |
| Host key rejected | Add host to `~/.ssh/known_hosts` or use `set strict_host_key False` |
| Port not open | Run `discover 192.168.1.1` first to confirm SSH is listening |
| `paramiko` not installed | `pip install paramiko` |

---

### Telnet — connection refused

```
[-] Connection refused: 192.168.1.1:23
```

Telnet is disabled on most modern devices. Confirm the port is open:

```bash
python -m embedxpl -m scanners/generic/port_scanner -s "target 192.168.1.1" -s "ports 23"
```

If `telnetlib3` is missing:

```bash
pip install telnetlib3
```

---

### HTTP/HTTPS — SSL certificate errors

```
ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED]
```

**Fix:** Most IoT devices use self-signed certificates. Set the `ssl_verify` option to `false`:

```
exf (module) > set ssl_verify false
```

Or globally:

```
exf> setg ssl_verify false
```

---

### SNMP — no response

```
[-] SNMP: no response from 192.168.1.1 (timeout after 5s)
```

**Common causes:**

| Cause | Fix |
|-------|-----|
| Wrong community string | `set community public` / `set community private` |
| SNMP v1/v2 disabled | Try `set snmp_version 3` |
| Firewall blocking UDP 161 | Confirm with `nmap -sU -p 161 192.168.1.1` |
| `pysnmp` not installed | `pip install pysnmp` |

---

### Modbus TCP — connection errors

```
[-] Modbus: connection refused on 192.168.1.100:502
```

Modbus TCP listens on port 502. Confirm:

```bash
nmap -p 502 192.168.1.100
```

If the port is filtered, the target may require direct serial RS-485 (Modbus RTU) access instead of TCP.

---

### FTP — `530 Login incorrect`

```
[-] FTP authentication failed: 530 Login incorrect
```

Use the creds module to brute-force or try the manufacturer defaults:

```
exf> use creds/routers/tplink/ftp_default_creds
exf (tplink/ftp_default_creds) > set target 192.168.1.1
exf (tplink/ftp_default_creds) > run
```

---

## NSE-specific issues

### `nmap: command not found`

```
[ERROR] Nmap not found. Install Nmap to use this command.
```

Install Nmap for your OS:

| OS | Command |
|----|---------|
| Debian/Ubuntu | `sudo apt-get install nmap` |
| Fedora/RHEL | `sudo dnf install nmap` |
| Arch | `sudo pacman -S nmap` |
| macOS (Homebrew) | `brew install nmap` |
| Windows (winget) | `winget install insecure.nmap` |
| Windows (Chocolatey) | `choco install nmap` |
| Windows (manual) | https://nmap.org/download.html |

After installing:

```bash
embedxpl-nse install
```

---

### NSE scripts directory not found

```
[ERR] Could not locate Nmap scripts directory.
```

Manually specify the directory:

```bash
embedxpl-nse install --nse-dir /usr/share/nmap/scripts
# Windows:
embedxpl-nse install --nse-dir "C:\Program Files (x86)\Nmap\scripts"
```

---

### `Permission denied` installing NSE scripts

```
[ERR] Permission denied: /usr/share/nmap/scripts/embedxpl-iot-cve-check.nse
```

Run with elevated privileges:

```bash
# Linux/macOS
sudo embedxpl-nse install

# Windows (run from Administrator PowerShell)
embedxpl-nse install
```

---

### NSE script not found after install

```
nmap: warning: 'embedxpl-iot-cve-check.nse' not found in nmap-scripts
```

The script database needs updating:

```bash
sudo nmap --script-updatedb
```

Or reinstall with force:

```bash
sudo embedxpl-nse install --force
```

---

### NSE `check` returns false positives

If `embedxpl-nse run` reports vulnerabilities on clearly non-vulnerable targets, the port selection may be too broad. Narrow the port list:

```bash
embedxpl-nse run --target 192.168.1.1 --scripts hikvision-vuln --ports 80,443,8080
```

---

## CVE-specific issues

### CVE-2022-40684 (FortiOS auth bypass) — HTTP 404

```
[-] HTTP 404 on /api/v2/cmdb/system/admin/admin
```

The target may be running FortiOS 7.2.2+ (patched). Confirm the version banner:

```
exf> use scanners/firewalls/fortinet/fortios_version_check
exf (fortios_version_check) > set target 192.168.1.1
exf (fortios_version_check) > run
```

Affected versions: FortiOS 5.x, 6.x, 7.0.0–7.0.6, 7.2.0–7.2.1.

---

### CVE-2021-36260 (Hikvision RCE) — command not executed

```
[*] Sent payload but no connection received on 0.0.0.0:4444
```

**Common causes:**

| Cause | Fix |
|-------|-----|
| Device patched (firmware ≥ V5.5.800) | Use `check` to verify before `run` |
| Firewall blocking reverse shell | Use `set shell_type bind` instead |
| Wrong LHOST | `set lhost <your-attacker-IP>` |
| Port in use | `set lport 4445` |

---

### CVE-2024-3400 (PAN-OS GlobalProtect) — no session

```
[-] No shell received. Target may be patched.
```

Affected versions: PAN-OS 10.2.x < 10.2.9-h1, 11.0.x < 11.0.4-h1, 11.1.x < 11.1.2-h3.

Verify with:

```
exf> use scanners/firewalls/paloalto/panos_version_check
exf (panos_version_check) > set target 192.168.1.1
exf (panos_version_check) > check
```

---

### CVE-2023-27997 (FortiGate SSL-VPN heap overflow) — crash instead of shell

The heap overflow may crash the target before the payload executes on certain firmware variants. Use `check` first:

```
exf> use exploits/firewalls/fortinet/fortigate_ssl_vpn_heap_overflow_cve_2023_27997
exf (fortigate_ssl_vpn_heap_overflow_cve_2023_27997) > set target 192.168.1.1
exf (fortigate_ssl_vpn_heap_overflow_cve_2023_27997) > check
[+] Target is vulnerable — proceed with run
exf (fortigate_ssl_vpn_heap_overflow_cve_2023_27997) > run
```

Affected versions: FortiOS 6.0.x, 6.2.x, 6.4.x < 6.4.13, 7.0.x < 7.0.12, 7.2.x < 7.2.5.

---

### CVE-2018-14847 (MikroTik Winbox) — connection refused

```
[-] Connection refused on port 8291
```

Winbox listens on TCP 8291. Confirm the port is open:

```bash
nmap -p 8291 192.168.1.1
```

Affected versions: RouterOS < 6.42.

---

## GPU / compute issues

### `No GPU detected` at startup

```
[yellow][system][/yellow] Intel Core i7-11800H (16T) | 32768MB RAM | No GPU detected | compute_mode: auto->cpu
```

This is informational. GPU compute is only required for ML-based modules. CPU mode works for all standard modules.

If you have a GPU and it is not being detected:

```bash
# Check CUDA
python -c "import torch; print(torch.cuda.is_available())"

# Check ROCm (AMD)
python -c "import torch; print(torch.version.hip)"

# Install CUDA-enabled PyTorch
pip install torch --index-url https://download.pytorch.org/whl/cu121
```

---

### `GPU mode requested but no GPU detected` fallback

```
[WARN] No GPU detected -- falling back to compute_mode=cpu
```

This is expected behavior when `compute gpu` or `compute hybrid` is set on a machine without a GPU. The framework automatically falls back to CPU mode. To suppress, set:

```
exf> compute cpu
[+] compute_mode => cpu
```

---

### `compute hybrid` — only CPU work happening

Hybrid mode uses GPU for ML-accelerated modules (credential ranking, fuzzing entropy) and CPU for all standard exploit modules. If all selected modules are standard exploits, hybrid behaves identically to CPU.

---

## Session issues

### `No saved sessions` after running `discover`

```
[*] No saved sessions. Run 'discover <target>' to create one.
```

Sessions are stored in `~/.exf_sessions/` by default. If the directory is not writable:

```bash
ls -la ~/.exf_sessions/
# If missing:
mkdir -p ~/.exf_sessions && chmod 700 ~/.exf_sessions
```

---

### Session data appears stale after firmware update on target

If a target device was rebooted or firmware-updated, its MAC address or open ports may have changed. Force a fresh discovery to reset the session:

```
exf> discover 192.168.1.0/24 --fresh
```

Or delete the specific session:

```
exf> sessions delete 192.168.1.1
```

---

## Firmware tool issues

### `firmware_sources.yaml not found`

```
[ERROR] firmware_sources.yaml not found at .../embedxpl/resources/firmware_sources.yaml
```

The resources directory was not bundled. Reinstall:

```bash
pip install --force-reinstall embedxpl
# or from source:
pip install -e .
```

---

### `binwalk not installed`

```
[WARN] binwalk not found. Install: pip install binwalk or apt-get install binwalk
```

```bash
# Linux
sudo apt-get install binwalk

# Python wrapper (limited)
pip install binwalk

# Modern replacement (recommended)
pip install unblob
```

---

### `EMBA not found`

```
[WARN] EMBA not found. Clone from: https://github.com/e-m-b-a/emba and run sudo ./installer.sh
```

```bash
git clone https://github.com/e-m-b-a/emba /opt/emba
cd /opt/emba && sudo ./installer.sh
```

---

## Windows-specific issues

### `os.system()` not working in `exec` command

```
exf> exec ipconfig
```

On Windows, `os.system()` uses `cmd.exe`. For PowerShell commands:

```
exf> exec powershell -Command "Get-NetAdapter"
```

---

### Path separators in `use` command

```
exf> use exploits\routers\tplink\wr841n_credential_disclosure_cve_2023_50224
```

Both forward slash and backslash are accepted. The recommended form uses forward slashes:

```
exf> use exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224
```

---

### `readline` tab completion issues on Windows

Tab completion requires `pyreadline3` on Windows:

```bash
pip install pyreadline3
```

If still not working, the `_ReadlineShim` fallback is active and completion is disabled. All commands remain functional.

---

## macOS-specific issues

### `libedit` instead of GNU readline

On macOS, Python links against `libedit` instead of GNU readline. EmbedXPL-Forge detects this automatically and uses `bind ^I rl_complete` instead of `tab: complete`. Tab completion works normally.

---

### `Permission denied` writing history file

```
IOError: [Errno 13] Permission denied: '/Users/user/.exf_history'
```

```bash
touch ~/.exf_history && chmod 600 ~/.exf_history
```

---

## Common error codes reference

| Error | Meaning | Action |
|-------|---------|--------|
| `Unknown command: 'foo'` | Mistyped command | Type `help` to list valid commands |
| `You can't set option 'foo'` | Option does not exist for loaded module | Type `show options` to list valid options |
| `A module is required when running non-interactively` | `-m` flag missing in CLI mode | Add `-m <module_path>` |
| `Invalid target: 'foo'` | Target is not a valid IP or CIDR | Use dotted-decimal notation |
| `Discovery failed: ...` | Network scan error | Check `nmap` is installed, check firewall rules |
| `No live hosts found on ...` | All hosts unreachable | Verify CIDR range and network connectivity |
| `Module loaded. Set target and run` | apt run loaded a module | `set target <IP>` then `run` |
| `Unknown infra type 'foo'` | Invalid `--infra` argument | Valid values: `ot`, `it`, `iot` |
| `Unknown context 'foo' for infra 'ot'` | Invalid `--context` argument | Run without `--context` to see valid options |
