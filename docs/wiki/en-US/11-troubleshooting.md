# Troubleshooting

**Language:** English (en-US) | **pt-BR:** [../pt-BR/11-troubleshooting.md](../pt-BR/11-troubleshooting.md)

---

## Startup issues

### `ImportError` or `ModuleNotFoundError` on launch

```bash
pip install -r requirements.txt   # reinstall all dependencies
pip install embedxpl[all]          # or reinstall with all extras
```

Verify the environment:

```bash
python tools/env_doctor.py
```

### `stdin_open` / TTY error (non-interactive mode fails)

```text
[-] EmbedXPL-Forge requires an interactive terminal for the shell mode.
    Use -m flag for non-interactive execution.
```

Fix: run with the `-m` flag to use non-interactive mode, or ensure your terminal has a real TTY (not piped input).

### Module not found after moving files

Run from the repository root. Ensure `PYTHONPATH` is not overriding package discovery. Prefer the official entry point:

```bash
embedxpl              # after pip install
python -m embedxpl    # from repo
```

---

## Python version issues

### Telnet on Python 3.13+

`telnetlib` was removed in Python 3.13. `telnetlib3` is listed in `requirements.txt` and is used automatically:

```bash
pip install telnetlib3
```

### `syntax error` in module

Most modules require Python 3.8+. Check with:

```bash
python --version
```

---

## Network and OS issues

### Scapy errors / raw socket access

```text
[-] Scapy requires root or CAP_NET_RAW
```

Fix: run with `sudo` or grant the capability:

```bash
sudo embedxpl
# or (Linux):
sudo setcap cap_net_raw+eip $(which python3)
```

On **Windows**, install **Npcap** for raw-socket capture support.

### No colors on Windows

```bash
pip install colorama
```

`colorama` is included in `requirements.txt` and should be installed automatically.

### Permission denied on Linux (install scripts, raw sockets)

```bash
sudo embedxpl-nse install      # NSE installation to /usr/share/nmap/scripts
sudo embedxpl                  # raw socket access for discovery
```

---

## Shell stager issues

### Listener binds but no connection

1. Ensure `lhost` is the correct attacker IP reachable from the target.
2. Check firewall rules: `lport` must be open inbound.
3. Increase `listener_timeout` if the exploit takes long to execute.
4. Try a different `shell_type` (`python`, `nc_mkfifo`, `socat`).

### Terminal garbled after shell closes

The PTY listener restores the terminal via `termios`, but if it crashes:

```bash
reset         # restore terminal state
stty sane     # alternative
```

### Meterpreter stager fails

1. Ensure `msfvenom` is installed (`metasploit-framework`).
2. The module prints the `msfvenom` command — run it manually.
3. Start the handler: `msfconsole -r .tmp/msf_handler_<port>.rc`

---

## NSE script issues

### Scripts not found by Nmap after install

```bash
sudo nmap --script-updatedb
```

### `embedxpl-nse install` returns permission error

```bash
sudo embedxpl-nse install
# or specify a writable directory:
embedxpl-nse install --nse-dir ~/.nmap/scripts
```

### Nmap not in PATH

```text
embedxpl-nse check
# will print installation instructions and local file paths
```

---

## Module-specific issues

### `check()` returns "could not be verified"

The module's `check()` method threw an exception or returned an unexpected type. Run with `force_exploit=true` to proceed anyway, or check connectivity:

```text
exf (module_name) > set force_exploit true
exf (module_name) > run
```

### `[ERR] Permission denied` during exploit

Some exploits require root / SYSTEM privileges (raw sockets, port binding below 1024). Run with `sudo` or use a high port for `lport`.

### `[WARN] Target may be patched`

The exploit's detection heuristic did not confirm vulnerability. The target may be patched, behind a WAF, or using non-standard configuration. Use `force_exploit=true` to attempt anyway.

---

## Dependencies

Re-installing all dependencies:

```bash
pip install -r requirements.txt --upgrade
```

Full requirements list:

```
requests>=2.33.0 (or 2.32.4 for Python < 3.10)
paramiko
pysnmp
pycryptodome
scapy
colorama
setuptools
telnetlib3 (Python >= 3.13)
rich>=13.0
aiohttp>=3.9
numpy>=1.24
psutil>=5.9
python-nmap>=0.7.1
```

---

## Getting help

- **GitHub Issues:** https://github.com/mrhenrike/EmbedXPL-Forge/issues
- **Wiki hub:** [../README.md](../README.md)
- **Diagnostics:** `python tools/env_doctor.py`
- **Compatibility check:** `python tools/compat_smoke.py`


[Wiki hub](../README.md)
