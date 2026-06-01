# NSE Script Manager

**Language:** English (en-US) | **pt-BR:** [../pt-BR/12-nse-script-manager.md](../pt-BR/12-nse-script-manager.md)

---

## Overview

EmbedXPL-Forge ships **11 Nmap NSE scripts** that extend Nmap with IoT CVE detection, device fingerprinting, and direct links to EmbedXPL-Forge and FirewallXPL-Forge exploit modules.

The `embedxpl-nse` command (or `python -m embedxpl.nse`) manages installation, validation, listing, and execution of these scripts.

**Entry points:**

```bash
embedxpl-nse <command>         # after pip install
python -m embedxpl.nse <command>   # from source
```

---

## Script catalog

| Short name | File | Description |
|------------|------|-------------|
| `rtsp-discover` | `embedxpl-rtsp-discover.nse` | RTSP service discovery + banner grab + vendor fingerprint |
| `camera-identify` | `embedxpl-camera-identify.nse` | IP camera deep fingerprinting (HTTP + RTSP + ONVIF multi-protocol) |
| `camera-snapshot` | `embedxpl-camera-snapshot.nse` | Unauthenticated camera snapshot access detector (30+ endpoints) |
| `hikvision-vuln` | `embedxpl-hikvision-vuln.nse` | Hikvision CVE checker (CVE-2021-36260, CVE-2017-7921) |
| `dahua-vuln` | `embedxpl-dahua-vuln.nse` | Dahua CVE checker (CVE-2021-33044, CVE-2020-25078, CVE-2013-6117) |
| `rtsp-creds` | `embedxpl-rtsp-creds.nse` | Quick RTSP default credential tester (Basic auth) |
| `iot-cve-check` | `embedxpl-iot-cve-check.nse` | Multi-vendor IoT CVE fingerprint and validation (15+ CVEs including 2026) |
| `perimeter-vuln` | `embedxpl-perimeter-vuln.nse` | Firewall/VPN CVE checker — 15 vendors, 19+ CVEs (Fortinet/Cisco/PAN-OS/SonicWall...) |
| `router-vuln` | `embedxpl-router-vuln.nse` | SOHO router CVE checker — 15 vendors, 14+ CVEs (TP-Link/Netgear/ASUS/MikroTik...) |
| `printer-vuln` | `embedxpl-printer-vuln.nse` | Network printer CVE checker — 11 vendors, PJL/IPP/HTTP probes (HP/Canon/Lexmark...) |
| `suite-ref` | `embedxpl-suite-ref.nse` | XPL-Forge full suite reference + GTFOBins embedded Linux quick guide |

Default scan ports: `80,443,554,5554,8080,8443,8554,9100,37777,631`

---

## `install` — copy scripts to Nmap

### Syntax

```
embedxpl-nse install [--force] [--nse-dir <DIR>]
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `--force`, `-f` | flag | false | Overwrite scripts that are already installed |
| `--nse-dir DIR` | string | auto-detected | Override Nmap scripts directory path |

### Standard install (Nmap present)

```
$ embedxpl-nse install

EmbedXPL-Forge NSE Script Installer v2.0.0
--------------------------------------------------
[1/4] Checking Nmap installation...
[OK] Nmap found: /usr/bin/nmap (Nmap version 7.95 ( https://nmap.org ))
[OK] Nmap scripts directory: /usr/share/nmap/scripts
[2/4] Locating Nmap scripts directory...
      Target: /usr/share/nmap/scripts
[3/4] Verifying source NSE files...
[4/4] Installing scripts...
      [OK]  embedxpl-rtsp-discover.nse -> /usr/share/nmap/scripts/embedxpl-rtsp-discover.nse
      [OK]  embedxpl-camera-identify.nse -> /usr/share/nmap/scripts/embedxpl-camera-identify.nse
      [OK]  embedxpl-camera-snapshot.nse -> /usr/share/nmap/scripts/embedxpl-camera-snapshot.nse
      [OK]  embedxpl-hikvision-vuln.nse -> /usr/share/nmap/scripts/embedxpl-hikvision-vuln.nse
      [OK]  embedxpl-dahua-vuln.nse -> /usr/share/nmap/scripts/embedxpl-dahua-vuln.nse
      [OK]  embedxpl-rtsp-creds.nse -> /usr/share/nmap/scripts/embedxpl-rtsp-creds.nse
      [OK]  embedxpl-iot-cve-check.nse -> /usr/share/nmap/scripts/embedxpl-iot-cve-check.nse
      [OK]  embedxpl-perimeter-vuln.nse -> /usr/share/nmap/scripts/embedxpl-perimeter-vuln.nse
      [OK]  embedxpl-router-vuln.nse -> /usr/share/nmap/scripts/embedxpl-router-vuln.nse
      [OK]  embedxpl-printer-vuln.nse -> /usr/share/nmap/scripts/embedxpl-printer-vuln.nse
      [OK]  embedxpl-suite-ref.nse -> /usr/share/nmap/scripts/embedxpl-suite-ref.nse

Results:
  Installed  : 11

Updating nmap script database...
  [OK] nmap --script-updatedb complete

Installation complete.
Quick start:
  nmap -p 554,5554 --script embedxpl-rtsp-discover 192.168.1.0/24
  nmap -p 80,443   --script embedxpl-perimeter-vuln 10.0.0.0/24
  nmap -p 80,443   --script embedxpl-iot-cve-check 192.168.1.0/24
  nmap -p 80,9100  --script embedxpl-printer-vuln 10.0.0.0/24
  nmap -p 80,443   --script 'embedxpl-*' 192.168.1.100

  embedxpl-nse run --target 192.168.1.0/24 --scripts all
  embedxpl-nse run --target 10.0.0.1 --scripts perimeter-vuln,router-vuln

Exploit after NSE detection:
  pip install embedxpl && embedxpl
  pip install firewallxpl && fxf
```

### Install with `--force` (overwrite existing)

```
$ embedxpl-nse install --force

EmbedXPL-Forge NSE Script Installer v2.0.0
--------------------------------------------------
[1/4] Checking Nmap installation...
[OK] Nmap found: /usr/bin/nmap (Nmap version 7.95 ( https://nmap.org ))
[OK] Nmap scripts directory: /usr/share/nmap/scripts
[2/4] Locating Nmap scripts directory...
      Target: /usr/share/nmap/scripts
[3/4] Verifying source NSE files...
[4/4] Installing scripts...
      [OK]  embedxpl-rtsp-discover.nse -> /usr/share/nmap/scripts/embedxpl-rtsp-discover.nse
      [OK]  embedxpl-camera-identify.nse -> /usr/share/nmap/scripts/embedxpl-camera-identify.nse
      ... (11 scripts overwritten)

Results:
  Installed  : 11

Updating nmap script database...
  [OK] nmap --script-updatedb complete

Installation complete.
```

### Install — Nmap not found (graceful fallback)

```
$ embedxpl-nse install

EmbedXPL-Forge NSE Script Installer v2.0.0
--------------------------------------------------
[1/4] Checking Nmap installation...

====================================================================
  Nmap is NOT installed or not found in PATH.
====================================================================

Install Nmap to use the NSE scripts with automatic detection:

  Debian / Ubuntu:   sudo apt-get install nmap
  Fedora / RHEL:     sudo dnf install nmap
  Arch:              sudo pacman -S nmap

Once installed, run:  embedxpl-nse install

--------------------------------------------------------------------
  NSE script files are available at:
    /home/user/.local/lib/python3.12/site-packages/nse/embedxpl-rtsp-discover.nse
    /home/user/.local/lib/python3.12/site-packages/nse/embedxpl-camera-identify.nse
    ... (11 files listed)

  Manual usage (without install):
  nmap --script <path/to/script.nse> -p 80,443 <target>
====================================================================
```

### Install — custom directory

```
$ sudo embedxpl-nse install --nse-dir /opt/nmap/scripts

EmbedXPL-Forge NSE Script Installer v2.0.0
--------------------------------------------------
[1/4] Checking Nmap installation...
[OK] Nmap found: /usr/bin/nmap (Nmap version 7.95 ( https://nmap.org ))
[OK] Nmap scripts directory: /opt/nmap/scripts
[2/4] Locating Nmap scripts directory...
      Target: /opt/nmap/scripts
...
```

### Install — permission denied

```
$ embedxpl-nse install

...
[4/4] Installing scripts...
      [ERR] Permission denied: /usr/share/nmap/scripts/embedxpl-iot-cve-check.nse
      [ERR] Permission denied: /usr/share/nmap/scripts/embedxpl-router-vuln.nse
      ... (11 errors)

Results:
  Installed  : 0
  Failed     : 11 -- run with sudo/Administrator
               sudo embedxpl-nse install
```

---

## `list` — show installation status

### Syntax

```
embedxpl-nse list
```

### Output (Nmap found, all installed)

```
$ embedxpl-nse list

EmbedXPL-Forge NSE Scripts  (v2.0.0 -- 11 scripts)
----------------------------------------------------------------------------------
Nmap binary    : /usr/bin/nmap
Scripts dir    : /usr/share/nmap/scripts
Local NSE dir  : /home/user/.local/lib/python3.12/site-packages/nse
----------------------------------------------------------------------------------
NSE Script                     Status         Description
----------------------------------------------------------------------------------
  embedxpl-rtsp-discover       INSTALLED      RTSP service discovery + banner grab + vendor fingerprint
  embedxpl-camera-identify     INSTALLED      IP camera deep fingerprinting (HTTP + RTSP + ONVIF multi-protocol)
  embedxpl-camera-snapshot     INSTALLED      Unauthenticated camera snapshot access detector (30+ endpoints)
  embedxpl-hikvision-vuln      INSTALLED      Hikvision CVE checker (CVE-2021-36260, CVE-2017-7921)
  embedxpl-dahua-vuln          INSTALLED      Dahua CVE checker (CVE-2021-33044, CVE-2020-25078, CVE-2013-6117)
  embedxpl-rtsp-creds          INSTALLED      Quick RTSP default credential tester (Basic auth)
  embedxpl-iot-cve-check       INSTALLED      Multi-vendor IoT CVE fingerprint & validation (15+ CVEs incl. 2026)
  embedxpl-perimeter-vuln      INSTALLED      Firewall/VPN CVE checker -- 15 vendors, 19+ CVEs
  embedxpl-router-vuln         INSTALLED      SOHO router CVE checker -- 15 vendors, 14+ CVEs
  embedxpl-printer-vuln        INSTALLED      Network printer CVE checker -- 11 vendors, PJL/IPP/HTTP probes
  embedxpl-suite-ref           INSTALLED      XPL-Forge full suite reference + GTFOBins embedded Linux quick guide

Quick start:
  nmap -p 554,5554 --script embedxpl-rtsp-discover 192.168.1.0/24
  ...
```

### Output (Nmap not found)

```
$ embedxpl-nse list

EmbedXPL-Forge NSE Scripts  (v2.0.0 -- 11 scripts)
----------------------------------------------------------------------------------
Nmap binary    : NOT FOUND
Scripts dir    : NOT FOUND
Local NSE dir  : /home/user/.local/lib/python3.12/site-packages/nse
----------------------------------------------------------------------------------
NSE Script                     Status         Description
----------------------------------------------------------------------------------
  embedxpl-rtsp-discover       nmap not found RTSP service discovery + banner grab + vendor fingerprint
  embedxpl-camera-identify     nmap not found IP camera deep fingerprinting (HTTP + RTSP + ONVIF multi-protocol)
  ...

Install Nmap to use these scripts with automatic integration.
After installing Nmap, run:  embedxpl-nse install

Manual usage (copy from):
    /home/user/.local/lib/python3.12/site-packages/nse/embedxpl-rtsp-discover.nse
    ...
```

---

## `check` — validate Nmap installation

### Syntax

```
embedxpl-nse check
```

### Output (Nmap present)

```
$ embedxpl-nse check

[OK] Nmap found: /usr/bin/nmap (Nmap version 7.95 ( https://nmap.org ))
[OK] Nmap scripts directory: /usr/share/nmap/scripts

$ echo $?
0
```

### Output (Nmap not found)

```
$ embedxpl-nse check

====================================================================
  Nmap is NOT installed or not found in PATH.
====================================================================
...

$ echo $?
1
```

---

## `run` — execute NSE scripts via Nmap

### Syntax

```
embedxpl-nse run --target <TARGET> [--scripts <SCRIPTS>] [--ports <PORTS>] [--output <FILE>] [--args <EXTRA_NMAP_ARGS>]
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `--target`, `-t` | string | *required* | IP, CIDR range, or hostname |
| `--scripts`, `-s` | string | `all` | `all` or comma-separated short names (e.g. `hikvision-vuln,rtsp-creds`) |
| `--ports`, `-p` | string | `80,443,554,5554,8080,8443,8554,9100,37777,631` | Comma-separated ports to scan |
| `--output`, `-o` | string | none | Write Nmap output to file (`-oN`) |
| `--args` | string | none | Extra raw Nmap arguments (quoted string) |

### Run all scripts against a subnet

```
$ embedxpl-nse run --target 192.168.1.0/24 --scripts all

[NSE] Running: /usr/bin/nmap -sV -p 80,443,554,5554,8080,8443,8554,9100,37777,631
      --script embedxpl-rtsp-discover,embedxpl-camera-identify,embedxpl-camera-snapshot,
               embedxpl-hikvision-vuln,embedxpl-dahua-vuln,embedxpl-rtsp-creds,
               embedxpl-iot-cve-check,embedxpl-perimeter-vuln,embedxpl-router-vuln,
               embedxpl-printer-vuln,embedxpl-suite-ref 192.168.1.0/24

Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-01 19:00 UTC
Nmap scan report for 192.168.1.1
Host is up (0.0012s latency).
PORT     STATE  SERVICE    VERSION
80/tcp   open   http       TP-Link WR841N httpd
| embedxpl-router-vuln:
|   VULNERABLE
|   CVE-2023-50224 (TP-Link WR841N Credential Disclosure)
|     State: VULNERABLE
|     Risk factor: High  CVSS: 7.5
|     Description: Unauthenticated credential extraction via /loginFs/ bypass
|     References:
|       https://nvd.nist.gov/vuln/detail/CVE-2023-50224
|_    EmbedXPL module: use exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224

Nmap scan report for 192.168.1.100
Host is up (0.0023s latency).
PORT     STATE  SERVICE    VERSION
80/tcp   open   http       Hikvision IP camera web server
| embedxpl-hikvision-vuln:
|   VULNERABLE
|   CVE-2021-36260 (Hikvision RTSP Unauthenticated RCE)
|     State: VULNERABLE
|     Risk factor: Critical  CVSS: 9.8
|     Description: Command injection via RTSP channel allowing unauthenticated RCE
|     References:
|       https://nvd.nist.gov/vuln/detail/CVE-2021-36260
|_    EmbedXPL module: use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260

Nmap done: 256 IP addresses (4 hosts up) scanned in 48.32 seconds
```

### Run specific scripts only

```
$ embedxpl-nse run --target 10.0.0.1 --scripts perimeter-vuln,router-vuln --ports 80,443,8443

[NSE] Running: /usr/bin/nmap -sV -p 80,443,8443
      --script embedxpl-perimeter-vuln,embedxpl-router-vuln 10.0.0.1

Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-01 19:05 UTC
Nmap scan report for 10.0.0.1
Host is up (0.0008s latency).
PORT     STATE  SERVICE    VERSION
443/tcp  open   ssl/https  Fortinet FortiGate SSL-VPN
| embedxpl-perimeter-vuln:
|   VULNERABLE
|   CVE-2024-21762 (FortiOS SSL-VPN Out-of-Bounds Write RCE)
|     State: VULNERABLE
|     Risk factor: Critical  CVSS: 9.6
|     Description: OOB write via specially crafted HTTP requests, allows unauthenticated RCE
|     References:
|       https://nvd.nist.gov/vuln/detail/CVE-2024-21762
|_    FirewallXPL module: use exploits/firewalls/fortinet/fortios_sslvpn_rce_cve_2024_21762

Nmap done: 1 IP address (1 host up) scanned in 3.14 seconds
```

### Run with output file

```
$ embedxpl-nse run --target 192.168.1.0/24 --scripts iot-cve-check --output /tmp/scan_results.txt

[NSE] Running: /usr/bin/nmap -sV -p 80,443,554,5554,8080,8443,8554,9100,37777,631
      --script embedxpl-iot-cve-check 192.168.1.0/24 -oN /tmp/scan_results.txt

Starting Nmap 7.95 ...
...
Nmap done: 256 IP addresses (7 hosts up) scanned in 62.18 seconds

$ cat /tmp/scan_results.txt
# Nmap 7.95 scan initiated ...
```

### Run with extra Nmap arguments

```
$ embedxpl-nse run --target 192.168.1.1 --scripts hikvision-vuln --args "-T4 --open"

[NSE] Running: /usr/bin/nmap -sV -p 80,443,554,5554,8080,8443,8554,9100,37777,631
      --script embedxpl-hikvision-vuln -T4 --open 192.168.1.1

Starting Nmap 7.95 ...
```

---

## `info` — show script details

### Syntax

```
embedxpl-nse info <script_name>
```

Accepts both short names (`hikvision-vuln`) and full names (`embedxpl-hikvision-vuln`).

### Output

```
$ embedxpl-nse info hikvision-vuln

Script      : embedxpl-hikvision-vuln
File        : embedxpl-hikvision-vuln.nse
Description : Hikvision CVE checker (CVE-2021-36260, CVE-2017-7921)
Source      : /home/user/.local/lib/python3.12/site-packages/nse/embedxpl-hikvision-vuln.nse
Installed   : YES -- /usr/share/nmap/scripts/embedxpl-hikvision-vuln.nse

--- Script header (first 30 comment lines) ---
  -- embedxpl-hikvision-vuln.nse
  -- EmbedXPL-Forge | Hikvision Vulnerability Scanner
  -- CVEs: CVE-2021-36260 (CVSS 9.8), CVE-2017-7921 (CVSS 8.8)
  --
  -- CVE-2021-36260: Command injection via /SDK/webLanguage endpoint
  --   Affected: Firmware < V5.5.800
  --   PoC: curl -X PUT http://TARGET/SDK/webLanguage -d '<?xml ...>$(id)>...'
  --
  -- CVE-2017-7921: Authentication bypass via snapshot endpoint
  --   Affected: Firmware < V5.4.5
  --   PoC: http://TARGET/onvif-http/snapshot?auth=YWRtaW46MTETC
  --
  -- EmbedXPL modules:
  --   use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
  --   use exploits/cameras/hikvision/info_disclosure_cve_2017_7921
  --
  -- Author: Andre Henrique (@mrhenrike) | Uniao Geek
  -- Version: 2.0.0
```

### Error — unknown script

```
$ embedxpl-nse info bad-script-name

Unknown script: bad-script-name
Available: embedxpl-rtsp-discover, embedxpl-camera-identify, embedxpl-camera-snapshot,
           embedxpl-hikvision-vuln, embedxpl-dahua-vuln, embedxpl-rtsp-creds,
           embedxpl-iot-cve-check, embedxpl-perimeter-vuln, embedxpl-router-vuln,
           embedxpl-printer-vuln, embedxpl-suite-ref
```

---

## `uninstall` — remove scripts from Nmap

### Syntax

```
embedxpl-nse uninstall
```

### Output

```
$ sudo embedxpl-nse uninstall

  [OK] Removed: /usr/share/nmap/scripts/embedxpl-rtsp-discover.nse
  [OK] Removed: /usr/share/nmap/scripts/embedxpl-camera-identify.nse
  [OK] Removed: /usr/share/nmap/scripts/embedxpl-camera-snapshot.nse
  [OK] Removed: /usr/share/nmap/scripts/embedxpl-hikvision-vuln.nse
  [OK] Removed: /usr/share/nmap/scripts/embedxpl-dahua-vuln.nse
  [OK] Removed: /usr/share/nmap/scripts/embedxpl-rtsp-creds.nse
  [OK] Removed: /usr/share/nmap/scripts/embedxpl-iot-cve-check.nse
  [OK] Removed: /usr/share/nmap/scripts/embedxpl-perimeter-vuln.nse
  [OK] Removed: /usr/share/nmap/scripts/embedxpl-router-vuln.nse
  [OK] Removed: /usr/share/nmap/scripts/embedxpl-printer-vuln.nse
  [OK] Removed: /usr/share/nmap/scripts/embedxpl-suite-ref.nse

Removed 11 script(s).
```

### Error — nothing to uninstall

```
$ embedxpl-nse uninstall
[WARN] Nmap not found. Nothing to uninstall.
```

---

## Using scripts directly with Nmap (without `embedxpl-nse run`)

After install, standard Nmap syntax works:

```bash
# Single script, single host
nmap -sV -p 80,443 --script embedxpl-hikvision-vuln 192.168.1.100

# Multiple scripts
nmap -sV -p 80,443,554 --script embedxpl-hikvision-vuln,embedxpl-rtsp-discover 192.168.1.0/24

# All EmbedXPL scripts (wildcard)
nmap -sV -p 80,443,554,5554 --script 'embedxpl-*' 192.168.1.0/24

# Camera discovery across subnet
nmap -sV -p 554,5554,8554 --script embedxpl-rtsp-discover,embedxpl-camera-identify 10.0.0.0/24

# Firewall/VPN CVE check
nmap -sV -p 443,8443 --script embedxpl-perimeter-vuln 10.0.0.1

# Printer CVE check
nmap -sV -p 80,9100,631 --script embedxpl-printer-vuln 192.168.1.0/24
```

---

## Manual installation (without `embedxpl-nse install`)

If automatic installation fails, copy the `.nse` files manually:

```bash
# Linux — find the NSE source directory
python -c "import embedxpl.nse.manager as m; print(m._NSE_PACKAGE_DIR)"
# Output: /home/user/.local/lib/python3.12/site-packages/nse

# Copy to Nmap
sudo cp /home/user/.local/lib/python3.12/site-packages/nse/embedxpl-*.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
```

```powershell
# Windows — find the NSE source directory
python -c "import embedxpl.nse.manager as m; print(m._NSE_PACKAGE_DIR)"
# Output: C:\Users\user\AppData\Local\Programs\Python\Python312\Lib\site-packages\nse

# Copy to Nmap (run as Administrator)
Copy-Item "C:\Users\user\AppData\...\nse\embedxpl-*.nse" "C:\Program Files (x86)\Nmap\scripts\"
nmap --script-updatedb
```
