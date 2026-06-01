# NSE Script Manager

**Language:** English (en-US) | **pt-BR:** [../pt-BR/12-nse-script-manager.md](../pt-BR/12-nse-script-manager.md)

---

## Overview

EmbedXPL-Forge ships **11 Nmap NSE scripts** that extend Nmap with IoT CVE detection, device fingerprinting, and direct links to EmbedXPL-Forge and FirewallXPL-Forge exploit modules.

The `embedxpl-nse` command manages installation, validation, and execution of these scripts.

---

## Installation (pip)

```bash
pip install "embedxpl[nse]"    # includes NSE support
# then install scripts to Nmap:
embedxpl-nse install
```

Or without the extra:

```bash
pip install embedxpl
embedxpl-nse install
```

---

## Command reference

### `check` — validate Nmap installation

```bash
embedxpl-nse check
```

Verifies that Nmap is installed and the scripts directory is found. Exits 0 on success, 1 if not found.

**Output — Nmap found:**

```text
[OK] Nmap found: /usr/bin/nmap (Nmap version 7.94 ( https://nmap.org ))
[OK] Nmap scripts directory: /usr/share/nmap/scripts
```

**Output — Nmap NOT found:**

```text
================================================================
  Nmap is NOT installed or not found in PATH.
================================================================

Install Nmap to use the NSE scripts with automatic integration:

  Debian / Ubuntu:   sudo apt-get install nmap
  Fedora / RHEL:     sudo dnf install nmap
  Arch:              sudo pacman -S nmap

Once installed, run:  embedxpl-nse install

----------------------------------------------------------------
  NSE script files are available at:
    /home/user/.local/lib/python3.11/site-packages/nse/embedxpl-rtsp-discover.nse
    /home/user/.local/lib/python3.11/site-packages/nse/embedxpl-camera-identify.nse
    ...

  Manual usage (without install):
  nmap --script <path/to/script.nse> -p 80,443 <target>
================================================================
```

---

### `install` — install scripts to Nmap

```bash
embedxpl-nse install
embedxpl-nse install --force        # overwrite already-installed scripts
embedxpl-nse install --nse-dir DIR  # specify Nmap scripts directory manually
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--force` / `-f` | bool | false | Overwrite existing scripts |
| `--nse-dir` | path | auto-detect | Override Nmap scripts directory |

**Sample output:**

```text
EmbedXPL-Forge NSE Script Installer v2.0.0
--------------------------------------------------
[1/4] Checking Nmap installation...
[OK] Nmap found: /usr/bin/nmap (Nmap version 7.94)
[OK] Nmap scripts directory: /usr/share/nmap/scripts

[2/4] Locating Nmap scripts directory...
      Target: /usr/share/nmap/scripts

[3/4] Verifying source NSE files...

[4/4] Installing scripts...
      [OK]  embedxpl-rtsp-discover.nse -> /usr/share/nmap/scripts/embedxpl-rtsp-discover.nse
      [OK]  embedxpl-camera-identify.nse -> /usr/share/nmap/scripts/embedxpl-camera-identify.nse
      [OK]  embedxpl-hikvision-vuln.nse -> /usr/share/nmap/scripts/embedxpl-hikvision-vuln.nse
      [OK]  embedxpl-dahua-vuln.nse -> /usr/share/nmap/scripts/embedxpl-dahua-vuln.nse
      [OK]  embedxpl-rtsp-creds.nse -> /usr/share/nmap/scripts/embedxpl-rtsp-creds.nse
      [OK]  embedxpl-iot-cve-check.nse -> /usr/share/nmap/scripts/embedxpl-iot-cve-check.nse
      [OK]  embedxpl-perimeter-vuln.nse -> /usr/share/nmap/scripts/embedxpl-perimeter-vuln.nse
      [OK]  embedxpl-router-vuln.nse -> /usr/share/nmap/scripts/embedxpl-router-vuln.nse
      [OK]  embedxpl-printer-vuln.nse -> /usr/share/nmap/scripts/embedxpl-printer-vuln.nse
      [OK]  embedxpl-camera-snapshot.nse -> /usr/share/nmap/scripts/embedxpl-camera-snapshot.nse
      [OK]  embedxpl-suite-ref.nse -> /usr/share/nmap/scripts/embedxpl-suite-ref.nse

Results:
  Installed  : 11

Updating nmap script database...
  [OK] nmap --script-updatedb complete

Installation complete.
Quick start:
  nmap -p 554,5554 --script embedxpl-rtsp-discover 192.168.1.0/24
  nmap -p 80,443   --script embedxpl-perimeter-vuln 10.0.0.0/24
  ...
```

**If Nmap is not installed**, the installer exits cleanly with local file paths and installation instructions — it does **not** return an error.

**Permission error (Linux):** if the Nmap scripts directory requires root:

```text
      [ERR] Permission denied: /usr/share/nmap/scripts/...
```

Fix: `sudo embedxpl-nse install`

---

### `list` — list all scripts and status

```bash
embedxpl-nse list
```

**Sample output:**

```text
EmbedXPL-Forge NSE Scripts  (v2.0.0 -- 11 scripts)
----------------------------------------------------------------------------------
Nmap binary    : /usr/bin/nmap
Scripts dir    : /usr/share/nmap/scripts
Local NSE dir  : /usr/lib/python3/dist-packages/nse
----------------------------------------------------------------------------------
NSE Script                   Status         Description
----------------------------------------------------------------------------------
  embedxpl-rtsp-discover     INSTALLED      RTSP service discovery + banner
  embedxpl-camera-identify   INSTALLED      IP camera deep fingerprinting
  embedxpl-camera-snapshot   INSTALLED      Unauthenticated snapshot access
  embedxpl-hikvision-vuln    INSTALLED      Hikvision CVE checker
  embedxpl-dahua-vuln        INSTALLED      Dahua CVE checker
  embedxpl-rtsp-creds        INSTALLED      RTSP default credential tester
  embedxpl-iot-cve-check     INSTALLED      Multi-vendor IoT CVE fingerprint
  embedxpl-perimeter-vuln    not installed  Firewall/VPN CVE checker
  embedxpl-router-vuln       not installed  SOHO router CVE checker
  embedxpl-printer-vuln      not installed  Network printer CVE checker
  embedxpl-suite-ref         not installed  XPL-Forge suite reference

Quick start:
  nmap -p 554,5554 --script embedxpl-rtsp-discover 192.168.1.0/24
  ...
```

---

### `run` — run scripts against a target

```bash
embedxpl-nse run --target 192.168.1.0/24 --scripts all
embedxpl-nse run -t 10.0.0.1 -s perimeter-vuln,router-vuln
embedxpl-nse run -t 192.168.1.100 -s hikvision-vuln -p 80,443,8080
embedxpl-nse run -t 10.0.0.0/24 -s iot-cve-check --output /tmp/scan.txt
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | `-t` | `str` | **required** | IP, CIDR, range, or hostname |
| `--scripts` | `-s` | `str` | `all` | `all` or comma-separated names |
| `--ports` | `-p` | `str` | `80,443,554,5554,8080,8443,8554,9100,37777,631` | Nmap port list |
| `--output` | `-o` | `str` | — | Write output to file (`-oN`) |
| `--args` | — | `str` | — | Extra Nmap arguments (quoted string) |

Script short names (no `embedxpl-` prefix needed):

```
rtsp-discover, camera-identify, camera-snapshot, hikvision-vuln,
dahua-vuln, rtsp-creds, iot-cve-check, perimeter-vuln,
router-vuln, printer-vuln, suite-ref
```

**Sample output:**

```text
[NSE] Running: nmap -sV -p 80,443,554 --script embedxpl-camera-identify 192.168.1.100

Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.1.100
PORT    STATE SERVICE  VERSION
80/tcp  open  http     mini_httpd 1.30
| embedxpl-camera-identify:
|   Protocol : HTTP (HTTP 200)
|   Vendor   : Hikvision
|   Model    : DS-2CD2143G0-I
|   Firmware : V5.6.2 build 190401
|   Serial   : DS-2CD2143G0-I20190401AAWRA123456789
|   CVEs     : CVE-2021-36260 (RCE, CVSS 9.8) | CVE-2017-7921 (Auth Bypass)
|   Vuln assessment: LIKELY VULNERABLE (endpoint accessible without auth)
|   EmbedXPL module: exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
|_  Run exploit: embedxpl > use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
```

---

### `info` — show script details

```bash
embedxpl-nse info hikvision-vuln
embedxpl-nse info embedxpl-perimeter-vuln
```

**Sample output:**

```text
Script      : embedxpl-hikvision-vuln
File        : embedxpl-hikvision-vuln.nse
Description : Hikvision CVE checker (CVE-2021-36260, CVE-2017-7921)
Source      : /usr/share/nmap/scripts/embedxpl-hikvision-vuln.nse
Installed   : YES -- /usr/share/nmap/scripts/embedxpl-hikvision-vuln.nse

--- Script header (first 30 comment lines) ---
  -- embedxpl-hikvision-vuln.nse
  -- Tests Hikvision IP cameras, NVR, and DVR for:
  --   CVE-2021-36260 — Unauthenticated Remote Code Execution (CVSS 9.8)
  --   CVE-2017-7921  — Authentication bypass via crafted URL parameter
  ...
```

---

### `uninstall` — remove scripts from Nmap

```bash
embedxpl-nse uninstall
# then update the database:
sudo nmap --script-updatedb
```

---

## Manual Nmap usage (without embedxpl-nse)

After `embedxpl-nse install`:

```bash
# Camera RTSP discovery
nmap -p 554,5554,8554 --script embedxpl-rtsp-discover 192.168.1.0/24

# IP camera deep fingerprinting
nmap -p 80,443,8080,554 --script embedxpl-camera-identify 192.168.1.100

# Hikvision CVE check
nmap -p 80,443 --script embedxpl-hikvision-vuln 192.168.1.100

# Dahua CVE check
nmap -p 80,37777 --script embedxpl-dahua-vuln 192.168.1.100

# Perimeter devices (firewalls, VPNs) — all vendors, 19+ CVEs
nmap -p 443,8443 --script embedxpl-perimeter-vuln 10.0.0.0/24

# SOHO routers — 15 vendors, 14+ CVEs
nmap -p 80,443,8080 --script embedxpl-router-vuln 192.168.1.0/24

# Printers — 11 vendors, PJL/IPP/HTTP
nmap -p 80,443,631,9100 --script embedxpl-printer-vuln 10.0.0.0/24

# Multi-vendor IoT CVE check (15+ CVEs)
nmap -p 80,443 --script embedxpl-iot-cve-check 192.168.1.0/24

# All EmbedXPL scripts at once
nmap -p 80,443,554,9100 --script 'embedxpl-*' 192.168.1.100

# Run all scripts and save output
nmap -p 80,443,554 --script 'embedxpl-*' -oN /tmp/scan.txt 192.168.1.0/24
```

---

## Available NSE scripts

| Script | Target | CVEs / Techniques |
|--------|--------|-------------------|
| `embedxpl-rtsp-discover` | IP cameras | RTSP OPTIONS banner grab, vendor fingerprint |
| `embedxpl-camera-identify` | IP cameras/NVR | HTTP + RTSP + ONVIF multi-protocol fingerprint |
| `embedxpl-camera-snapshot` | IP cameras | Unauthenticated snapshot access (30+ endpoints) |
| `embedxpl-hikvision-vuln` | Hikvision | CVE-2021-36260 (RCE), CVE-2017-7921 (auth bypass) |
| `embedxpl-dahua-vuln` | Dahua/OEM | CVE-2021-33044 (auth bypass), CVE-2020-25078, CVE-2013-6117 |
| `embedxpl-rtsp-creds` | RTSP cameras | Default credential test (Basic auth) |
| `embedxpl-iot-cve-check` | Multi-vendor IoT | 15+ CVEs: Hikvision, Dahua, D-Link NAS, Reolink, SonicWall, GPON, Fortinet, PAN-OS, TP-Link |
| `embedxpl-perimeter-vuln` | Firewalls/VPN | 19 CVEs — 15 vendors: Fortinet, Cisco, PAN-OS, SonicWall, Sophos, Juniper, Zyxel, Check Point, Ivanti, Citrix, pfSense, WatchGuard, Barracuda |
| `embedxpl-router-vuln` | SOHO routers | 14 CVEs — 15 vendors: TP-Link, D-Link, Netgear, ASUS, Linksys, MikroTik, Huawei, ZTE, Intelbras, Tenda, Totolink, DrayTek, GPON, Zyxel, OpenWrt |
| `embedxpl-printer-vuln` | Printers/MFPs | 14 CVEs — 11 vendors: HP, Canon, Lexmark, Xerox, Ricoh, Brother, Kyocera, CUPS, Epson, Konica, Samsung |
| `embedxpl-suite-ref` | Any | XPL-Forge suite install reference + GTFOBins quick guide |


[Wiki hub](../README.md)
