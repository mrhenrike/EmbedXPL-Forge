# Herospeed / Longsee NVR — Comprehensive Security Research Report

**Research scope:** All publicly available Herospeed/Longsee N-series NVR firmware (2023-2026) + full NAND flash dump
**Method:** Firmware download, static analysis, binwalk extraction, reverse engineering, QEMU emulation, live API testing, NAND flash analysis
**Date:** May 2026
**Researcher:** André Henrique (@mrhenrike) — EmbedXPL-Forge
**Community discovery credit:** c3l3r1on (github.com/c3l3r1on) — original lab research, Cases A/B/C/D, nvr_h4rv3st3r.py v8

---

## Shodan/FOFA Fingerprints (Updated)

| Source | Query | Scope |
|---|---|---|
| **Shodan** (c3l3r1on, confirmed) | `http.html:"statics/js/variable.js"` | **Best fingerprint** -- all NVR families |
| **Shodan** (c3l3r1on, confirmed) | `http.favicon.hash:-873627015` | **Favicon hash fingerprint** -- all NVR families (web UI favicon) |
| Shodan | `http.html:"longseSha256"` | Longsee platform |
| Shodan | `http.html:"LsNXVRPlugin"` | NVR-specific plugin |
| Shodan | `"Boa/0.94.13" http.title:"NVR"` | Boa HTTP server |
| FOFA (c3l3r1on, May 2026) | `body="longseSha256"` | ~100k+ EU, ~50k+ global |

**`variable.js` contains `DEFAULT_ADMIN_PASSWORD="12345"` hardcoded** — confirms the Shodan fingerprint also reveals the default credential.

## Known OEM Re-brands (c3l3r1on, not independently verified)

| Brand | Models | Firmware |
|---|---|---|
| HeroSpeed (OEM) | 6804 / 6808 / 6816 | V21.1.50.4 / V21.1.34.4 |
| TVT Digital | TD-3000H1 / TD-3300 | V21.1.x / V22.1.x |
| GISE (Poland) | V5 series (XVR/NVR) | V21.1.20.x - V21.1.27.x |
| Longse | LSN-9836 / LSN-9436 | Web v6.0 series (2021-2023) |
| Zintronic | P5 / NVR series | N9000 platform (BitVision) |
| Turing AI (USA) | SMART series | N9000 platform |
| Speco Technologies | ZIP series | OEM TVT variants |
| Alibi Security | Vigilant series | OEM TVT variants |
| IRBIS | MBD6804T-EL | V4.02.R11 (legacy) |

---

## Firmware Coverage

| Firmware | Channels | Version | Date | SoC | Files | libweb.so |
|---|---|---|---|---|---|---|
| N3009_32NR_ALH1P4 | 9CH | **v2.0.4** (VULNERABLE) | 2023-09-04 | MC6830 | 970 | 686KB |
| N3009_32NR_BVH1P4 | 9CH | **v2.0.6** (patched+new vuln) | 2024-08-26 | MC6830 | 892 | 847KB |
| N3016_32NR_ALH1P8 | 16CH | **v2.0.4** (VULNERABLE) | 2023-09-04 | MC6830 | 970 | 686KB |
| N3016_32NR_BVH1P8 | 16CH | **v2.0.6** | 2024-08-26 | MC6830 | 892 | 847KB |
| N3109_32NR_BVH1P4A0 | 9CH | v2.0.6 | 2024-08-23 | MC6830 | 963 | 815KB |
| N3332_32NR_ALH2P0A4 | 32CH | **v2.0.4** (VULNERABLE) | 2023-09-04 | MC6830 | 1102 | 742KB |
| NVR_F30_BV | F30 | v2.0.8 | 2025-12-03 | MC6830 | 913 | 919KB |
| HI3536D_H265_9CH_BD | 9CH | V21.1.23.3 | 2021-06 | HI3536D | 7737 | (Boa embedded in demo) |
| **nvr_full_flash.bin** (c3l3r1on lab) | 9CH? | **2024-04-28** | Lab device | MC6830 | 860 | 814KB |

**Total firmwares analyzed: 9** (8 standard + 1 full NAND flash dump from c3l3r1on's lab device)

### Flash Dump Key Findings (nvr_full_flash.bin)
- **PERF magic**: Full NAND flash (32MB) — kernel at 0x60000, SquashFS at 0x400000, JFFS2 config at 0x1900000
- **Plugin**: `LsNXVRPlugin_V24.2.3.240201_R1.exe` (2024-02-01 build)
- **Root hash**: `12ZpTwfyH6/Bs` — same hardcoded hash confirmed in real device
- **libweb.so**: 814,008B — unique version between v2.0.4 (686KB) and v2.0.6 (868KB)
- **nvr_main**: 5,357KB (larger than N3009 v2.0.4 4,820KB — more features)
- **AES key in libdatamanager.so**: `0123456789ABCDEF0123456789abcdef` (hardcoded encryption key)
- **Case B confirmed**: `FTP_UploadJpgBuffer(server:%s)` + `popen()` in nvr_main

---

## Platform Architecture

### SoC: SiGmaStar MC6830 (ARM Cortex-A7)
All N-series firmware (2023-2025) runs on the **SiGmaStar MC6830** processor:
- ARM Cortex-A7, 32-bit, little-endian
- Linux kernel (ARM) + BusyBox userland
- Qt5 GUI (`libQt5Core`, `libQt5Gui`, `libQt5Widgets`)
- Boa/0.94.13 HTTP server embedded in `libweb.so`
- SquashFS filesystem (xz compressed) at offset 0x110 (272 bytes) in firmware binary

### HTTP API Architecture
- **HTTP server:** Boa/0.94.13 embedded in `/app/bin/lib/libweb.so`
- **API version:** v4.0.0 (all versions)
- **Main application:** `/app/bin/nvr_main` (Qt5 GUI + business logic)
- **Network comm:** `/app/bin/lib/libnetcommmanager.so` (ONVIF, RTSP, P2P)
- **Startup:** `/root/init.sh` → `/app/appStart.sh` → `nvr_main`

### Firmware Package Format
```
[0x00-0x10F]: Partition table (272 bytes)
  - Entry: name(32) + offset(4) + size(4)
  - Partitions: CORE (SquashFS), BASE (kernel), LOGO, UBOOT, version
[0x110]:       SquashFS filesystem (main rootfs)
[offset]:      Linux kernel ARM (zImage)
[offset]:      Flattened device tree (.dtb)
[offset]:      version file (plaintext, sourced by update.sh)
```

---

## Vulnerabilities Discovered

### VULN-1: Unauthenticated Credential Metadata Disclosure
**CVSS: 9.1 Critical** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

**All versions affected** (v2.0.4, v2.0.6, v2.0.8, HI3536D).

`POST /api/session/login-capabilities` with `{"username":"admin"}` returns without authentication:
- Per-user `salt` (32-byte hex, derived from stored credential)
- Random `challenge` nonce
- `iterations` count (100 by default)
- `sessionID` (valid until expiry)

These values enable offline SHA-256 KDF reconstruction of any user's credentials without triggering rate-limiting or lockout.

**Module:** `exploits/cameras/herospeed/herospeed_nvr_unauth_account_enum`
**Status:** Confirmed via live API testing against QEMU-emulated HI3536D firmware

---

### VULN-2: XVR Legacy Interface Credential Disclosure
**CVSS: 6.5 Medium** | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

**All versions affected.** `libweb.so` contains `/vb.htm` and `selectalluserlist`.

`GET /vb.htm?selectalluserlist` with Basic HTTP auth returns all user accounts with passwords encoded in Base64. Response format:
```
1=default_id, 2=admin, 3=MTIzNDU=, 4=0, ...
```
Where field 3 (`MTIzNDU=`) decodes to the admin password (`12345`).

Basic HTTP auth (`username:password` in Base64) is simpler to brute-force than the SHA-256 KDF used by the `/api/session/` endpoints.

Related pattern: CVE-2017-7921 (Hikvision XVR/DVR interface, similar design).

**Module:** `exploits/cameras/herospeed/herospeed_nvr_vbhtm_cred_disclosure`
**Status:** Confirmed via live API testing against QEMU-emulated HI3536D firmware

---

### VULN-3: Authenticated Upgrade Package Shell Execution RCE
**CVSS: 8.8 High** | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`

**All versions affected, with different exploitation mechanisms:**

#### v2.0.4 variant — Shell Source Injection
`update.sh` sources the `version` file from the upgrade package:
```sh
version_remote_file="${UPDATA_PATH}/version"
. $version_remote_file   # <-- source injection, any line executed
```
Craft a `version` file with shell commands alongside variable definitions. Commands execute as root.

#### v2.0.6 "patch" — Retreat.sh Explicit Execution (NEW)
The v2.0.6 "security patch" introduced a NEW, MORE EXPLICIT execution path:
```sh
detect_shell=/tmp/update/version
if head -n 1 "$detect_shell" | grep -q '^#!/bin'; then
    cp ${detect_shell} /tmp/retreat.sh
    chmod -R 777 /tmp/retreat.sh
    /tmp/retreat.sh        # <-- DIRECT SHELL SCRIPT EXECUTION
else
    echo "$detect_shell not linux shell"
fi
```
If the `version` file starts with `#!/bin/sh`, `update.sh` **explicitly copies and executes it**. This is direct shell script execution, not ambiguous source injection.

**Payload for v2.0.6:**
```sh
#!/bin/sh
/usr/sbin/telnetd -l /bin/sh -p 23 &
id > /tmp/pwned.txt
```

**Exploitation chain:**
1. Obtain valid credentials (via VULN-1 or VULN-2)
2. Authenticate to `/api/session/login`
3. Upload crafted firmware binary to `POST /api/upgrade/upgrade-file`
4. `update.sh` sources/executes the embedded `version` file
5. Commands execute as root; default payload spawns telnetd on port 23

**Module:** `exploits/cameras/herospeed/herospeed_nvr_upgrade_source_injection_rce`
**Status:** Confirmed — file creation (`touch /tmp/pwn_upgrade_rce.txt`) observed after source injection via QEMU ARM chroot emulation

---

### VULN-4: Hardcoded Root Password Hash (Universal, All 2023-2025 Versions)
**CVSS: 9.8 Critical** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Root password hash is identical in ALL analyzed firmware versions 2023-2025:**

```
root:12ZpTwfyH6/Bs:0:0::/root:/bin/sh
```

DES crypt hash, salt `12`, password unknown (not cracked from common wordlist).

| Firmware | Version | Root Hash |
|---|---|---|
| N3009_32NR_ALH1P4 | v2.0.4.230818 | `12ZpTwfyH6/Bs` |
| N3009_32NR_BVH1P4 | v2.0.6.240826 | `12ZpTwfyH6/Bs` |
| N3016_32NR_ALH1P8 | v2.0.4.230817 | `12ZpTwfyH6/Bs` |
| N3016_32NR_BVH1P8 | v2.0.6.240826 | `12ZpTwfyH6/Bs` |
| N3109_32NR_BVH1P4A0 | v2.0.6.240823 | `12ZpTwfyH6/Bs` |
| N3332_32NR_ALH2P0A4 | v2.0.4.230825 | `12ZpTwfyH6/Bs` |
| NVR_F30_BV | v2.0.8.250609 | `12ZpTwfyH6/Bs` |

Combined with VULN-3 (code execution), the attacker gains full root access to all affected devices sharing this firmware.

`busybox telnetd` is available in all firmware versions and can be spawned after code execution.

**Module:** `exploits/cameras/herospeed/herospeed_nvr_hardcoded_root_hash`
**Status:** Confirmed by static analysis of all 7 firmware images

---

### VULN-5 (Potential): Ping/NTP popen() Command Injection
**CVSS: TBD** | Requires further verification

`libweb.so` and `libnetcommmanager.so` contain `popen()` calls. The HI3536D `demo` binary contains `ping -w %d %s` and `ping %s -w 5` format strings fed to `popen()`.

A diagnostic endpoint (ping test) exists in the API but the exact path was not found via HTTP probing in the emulated N-series firmware. The NTP server configuration (`/api/network/ntp`) accepts and stores arbitrary server strings but the actual NTP sync appears to use a socket-based C implementation rather than `system("ntpdate ...")`.

Further testing on live hardware is required to confirm exploitability.

---

## Version Comparison Analysis

### libweb.so Sizes (HTTP API Server)
```
v2.0.4 (N3009, N3016):      702,752 bytes — IDENTICAL MD5
v2.0.4 (N3332, 32CH):       760,824 bytes — different (extra channels)
v2.0.6 (N3009, N3016):      867,672 bytes — IDENTICAL MD5 (patched)
v2.0.6 (N3109):              834,924 bytes — different hardware variant
v2.0.8 (F30, 2025):         941,964 bytes — newest, most features
```

N3009 and N3016 share **identical libweb.so** within each version — same firmware, different channel count only.

### Key Changes in v2.0.6 libweb.so
New strings added:
- `auth failed !` — login failure tracking
- `session timeout!` — session management
- `error ! invalid user id` — user validation
- `user_sha256.license_key` — new license key mechanism
- `getonlineupgradeurl` / `setonlineupgradeurl` — OTA update support
- `login_time` — login timestamp tracking
- `set_block_fd(req->fd) == -1` — connection limiting

No API endpoints were added or removed between v2.0.4 and v2.0.6 (same set of `/api/` paths).

---

## EmbedXPL-Forge Modules

| Module | CVSS | Description |
|---|---|---|
| `exploits/cameras/herospeed/herospeed_nvr_unauth_account_enum` | 9.1 | VULN-1: Unauthenticated credential metadata |
| `exploits/cameras/herospeed/herospeed_nvr_rce` | 9.8 | Post-auth API command injection chain |
| `exploits/cameras/herospeed/herospeed_nvr_vbhtm_cred_disclosure` | 6.5 | VULN-2: XVR /vb.htm credential disclosure |
| `exploits/cameras/herospeed/herospeed_nvr_upgrade_source_injection_rce` | 8.8 | VULN-3: Upgrade shell execution (v2.0.4 source + v2.0.6 retreat.sh) |
| `exploits/cameras/herospeed/herospeed_nvr_hardcoded_root_hash` | 9.8 | VULN-4: Universal hardcoded root hash 2023-2025 |
| `exploits/cameras/herospeed/herospeed_nvr_config_export_cred_recovery` | 8.8 | **Case A (c3l3r1on)**: Config export + hardcoded AES key decryption |
| `exploits/cameras/herospeed/herospeed_nvr_ftp_diagnostic_rce` | 8.8 | **Case B (c3l3r1on)**: FTP diagnostic server parameter injection RCE |
| `exploits/cameras/herospeed/herospeed_nvr_telnet_safecode_backdoor` | **9.8** | `/open_telnet` with SafeCode from MAC/SN → root:`cxlinux` |
| `exploits/cameras/herospeed/herospeed_nvr_paramconfig_bypass` | **9.8** | `MI1YSANORQ4NAELR` hardcoded bypass for `/paramconfig` |
| `exploits/cameras/herospeed/herospeed_nvr_camera_creds_decrypt` | 7.5 | Camera creds via static salt `World!@##$` + roundFive AES |
| `scanners/cameras/herospeed_longsee_nvr_scan` | 9.1 | Device discovery + vuln fingerprint (Shodan query: variable.js) |

**Total: 11 modules covering 9 confirmed vulnerability classes**

### Root Password Cracked

**c3l3r1on cracked the root hash** (`12ZpTwfyH6/Bs`) → **password: `cxlinux`**

This was confirmed in `_encyklopedia` (March 2026):
```
"12ZpTwfyH6/Bs" | Sama platforma FH6830 | /etc/shadow | Root access: hasło "cxlinux"
```
This affects ALL firmware versions 2023-2025 sharing the same hardcoded hash.

### c3l3r1on Cases + New Discoveries Summary

| # | Description | CVSS | Module | Source |
|---|---|---|---|---|
| Case A | Pre-auth config export + **DES key `13141314`** + SQLite DB → all credentials | 8.8 | `herospeed_nvr_config_export_cred_recovery` | nvr_h4rv3st3r.py |
| Case B | FTP diagnostic server param → popen() → root RCE (live hardware confirmed) | 8.8 | `herospeed_nvr_ftp_diagnostic_rce` | lab + Discord |
| Case C | Persistence via `debug.sh` in `appStart.sh` (survives reboots/factory reset) | Doc | research report | _encyklopedia |
| Case D | Unsigned firmware updates, no integrity verification | Doc | VULN-3 | _encyklopedia |
| **NEW** | `/open_telnet` backdoor with SafeCode from MAC/SN + root:`cxlinux` | **9.8** | `herospeed_nvr_telnet_safecode_backdoor` | longse_auth_matrix.py |
| **NEW** | `/paramconfig` hardcoded bypass `MI1YSANORQ4NAELR` (admin access, no auth) | **9.8** | `herospeed_nvr_paramconfig_bypass` | longse_auth_matrix.py + _encyklopedia |
| **NEW** | Camera credential decryption via static salt **`World!@##$`** + roundFive | 7.5 | `herospeed_nvr_camera_creds_decrypt` | nvr_api.py + Discord |

### c3l3r1on Discord Notes (May 2026)
- "yep, search (shifted bits, roundFive, **statyczna sól 'World!@##$'** w JS"
- "i've over 20mb of pure text describing this platform (n9000)"
- "currently the challenge is dynamically downloaded from js" (newer firmware anti-scraping)
- `roundFive` = extract chars `[22:38]` from SHA-256 hash = 16-char AES key

### Hardcoded Keys Registry (from c3l3r1on _encyklopedia)

| Key/Password | Purpose | Location | Source |
|---|---|---|---|
| `cxlinux` | Root password (hash `12ZpTwfyH6/Bs`) | `/etc/passwd` | c3l3r1on cracked |
| `13141314` | DES key for `sys_data.db` / config export | `libalgorithm.so` | nvr_h4rv3st3r.py |
| `MI1YSANORQ4NAELR` | Admin hardcoded bypass | `/paramconfig`, `/cmdlist.htm` | longse_auth_matrix.py |
| `World!@##$` | Static salt for camera cred AES key | `reverseRoundThree` in JS | nvr_api.py line 64 |
| `afe13ds34cdjk08c` | AES-128-CBC IV for camera credentials | `/api/channel/search-camera` | nvr_api.py |
| `+2G-WQVK00hCt7Yb(*__*)+_%^LONGSE` | SafeCode AES key | `/open_telnet` | longse_auth_matrix.py |
| `(*__*)+_%^LONGSE` | SafeCode AES IV | `/open_telnet` | longse_auth_matrix.py |

---

## Disclosure

- c3l3r1on (github.com/c3l3r1on): Original research on QNVR/Herospeed API authentication bypass, live device testing (May 2026)
- VULN-1 (login-capabilities): Reported to CERT Polska / CERT-CC VINCE (May 2026)
- VULN-3 (upgrade RCE): Discovered independently via firmware RE
- VULN-4 (hardcoded root): Discovered via systematic firmware analysis
- VULN-2 (XVR /vb.htm): Discovered via firmware RE

**Vendor contact:** Herospeed Technology Limited — contact attempted via herospeed.net. ZDI declined (not enterprise scope). CERT Polska notified for VULN-1.

---

## Remediation

1. Remove hardcoded root password hash — generate device-unique credentials at factory
2. Restrict `/api/session/login-capabilities` to require prior authentication or rate-limit heavily
3. Disable or remove `/vb.htm` legacy XVR interface from NVR firmware
4. Rewrite `update.sh` to validate upgrade package integrity before sourcing `version` file (use explicit allowlist of variable names, not shell source)
5. Replace DES crypt (`/etc/passwd`) with SHA-512 crypt or bcrypt
6. Isolate NVR management interface from WAN access (firewall-level)

---

*Report generated by EmbedXPL-Forge research pipeline | github.com/mrhenrike/EmbedXPL-Forge*
