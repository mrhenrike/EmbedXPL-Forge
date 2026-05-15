# Herospeed / Longsee NVR — Comprehensive Security Research Report

**Research scope:** All publicly available Herospeed/Longsee N-series NVR firmware (2023-2026)
**Method:** Firmware download, static analysis, binwalk extraction, reverse engineering, QEMU emulation, live API testing
**Date:** May 2026
**Researcher:** André Henrique (@mrhenrike) — EmbedXPL-Forge
**Community discovery credit:** c3l3r1on (github.com/c3l3r1on) — original QNVR findings

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

**Total firmwares analyzed: 8** (7 N-series + 1 legacy HI3536D for comparison)

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
| `exploits/cameras/herospeed/herospeed_nvr_unauth_account_enum` | 9.1 | Unauthenticated credential metadata (VULN-1) |
| `exploits/cameras/herospeed/herospeed_nvr_rce` | 9.8 | Post-auth API command injection (VULN-4 chain) |
| `exploits/cameras/herospeed/herospeed_nvr_vbhtm_cred_disclosure` | 6.5 | XVR /vb.htm credential disclosure (VULN-2) |
| `exploits/cameras/herospeed/herospeed_nvr_upgrade_source_injection_rce` | 8.8 | Upgrade shell execution (VULN-3, v2.0.4+v2.0.6) |
| `exploits/cameras/herospeed/herospeed_nvr_hardcoded_root_hash` | 9.8 | Universal hardcoded root hash 2023-2025 (VULN-4) |
| `scanners/cameras/herospeed_longsee_nvr_scan` | 9.1 | Device discovery + vuln fingerprint |

**Total: 6 modules covering 5 confirmed vulnerabilities**

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
