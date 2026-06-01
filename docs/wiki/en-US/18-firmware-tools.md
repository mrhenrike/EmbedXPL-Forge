# Firmware Tools: `firmware-dl` and `firmware-analyze`

**Language:** English (en-US) | **pt-BR:** [../pt-BR/18-firmware-tools.md](../pt-BR/18-firmware-tools.md)

---

## Overview

EmbedXPL-Forge ships two CLI tools for IoT/OT firmware research:

| Tool | Entry point | Purpose |
|------|------------|---------|
| `firmware-dl` | `python -m embedxpl.tools.firmware_downloader` | Download firmware from public vendor portals |
| `firmware-analyze` | `python -m embedxpl.tools.firmware_analyzer` | Analyze firmware using binwalk, unblob, Firmwalker, EMBA |

Both tools are located in `embedxpl/tools/` and are usable independently of the interactive shell.

---

## `firmware-dl` — Firmware Downloader

### Entry point

```bash
python -m embedxpl.tools.firmware_downloader [flags]
# or after pip install:
firmware-dl [flags]
```

### Parameters

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--list` | flag | no | List all vendor entries from `firmware_sources.yaml` |
| `--vendor <key>` | string | no | Vendor key (e.g. `hikvision`, `tplink`, `cisco`) — see `--list` |
| `--model <name>` | string | no | Device model name (informational; used for portal navigation guidance) |
| `--url <url>` | string | no | Direct firmware download URL (bypasses vendor lookup) |
| `--output <dir>` | string | no | Output directory (default: `./firmware_downloads`) |
| `--filename <name>` | string | no | Override the output filename (default: inferred from URL) |

Either `--vendor` or `--url` is required (unless `--list` is used).

---

### `--list` — list available vendor sources

```
$ python -m embedxpl.tools.firmware_downloader --list

2026-06-01 19:10:00 [INFO] Available firmware sources (18 vendors):
  hikvision            | ip-cameras      Hikvision
  dahua                | ip-cameras      Dahua
  axis                 | ip-cameras      Axis Communications
  tplink               | routers         TP-Link
  netgear              | routers         Netgear
  asus                 | routers         ASUSTeK
  mikrotik             | routers         MikroTik
  cisco                | routers-switches Cisco [requires-login]
  fortinet             | firewalls        Fortinet [requires-login]
  paloalto             | firewalls        Palo Alto Networks [requires-login]
  sonicwall            | firewalls        SonicWall [requires-login]
  juniper              | firewalls        Juniper Networks [requires-login]
  zyxel                | firewalls        Zyxel
  checkpoint           | firewalls        Check Point [requires-login]
  siemens              | ics             Siemens
  schneider            | ics             Schneider Electric
  rockwell             | ics             Rockwell Automation [requires-login]
  hiab                 | cameras         Hiab cameras
```

---

### `--vendor` without `--url` (portal guidance, no direct download)

```
$ python -m embedxpl.tools.firmware_downloader --vendor hikvision --model DS-2CD2143G2-I

2026-06-01 19:10:05 [INFO] Vendor: Hikvision (ip-cameras)
2026-06-01 19:10:05 [INFO] Portal: https://www.hikvision.com/en/support/download/firmware/
2026-06-01 19:10:05 [INFO] Model: DS-2CD2143G2-I
2026-06-01 19:10:05 [INFO] Portal URL for manual download: https://www.hikvision.com/en/support/download/firmware/
2026-06-01 19:10:05 [INFO] Use --url <direct_url> to download a specific firmware file.
```

---

### `--vendor --url` — download via direct URL

```
$ python -m embedxpl.tools.firmware_downloader \
    --vendor hikvision \
    --url "https://firmware.hikvision.com/firmware/DS-2CD2143G2-I_V5.7.16_230415.zip" \
    --output ./firmware_downloads

2026-06-01 19:10:10 [INFO] Vendor: Hikvision (ip-cameras)
2026-06-01 19:10:10 [INFO] Portal: https://www.hikvision.com/en/support/download/firmware/
2026-06-01 19:10:10 [INFO] Downloading: https://firmware.hikvision.com/.../DS-2CD2143G2-I_V5.7.16_230415.zip
                             → ./firmware_downloads/DS-2CD2143G2-I_V5.7.16_230415.zip
  Progress: 34% (12582912/36962304 bytes)
  Progress: 67% (24903680/36962304 bytes)
  Progress: 100% (36962304/36962304 bytes)

2026-06-01 19:10:38 [INFO] Download complete: ./firmware_downloads/DS-2CD2143G2-I_V5.7.16_230415.zip (36962304 bytes)
```

---

### `--url` only (no vendor, direct download)

```
$ python -m embedxpl.tools.firmware_downloader \
    --url "https://example.com/router_fw_v2.1.bin" \
    --output /tmp/fw \
    --filename router_v2.1.bin

2026-06-01 19:12:00 [INFO] Downloading: https://example.com/router_fw_v2.1.bin → /tmp/fw/router_v2.1.bin
  Progress: 100% (4194304/4194304 bytes)

2026-06-01 19:12:05 [INFO] Download complete: /tmp/fw/router_v2.1.bin (4194304 bytes)
```

---

### Vendor requires login

```
$ python -m embedxpl.tools.firmware_downloader --vendor cisco --model RV325

2026-06-01 19:13:00 [INFO] Vendor: Cisco (routers-switches)
2026-06-01 19:13:00 [INFO] Portal: https://software.cisco.com/download/home
2026-06-01 19:13:00 [WARN] This vendor requires portal login. Automatic download not supported.
                            Visit: https://software.cisco.com/download/home
2026-06-01 19:13:00 [INFO] Model requested: RV325
```

---

### Unknown vendor

```
$ python -m embedxpl.tools.firmware_downloader --vendor unknownbrand

2026-06-01 19:14:00 [ERROR] Unknown vendor: 'unknownbrand'. Use --list to see available vendors.
```

---

### No flags provided

```
$ python -m embedxpl.tools.firmware_downloader

usage: firmware_downloader [-h] [--list] [--vendor VENDOR] [--model MODEL]
                           [--url URL] [--output OUTPUT] [--filename FILENAME]

EmbedXPL-Forge — Firmware Downloader CLI

optional arguments:
  --list              List all known firmware sources
  --vendor VENDOR     Vendor key (e.g. hikvision, tplink)
  --model MODEL       Device model name (informational)
  --url URL           Direct firmware download URL
  --output OUTPUT     Output directory (default: ./firmware_downloads)
  --filename FILENAME Override output filename
```

---

### HTTP error

```
$ python -m embedxpl.tools.firmware_downloader --url "https://example.com/notfound.bin"

2026-06-01 19:15:00 [ERROR] HTTP 404: https://example.com/notfound.bin
Traceback (most recent call last):
  ...
urllib.error.HTTPError: HTTP Error 404: Not Found
```

---

## `firmware-analyze` — Firmware Analyzer

### Entry point

```bash
python -m embedxpl.tools.firmware_analyzer [flags]
# or after pip install:
firmware-analyze [flags]
```

### Parameters

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--file <path>` | string | **yes** | - | Path to firmware binary to analyze |
| `--tool <tool>` | string | no | `all` | Analysis tool: `binwalk`, `unblob`, `firmwalker`, `emba`, or `all` |
| `--output <dir>` | string | no | `firmware_analysis_<stem>` | Output directory for all tool outputs |

---

### `--tool all` (default) — full pipeline

```
$ python -m embedxpl.tools.firmware_analyzer \
    --file ./firmware_downloads/DS-2CD2143G2-I_V5.7.16_230415.zip \
    --output ./analysis_hikvision_v5716

2026-06-01 19:20:00 [INFO] Starting firmware analysis pipeline...
2026-06-01 19:20:00 [INFO] Firmware: /home/user/firmware_downloads/DS-2CD2143G2-I_V5.7.16_230415.zip (36962304 bytes)

2026-06-01 19:20:01 [INFO] Running binwalk: binwalk --extract --directory ./analysis_hikvision_v5716/binwalk_extract --quiet DS-2CD2143G2-I_V5.7.16_230415.zip
  Progress: 100%
2026-06-01 19:20:45 [INFO] binwalk extraction complete → ./analysis_hikvision_v5716/binwalk_extract

2026-06-01 19:20:46 [INFO] Running unblob: unblob --extract-dir ./analysis_hikvision_v5716/unblob_extract DS-2CD2143G2-I_V5.7.16_230415.zip
  Processing chunks...  [100%]
2026-06-01 19:21:10 [INFO] unblob extraction complete → ./analysis_hikvision_v5716/unblob_extract

2026-06-01 19:21:11 [INFO] Running Firmwalker on ./analysis_hikvision_v5716/unblob_extract...
2026-06-01 19:21:35 [INFO] Firmwalker report: ./analysis_hikvision_v5716/firmwalker_report.txt

2026-06-01 19:21:36 [INFO] Running EMBA: sudo bash /opt/emba/emba.sh -f DS-2CD2143G2-I_V5.7.16_230415.zip -l ./analysis_hikvision_v5716/emba_output -s
  [*] EMBA starting firmware analysis...
  [*] Module P02_firmware_bin_file_check
  [*] Module S15_radare2_decompile
  [*] Module S25_kernel_check
  [*] Module F20_file_details
  [*] EMBA analysis complete
2026-06-01 19:28:44 [INFO] EMBA analysis complete → ./analysis_hikvision_v5716/emba_output

============================================================
  Firmware Analysis Summary
============================================================
  binwalk         OK
  unblob          OK
  firmwalker      OK
  emba            OK
============================================================
```

---

### `--tool binwalk` only

```
$ python -m embedxpl.tools.firmware_analyzer \
    --file ./router_fw_v2.1.bin \
    --tool binwalk

2026-06-01 19:30:00 [INFO] Starting firmware analysis pipeline...
2026-06-01 19:30:00 [INFO] Firmware: ./router_fw_v2.1.bin (4194304 bytes)
2026-06-01 19:30:01 [INFO] Running binwalk: binwalk --extract --directory ./firmware_analysis_router_fw_v2.1/binwalk_extract --quiet router_fw_v2.1.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             TRX firmware header, little endian, header size: 28 bytes, image size: 4194272 bytes, CRC32: 0xAABBCCDD
28            0x1C            LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, missing uncompressed size
4096          0x1000          Squashfs filesystem, little endian, version 4.0, compression:lz4, size: 3985408 bytes, 463 inodes, blocksize: 131072 bytes

2026-06-01 19:30:32 [INFO] binwalk extraction complete → ./firmware_analysis_router_fw_v2.1/binwalk_extract

============================================================
  Firmware Analysis Summary
============================================================
  binwalk         OK
============================================================
```

---

### `--tool unblob` only

```
$ python -m embedxpl.tools.firmware_analyzer \
    --file ./router_fw_v2.1.bin \
    --tool unblob

2026-06-01 19:32:00 [INFO] Firmware: ./router_fw_v2.1.bin (4194304 bytes)
2026-06-01 19:32:00 [INFO] Running unblob: unblob --extract-dir ./firmware_analysis_router_fw_v2.1/unblob_extract router_fw_v2.1.bin
  Processing handler: TRXHandler
  Processing handler: SquashFSHandler (lz4)
  Extracted: 463 files to ./firmware_analysis_router_fw_v2.1/unblob_extract

============================================================
  Firmware Analysis Summary
============================================================
  unblob          OK
============================================================
```

---

### `--tool firmwalker` (no extraction done first)

```
$ python -m embedxpl.tools.firmware_analyzer \
    --file ./router_fw_v2.1.bin \
    --tool firmwalker

2026-06-01 19:34:00 [WARN] firmwalker: no extracted filesystem found; run binwalk or unblob first

============================================================
  Firmware Analysis Summary
============================================================
============================================================
```

Run `--tool all` or run binwalk/unblob first, then firmwalker:

```bash
# Step 1 — extract
python -m embedxpl.tools.firmware_analyzer --file router_fw_v2.1.bin --tool binwalk

# Step 2 — analyze extracted filesystem
python -m embedxpl.tools.firmware_analyzer --file router_fw_v2.1.bin --tool firmwalker
```

---

### `--tool emba` only

```
$ python -m embedxpl.tools.firmware_analyzer \
    --file ./router_fw_v2.1.bin \
    --tool emba \
    --output ./emba_results

2026-06-01 19:35:00 [INFO] Firmware: ./router_fw_v2.1.bin (4194304 bytes)
2026-06-01 19:35:01 [INFO] Running EMBA: sudo bash /opt/emba/emba.sh -f router_fw_v2.1.bin -l ./emba_results/emba_output -s
  [*] EMBA starting...
  [*] P02_firmware_bin_file_check: MIPS32 Linux, SquashFS
  [*] S15_radare2_decompile: 12 interesting functions
  [*] S25_kernel_check: Linux 3.10.108, no KASLR, no stack canary
  [*] F20_file_details: 463 files, 23 ELF binaries, 5 SUID binaries
  [*] CVE check: 4 potential vulnerabilities found
  [*] EMBA complete — report at ./emba_results/emba_output/index.html

============================================================
  Firmware Analysis Summary
============================================================
  emba            OK
============================================================
```

---

### Tool not installed

```
$ python -m embedxpl.tools.firmware_analyzer --file router_fw_v2.1.bin --tool binwalk

2026-06-01 19:40:00 [WARN] binwalk not found. Install: pip install binwalk or apt-get install binwalk

============================================================
  Firmware Analysis Summary
============================================================
  binwalk         SKIP
============================================================
```

```
$ python -m embedxpl.tools.firmware_analyzer --file router_fw_v2.1.bin --tool emba

2026-06-01 19:41:00 [WARN] EMBA not found. Clone from: https://github.com/e-m-b-a/emba and run sudo ./installer.sh

============================================================
  Firmware Analysis Summary
============================================================
  emba            SKIP
============================================================
```

---

### File not found

```
$ python -m embedxpl.tools.firmware_analyzer --file /nonexistent/fw.bin

2026-06-01 19:42:00 [ERROR] Firmware file not found: /nonexistent/fw.bin
```

---

## Output directory structure

After a full `--tool all` run, the output directory contains:

```
firmware_analysis_DS-2CD2143G2-I_V5.7.16_230415/
  binwalk_extract/            # Files extracted by binwalk
    _DS-2CD2143G2-I_V5.7.16_230415.zip.extracted/
      squashfs-root/          # Extracted filesystem root
        etc/
        bin/
        usr/
        www/
  unblob_extract/             # Files extracted by unblob
    squashfs-root/
      etc/
      bin/
      ...
  firmwalker_report.txt       # Firmwalker analysis report
  emba_output/                # EMBA analysis output
    index.html                # EMBA HTML report (open in browser)
    csv_logs/
    log/
```

---

## Tool installation reference

| Tool | Install command | Notes |
|------|----------------|-------|
| binwalk | `sudo apt-get install binwalk` or `pip install binwalk` | Python wrapper has limited extraction |
| unblob | `pip install unblob` | Recommended — more reliable extraction |
| Firmwalker | `git clone https://github.com/craigz28/firmwalker` | Shell script, requires bash |
| EMBA | `git clone https://github.com/e-m-b-a/emba && sudo ./installer.sh` | Requires Docker and root/sudo |
