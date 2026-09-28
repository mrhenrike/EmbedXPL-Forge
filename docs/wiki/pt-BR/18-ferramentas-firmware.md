# Ferramentas de Firmware: `firmware-dl` e `firmware-analyze`

**Idioma:** Português (pt-BR). **English:** [../en-US/18-firmware-tools.md](../en-US/18-firmware-tools.md)

---

## Visão geral

O EmbedXPL-Forge inclui duas ferramentas CLI para pesquisa de firmware IoT/OT:

| Ferramenta | Ponto de entrada | Finalidade |
|------------|-----------------|-----------|
| `firmware-dl` | `python -m embedxpl.tools.firmware_downloader` | Baixar firmware de portais públicos de vendors |
| `firmware-analyze` | `python -m embedxpl.tools.firmware_analyzer` | Analisar firmware usando binwalk, unblob, Firmwalker, EMBA |

Ambas as ferramentas estão localizadas em `embedxpl/tools/` e são utilizáveis independentemente do shell interativo.

---

## `firmware-dl` — Downloader de Firmware

### Ponto de entrada

```bash
python -m embedxpl.tools.firmware_downloader [flags]
# ou após pip install:
firmware-dl [flags]
```

### Parâmetros

| Flag | Tipo | Obrigatório | Descrição |
|------|------|-------------|-----------|
| `--list` | flag | não | Listar todas as entradas de vendor de `firmware_sources.yaml` |
| `--vendor <chave>` | string | não | Chave de vendor (ex.: `hikvision`, `tplink`, `cisco`) — veja `--list` |
| `--model <nome>` | string | não | Nome do modelo do dispositivo (informativo; usado para orientação de navegação no portal) |
| `--url <url>` | string | não | URL de download direto do firmware (ignora o lookup de vendor) |
| `--output <dir>` | string | não | Diretório de saída (padrão: `./firmware_downloads`) |
| `--filename <nome>` | string | não | Substituir o nome do arquivo de saída (padrão: inferido da URL) |

`--vendor` ou `--url` é obrigatório (a menos que `--list` seja usado).

---

### `--list` — listar fontes de vendor disponíveis

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

### `--vendor` sem `--url` (orientação de portal, sem download direto)

```
$ python -m embedxpl.tools.firmware_downloader --vendor hikvision --model DS-2CD2143G2-I

2026-06-01 19:10:05 [INFO] Vendor: Hikvision (ip-cameras)
2026-06-01 19:10:05 [INFO] Portal: https://www.hikvision.com/en/support/download/firmware/
2026-06-01 19:10:05 [INFO] Model: DS-2CD2143G2-I
2026-06-01 19:10:05 [INFO] Portal URL for manual download: https://www.hikvision.com/en/support/download/firmware/
2026-06-01 19:10:05 [INFO] Use --url <direct_url> to download a specific firmware file.
```

---

### `--vendor --url` — download via URL direta

```
$ python -m embedxpl.tools.firmware_downloader \
    --vendor hikvision \
    --url "https://firmware.hikvision.com/firmware/DS-2CD2143G2-I_V5.7.16_230415.zip" \
    --output ./firmware_downloads

2026-06-01 19:10:10 [INFO] Vendor: Hikvision (ip-cameras)
2026-06-01 19:10:10 [INFO] Downloading: https://firmware.hikvision.com/.../DS-2CD2143G2-I_V5.7.16_230415.zip
                             → ./firmware_downloads/DS-2CD2143G2-I_V5.7.16_230415.zip
  Progress: 34% (12582912/36962304 bytes)
  Progress: 67% (24903680/36962304 bytes)
  Progress: 100% (36962304/36962304 bytes)

2026-06-01 19:10:38 [INFO] Download complete: ./firmware_downloads/DS-2CD2143G2-I_V5.7.16_230415.zip (36962304 bytes)
```

---

### `--url` apenas (sem vendor, download direto)

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

### Vendor requer login

```
$ python -m embedxpl.tools.firmware_downloader --vendor cisco --model RV325

2026-06-01 19:13:00 [INFO] Vendor: Cisco (routers-switches)
2026-06-01 19:13:00 [INFO] Portal: https://software.cisco.com/download/home
2026-06-01 19:13:00 [WARN] This vendor requires portal login. Automatic download not supported.
                            Visit: https://software.cisco.com/download/home
2026-06-01 19:13:00 [INFO] Model requested: RV325
```

---

### Vendor desconhecido

```
$ python -m embedxpl.tools.firmware_downloader --vendor unknownbrand

2026-06-01 19:14:00 [ERROR] Unknown vendor: 'unknownbrand'. Use --list to see available vendors.
```

---

### Nenhuma flag fornecida

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

### Erro HTTP

```
$ python -m embedxpl.tools.firmware_downloader --url "https://example.com/notfound.bin"

2026-06-01 19:15:00 [ERROR] HTTP 404: https://example.com/notfound.bin
Traceback (most recent call last):
  ...
urllib.error.HTTPError: HTTP Error 404: Not Found
```

---

## `firmware-analyze` — Analisador de Firmware

### Ponto de entrada

```bash
python -m embedxpl.tools.firmware_analyzer [flags]
# ou após pip install:
firmware-analyze [flags]
```

### Parâmetros

| Flag | Tipo | Obrigatório | Padrão | Descrição |
|------|------|-------------|--------|-----------|
| `--file <caminho>` | string | **sim** | - | Caminho para o binário de firmware a analisar |
| `--tool <ferramenta>` | string | não | `all` | Ferramenta de análise: `binwalk`, `unblob`, `firmwalker`, `emba` ou `all` |
| `--output <dir>` | string | não | `firmware_analysis_<stem>` | Diretório de saída para todas as saídas das ferramentas |

---

### `--tool all` (padrão) — pipeline completo

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

### `--tool binwalk` apenas

```
$ python -m embedxpl.tools.firmware_analyzer \
    --file ./router_fw_v2.1.bin \
    --tool binwalk

2026-06-01 19:30:00 [INFO] Firmware: ./router_fw_v2.1.bin (4194304 bytes)
2026-06-01 19:30:01 [INFO] Running binwalk: binwalk --extract ...

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             TRX firmware header, little endian, header size: 28 bytes
28            0x1C            LZMA compressed data, properties: 0x5D
4096          0x1000          Squashfs filesystem, little endian, version 4.0, compression:lz4

2026-06-01 19:30:32 [INFO] binwalk extraction complete → ./firmware_analysis_router_fw_v2.1/binwalk_extract

============================================================
  Firmware Analysis Summary
============================================================
  binwalk         OK
============================================================
```

---

### `--tool unblob` apenas

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

### `--tool firmwalker` (sem extração prévia)

```
$ python -m embedxpl.tools.firmware_analyzer \
    --file ./router_fw_v2.1.bin \
    --tool firmwalker

2026-06-01 19:34:00 [WARN] firmwalker: no extracted filesystem found; run binwalk or unblob first
```

Execute `--tool all` ou execute binwalk/unblob primeiro, depois firmwalker:

```bash
# Passo 1 — extrair
python -m embedxpl.tools.firmware_analyzer --file router_fw_v2.1.bin --tool binwalk

# Passo 2 — analisar sistema de arquivos extraído
python -m embedxpl.tools.firmware_analyzer --file router_fw_v2.1.bin --tool firmwalker
```

---

### `--tool emba` apenas

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

### Ferramenta não instalada

```
$ python -m embedxpl.tools.firmware_analyzer --file router_fw_v2.1.bin --tool binwalk

2026-06-01 19:40:00 [WARN] binwalk not found. Install: pip install binwalk or apt-get install binwalk

============================================================
  Firmware Analysis Summary
============================================================
  binwalk         SKIP
============================================================
```

---

### Arquivo não encontrado

```
$ python -m embedxpl.tools.firmware_analyzer --file /nonexistent/fw.bin

2026-06-01 19:42:00 [ERROR] Firmware file not found: /nonexistent/fw.bin
```

---

## Estrutura do diretório de saída

Após uma execução completa de `--tool all`, o diretório de saída contém:

```
firmware_analysis_DS-2CD2143G2-I_V5.7.16_230415/
  binwalk_extract/            # Arquivos extraídos pelo binwalk
    _DS-2CD2143G2-I_V5.7.16_230415.zip.extracted/
      squashfs-root/          # Raiz do sistema de arquivos extraído
        etc/
        bin/
        usr/
        www/
  unblob_extract/             # Arquivos extraídos pelo unblob
    squashfs-root/
      etc/
      bin/
      ...
  firmwalker_report.txt       # Relatório de análise do Firmwalker
  emba_output/                # Saída de análise EMBA
    index.html                # Relatório HTML EMBA (abrir no navegador)
    csv_logs/
    log/
```

---

## Referência de instalação de ferramentas

| Ferramenta | Comando de instalação | Notas |
|------------|----------------------|-------|
| binwalk | `sudo apt-get install binwalk` ou `pip install binwalk` | Wrapper Python tem extração limitada |
| unblob | `pip install unblob` | Recomendado — extração mais confiável |
| Firmwalker | `git clone https://github.com/craigz28/firmwalker` | Script shell, requer bash |
| EMBA | `git clone https://github.com/e-m-b-a/emba && sudo ./installer.sh` | Requer Docker e root/sudo |

---

[Hub da Wiki](../README.md)
