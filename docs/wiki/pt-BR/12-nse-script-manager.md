# Gerenciador de Scripts NSE

**Idioma:** Português (pt-BR). **English:** [../en-US/12-nse-script-manager.md](../en-US/12-nse-script-manager.md)

---

## Visão geral

O EmbedXPL-Forge inclui **11 scripts NSE do Nmap** que estendem o Nmap com detecção de CVEs IoT, fingerprinting de dispositivos e links diretos para módulos de exploit do EmbedXPL-Forge e FirewallXPL-Forge.

O comando `embedxpl-nse` (ou `python -m embedxpl.nse`) gerencia a instalação, validação, listagem e execução desses scripts.

**Pontos de entrada:**

```bash
embedxpl-nse <comando>         # após pip install
python -m embedxpl.nse <comando>   # a partir do código-fonte
```

---

## Catálogo de scripts

| Nome curto | Arquivo | Descrição |
|------------|---------|-----------|
| `rtsp-discover` | `embedxpl-rtsp-discover.nse` | Descoberta de serviço RTSP + captura de banner + fingerprint de vendor |
| `camera-identify` | `embedxpl-camera-identify.nse` | Fingerprinting profundo de câmera IP (HTTP + RTSP + ONVIF multi-protocolo) |
| `camera-snapshot` | `embedxpl-camera-snapshot.nse` | Detector de acesso não autenticado a snapshot de câmera (30+ endpoints) |
| `hikvision-vuln` | `embedxpl-hikvision-vuln.nse` | Verificador de CVE Hikvision (CVE-2021-36260, CVE-2017-7921) |
| `dahua-vuln` | `embedxpl-dahua-vuln.nse` | Verificador de CVE Dahua (CVE-2021-33044, CVE-2020-25078, CVE-2013-6117) |
| `rtsp-creds` | `embedxpl-rtsp-creds.nse` | Testador rápido de credenciais padrão RTSP (autenticação Basic) |
| `iot-cve-check` | `embedxpl-iot-cve-check.nse` | Fingerprint e validação de CVE IoT multi-vendor (15+ CVEs incluindo 2026) |
| `perimeter-vuln` | `embedxpl-perimeter-vuln.nse` | Verificador de CVE Firewall/VPN — 15 vendors, 19+ CVEs (Fortinet/Cisco/PAN-OS/SonicWall...) |
| `router-vuln` | `embedxpl-router-vuln.nse` | Verificador de CVE roteador SOHO — 15 vendors, 14+ CVEs (TP-Link/Netgear/ASUS/MikroTik...) |
| `printer-vuln` | `embedxpl-printer-vuln.nse` | Verificador de CVE impressora de rede — 11 vendors, sondas PJL/IPP/HTTP (HP/Canon/Lexmark...) |
| `suite-ref` | `embedxpl-suite-ref.nse` | Referência completa da suite XPL-Forge + guia rápido GTFOBins embedded Linux |

Portas de varredura padrão: `80,443,554,5554,8080,8443,8554,9100,37777,631`

---

## `install` — copiar scripts para o Nmap

### Sintaxe

```
embedxpl-nse install [--force] [--nse-dir <DIR>]
```

### Parâmetros

| Parâmetro | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `--force`, `-f` | flag | false | Sobrescrever scripts já instalados |
| `--nse-dir DIR` | string | auto-detectado | Substituir o caminho do diretório de scripts Nmap |

### Instalação padrão (Nmap presente)

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
```

### Instalação — Nmap não encontrado (fallback elegante)

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
    ... (11 files listed)

  Manual usage (without install):
  nmap --script <path/to/script.nse> -p 80,443 <target>
====================================================================
```

### Instalação — permissão negada

```
$ embedxpl-nse install

...
[4/4] Installing scripts...
      [ERR] Permission denied: /usr/share/nmap/scripts/embedxpl-iot-cve-check.nse
      ... (11 erros)

Results:
  Installed  : 0
  Failed     : 11 -- run with sudo/Administrator
               sudo embedxpl-nse install
```

---

## `list` — exibir status de instalação

### Sintaxe

```
embedxpl-nse list
```

### Saída (Nmap encontrado, todos instalados)

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
```

---

## `check` — validar instalação do Nmap

### Sintaxe

```
embedxpl-nse check
```

### Saída (Nmap presente)

```
$ embedxpl-nse check

[OK] Nmap found: /usr/bin/nmap (Nmap version 7.95 ( https://nmap.org ))
[OK] Nmap scripts directory: /usr/share/nmap/scripts

$ echo $?
0
```

### Saída (Nmap não encontrado)

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

## `run` — executar scripts NSE via Nmap

### Sintaxe

```
embedxpl-nse run --target <ALVO> [--scripts <SCRIPTS>] [--ports <PORTAS>] [--output <ARQUIVO>] [--args <ARGS_NMAP>]
```

### Parâmetros

| Parâmetro | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `--target`, `-t` | string | *obrigatório* | IP, faixa CIDR ou hostname |
| `--scripts`, `-s` | string | `all` | `all` ou nomes curtos separados por vírgula (ex.: `hikvision-vuln,rtsp-creds`) |
| `--ports`, `-p` | string | `80,443,554,5554,8080,8443,8554,9100,37777,631` | Portas a varrer separadas por vírgula |
| `--output`, `-o` | string | nenhum | Escrever saída Nmap em arquivo (`-oN`) |
| `--args` | string | nenhum | Argumentos Nmap extras brutos (string entre aspas) |

### Executar todos os scripts contra uma subnet

```
$ embedxpl-nse run --target 192.168.1.0/24 --scripts all

[NSE] Running: /usr/bin/nmap -sV -p 80,443,554,5554,8080,8443,8554,9100,37777,631
      --script embedxpl-rtsp-discover,embedxpl-camera-identify,...

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

### Executar scripts específicos apenas

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
|_    FirewallXPL module: use exploits/firewalls/fortinet/fortios_sslvpn_rce_cve_2024_21762
```

---

## `info` — exibir detalhes do script

### Sintaxe

```
embedxpl-nse info <nome_script>
```

Aceita tanto nomes curtos (`hikvision-vuln`) quanto nomes completos (`embedxpl-hikvision-vuln`).

### Saída

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
  -- EmbedXPL modules:
  --   use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
  --   use exploits/cameras/hikvision/info_disclosure_cve_2017_7921
  --
  -- Author: Andre Henrique (@mrhenrike) | Uniao Geek
  -- Version: 2.0.0
```

---

## `uninstall` — remover scripts do Nmap

### Sintaxe

```
embedxpl-nse uninstall
```

### Saída

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

---

## Usando scripts diretamente com o Nmap (sem `embedxpl-nse run`)

Após a instalação, a sintaxe padrão do Nmap funciona:

```bash
# Script único, host único
nmap -sV -p 80,443 --script embedxpl-hikvision-vuln 192.168.1.100

# Múltiplos scripts
nmap -sV -p 80,443,554 --script embedxpl-hikvision-vuln,embedxpl-rtsp-discover 192.168.1.0/24

# Todos os scripts EmbedXPL (wildcard)
nmap -sV -p 80,443,554,5554 --script 'embedxpl-*' 192.168.1.0/24

# Descoberta de câmeras em subnet
nmap -sV -p 554,5554,8554 --script embedxpl-rtsp-discover,embedxpl-camera-identify 10.0.0.0/24

# Verificação de CVE Firewall/VPN
nmap -sV -p 443,8443 --script embedxpl-perimeter-vuln 10.0.0.1

# Verificação de CVE impressora
nmap -sV -p 80,9100,631 --script embedxpl-printer-vuln 192.168.1.0/24
```

---

## Instalação manual (sem `embedxpl-nse install`)

Se a instalação automática falhar, copie os arquivos `.nse` manualmente:

```bash
# Linux — encontrar o diretório de origem NSE
python -c "import embedxpl.nse.manager as m; print(m._NSE_PACKAGE_DIR)"
# Saída: /home/user/.local/lib/python3.12/site-packages/nse

# Copiar para o Nmap
sudo cp /home/user/.local/lib/python3.12/site-packages/nse/embedxpl-*.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
```

```powershell
# Windows — encontrar o diretório de origem NSE
python -c "import embedxpl.nse.manager as m; print(m._NSE_PACKAGE_DIR)"
# Saída: C:\Users\user\AppData\Local\Programs\Python\Python312\Lib\site-packages\nse

# Copiar para o Nmap (execute como Administrador)
Copy-Item "C:\Users\user\AppData\...\nse\embedxpl-*.nse" "C:\Program Files (x86)\Nmap\scripts\"
nmap --script-updatedb
```

---

[Hub da Wiki](../README.md)
