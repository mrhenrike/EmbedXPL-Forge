# EmbedXPL-Forge

**Framework de Avaliação de Segurança em Dispositivos Embarcados e de Perímetro**

EmbedXPL-Forge é um framework de exploração open-source para profissionais de segurança auditarem roteadores, switches, câmeras IP, NVR/DVR, GPON ONTs, CPEs de ISP e dispositivos IoT/embarcados. Oferece **3200+ módulos** cobrindo testes de credenciais, exploração de vulnerabilidades, varredura de rede, geração de payloads, ataques a câmeras RTSP, manipulação de firmware e orquestração PolyExploit multilinguagem — com **680+ CVEs** mapeados em **114+ fabricantes** e um **APT Group Attack Engine** que reproduz cadeias de ataque reais de grupos nação-estado.

> **Autor:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)
> **Versão:** 2.13.0

---

## Funcionalidades

- **570+ módulos de exploit** — RCE, auth bypass, path traversal, info disclosure, buffer overflow, DNS hijacking, command injection, backdoor, CSRF, config decrypt, gerador WPA/WPS, gerador de senha de fábrica
- **88 módulos de credenciais** — ataques de dicionário contra FTP, SSH, Telnet, HTTP, SNMP, SFTP
- **Motor RTSP completo** — portado do [cameradar](https://github.com/ullaakut/cameradar): brute-force de rotas (195+ rotas), brute-force de credenciais (80+ pares), auth Basic/Digest, RTSPS/TLS, **tunelamento RTSP-over-HTTP (Python puro, RFC 2326 App-C)**, scanner nmap/masscan/direto, ONVIF WS-Discovery
- **7 scripts NSE Nmap personalizados** — descoberta RTSP, fingerprint de câmera, validação CVE Hikvision/Dahua, teste de credenciais padrão, verificação multi-vendor CVE, captura de snapshot (`pip install embedxpl[nse]`)
- **Suite de exploração de firmware** — detecção de formato, injeção de backdoor, patch de checksum, bypass de flash por fabricante (NETGEAR, TP-Link, D-Link, ASUS)
- **Orquestrador PolyExploit** — compilação C/C++ em tempo de execução (gcc/clang/mingw/cross), execução de exploits Ruby/Node.js/PHP/Bash/Perl, integração msfconsole, integração ExploitDB/searchsploit
- **5 módulos de scanner** — AutoPwn, scanners específicos por dispositivo
- **32 módulos de payload** — reverse/bind TCP shells para x86, x64, ARM, MIPS, Python, Perl, PHP
- **13 módulos de encoder** — Base64 e hex encoding para Python, PHP, Perl
- **14 módulos genéricos** — Heartbleed, ShellShock, UPnP IGD, SNMP bruteforce, TCP Xmas, amplificação UDP, consulta CVE, detector DNS hijack, interceptor AITM
- **680+ CVEs mapeados** — de 2001 a 2026, cobrindo todas as classes de vulnerabilidade
- **APT Group Attack Engine** — reproduz cadeias de ataque do APT28, Volt Typhoon, Sandworm, Quad7, Turla, APT40 com mapeamento MITRE ATT&CK
- **23 wordlists por fabricante** — credenciais padrão externalizadas por vendor (incluindo ISPs brasileiros específicos)

## Tipos de Dispositivos Suportados

| Tipo | Cobertura | Descrição |
|------|-----------|-----------|
| **Roteadores / GPON ONT / CPE** | 580+ módulos | Roteadores SOHO, gateways enterprise, CPE/ONT GPON |
| **Câmeras IP / NVR / DVR** | 60+ módulos | Hikvision, Dahua, Axis, Reolink, Amcrest, Uniview, Tapo, Swann, ANNKE, Edimax, Intelbras e mais |
| **NAS (Armazenamento em Rede)** | 20+ módulos | QNAP, Synology, D-Link NAS, Zyxel |
| **VPN / Firewall Appliances** | 20+ módulos | Ivanti, Fortinet, SonicWall, Zyxel |
| **Switches L2/L3** | 3 módulos | Switches gerenciados (Cisco, D-Link, NETGEAR) |
| **SOHO Edge** | 9 módulos | Roteadores de viagem, NAS, APs wireless |

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

## Novidades v2.13.0

Análise de gap contra [routerpwn.com](https://github.com/hkm/routerpwn.com) e [routerPWN](https://github.com/lilloX/routerPWN) — **27 novos módulos**, **19 novos fabricantes**:

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

---

> **Autor:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
