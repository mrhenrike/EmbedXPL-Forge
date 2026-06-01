# Introdução, Escopo e Instalação

**Idioma:** Português (pt-BR). **English:** [../en-US/01-introduction-and-installation.md](../en-US/01-introduction-and-installation.md)

---

## O que é o EmbedXPL-Forge

**EmbedXPL-Forge** (`embedxpl`, atalho de CLI: `exf`) é um framework Python modular e de código aberto para avaliação de segurança **autorizada** de dispositivos de rede, appliances IoT e sistemas embarcados. Ele reúne testes de credenciais, exploração de vulnerabilidades, descoberta e fingerprinting de redes, geração de payloads, gerenciamento de scripts NSE, inteligência sobre CVEs e utilitários de pós-exploração em uma única ferramenta extensível.

> **Autorização obrigatória.** Use apenas em sistemas que você possui ou para os quais possui permissão escrita explícita para testar. O uso não autorizado é ilegal.

| Métrica | Valor |
|---------|-------|
| Módulos ativos | 2800+ |
| CVEs mapeados | 700+ (2001–2026) |
| Famílias de vendors | 114+ |
| Versões Python | 3.8 – 3.13 |
| Plataformas | Linux, macOS, Windows |
| Licença | BSD-3-Clause |
| Arquivo de histórico | `~/.exf_history` (100 entradas) |
| Armazenamento de sessão | `~/.exf_sessions/` (um JSON por host) |

---

## Classes de Dispositivos Suportados

| Classe | Cobertura |
|--------|-----------|
| **Roteadores / GPON ONT / CPE** | Foco principal — 580+ módulos, 85+ pastas de vendor (D-Link, TP-Link, NETGEAR, Huawei, ZTE, MikroTik, Ubiquiti, ASUS, Linksys, Totolink e mais) |
| **Câmeras IP / NVR / DVR** | Hikvision, Dahua, Herospeed/Longsee (todas as marcas OEM), Axis, Reolink, Amcrest, Annke, Intelbras, Uniview, Bosch, ACTi, Avigilon e mais |
| **Firewalls / VPN / Appliances de Perímetro** | 80+ módulos — Fortinet, Palo Alto, Cisco, SonicWall, Check Point, Sophos, WatchGuard, Juniper |
| **Impressoras / MFP** | 185+ módulos — HP, Canon, Lexmark, Xerox, Ricoh, Brother, Epson, Kyocera, Samsung, CUPS |
| **Switches Gerenciados L2/L3** | Cisco, D-Link, NETGEAR |
| **ICS / OT / Industrial** | 35+ módulos — PLCs, SCADA HMIs, Modbus, S7comm, EtherNet/IP, Universal Robots |
| **BMC / IPMI** | ASUS ASMB8 (IPMI), Dell iDRAC9, Supermicro IPMI |
| **BMS (Gestão Predial)** | ABB Cylon Aspect |
| **NAS** | QNAP, Synology, D-Link NAS |
| **Casa Inteligente** | eNet SMART HOME, OpenRemote, Tuya |
| **OS Embarcado** | OpenWrt, VxWorks, RIOT OS, wolfSSL, QNX, RAUC |
| **Hypervisors** | Proxmox VE |
| **SOHO Edge** | Roteadores de viagem, access points, HooToo |
| **Smart TV** | Samsung, LG, Sony Bravia, Roku, Amazon Fire TV |
| **APs (Access Points)** | Série MediaTek MT7622 |

---

## Requisitos

| Requisito | Valor | Observações |
|-----------|-------|-------------|
| Python | **3.8 – 3.13** | Testado no CPython |
| pip | 21.0 ou mais recente | Recomendado |
| nmap | Opcional | Habilita varredura avançada no `discover` |
| Npcap | Opcional (Windows) | Necessário para operações de socket raw com Scapy |

### Dependências obrigatórias em tempo de execução

Instaladas automaticamente via `pip install embedxpl`:

```
requests        - Cliente HTTP/HTTPS
paramiko        - Cliente SSH
pysnmp          - SNMP v1/v2c/v3
pycryptodome    - Primitivas criptográficas AES/DES/RSA
scapy           - Criação de pacotes raw e descoberta de rede
colorama        - Cores de terminal multiplataforma
rich >= 13.0    - Tabelas e painéis ricos no terminal
aiohttp >= 3.9  - HTTP assíncrono (módulos de câmera/NVR)
numpy >= 1.24   - Cálculos do advisor de ML
psutil >= 5.9   - Perfilamento de hardware do sistema (sysinfo)
python-nmap >= 0.7.1  - Binding Python do nmap
```

> Python 3.13+ usa `telnetlib3` em vez do `telnetlib` removido. O EmbedXPL-Forge lida com isso automaticamente.

---

## Instalação

### Opção 1 — PyPI (recomendado para a maioria dos usuários)

```bash
pip install embedxpl
```

Saída esperada (abreviada):

```text
Collecting embedxpl
  Downloading embedxpl-1.0.0-py3-none-any.whl (4.2 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 4.2/4.2 MB 12.3 MB/s eta 0:00:00
Collecting requests>=2.28.0
  ...
Successfully installed embedxpl-1.0.0 requests-2.34.2 paramiko-5.0.0 ...
```

### Extras opcionais

Instale capacidades adicionais com extras do pip:

| Extra | Comando | O que adiciona |
|-------|---------|----------------|
| Gerenciador NSE | `pip install "embedxpl[nse]"` | 11 pacotes de scripts NSE do Nmap, ponto de entrada `embedxpl-nse` |
| Stack de impressoras | `pip install "embedxpl[printers]"` | Stack estendido de exploração de impressoras |
| Todos os extras | `pip install "embedxpl[all]"` | Tudo acima |

```bash
pip install "embedxpl[nse]"

# Saída esperada:
Collecting embedxpl[nse]
  ...
Collecting python-nmap>=0.7.1
  Downloading python_nmap-0.7.1-py3-none-any.whl (23 kB)
Successfully installed embedxpl-1.0.0 python-nmap-0.7.1
```

### Pontos de entrada após a instalação

| Comando | Finalidade |
|---------|-----------|
| `embedxpl` | Iniciar o shell interativo |
| `exf` | Alias para `embedxpl` |
| `fxf` | Alias para `embedxpl` (compatibilidade FirewallXPL) |
| `embedxpl-nse` | Gerenciador de scripts NSE (requer extra `[nse]`) |
| `firmware-dl` | Utilitário de download de firmware |
| `firmware-analyze` | Utilitário de análise de firmware |

---

### Opção 2 — Clone do Git + instalação editável (desenvolvimento / contribuição)

```bash
git clone https://github.com/mrhenrike/EmbedXPL-Forge.git
cd EmbedXPL-Forge

# Criar e ativar um ambiente virtual (fortemente recomendado)
python3 -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\Activate.ps1       # Windows PowerShell
# .venv\Scripts\activate.bat       # Windows cmd.exe

pip install -r requirements.txt
pip install -e ".[nse]"           # instalação editável com suporte a NSE
```

Pontos de entrada alternativos a partir da raiz do clone:

```bash
python exf.py              # script bootstrap legado
python -m embedxpl         # invocação de módulo
```

---

### Opção 3 — Modo não interativo de única execução (sem shell)

```bash
pip install embedxpl
embedxpl -m exploits/routers/dlink/dir_300_600_rce -s "target 192.168.0.1"
```

Consulte [04-modo-nao-interativo.md](04-modo-nao-interativo.md) para a referência completa da CLI.

---

## Primeira execução — shell interativo

```text
$ embedxpl

  ____  __  __ _____
 |  _ \ \ \/ /|  ___|   EmbedXPL-Forge v1.0.0
 | |_) | \  / | |_      Network Device Security Assessment Framework
 |  _ <  /  \ |  _|
 |_| \_\/_/\_\|_|        Author: Andre Henrique (@mrhenrike) | Uniao Geek

 Target scope: Routers - Switches L2/L3 - IP Cameras - GPON ONTs - ISP CPEs - IoT/Embedded Edge

 [modules] 2807 total -- Exploits: 1842 | Scanners: 134 | Creds: 687 | Generic: 22 | Payloads: 32 | Encoders: 13
 [system]  Intel Core i7-12700H | 16 cores | 32 GB RAM | NVIDIA RTX 3060 6 GB | compute: auto

exf >
```

> A linha `[modules]` exibe o total real da instalação local. A linha `[system]` é gerada por `HWProfiler.detect()` na inicialização.

---

## Diagnóstico do ambiente (`env_doctor`)

Execute após a instalação para verificar todas as dependências e detectar componentes opcionais ausentes:

```bash
python tools/env_doctor.py
```

Saída de exemplo (sistema saudável):

```text
[OK]  Python 3.11.9
[OK]  requests 2.34.2
[OK]  paramiko 5.0.0
[OK]  pycryptodome 3.23.0
[OK]  scapy 2.7.0
[OK]  rich 15.0.0
[OK]  colorama 0.4.6
[OK]  aiohttp 3.10.1
[OK]  numpy 1.26.4
[OK]  psutil 5.9.8
[OK]  python-nmap 0.7.1
[OK]  nmap found in PATH (/usr/bin/nmap, version 7.95)
[OK]  Module index: 2807 modules loaded
```

Saída de exemplo (nmap ausente):

```text
[OK]  Python 3.11.9
[OK]  requests 2.34.2
...
[WARN] nmap not found in PATH — discover fingerprinting will use Scapy only (reduced accuracy)
[OK]  Module index: 2807 modules loaded
```

Saída de exemplo (problema de dependência):

```text
[OK]  Python 3.9.18
[-]   rich not installed — install with: pip install "rich>=13.0"
[OK]  Module index: 2807 modules loaded
```

---

## Arquivos de log e histórico

| Caminho | Conteúdo | Rotação |
|---------|---------|---------|
| `./embedxpl.log` | Arquivo de log rotativo | Máx. 500 KB, rotaciona para `.1` automaticamente |
| `~/.exf_history` | Histórico de comandos do shell interativo | 100 entradas (as mais antigas são removidas no estouro) |
| `~/.exf_sessions/` | Arquivos de sessão de varredura persistentes (JSON) | Um arquivo por host, indexado por `sha256(ip + mac)` |

### Comportamento da rotação de logs

O arquivo de log `embedxpl.log` é criado no diretório de trabalho atual (onde você invoca o `exf`). Quando excede 500 KB, é renomeado para `embedxpl.log.1` e um novo arquivo é iniciado. Apenas um backup é mantido (`embedxpl.log.1`).

---

## Modo de computação (aceleração por GPU)

O EmbedXPL-Forge suporta aceleração por GPU para fingerprinting de dispositivos assistido por ML e o advisor do AutoPwn:

```text
exf > compute auto      # Detectar automaticamente o melhor backend (padrão na inicialização)
[+] compute_mode => auto
    auto resolves to: hybrid

exf > compute cpu       # Forçar modo apenas CPU
[+] compute_mode => cpu

exf > compute gpu       # Exigir GPU (volta para cpu se nenhuma GPU for encontrada)
[+] compute_mode => gpu

exf > compute hybrid    # CPU + GPU misto
[+] compute_mode => hybrid
```

Tentativa de definir `gpu` quando nenhuma GPU é detectada:

```text
exf > compute gpu
[!] No GPU detected -- falling back to compute_mode=cpu
```

Modos válidos: `cpu`, `gpu`, `hybrid`, `auto`. O modo selecionado é persistido na configuração local e restaurado na próxima inicialização.

---

## `sysinfo` — perfil de hardware

```text
exf > sysinfo
```

Saída de exemplo (sistema com GPU):

```text
┌──────────────────────────────────────┐
│                  CPU                 │
├──────────────┬───────────────────────┤
│ Property     │ Value                 │
├──────────────┼───────────────────────┤
│ Model        │ Intel Core i7-12700H  │
│ Architecture │ x86_64                │
│ Cores        │ 14                    │
│ Threads      │ 20                    │
│ Frequency    │ 2300 MHz              │
└──────────────┴───────────────────────┘

┌──────────────────────────────────────┐
│             Memory (RAM)             │
├──────────────┬───────────────────────┤
│ Property     │ Value                 │
├──────────────┼───────────────────────┤
│ Total        │ 32,768 MB             │
│ Available    │ 24,512 MB             │
└──────────────┴───────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                              GPU Devices                                     │
├───┬────────────────────┬────────┬──────────┬─────────┬─────────┬────────────┤
│ # │ Name               │ Vendor │ VRAM     │ Backend │ Driver  │ Compute Cap│
├───┼────────────────────┼────────┼──────────┼─────────┼─────────┼────────────┤
│ 0 │ NVIDIA RTX 3060    │ NVIDIA │ 6,144 MB │ cuda    │ 545.23  │ 8.6        │
└───┴────────────────────┴────────┴──────────┴─────────┴─────────┴────────────┘

 Compute mode: auto -> hybrid  |  Best backend: cuda
```

Saída de exemplo (sem GPU):

```text
...tabela de RAM...
[!] No GPU detected on this system

 Compute mode: auto -> cpu  |  Best backend: cpu
```

---

## Visão geral da arquitetura

```
CLI (exf / embedxpl / fxf)
    │
    ├── Shell Interativo  (embedxpl/interpreter.py)
    │       ├── Global: help, use, search, show, exec, sysinfo, compute
    │       ├── Global: discover, sessions, apt
    │       └── Módulo: run/exploit, check, set, setg, unsetg, back
    │
    ├── Modo Não Interativo  (-m / -s / -T / --infra flags)
    │
    ├── Engine Principal  (embedxpl/core/)
    │       ├── Cliente HTTP/HTTPS com retry + TLS
    │       ├── Clientes de protocolo SSH / Telnet / FTP / SNMP
    │       ├── RTSP / Integração com Cameradar
    │       ├── Shell Stager (PTY, Meterpreter, bind/reverse)
    │       ├── Banco de dados CVE (embutido + consulta NVD)
    │       └── InfraOrchestrator (planejamento de varredura --infra)
    │
    ├── Camada de Inteligência
    │       ├── HWProfiler (detecção de CPU/RAM/GPU)
    │       ├── ML Fingerprinter (análise OUI + banner, AttackAdvisor)
    │       ├── APT Attack Engine (reprodução de cadeia de ataques nation-state)
    │       └── SessionManager (estado de varredura persistente por host)
    │
    └── Arsenal de Módulos  (embedxpl/modules/)
            ├── exploits/     (1842 módulos — roteadores, câmeras, firewalls, impressoras, ICS, BMC...)
            ├── creds/        (687 módulos — SSH, Telnet, FTP, HTTP, SNMP por vendor)
            ├── scanners/     (134 módulos — descoberta de rede, scanners de protocolo, autopwn)
            ├── payloads/     (32 módulos — x86, x64, ARM, MIPS, cmd, perl, php, python)
            ├── encoders/     (13 módulos — base64, hex, Python/PHP/Perl)
            └── generic/      (22 módulos — lookup de CVE, UPnP, SNMP, wordlist, DNS, PCAP)
```

---

## Ferramentas relacionadas (Suite XPL-Forge)

| Ferramenta | pip install | CLI | Escopo |
|------------|-------------|-----|--------|
| EmbedXPL-Forge | `pip install embedxpl` | `embedxpl` / `exf` | IoT / dispositivos de rede (amplo) |
| FirewallXPL-Forge | `pip install firewallxpl` | `fxf` | Especialista em Firewall / VPN |
| PrinterXPL-Forge | `pip install printerxpl-forge` | `printerxpl-forge` | Especialista em Impressoras / MFP |
| WirelessXPL-Forge | `pip install wirelessxpl` | `wxf` | Wireless — Wi-Fi, BLE, Zigbee, Z-Wave |
| MikrotikAPI-BF | `pip install mikrotikapi-bf` | `mikrotik-bf` | Brute-force da API RouterOS MikroTik |

---

[Hub da Wiki](../README.md)
