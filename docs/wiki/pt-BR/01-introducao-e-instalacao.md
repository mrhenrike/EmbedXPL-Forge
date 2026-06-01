# Introducao, Escopo e Instalacao

**Idioma:** Portugues (pt-BR) | **English (en-US):** [../en-US/01-introduction-and-installation.md](../en-US/01-introduction-and-installation.md)

---

## O que e o EmbedXPL-Forge

**EmbedXPL-Forge** (`embedxpl`, CLI: `exf`) e um framework Python modular e open-source para avaliacao de seguranca **autorizada** de dispositivos IoT, appliances de perimetro e sistemas embarcados. Reune testes de credenciais, exploracao de vulnerabilidades, varredura de rede, geracao de payloads, gerenciamento de scripts NSE, analise de firmware e utilitarios de pos-exploracao em uma unica ferramenta extensivel.

> **Autorizacao obrigatoria.** Use apenas em sistemas proprios ou com permissao escrita explicita.

| Metrica | Valor |
|---------|-------|
| Modulos ativos | 2800+ |
| CVEs mapeados | 700+ (2001-2026) |
| Familias de fabricantes | 114+ |
| Versoes Python | 3.8 - 3.13 |
| Plataformas | Linux, macOS, Windows |
| Licenca | BSD-3-Clause |

---

## Classes de dispositivos suportadas

| Classe | Cobertura |
|--------|-----------|
| **Roteadores / GPON ONT / CPE** | Foco principal -- 580+ modulos, 85+ pastas de fabricante |
| **Impressoras / MFP** | 185+ modulos -- HP, Canon, Lexmark, Xerox, Ricoh, Brother, Epson, Kyocera, Samsung, CUPS |
| **Firewalls / VPN / Perimetro** | 80+ modulos -- Fortinet, Palo Alto, Cisco, SonicWall, Check Point, Sophos, WatchGuard, Juniper |
| **Cameras IP / NVR / DVR / RTSP** | Hikvision, Dahua, Herospeed, Longsee, Uniview, Reolink, Axis, Amcrest |
| **ICS / OT / Industrial** | 35+ modulos -- PLCs, SCADA, Modbus, S7comm, EtherNet/IP, Universal Robots |
| **Casa Inteligente / Maritimo** | eNet SMART HOME, OpenRemote, Metis maritime IoT |
| **Embedded OS** | RIOT OS, OpenWrt, VxWorks, QNX, wolfSSL, Tuya |
| **Switches Gerenciados L2/L3** | Cisco, D-Link, NETGEAR |
| **SOHO Edge** | NAS, APs, roteadores portateis |
| **NAS** | QNAP, Synology, D-Link NAS |

---

## Requisitos

| Requisito | Valor |
|-----------|-------|
| Python | **3.8 - 3.13** |
| Pip | 21.0 ou mais recente recomendado |
| Opcional | binario `nmap` para descoberta de rede aprimorada |
| Opcional | Npcap (Windows) para raw sockets com Scapy |

---

## Instalacao

### Opcao 1 -- PyPI (recomendada)

```bash
pip install embedxpl
```

Extras opcionais:

```bash
pip install "embedxpl[nse]"       # gerenciador de scripts NSE Nmap (11 scripts)
pip install "embedxpl[printers]"  # pilha estendida de impressoras
pip install "embedxpl[all]"       # tudo incluido
```

Apos a instalacao, os seguintes comandos ficam disponiveis:

| Comando | Funcao |
|---------|--------|
| `embedxpl` | Abre o shell interativo |
| `exf` | Alias de `embedxpl` |
| `fxf` | Alias de `embedxpl` |
| `embedxpl-nse` | Gerenciador de scripts NSE |
| `firmware-dl` | Utilitario de download de firmware |
| `firmware-analyze` | Utilitario de analise de firmware |

### Opcao 2 -- Clone do repositorio (desenvolvimento)

```bash
git clone https://github.com/mrhenrike/EmbedXPL-Forge.git
cd EmbedXPL-Forge
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows PowerShell
pip install -r requirements.txt
pip install -e ".[nse]"          # instalacao editavel com suporte NSE
```

### Opcao 3 -- Execucao nao-interativa direta

```bash
pip install embedxpl
embedxpl -m exploits/routers/dlink/dir_300_600_rce -s "target 192.168.0.1"
```

---

## Primeiro uso

```text
$ embedxpl

    EmbedXPL-Forge v3.2.1  |  2800+ modulos  |  700+ CVEs  |  114+ fabricantes
    https://github.com/mrhenrike/EmbedXPL-Forge

exf >
```

---

## Diagnostico do ambiente

```bash
python tools/env_doctor.py
```

Saida esperada:

```text
[OK]  Python 3.11.9
[OK]  requests 2.34.2
[OK]  paramiko 5.0.0
[OK]  colorama 0.4.6
[WARN] nmap nao encontrado no PATH -- descoberta de rede limitada
[OK]  Indice de modulos: 2807 modulos carregados
```

---

## Arquivos de log e historico

| Caminho | Conteudo |
|---------|----------|
| `./embedxpl.log` | Log rotativo (max 500 KB), criado no diretorio atual |
| `~/.exf_history` | Historico de comandos do shell (100 entradas) |
| `~/.exf_sessions/` | Sessoes de scan persistentes, um JSON por host |

---

## Suite XPL-Forge relacionada

| Ferramenta | pip | CLI | Escopo |
|------------|-----|-----|--------|
| EmbedXPL-Forge | `pip install embedxpl` | `embedxpl` | IoT/perimetro amplo |
| FirewallXPL-Forge | `pip install firewallxpl` | `fxf` | Especialista em firewalls/VPN |
| PrinterXPL-Forge | `pip install printerxpl-forge` | `printerxpl-forge` | Especialista em impressoras |
| WirelessXPL-Forge | `pip install wirelessxpl` | `wxf` | Wireless (Wi-Fi/BLE/Zigbee) |
| MikrotikAPI-BF | `pip install mikrotikapi-bf` | `mikrotik-bf` | MikroTik RouterOS |


[Hub da wiki](../README.md)
