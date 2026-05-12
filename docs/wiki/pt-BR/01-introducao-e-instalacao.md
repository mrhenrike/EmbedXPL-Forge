# Introdução, escopo e instalação

**Idioma: Português (pt-BR)**. **en-US:** [../en-US/01-introduction-and-installation.md](../en-US/01-introduction-and-installation.md)

## O que é o EmbedXPL-Forge

O **EmbedXPL-Forge** é um framework modular em **Python** para testes de segurança **autorizados** em roteadores, ONTs GPON, CPEs, impressoras, IoT, OT/ICS, smart home, IoT maritimo e dispositivos de borda SOHO. Reúne verificação de credenciais, módulos orientados a vulnerabilidades, scanners, payloads, cadeias de exploit e utilitários de apoio.

- **2800+** módulos ativos organizados por função e vendor (625+ exploits, 185+ exploits de impressoras, 88 creds, 14 genéricos, 5+ scanners, 32 payloads, 13 encoders).
- **114+** famílias de vendor cobertas, **700+ CVEs** mapeados (2001-2026).
- **Discovery de rede** com perfis de timing T0–T5, lookup OUI (IEEE 39k+ entradas) e gerenciamento de sessões.
- **Módulos autopwn encadeados** — cadeias de exploração multi-fase (Huawei EG8145X6, CUPS Pwn2Own 2026, Lexmark Pwn2Own 2026, etc.).
- **7 gates de qualidade automatizados** — `tools/phase_gate.py` valida todos os módulos antes do release.

## Classes de dispositivo suportadas

| Classe | Cobertura |
|--------|-----------|
| **Roteadores / GPON ONT / CPE** | Foco principal — 580+ módulos, 85+ pastas de vendor |
| **Impressoras / MFP** | 185+ módulos — HP, Canon, Lexmark, Xerox, Ricoh, Brother, Epson, Kyocera, Samsung |
| **Firewalls / VPN / Perímetro** | 80+ módulos — Fortinet, Palo Alto, Cisco, SonicWall, CheckPoint, Sophos, WatchGuard |
| **ICS / OT / Industrial** | 35+ módulos — PLCs, SCADA, Modbus, S7comm, EtherNet/IP, Universal Robots |
| **Smart Home / Marítimo** | 10+ módulos — eNet SMART HOME, OpenRemote, Metis maritime IoT |
| **SO Embarcado** | 25+ módulos — RIOT OS, OpenWrt, VxWorks, QNX, wolfSSL, Tuya |
| **Switches gerenciados L2/L3** | Limitada — 3 módulos de exploit (Cisco, D-Link, NETGEAR) |
| **SOHO Edge** (NAS, APs, travel routers) | 9 módulos de exploit |

## Arquitetura do Framework

### Arquitetura de Componentes

Visao em camadas: CLI, Core Engine (orquestrador, clientes de protocolo, shell engines), Camada de Inteligencia (ML, OUI lookup, banco CVE), Quality Gates e o arsenal de 2800+ modulos.

<p align="center">
  <img src="../../assets/embedxpl_architecture.png" width="920" alt="EmbedXPL-Forge Arquitetura de Componentes v3.1.0"/>
</p>

### Fluxo de Auditoria e Exploracao

Fluxo de ponta a ponta: entrada do alvo, discovery, identificacao de dispositivo, selecao de modulo, exploracao e relatorio.

<p align="center">
  <img src="../../assets/embedxpl_flow.png" width="920" alt="EmbedXPL-Forge Fluxo de Exploracao v3.1.0"/>
</p>

## Requisitos

- **Python 3.8–3.13**
- Opcional: binário `nmap` para discovery de rede aprimorado
- Dependências em `requirements.txt` após clonar o repositório.

## Instalação

```bash
git clone https://github.com/mrhenrike/EmbedXPL-Forge.git
cd EmbedXPL-Forge
python3 -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows
python3 -m pip install -r requirements.txt
```

## Diagnóstico

```bash
python tools/env_doctor.py
```

## Iniciar o shell interativo

```bash
python exf.py
```

## Log e histórico

- **Arquivo de log:** `embedxpl.log` (no diretório de trabalho atual).
- **Histórico de comandos:** em geral `~/.exf_history`.
- **Dados de sessão:** `~/.exf_sessions/` — histórico persistente de scan por host.


[Hub wiki](../README.md)
