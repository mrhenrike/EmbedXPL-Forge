# RouterXPL-Forge

**Idioma:** **Português (pt-BR)**. **English (en-US, padrão do repositório):** [README.md](README.md)

Framework open source para testes de segurança em **dispositivos embutidos**, com foco em **roteadores, switches camada 2–3, TAPs e edge SOHO/CPE**. **Firewall / NGFW / UTM / WAF / perímetro em nuvem** ficam no projeto irmão [**FirewallXPL-Forge**](https://github.com/mrhenrike/FirewallXPL-Forge) (fork privado de laboratório).

**Mantenedor:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| [União Geek](https://github.com/Uniao-Geek)  
**Linhagem upstream:** [threat9/routersploit](https://github.com/threat9/routersploit)

[![Python 3.8–3.13](https://img.shields.io/badge/Python-3.8--3.13-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/mrhenrike/RouterXPL-Forge/actions/workflows/compat-matrix.yml/badge.svg)](https://github.com/mrhenrike/RouterXPL-Forge/actions)

---

## O que o projeto faz

O RouterXPL-Forge organiza **módulos** que apoiam avaliações autorizadas (pentest, laboratório, red team controlado):

| Tipo | Função |
|------|--------|
| **exploits** | Abuso de vulnerabilidades conhecidas (com `check()` quando implementado) |
| **creds** | Teste de credenciais padrão e força bruta em serviços de rede |
| **scanners** | Identificação de superfície vulnerável; **autopwn** orquestra módulos com perfis de tempo estilo Nmap |
| **generic** | Utilitários transversais: SNMP, SSDP, PCAP/Wi‑Fi offline, **CVE lookup**, gerador de wordlists, Bluetooth LE |
| **payloads** | Geração de cargas por arquitetura (ARM/MIPS/x86, shells reversas/bind) |
| **encoders** | Codificação de payloads (Python, PHP, Perl) |

**Fora de escopo neste repositório:** módulos voltados a câmeras IP, impressoras e DVRs como alvo principal.

### Arquitetura e superfície de ataque (por categoria)

Diagramas estilo hub-and-spoke (mesma linha do [MikrotikAPI-BF](https://github.com/mrhenrike/MikrotikAPI-BF), `img/mikrotik_*`): núcleo do equipamento, **vetores de entrada** remotos e correspondência com cobertura **RouterXPL-Forge**. Fontes Mermaid: [docs/diagrams/architecture/](docs/diagrams/architecture/).

| Router SOHO | Switch L2–L3 gerido |
|:---:|:---:|
| ![Router SOHO — superfície e cobertura RXF](docs/img/architecture/rxf_arch_router_soho.png) | ![Switch — superfície e cobertura RXF](docs/img/architecture/rxf_arch_switch_l2l3.png) |

| NGFW / UTM | CPE ISP / gateway residencial |
|:---:|:---:|
| ![NGFW UTM — superfície e cobertura RXF](docs/img/architecture/rxf_arch_ngfw_utm.png) | ![CPE ISP — superfície e cobertura RXF](docs/img/architecture/rxf_arch_isp_cpe.png) |

| Edge misto (router + UTM-lite) |
|:---:|
| ![Edge misto — superfície e cobertura RXF](docs/img/architecture/rxf_arch_edge_mixed.png) |

---

## Documentação wiki

- **Português (pt-BR):** [docs/wiki/pt-BR/README.md](docs/wiki/pt-BR/README.md)  
- **English (en-US):** [docs/wiki/en-US/README.md](docs/wiki/en-US/README.md)  
- **Hub:** [docs/wiki/README.md](docs/wiki/README.md)

---

## Instalação rápida

### Dependências (`requirements.txt`)

- `requests`, `paramiko`, `pysnmp`, `pycryptodome`, `scapy`, `setuptools`
- `telnetlib3` em Python ≥ 3.13

### Clonar e executar

```bash
git clone https://github.com/mrhenrike/RouterXPL-Forge.git
cd RouterXPL-Forge
python3 -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
# .venv\Scripts\activate
python3 -m pip install -r requirements.txt
python3 rxf.py
```

### Diagnóstico do ambiente

```bash
python tools/env_doctor.py
```

---

## Uso resumido

### Shell interativo

Após `python rxf.py`:

```text
help
use creds/generic/ssh_default
set target 192.168.0.1
show options
show info
check
run
back
search type=exploits vendor=linksys wrt
exec uname -a
exit
```

### Modo não interativo

```bash
python rxf.py -m creds/generic/ssh_default -s "target 192.168.0.1" -s "port 22"
```

### Logs

O bootstrap regista em **`routerxpl.log`**.

---

## Governança (bilíngue)

| Português (pt-BR) | English (default) |
|-------------------|-------------------|
| [CONTRIBUTING.pt-BR.md](CONTRIBUTING.pt-BR.md) | [CONTRIBUTING.md](CONTRIBUTING.md) |
| [CODE_OF_CONDUCT.pt-BR.md](CODE_OF_CONDUCT.pt-BR.md) | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) |
| [SECURITY.pt-BR.md](SECURITY.pt-BR.md) | [SECURITY.md](SECURITY.md) |
| [CONTRIBUTORS.pt-BR.md](CONTRIBUTORS.pt-BR.md) | [CONTRIBUTORS.md](CONTRIBUTORS.md) |

---

## Outros recursos

| Caminho | Conteúdo |
|---------|----------|
| [docs/README.md](docs/README.md) · [docs/README.pt-BR.md](docs/README.pt-BR.md) | Hub da pasta `docs/` |
| [docs/COVERAGE_MATRIX.md](docs/COVERAGE_MATRIX.md) | Matriz de cobertura |
| [docs/FULL_CATALOG.md](docs/FULL_CATALOG.md) | Catálogo ampliado |

---

## Notas de versão — 3.4.9

- **Divisão de repositório:** Módulos de **perímetro** (Fortinet, WatchGuard, *appliances* Cisco de segurança empresarial, edge estilo pfSense/IPFire, scanner **FortiGate SSL VPN**, etc.) foram movidos para [**FirewallXPL-Forge**](https://github.com/mrhenrike/FirewallXPL-Forge). O RouterXPL-Forge mantém roteadores SOHO, switches, TAPs e um escopo de borda mais leve; catálogos e documentação foram regenerados.
- **Ferramentas:** `tools/bootstrap_firewallxpl_forge.py` (clone + *slim* + renomear para `firewallxpl`) e `tools/trim_routerxpl_edge_scope.py` (aparar esta árvore após o *split*).

## Notas de versão — 3.4.8

- **Catálogo CVE:** `cve_extended_catalog.json` passa a fundir a matriz estática, *hints* de `external_tool_intel_sources.json`, CVEs citados em `routerxpl/modules`, o conjunto em `_EMBEDDED_CVES`, `related_cves_hint` do Discord e **URLs de repositórios PoC** normalizados a partir do tg12 `cve_links.txt` vendored (só IDs em âmbito edge/RouterXPL).
- **Documentação:** `FULL_CATALOG` inclui **pegada em disco**, pastas mais pesadas e contagens de `.py` de primeira parte (`tools/generate_full_catalog.py`).
- **Exploit-DB offline:** `generic/external/exploitdb_embedded_lookup` pesquisa o `files_exploits.csv` do espelho local (sem CLI `searchsploit`); o antigo módulo ponte SearchSploit foi removido.
- **Arsenal:** espelhos PoC de terceiros em `routerxpl/resources/arsenal/pocs/incorporated_third_party/` (Exploit-DB GPLv2 e repos curados); índices JSON em `routerxpl/resources/catalogs/`. Catálogo SOHO estático + `scanners/misc/soho_exploit_catalog_server` para visualização HTTP em laboratório.

---

## Testes sugeridos (contribuidores)

```bash
python tools/compat_smoke.py
python tools/validate_market_priority_minimums.py
python tools/generate_coverage_matrix.py
```

---

## Licença

BSD — ver [LICENSE](LICENSE).

---

## Agradecimentos

- [Riposte](https://github.com/fwkz/riposte)
- [threat9/routersploit](https://github.com/threat9/routersploit)
- [CONTRIBUTORS.md](CONTRIBUTORS.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
