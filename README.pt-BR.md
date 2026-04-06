# RouterXPL-Forge

**Framework de Avaliação de Segurança em Dispositivos de Rede**

RouterXPL-Forge é um framework de exploração open-source projetado para profissionais de segurança auditarem roteadores, switches, TAPs e dispositivos SOHO edge. Oferece 271 módulos cobrindo testes de credenciais, exploração de vulnerabilidades, varredura de rede, geração de payloads e encoding.

> **Autor:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)

---

## Funcionalidades

- **125 módulos de exploit** — RCE, auth bypass, path traversal, info disclosure, DNS hijacking
- **88 módulos de credenciais** — ataques de dicionário contra FTP, SSH, Telnet, HTTP, SNMP, SFTP
- **5 módulos de scanner** — AutoPwn, scanners específicos por dispositivo
- **32 módulos de payload** — reverse/bind TCP shells para x86, x64, ARM, MIPS, Python, Perl, PHP
- **13 módulos de encoder** — Base64 e hex encoding para Python, PHP, Perl
- **8 módulos genéricos** — Heartbleed, ShellShock, UPnP SSDP, SNMP, consulta CVE
- **23 wordlists por vendor** — credenciais padrão externalizadas por fabricante

## Tipos de Dispositivos Suportados

| Tipo | Cobertura | Descrição |
|------|-----------|-----------|
| **Roteadores** | 187 módulos | Roteadores SOHO, gateways enterprise, CPE |
| **Switches L2/L3** | 3 módulos | Switches gerenciados e não-gerenciados |
| **SOHO Edge** | 7 módulos | Roteadores de viagem, NAS, APs wireless, smart plugs |
| **TAPs** | Planejado | Dispositivos TAP de rede |

## Fabricantes Suportados

2Wire · 3Com · Asmax · ASUS · Belkin · BHU · Billion · Cisco · Comtrend · D-Link · HooToo · Huawei · IPFire · Juniper · LG · Linksys · MikroTik · Movistar · Netcore · NETGEAR · Netsys · Shuttle · Technicolor · Thomson · TP-Link · Ubiquiti · ZTE · ZyXEL

## Início Rápido

```bash
# Clonar o repositório
git clone https://github.com/mrhenrike/RouterXPL-Forge.git
cd RouterXPL-Forge

# Instalar dependências
pip install -r requirements.txt

# Iniciar o shell interativo
python rxf.py

# Ou executar um módulo específico não-interativamente
python rxf.py -m exploits/routers/dlink/dir_300_600_rce -s target 192.168.1.1
```

## Uso

### Shell Interativo

```
rxf > use exploits/routers/dlink/dir_300_600_rce
rxf (D-Link DIR-300 & DIR-600 RCE) > show options
rxf (D-Link DIR-300 & DIR-600 RCE) > set target 192.168.1.1
rxf (D-Link DIR-300 & DIR-600 RCE) > check
rxf (D-Link DIR-300 & DIR-600 RCE) > run
```

### Comandos Principais

| Comando | Descrição |
|---------|-----------|
| `use <modulo>` | Selecionar um módulo |
| `show options` | Exibir opções configuráveis |
| `show info` | Exibir metadados e referências do módulo |
| `show devices` | Listar tipos de dispositivos suportados |
| `set <opcao> <valor>` | Configurar uma opção |
| `check` | Verificar se o alvo é vulnerável |
| `run` | Executar o módulo |
| `search <termo>` | Buscar módulos por palavra-chave |

### Scanner AutoPwn

```
rxf > use scanners/autopwn
rxf (AutoPwn) > set target 192.168.1.0/24
rxf (AutoPwn) > run
```

## Estrutura de Módulos

```
routerxpl/modules/
├── creds/             # Testes de credenciais (FTP, SSH, Telnet, HTTP, SNMP)
│   ├── generic/       # Bruteforce e defaults agnósticos de protocolo
│   └── routers/       # Credenciais padrão por fabricante
├── exploits/          # Exploração de vulnerabilidades
│   ├── generic/       # Cross-vendor (Heartbleed, ShellShock)
│   ├── routers/       # Exploits de roteadores por fabricante
│   ├── switches/      # Exploits de switches (Cisco, D-Link, NETGEAR)
│   └── soho_edge/     # Exploits de dispositivos SOHO edge
├── scanners/          # Varredura de rede e AutoPwn
├── payloads/          # Reverse/bind shells (multi-arch)
├── encoders/          # Encoding de payloads (Base64, Hex)
└── generic/           # CVE lookup, SNMP, UPnP, ferramentas de wordlist
```

## Requisitos

- Python 3.8+
- Dependências: `requests`, `paramiko`, `pysnmp`, `pycryptodome`, `scapy`, `colorama`

## Aviso Legal

RouterXPL-Forge é destinado exclusivamente para testes de segurança autorizados e pesquisa. Use esta ferramenta apenas em sistemas que você possui ou tem permissão explícita e escrita para testar. Acesso não autorizado a sistemas computacionais é ilegal. Os autores não assumem responsabilidade por uso indevido.

## Licença

Licença BSD — veja [LICENSE](LICENSE) para detalhes.

---

> **Autor:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)