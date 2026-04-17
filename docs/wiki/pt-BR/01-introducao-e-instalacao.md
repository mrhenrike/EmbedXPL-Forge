# Introdução, escopo e instalação

**Idioma: Português (pt-BR)**. **en-US:** [../en-US/01-introduction-and-installation.md](../en-US/01-introduction-and-installation.md)

## O que é o EmbedXPL-Forge

O **EmbedXPL-Forge** é um framework modular em **Python** para testes de segurança **autorizados** em roteadores, ONTs GPON, CPEs e dispositivos de borda SOHO. Reúne verificação de credenciais, módulos orientados a vulnerabilidades, scanners, payloads e utilitários de apoio.

- **647** módulos organizados por função e vendor (500 exploits, 88 creds, 9 genéricos, 5 scanners, 32 payloads, 13 encoders).
- **49** famílias de vendor cobertas, **338 CVEs** mapeados.
- **Discovery de rede** com perfis de timing T0–T5, lookup OUI e gerenciamento de sessões.
- **Módulos autopwn encadeados** — cadeias de exploração multi-fase para vendors validados (ex: série GPON ONT Huawei).

## Classes de dispositivo suportadas

| Classe | Cobertura |
|--------|-----------|
| **Roteadores / GPON ONT / CPE** | Foco principal — 580+ módulos, 49 vendors |
| **Switches gerenciados L2/L3** | Limitada — 3 módulos de exploit (Cisco, D-Link, NETGEAR) |
| **SOHO Edge** (NAS, APs, travel routers) | 9 módulos de exploit |

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

---

[Hub wiki](../README.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
