# Introdução, escopo e instalação

**Idioma: Português (pt-BR)**. **en-US:** [../en-US/01-introduction-and-installation.md](../en-US/01-introduction-and-installation.md)

## O que é o RouterXPL-Forge

O **RouterXPL-Forge** é um framework modular em **Python** para testes de segurança **autorizados** em roteadores, switches, TAPs e dispositivos de borda SOHO. Reúne verificação de credenciais, módulos orientados a vulnerabilidades, scanners, payloads e utilitários de apoio.

- **263** módulos organizados por função e vendor.
- **28+** famílias orientadas a vendor mais blocos genéricos.

## Requisitos

- **Python 3.8–3.13**
- Dependências em `requirements.txt` após clonar o repositório.

## Instalação

```bash
git clone https://github.com/mrhenrike/RouterXPL-Forge.git
cd RouterXPL-Forge
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
python rxf.py
```

## Log e histórico

- **Arquivo de log:** `routerxpl.log` (no diretório de trabalho atual).
- **Histórico de comandos:** em geral `~/.rxf_history`.

---

[Hub wiki](../README.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
