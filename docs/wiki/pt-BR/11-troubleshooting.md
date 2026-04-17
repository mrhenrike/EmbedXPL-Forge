# Solução de problemas

**Idioma: Português (pt-BR)**. **en-US:** [../en-US/11-troubleshooting.md](../en-US/11-troubleshooting.md)

## ImportError na inicialização

Execute novamente `python -m pip install -r requirements.txt` dentro do `venv` ativo. Se uma pilha opcional falhar, instale a dependência extra (por exemplo **Scapy** para módulos `generic/pcap`).

## Telnet no Python 3.13+

A biblioteca padrão removeu `telnetlib`; instale e use **`telnetlib3`** conforme `requirements.txt` para módulos Telnet.

## Erros do Scapy

Confirme que **Scapy** está instalado e que pré-requisitos de captura ao vivo (por exemplo **Npcap** no Windows) existem quando o módulo faz captura raw.

## Sem cores no Windows

Instale **`colorama`** (via `requirements.txt`) para ANSI em consoles padrão.

## Módulo não encontrado após mover arquivos

Rode a partir da raiz do repositório e garanta que `PYTHONPATH` não esteja sobrescrevendo a descoberta de pacotes. Prefira `python exf.py` sem relocar `embedxpl/`.

## Permission denied no Linux

Sockets raw e alguns caminhos de captura exigem capability elevada ou `sudo` quando o SO exige — use o menor privilégio compatível com as regras do engagement.

---

[Hub wiki](../README.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
