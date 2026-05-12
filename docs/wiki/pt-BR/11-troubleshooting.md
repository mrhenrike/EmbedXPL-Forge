# Solução de problemas

**Idioma: Português (pt-BR)**. **en-US:** [../en-US/11-troubleshooting.md](../en-US/11-troubleshooting.md)

## ImportError na inicialização

Execute novamente `python -m pip install -r requirements.txt` dentro do `venv` ativo. Se um pacote opcional falhar, instale a dependencia extra correspondente (por exemplo **Scapy** para descoberta de rede com captura raw, ou **telnetlib3** para modulos Telnet em Python 3.13+).

## Telnet no Python 3.13+

A biblioteca padrão removeu `telnetlib`; instale e use **`telnetlib3`** conforme `requirements.txt` para módulos Telnet.

## Erros do Scapy

Confirme que **Scapy** está instalado e que pré-requisitos de captura ao vivo (por exemplo **Npcap** no Windows) existem quando o módulo faz captura raw.

## Sem cores no Windows

Instale **`colorama`** (via `requirements.txt`) para ANSI em consoles padrão.

## Módulo não encontrado após mover arquivos

Rode a partir da raiz do repositorio e garanta que `PYTHONPATH` nao esteja sobrescrevendo a descoberta de pacotes. Prefira o entry point oficial `embedxpl` (instalado via `pip install embedxpl`) ou `python -m embedxpl`. O bootstrap legacy `./exf.py` continua disponivel se voce esta rodando direto do clone.

## Permission denied no Linux

Sockets raw e alguns caminhos de captura exigem capability elevada ou `sudo` quando o SO exige; use o menor privilegio compativel com as regras do engagement.


[Hub wiki](../README.md)
