# Troubleshooting

**Language:** English (en-US). **pt-BR:** [../pt-BR/11-troubleshooting.md](../pt-BR/11-troubleshooting.md)

## ImportError on startup

Re-run `python -m pip install -r requirements.txt` inside the active virtual environment. If a single optional stack fails, install its extra dependency (for example **Scapy** for PCAP-oriented generic modules).

## Telnet on Python 3.13+

The standard library removed `telnetlib`; install and use **`telnetlib3`** as described in `requirements.txt` for Telnet-oriented modules.

## Scapy errors

Confirm **Scapy** is installed and that live capture prerequisites (for example **Npcap** on Windows) are present when a module performs raw capture.

## No colors on Windows

Install **`colorama`** (pulled via `requirements.txt`) so ANSI colors render in standard consoles.

## Module not found after moving files

Run from the repository root and ensure `PYTHONPATH` is not overriding package discovery. Prefer `python exf.py` without relocating `embedxpl/`.

## Permission denied on Linux

Raw sockets and some capture paths require elevated capability or `sudo` where the OS mandates it—use the least privilege consistent with your engagement rules.


[Wiki hub](../README.md)
