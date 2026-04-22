# Author: André Henrique (LinkedIn/X: @mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""EmbedXPL-Forge — Nmap NSE Script Manager.

Installs, updates, and lists EmbedXPL custom NSE scripts into Nmap's
script directory so they can be called with ``--script embedxpl-*``.

Usage::

    pip install embedxpl[nse]
    python -m embedxpl.nse install
    python -m embedxpl.nse list
    python -m embedxpl.nse run --target 192.168.1.1 --scripts all

Author: André Henrique (@mrhenrike) | União Geek
Version: 1.0.0
"""
