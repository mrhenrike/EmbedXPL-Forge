#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Local Installed Printer Discovery
==================================
Enumerates printers installed on the local host across all platforms.

Supports:
  - Windows  : Get-Printer + Get-PrinterPort (PowerShell)
  - Linux    : CUPS via lpstat or /etc/cups/printers.conf
  - macOS    : CUPS via lpstat
  - Android  : CUPS via lpstat (if installed)
  - BSD      : CUPS via lpstat
"""

# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import re
import shutil
import subprocess
import socket
from typing import Dict, List, Optional

from core.osdetect import get_os
from utils.helper import output


# ── dataclass-like dict keys ─────────────────────────────────────────────────
# Each printer entry dict has these keys (all strings):
#   name, driver, port, ip, protocol, status, shared, source


def discover_local_installed() -> List[Dict[str, str]]:
    """
    Enumerate all printers installed on this host.

    Returns a list of dicts with printer info.
    Each dict has: name, driver, port, ip, protocol, status, shared, source.
    """
    os_type = get_os()

    if os_type in ('windows', 'wsl'):
        return _windows_printers()
    elif os_type in ('linux', 'darwin', 'bsd', 'android', 'wsl'):
        return _cups_printers()
    else:
        output().warning("Local printer discovery not supported on this OS.")
        return []


# ── Windows ──────────────────────────────────────────────────────────────────

def _windows_printers() -> List[Dict[str, str]]:
    """Use PowerShell Get-Printer to list installed printers, then resolve IPs."""
    pwsh = shutil.which('powershell.exe') or shutil.which('pwsh.exe')
    if not pwsh:
        output().warning("PowerShell not found; cannot enumerate local printers.")
        return []

    script = (
        "Get-Printer | Select-Object Name,DriverName,PortName,PrinterStatus,Shared"
        " | ConvertTo-Json -Compress"
    )
    try:
        raw = subprocess.check_output(
            [pwsh, '-NoProfile', '-Command', script],
            text=True, timeout=20, stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        output().warning(f"Get-Printer failed: {e}")
        return []

    import json
    try:
        data = json.loads(raw) if raw.strip() else []
    except json.JSONDecodeError:
        output().warning("Could not parse Get-Printer JSON output.")
        return []

    if isinstance(data, dict):
        data = [data]

    results = []
    for p in data:
        name     = str(p.get('Name', ''))
        driver   = str(p.get('DriverName', ''))
        port     = str(p.get('PortName', ''))
        status   = _win_status(str(p.get('PrinterStatus', '0')))
        shared   = 'yes' if p.get('Shared') else 'no'

        ip, proto = _resolve_win_printer(port, name)

        results.append({
            'name':     name,
            'driver':   driver,
            'port':     port,
            'ip':       ip,
            'protocol': proto,
            'status':   status,
            'shared':   shared,
            'source':   'windows-local',
        })
    return results


def _resolve_win_printer(port_name: str, printer_name: str) -> tuple:
    """
    Resolve IP and protocol from a Windows printer port name and printer name.

    Returns (ip_str, protocol_str).
    """
    # Pattern: IP_x.x.x.x or IP_x.x.x.x_N  (standard TCP/IP port monitor)
    m = re.match(r'IP_(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', port_name)
    if m:
        return m.group(1), 'TCP/9100'

    # Pattern: direct IP in port name (e.g. '192.168.1.5:9100')
    m = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?', port_name)
    if m:
        return m.group(1), f"TCP/{m.group(2) or '9100'}"

    # Pattern: Epson port like EP3F9F9C:L3250 SERIES
    m = re.match(r'EP([0-9A-Fa-f]{4,8})', port_name, re.I)
    if m:
        hostname = 'EPSON' + m.group(1).upper()
        ip = _try_resolve(hostname) or ''
        return ip, 'WSD/IPP'

    # WSD port: try to resolve from the printer name
    # Windows WSD printer names often start with the device hostname
    # e.g. "EPSON3F9F9C (L3250 Series)", "PROMETHEUSPRINTER (HP DeskJet 2700 series)"
    if port_name.startswith('WSD-') or port_name.startswith('wsd-'):
        hostname = printer_name.split(' ')[0].strip()
        ip = _try_resolve(hostname) or ''
        proto = 'WSD/IPP'
        # Fallback: try extracting hostname from parentheses if first word fails
        if not ip:
            m2 = re.search(r'\(([^)]+)\)', printer_name)
            if m2:
                ip = _try_resolve(m2.group(1).strip()) or ''
        return ip, proto

    # Virtual/local ports
    virtual = ('nul:', 'PORTPROMPT:', 'SHRFAX:', 'USB001', 'FILE:',
                'LPT', 'COM', 'XPS')
    if any(port_name.startswith(v) for v in virtual):
        return '', 'Virtual'

    return '', 'WSD'


def _win_status(code: str) -> str:
    """Map Windows PrinterStatus integer to human-readable string."""
    try:
        n = int(code)
    except ValueError:
        return code
    mapping = {
        0:   'Ready',
        1:   'Paused',
        2:   'Error',
        3:   'Pending Deletion',
        4:   'Paper Jam',
        5:   'Paper Out',
        6:   'Manual Feed',
        7:   'Paper Problem',
        8:   'Offline',
        16:  'Printing',
        32:  'Output Bin Full',
        64:  'Paper jam (alt)',
        128: 'No Toner/Ink',
        132: 'Offline (no toner)',
    }
    return mapping.get(n, f'Status:{n}')


def _try_resolve(hostname: str) -> Optional[str]:
    """Try to resolve a hostname to an IPv4 address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


# ── CUPS (Linux / macOS / BSD / Android) ─────────────────────────────────────

def _cups_printers() -> List[Dict[str, str]]:
    """Use lpstat -v to enumerate CUPS-managed printers."""
    lpstat = shutil.which('lpstat')
    if not lpstat:
        output().warning("lpstat not found. Install CUPS client tools.")
        return []

    results = []
    try:
        # lpstat -v: lists printer names and device URIs
        raw_v = subprocess.check_output(
            [lpstat, '-v'], text=True, timeout=10, stderr=subprocess.DEVNULL,
        )
        # lpstat -l -p: detailed printer info (status etc)
        try:
            raw_l = subprocess.check_output(
                [lpstat, '-l', '-p'], text=True, timeout=10,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            raw_l = ''

        # Parse "device for <name>: <uri>"
        for line in raw_v.splitlines():
            m = re.match(r'device for (.+?):\s+(.+)', line)
            if not m:
                continue
            name, uri = m.group(1).strip(), m.group(2).strip()
            ip, protocol = _parse_cups_uri(uri)
            status = _cups_status(name, raw_l)
            results.append({
                'name':     name,
                'driver':   '',
                'port':     uri,
                'ip':       ip,
                'protocol': protocol,
                'status':   status,
                'shared':   '',
                'source':   'cups-local',
            })
    except Exception as e:
        output().warning(f"lpstat failed: {e}")

    return results


def _parse_cups_uri(uri: str):
    """Parse a CUPS device URI and return (ip, protocol)."""
    # socket://192.168.1.100:9100
    m = re.match(r'socket://([^:/]+)(?::(\d+))?', uri)
    if m:
        ip = _try_resolve(m.group(1)) or m.group(1)
        port = m.group(2) or '9100'
        return ip, f'RAW/{port}'

    # ipp://host:port/path  or  ipps://...
    m = re.match(r'ipps?://([^:/]+)(?::(\d+))?(/.*)?', uri)
    if m:
        ip = _try_resolve(m.group(1)) or m.group(1)
        port = m.group(2) or '631'
        scheme = 'IPP' if uri.startswith('ipp://') else 'IPP/TLS'
        return ip, f'{scheme}/{port}'

    # lpd://host/queue
    m = re.match(r'lpd://([^/]+)', uri)
    if m:
        ip = _try_resolve(m.group(1)) or m.group(1)
        return ip, 'LPD/515'

    # usb://Make/Model
    if uri.startswith('usb://'):
        return '', 'USB'

    # dnssd:// or mdns://
    if 'dnssd' in uri or 'mdns' in uri:
        m = re.search(r'/([^/]+)/queue', uri)
        hostname = m.group(1) if m else ''
        ip = _try_resolve(hostname) or ''
        return ip, 'Bonjour/IPP'

    return '', uri.split('://')[0].upper()


def _cups_status(name: str, lpstat_output: str) -> str:
    """Extract printer status from lpstat -l -p output."""
    # Look for "printer <name> ..." section
    m = re.search(
        rf'printer {re.escape(name)}\s+(?:is\s+)?(\S+)',
        lpstat_output, re.I,
    )
    if m:
        return m.group(1).replace('-', ' ').title()
    return '?'


# ── Display ──────────────────────────────────────────────────────────────────

def print_local_printers(printers: List[Dict[str, str]]) -> None:
    """Pretty-print the list of local installed printers."""
    if not printers:
        print("  [!] No local printers found.")
        return

    header = f"  {'HOST':<18} {'NAME':<35} {'PROTO':<12} {'STATUS':<14} {'DRIVER'}"
    print(f"\033[1;32m{header}\033[0m")
    print("  " + "─" * 98)

    for p in printers:
        host   = (p['ip'] or '-').ljust(18)[:18]
        name   = (p['name'] or '-').ljust(35)[:35]
        proto  = (p['protocol'] or '-').ljust(12)[:12]
        status = (p['status'] or '-').ljust(14)[:14]
        driver = (p['driver'] or '-')[:30]
        print(f"  {host} {name} {proto} {status} {driver}")

    print()
