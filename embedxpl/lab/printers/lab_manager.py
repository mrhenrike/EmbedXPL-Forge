#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — Lab Manager
=========================
Orquestrador do laboratório de impressoras simuladas.

Uso:
  python lab_manager.py                     # menu interativo
  python lab_manager.py --start all         # iniciar todas as impressoras
  python lab_manager.py --start hp epson    # iniciar apenas HP e Epson
  python lab_manager.py --stop              # parar tudo
  python lab_manager.py --status            # ver o que está rodando
  python lab_manager.py --list              # listar perfis disponíveis
  python lab_manager.py --attack hp --tool printerreaper  # testar PrinterReaper contra HP

Cada impressora é lançada em portas distintas para coexistir no mesmo host:
  Printer   RAW   IPP   LPD   HTTP  SNMP  FTP
  HP        9101  9631  9515  9080  9161  9021
  Epson     9102  9632  9516  9082  9162  9022
  Ricoh     9103  9633  9517  9083  9163  9023
  Xerox     9104  9634  9518  9084  9164  9024
  Kyocera   9105  9635  9519  9085  9165  9025
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import argparse
import copy
import logging
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

# Ensure local modules are importable regardless of cwd
_HERE = Path(__file__).parent.resolve()
sys.path.insert(0, str(_HERE))

from simulators.base_printer import PrinterProfile
from simulators.pjl_sim      import PJLSimulator
from simulators.ipp_sim      import IPPSimulator
from simulators.lpd_sim      import LPDSimulator
from simulators.snmp_sim     import SNMPSimulator
from simulators.http_sim     import HTTPSimulator
from simulators.ftp_sim      import FTPSimulator
from printers                import ALL_PROFILES

# ── ANSI colours ──────────────────────────────────────────────────────────────
_RST = '\033[0m'
_BLD = '\033[1m'
_CYN = '\033[1;36m'
_GRN = '\033[1;32m'
_YLW = '\033[1;33m'
_RED = '\033[1;31m'
_DIM = '\033[2;37m'

# ── Port map: each printer gets an offset from base ports ────────────────────
# base ports × slot_id  →  unique port per lab instance
_PORT_BASES = {
    'hp':      1,
    'epson':   2,
    'ricoh':   3,
    'xerox':   4,
    'kyocera': 5,
    'brother': 6,
    'lexmark': 7,
    'dell':    8,
    'samsung': 9,
    'konica':  11,   # 10 skipped: 9170 conflicts with common port
    'oki':     12,
}

def _offset_profile(name: str, profile: PrinterProfile) -> PrinterProfile:
    """Clone the profile with unique ports for this lab slot."""
    slot = _PORT_BASES.get(name, 9)
    p = copy.deepcopy(profile)
    p.port_raw  = 9100 + slot
    p.port_ipp  = 9630 + slot
    p.port_lpd  = 9514 + slot
    p.port_http = 9079 + slot
    p.port_snmp = 9160 + slot
    p.port_ftp  = 9020 + slot
    return p


@dataclass
class PrinterInstance:
    """Holds all active simulators for one printer."""
    name:    str
    profile: PrinterProfile
    sims:    List  # list of BaseSimulator subclasses


# ── Lab manager ───────────────────────────────────────────────────────────────

class LabManager:
    """Starts, stops, and monitors all simulated printer instances."""

    HOST = '127.0.0.1'

    def __init__(self) -> None:
        self.instances: Dict[str, PrinterInstance] = {}
        self.log = logging.getLogger('LabManager')

    def start(self, names: List[str]) -> None:
        """Start simulators for the given printer names."""
        for name in names:
            if name not in ALL_PROFILES:
                self.log.error("Unknown profile: '%s'. Available: %s",
                               name, ', '.join(ALL_PROFILES))
                continue
            if name in self.instances:
                self.log.warning("'%s' is already running.", name)
                continue
            profile = _offset_profile(name, ALL_PROFILES[name])
            sims = self._build_sims(profile)
            for sim in sims:
                sim.start()
            self.instances[name] = PrinterInstance(name, profile, sims)
            self._print_started(name, profile)

    def stop(self, names: Optional[List[str]] = None) -> None:
        """Stop simulators. If names is None, stop all."""
        targets = names or list(self.instances.keys())
        for name in targets:
            if name not in self.instances:
                continue
            for sim in self.instances[name].sims:
                sim.stop()
            del self.instances[name]
            print(f"  {_YLW}▸{_RST} Stopped {_BLD}{name}{_RST}")

    def status(self) -> None:
        """Print status table of running instances."""
        if not self.instances:
            print(f"\n  {_DIM}No simulators running.{_RST}\n")
            return
        _hr()
        print(f"  {_CYN}{_BLD}RUNNING SIMULATORS{_RST}")
        _hr()
        header = f"  {'Name':<10} {'Make/Model':<30} {'RAW':>5} {'IPP':>5} {'LPD':>5} {'HTTP':>5} {'SNMP':>5} {'FTP':>5}"
        print(f"{_DIM}{header}{_RST}")
        print(f"  {_DIM}{'-'*82}{_RST}")
        for name, inst in self.instances.items():
            p = inst.profile
            alive = all(s.is_running for s in inst.sims if hasattr(s, 'is_running'))
            dot   = f"{_GRN}●{_RST}" if alive else f"{_RED}●{_RST}"
            print(f"  {dot} {name:<9} {p.make+' '+p.model:<30} "
                  f"{p.port_raw:>5} {p.port_ipp:>5} {p.port_lpd:>5} "
                  f"{p.port_http:>5} {p.port_snmp:>5} {p.port_ftp:>5}")
        _hr()
        print(f"\n  {_DIM}Connect PrinterReaper with: python src/main.py 127.0.0.1 --port <RAW>{_RST}\n")

    def list_profiles(self) -> None:
        """Print all available printer profiles."""
        _hr()
        print(f"  {_CYN}{_BLD}AVAILABLE PRINTER PROFILES{_RST}")
        _hr()
        for name, profile in ALL_PROFILES.items():
            slot  = _PORT_BASES.get(name, 9)
            ports = f"RAW:{9100+slot} IPP:{9630+slot} LPD:{9514+slot} HTTP:{9079+slot} SNMP:{9160+slot} FTP:{9020+slot}"
            vulns = [k for k, v in profile.vuln.items() if v]
            print(f"\n  {_GRN}{_BLD}[{name}]{_RST}  {profile.make} {profile.model}")
            print(f"  {_DIM}  Firmware : {profile.firmware}{_RST}")
            print(f"  {_DIM}  Serial   : {profile.serial}{_RST}")
            print(f"  {_DIM}  Ports    : {ports}{_RST}")
            print(f"  {_DIM}  Languages: {', '.join(profile.languages)}{_RST}")
            print(f"  {_DIM}  Vulns    : {', '.join(vulns[:6])}{'...' if len(vulns) > 6 else ''}{_RST}")
        _hr()

    def attack_guide(self, name: str) -> None:
        """Print PrinterReaper command guide for a given printer."""
        if name not in ALL_PROFILES:
            print(f"  {_RED}Unknown profile: {name}{_RST}")
            return
        profile = _offset_profile(name, ALL_PROFILES[name])
        host    = self.HOST
        _hr()
        print(f"  {_CYN}{_BLD}ATTACK GUIDE — {profile.make} {profile.model}{_RST}")
        _hr()
        pr = f"python {_HERE.parent / 'PrinterReaper' / 'src' / 'main.py'} {host}"
        print(f"\n  {_YLW}# 1. Full scan (fingerprint + CVE + exploits){_RST}")
        print(f"  {_DIM}{pr} --scan --port {profile.port_raw}{_RST}")
        print(f"\n  {_YLW}# 2. PJL directory traversal{_RST}")
        print(f"  {_DIM}{pr} --pjl --port {profile.port_raw}{_RST}")
        print(f"\n  {_YLW}# 3. IPP attack suite{_RST}")
        print(f"  {_DIM}{pr} --ipp --port {profile.port_ipp}{_RST}")
        print(f"\n  {_YLW}# 4. SNMP MIB dump + factory reset probe{_RST}")
        print(f"  {_DIM}{pr} --snmp --port {profile.port_snmp}{_RST}")
        print(f"\n  {_YLW}# 5. Brute-force default credentials{_RST}")
        print(f"  {_DIM}{pr} --bruteforce --bf-vendor {name} --port {profile.port_http}{_RST}")
        print(f"\n  {_YLW}# 6. FTP access + file download{_RST}")
        print(f"  {_DIM}{pr} --ftp --port {profile.port_ftp}{_RST}")
        print(f"\n  {_YLW}# 7. Full exploit library check{_RST}")
        print(f"  {_DIM}{pr} --xpl-check --port {profile.port_raw}{_RST}")
        print(f"\n  {_YLW}# 8. Full audit workflow{_RST}")
        print(f"  {_DIM}{pr} --scan --attack all --bruteforce --xpl --port {profile.port_raw}{_RST}")
        _hr()

    def _build_sims(self, profile: PrinterProfile) -> List:
        """Instantiate all simulators for a profile."""
        h = self.HOST
        return [
            PJLSimulator (h, profile.port_raw,  profile),
            IPPSimulator (h, profile.port_ipp,  profile),
            LPDSimulator (h, profile.port_lpd,  profile),
            HTTPSimulator(h, profile.port_http, profile),
            SNMPSimulator(h, profile.port_snmp, profile),
            FTPSimulator (h, profile.port_ftp,  profile),
        ]

    def _print_started(self, name: str, profile: PrinterProfile) -> None:
        print(f"\n  {_GRN}●{_RST} {_BLD}{name}{_RST}  "
              f"{_DIM}{profile.make} {profile.model} — {profile.firmware}{_RST}")
        print(f"    {_DIM}RAW:{profile.port_raw}  IPP:{profile.port_ipp}  "
              f"LPD:{profile.port_lpd}  HTTP:{profile.port_http}  "
              f"SNMP:{profile.port_snmp}  FTP:{profile.port_ftp}{_RST}")


# ── Interactive menu ──────────────────────────────────────────────────────────

def _hr() -> None:
    cols = min(os.get_terminal_size().columns if sys.stdout.isatty() else 80, 82)
    print(f"  {_DIM}{'─' * cols}{_RST}")


def run_interactive(mgr: LabManager) -> None:
    """Simple interactive menu for lab control."""
    while True:
        print(f"\n  {_CYN}{_BLD}PrinterLab — Printer Simulation Laboratory{_RST}")
        _hr()
        print(f"  {_GRN}1{_RST}  Start all printers")
        print(f"  {_GRN}2{_RST}  Start specific printer(s)")
        print(f"  {_GRN}3{_RST}  Stop all printers")
        print(f"  {_GRN}4{_RST}  Status")
        print(f"  {_GRN}5{_RST}  List available profiles")
        print(f"  {_GRN}6{_RST}  Attack guide (PrinterReaper commands)")
        print(f"  {_GRN}7{_RST}  Run scenario script")
        print(f"  {_GRN}0{_RST}  Quit")
        _hr()
        choice = input("  Choice: ").strip()

        if choice == '1':
            print(f"\n  {_YLW}Starting all simulators…{_RST}")
            mgr.start(list(ALL_PROFILES.keys()))
        elif choice == '2':
            names_input = input(f"  Printers ({'/'.join(ALL_PROFILES)}): ").strip().lower().split()
            mgr.start(names_input)
        elif choice == '3':
            mgr.stop()
        elif choice == '4':
            mgr.status()
        elif choice == '5':
            mgr.list_profiles()
        elif choice == '6':
            name = input(f"  Profile name ({'/'.join(ALL_PROFILES)}): ").strip().lower()
            mgr.attack_guide(name)
        elif choice == '7':
            _run_scenario()
        elif choice == '0':
            print(f"\n  {_DIM}Stopping all simulators…{_RST}")
            mgr.stop()
            break
        else:
            print(f"  {_RED}Invalid choice.{_RST}")


def _run_scenario() -> None:
    """List and run available scenario scripts."""
    scenarios_dir = _HERE / 'scenarios'
    scripts = sorted(scenarios_dir.glob('scenario_*.py'))
    if not scripts:
        print(f"  {_DIM}No scenario scripts found in scenarios/.{_RST}")
        return
    print(f"\n  {_CYN}Available scenarios:{_RST}")
    for i, s in enumerate(scripts, 1):
        print(f"  {_GRN}{i}{_RST}  {s.stem}")
    choice = input("  Select scenario (number): ").strip()
    try:
        idx = int(choice) - 1
        script = scripts[idx]
        print(f"\n  {_YLW}Running {script.name}…{_RST}")
        subprocess.run([sys.executable, str(script)], check=False)
    except (ValueError, IndexError):
        print(f"  {_RED}Invalid selection.{_RST}")


# ── CLI entry point ───────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog='lab_manager.py',
        description='PrinterLab — Printer simulation lab manager',
    )
    parser.add_argument('--start',   nargs='+', metavar='NAME',
                        help='Start printers (e.g. hp epson) or "all"')
    parser.add_argument('--stop',    nargs='*', metavar='NAME',
                        help='Stop printers (omit names to stop all)')
    parser.add_argument('--status',  action='store_true',  help='Show running simulators')
    parser.add_argument('--list',    action='store_true',  help='List available profiles')
    parser.add_argument('--attack',  metavar='NAME',        help='Show attack guide for a printer')
    parser.add_argument('--scenario',metavar='SCRIPT',      help='Run a scenario script by name')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive menu')
    args = parser.parse_args()

    mgr = LabManager()

    # Graceful shutdown on Ctrl+C / SIGTERM
    def _shutdown(sig, frame):
        print(f"\n  {_YLW}Shutting down lab…{_RST}")
        mgr.stop()
        sys.exit(0)
    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    if args.list:
        mgr.list_profiles()
        return

    if args.start:
        names = list(ALL_PROFILES.keys()) if args.start == ['all'] else args.start
        mgr.start(names)
        if not (args.status or args.attack):
            mgr.status()
            # Keep alive until interrupted
            print(f"  {_DIM}Lab running — press Ctrl+C to stop.{_RST}\n")
            while True:
                time.sleep(2)

    if args.stop is not None:
        mgr.stop(args.stop if args.stop else None)

    if args.status:
        mgr.status()

    if args.attack:
        mgr.attack_guide(args.attack)

    if args.scenario:
        script = _HERE / 'scenarios' / f'scenario_{args.scenario}.py'
        if not script.exists():
            script = _HERE / 'scenarios' / args.scenario
        if script.exists():
            subprocess.run([sys.executable, str(script)], check=False)
        else:
            print(f"  {_RED}Scenario not found: {script}{_RST}")

    if args.interactive or len(sys.argv) == 1:
        run_interactive(mgr)


if __name__ == '__main__':
    main()
