#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterXPL-Forge — Banner Grabber
================================
Collects identification banners from all relevant printer protocols:
  HTTP / HTTPS  — headers + title + WSD
  IPP           — Get-Printer-Attributes (model, firmware, serial, langs)
  RAW/9100      — PJL INFO ID
  LPD/515       — RFC 1179 queue listing
  SNMP          — sysDescr, hrDeviceDescr, prtInterpreterDescription
  SMB/445       — optional share enumeration

Returns a unified PrinterFingerprint dataclass with everything collected.
"""

# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import logging
import re
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_log = logging.getLogger(__name__)

# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class PrinterFingerprint:
    """Aggregated banner/fingerprint data from all probed protocols."""

    host: str
    open_ports: List[int]             = field(default_factory=list)

    # Identification
    make:    str = ''
    model:   str = ''
    firmware:str = ''
    serial:  str = ''
    uuid:    str = ''
    mac_hint:str = ''

    # Protocol data
    http_title:   str = ''
    http_server:  str = ''
    https_server: str = ''
    ipp_attrs:    Dict[str, str] = field(default_factory=dict)
    pjl_id:       str = ''
    snmp_descr:   str = ''
    snmp_langs:   List[str] = field(default_factory=list)
    wsd_info:     Dict[str, str] = field(default_factory=dict)
    lpd_queues:   List[str] = field(default_factory=list)
    smb_shares:   List[str] = field(default_factory=list)
    ftp_banner:   str = ''

    # Supported printer languages (CMD: field from device-id or SNMP)
    printer_langs: List[str] = field(default_factory=list)

    # Supported document formats (from IPP)
    doc_formats:   List[str] = field(default_factory=list)

    # Raw banners for ML and CVE matching
    raw_banners: Dict[str, str] = field(default_factory=dict)

    # Attack surface assessment
    attack_surface: Dict[str, str] = field(default_factory=dict)

    def summary(self) -> str:
        """One-line human-readable summary."""
        model_str = f"{self.make} {self.model}".strip() or '?'
        fw_str    = f" fw={self.firmware}" if self.firmware else ''
        langs_str = ','.join(self.printer_langs) if self.printer_langs else 'unknown'
        ports_str = ','.join(str(p) for p in sorted(self.open_ports))
        return (f"{self.host} — {model_str}{fw_str} "
                f"| langs={langs_str} | ports={ports_str}")

    def as_dict(self) -> dict:
        """Return a flat dict suitable for JSON serialisation."""
        import dataclasses
        return dataclasses.asdict(self)


# ── Port scanner ──────────────────────────────────────────────────────────────

def _resolved_printer_ports() -> dict:
    """
    Return the full set of ports to scan, merging PortConfig overrides and extras
    with the global printer port map.  UDP ports (SNMP/WSD) are probed separately.
    """
    try:
        from utils.ports import PortConfig
        return PortConfig.printer_port_labels()
    except Exception:
        from utils.ports import GLOBAL_PRINTER_TCP_PORTS
        return dict(GLOBAL_PRINTER_TCP_PORTS)


# ── psploit / PRET-2.0 capability fingerprints ───────────────────────────────
# and d1pakda5/PRET-2.0 (db/pjl.dat, db/ps.dat, db/pcl.dat)
# Maps known model strings (from PJL INFO ID / SNMP / HTTP title) to
# their supported printer languages and attack surface notes.

_PSPLOIT_CAPABILITIES: dict = {
    # HP LaserJet series
    "hp laserjet 4250":         {"langs": ["PJL", "PS", "PCL"], "nvram": False, "notes": "classic PJL target"},
    "hp laserjet 4350":         {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    "hp laserjet 5200":         {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    "hp laserjet m3027":        {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    "hp laserjet m3035":        {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    "hp laserjet m5025":        {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    "hp laserjet m5035":        {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    "hp laserjet m605":         {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    "hp laserjet m606":         {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    "hp laserjet m712":         {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    "hp laserjet enterprise":   {"langs": ["PJL", "PS", "PCL"], "nvram": False, "notes": "enterprise fw update"},
    "hp officejet":             {"langs": ["PJL", "PCL"], "nvram": False},
    "hp color laserjet":        {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    # Brother series (PJL NVRAM access)
    "brother hl-l2315dw":       {"langs": ["PJL", "PCL"], "nvram": True, "notes": "NVRAM destroy target"},
    "brother hl-l2350dw":       {"langs": ["PJL", "PCL"], "nvram": True},
    "brother mfc-7860dw":       {"langs": ["PJL", "PS", "PCL"], "nvram": True},
    "brother mfc-l2750dw":      {"langs": ["PJL", "PCL"], "nvram": True},
    "brother mfc-l8900cdw":     {"langs": ["PJL", "PS", "PCL"], "nvram": True},
    "brother dcp-l2550dw":      {"langs": ["PJL", "PCL"], "nvram": True},
    # Lexmark series
    "lexmark x792":             {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    "lexmark ms610":            {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    "lexmark mx710":            {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    "lexmark mx810":            {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    # Ricoh series
    "ricoh mp c3003":           {"langs": ["PJL", "PS", "PCL"], "nvram": False, "notes": "LDAP passback"},
    "ricoh mp c4503":           {"langs": ["PJL", "PS", "PCL"], "nvram": False, "notes": "LDAP passback"},
    "ricoh mp c6003":           {"langs": ["PJL", "PS", "PCL"], "nvram": False, "notes": "LDAP passback"},
    "ricoh aficio mp":          {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    # Konica Minolta / Bizhub
    "konica minolta bizhub":    {"langs": ["PJL", "PS", "PCL"], "nvram": False, "notes": "SOAP cred extract"},
    "bizhub c554":              {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    "bizhub c454":              {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    "bizhub c364":              {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    # Xerox series
    "xerox workcentre":         {"langs": ["PJL", "PS", "PCL"], "nvram": False, "notes": "DLM firmware inject"},
    "xerox altalink":           {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    "xerox versalink":          {"langs": ["PJL", "PS", "PCL"], "nvram": False, "notes": "CVE-2024-6333"},
    "xerox phaser":             {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    # Canon series
    "canon imagerunner":        {"langs": ["PJL", "PS", "PCL"], "nvram": False, "notes": "LDIF addr book"},
    "canon ir-adv":             {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    # Sharp series
    "sharp mx-2640n":           {"langs": ["PJL", "PCL"], "nvram": False, "notes": "SMTP passback"},
    "sharp mx-2640":            {"langs": ["PJL", "PCL"], "nvram": False},
    "sharp mfp":                {"langs": ["PJL", "PCL"], "nvram": False},
    # Kyocera series
    "kyocera taskalfa":         {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    "kyocera fs-":              {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    # OKI series
    "oki c":                    {"langs": ["PJL", "PCL"], "nvram": False},
    "oki mc":                   {"langs": ["PJL", "PS", "PCL"], "nvram": False},
    # Epson series
    "epson workforce":          {"langs": ["PCL"], "nvram": False},
    "epson al-":                {"langs": ["PJL", "PS", "PCL"], "nvram": False},
}

# PRET-2.0 db/ model lists (partial — first 50 entries per language)
# Full lists are in .tmp/vendor-repos/PRET-2.0/db/{pjl,ps,pcl}.dat
_PRET2_PJL_MODELS: list = [
    "10512", "10515", "2132", "2138", "2145", "2205", "2212", "2404WD",
    "2522", "2527", "2532", "2535", "2545", "2560", "2575", "2705", "2712",
    "3000cn", "3010cn", "3100cn", "3145", "3155", "3165", "3205", "3212",
    "3502", "3515", "3522", "3527", "3532", "3535", "3545", "3560",
    "4510", "4515", "4525", "4540", "4545", "4550", "4560", "4575",
    "5500", "5510", "5520", "5530", "5540", "5550", "5560", "5700",
]

# ── Praeda MFP fingerprint signatures (percx/Praeda data/data_list) ──────────
# Format: { "page_title_fragment": {"server": "Server-Header-fragment",
#            "vendor": "Vendor", "praeda_id": "P000XXX"} }
_PRAEDA_SIGNATURES: dict = {
    "HP Color LaserJet CP4005":    {"server": "HP-ChaiSOE",         "vendor": "HP"},
    "HP Color LaserJet 4700":      {"server": "HP-ChaiSOE",         "vendor": "HP"},
    "HP Color LaserJet CP3525":    {"server": "HP-ChaiSOE",         "vendor": "HP"},
    "HP Color LaserJet CP3505":    {"server": "HP-ChaiSOE",         "vendor": "HP"},
    "HP Officejet 6500 E709a":     {"server": "Virata-EmWeb",       "vendor": "HP"},
    "HP Officejet 6500 E709n":     {"server": "Virata-EmWeb",       "vendor": "HP"},
    "HP Photosmart C6200":         {"server": "Virata-EmWeb",       "vendor": "HP"},
    "HP Officejet Pro 8500 A909n": {"server": "Virata-EmWeb",       "vendor": "HP"},
    "HP Officejet Pro 8500 A909a": {"server": "Virata-EmWeb",       "vendor": "HP"},
    "HP Officejet Pro L7500":      {"server": "Virata-EmWeb",       "vendor": "HP"},
    "HP Officejet Pro L7600":      {"server": "Virata-EmWeb",       "vendor": "HP"},
    "HP HTTP Server":              {"server": "HP HTTP Server",     "vendor": "HP"},
    "Phaser 7750GX":               {"server": "Allegro-Software-RomPager/4.10",  "vendor": "Xerox"},
    "Phaser 6360DT":               {"server": "Allegro-Software-RomPager/4.34",  "vendor": "Xerox"},
    "XEROX WORKCENTRE PRO":        {"server": "Xerox_MicroServer",  "vendor": "Xerox"},
    "XEROX WORKCENTRE":            {"server": "Xerox_MicroServer",  "vendor": "Xerox"},
    "Xerox WorkCentre M20i":       {"server": "",                   "vendor": "Xerox"},
    "Xerox WorkCentre 4150":       {"server": "",                   "vendor": "Xerox"},
    "Xerox WorkCentre 4250":       {"server": "",                   "vendor": "Xerox"},
    "Xerox WorkCentre 4260":       {"server": "",                   "vendor": "Xerox"},
    "Xerox WorkCentre 5638":       {"server": "SNMP",               "vendor": "Xerox"},
    "Xerox WorkCentre 5645":       {"server": "SNMP",               "vendor": "Xerox"},
    "Xerox WorkCentre 5655":       {"server": "SNMP",               "vendor": "Xerox"},
    "Xerox WorkCentre 5735":       {"server": "SNMP",               "vendor": "Xerox"},
    "Xerox WorkCentre 5740":       {"server": "SNMP",               "vendor": "Xerox"},
    "Xerox WorkCentre 5745":       {"server": "SNMP",               "vendor": "Xerox"},
    "Xerox WorkCentre 5755":       {"server": "SNMP",               "vendor": "Xerox"},
    "Xerox WorkCentre 7775":       {"server": "SNMP",               "vendor": "Xerox"},
    "Xerox WorkCentre 7535":       {"server": "SNMP",               "vendor": "Xerox"},
    "Xerox WorkCentre 7545":       {"server": "SNMP",               "vendor": "Xerox"},
    "Xerox WorkCentre 7556":       {"server": "SNMP",               "vendor": "Xerox"},
    "TopAccess":                   {"server": "TOSHIBA TEC",        "vendor": "Toshiba"},
    "CANON HTTP Server":           {"server": "CANON HTTP Server",  "vendor": "Canon"},
    "Canon iR-ADV 4051":           {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR-ADV 4045":           {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR-ADV 4245":           {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR-ADV 6055":           {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR-ADV 6065":           {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR-ADV 6075":           {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR-ADV 6255":           {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR-ADV C5030":          {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR-ADV C5035":          {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR-ADV C5040":          {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR-ADV C5045":          {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR-ADV C5051":          {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR-ADV C5235":          {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR-ADV C5240":          {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR-ADV C5250":          {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR-ADV C7065":          {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR-ADV C7055":          {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR3320":                {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR2220":                {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR C5800":              {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR C2620":              {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR C3200":              {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR C3220":              {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR3035":                {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR3045":                {"server": "SNMP",               "vendor": "Canon"},
    "Canon iR5055":                {"server": "SNMP",               "vendor": "Canon"},
    "KONICA MINOLTA magicolor 4690MF": {"server": "LPC Http Server","vendor": "Konica Minolta"},
    "KONICA MINOLTA magicolor 1690MF": {"server": "LPC Http Server","vendor": "Konica Minolta"},
    "KONICA MINOLTA bizhub C452":  {"server": "SNMP",               "vendor": "Konica Minolta"},
    "KONICA MINOLTA bizhub C220":  {"server": "SNMP",               "vendor": "Konica Minolta"},
    "KONICA MINOLTA bizhub 223":   {"server": "SNMP",               "vendor": "Konica Minolta"},
    "KONICA MINOLTA bizhub C280":  {"server": "SNMP",               "vendor": "Konica Minolta"},
    "KONICA MINOLTA bizhub 283":   {"server": "SNMP",               "vendor": "Konica Minolta"},
    "KONICA MINOLTA bizhub C284e": {"server": "SNMP",               "vendor": "Konica Minolta"},
    "KONICA MINOLTA bizhub 363":   {"server": "SNMP",               "vendor": "Konica Minolta"},
    "KONICA MINOLTA bizhub 423":   {"server": "SNMP",               "vendor": "Konica Minolta"},
    "KONICA MINOLTA bizhub 552":   {"server": "SNMP",               "vendor": "Konica Minolta"},
    "KONICA MINOLTA bizhub C554":  {"server": "SNMP",               "vendor": "Konica Minolta"},
    "KONICA MINOLTA bizhub 602":   {"server": "SNMP",               "vendor": "Konica Minolta"},
    "Lexmark X656de":              {"server": "",                   "vendor": "Lexmark"},
    "Web Image Monitor":           {"server": "Web-Server/3.0",     "vendor": "Ricoh"},
    "Top Page - MX-2600N":         {"server": "Rapid Logic",        "vendor": "Sharp"},
    "Top Page - MX-2610N":         {"server": "Rapid Logic",        "vendor": "Sharp"},
    "Top Page - MX-B401":          {"server": "Rapid Logic",        "vendor": "Sharp"},
    "Top Page - MX-4100N":         {"server": "Rapid Logic",        "vendor": "Sharp"},
    "Top Page - MX-4101N":         {"server": "Rapid Logic",        "vendor": "Sharp"},
    "Top Page - MX-M283N":         {"server": "Rapid Logic",        "vendor": "Sharp"},
    "Top Page - MX-M363N":         {"server": "Rapid Logic",        "vendor": "Sharp"},
    "Top Page - MX-M453N":         {"server": "Rapid Logic",        "vendor": "Sharp"},
    "Top Page - MX-M503N":         {"server": "Rapid Logic",        "vendor": "Sharp"},
    "Top Page - MX-M623N":         {"server": "Rapid Logic",        "vendor": "Sharp"},
    "Top Page - MX-3501N":         {"server": "Rapid Logic",        "vendor": "Sharp"},
    "KYOCERA Document Solutions":  {"server": "SNMP",               "vendor": "Kyocera"},
    "KYOCERA MITA Printing System":{"server": "SNMP",               "vendor": "Kyocera"},
    "Unauthorized":                {"server": "Spyglass_MicroServer","vendor": "Xerox"},
    "Principal":                   {"server": "Spyglass_MicroServer","vendor": "Xerox"},
}


def praeda_match(title: str, server: str) -> dict | None:
    """Return matching Praeda signature if page title / server header matches."""
    title_l  = title.lower()
    server_l = server.lower()
    for key, sig in _PRAEDA_SIGNATURES.items():
        if key.lower() in title_l or (sig["server"] and sig["server"].lower() in server_l):
            return {"match": key, **sig}
    return None


def _scan_ports_nmap(host: str, timeout: float = 5.0) -> List[int]:
    """Use nmap when available (more reliable through filters/NAT)."""
    import re
    import shutil
    import subprocess

    nmap = shutil.which('nmap')
    if not nmap:
        return []
    ports = sorted(_resolved_printer_ports().keys())
    port_arg = ','.join(str(p) for p in ports)
    host_timeout = max(45, int(timeout * len(ports) * 0.6))
    try:
        out = subprocess.check_output(
            [
                nmap, '-Pn', '-n', '--open', '-p', port_arg,
                '--host-timeout', f'{host_timeout}s', '-T4', host,
            ],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=host_timeout + 15,
        )
        found = sorted({int(m.group(1)) for m in re.finditer(r'(\d+)/tcp\s+open', out)})
        return found
    except Exception as exc:
        _log.debug("nmap scan failed: %s", exc)
        return []


def scan_ports(host: str,
               timeout: float = 2.0,
               extra_ports: Optional[List[int]] = None) -> List[int]:
    """
    Return list of open TCP ports from the printer port set.

    Uses nmap (if installed), then parallel TCP connect probes.
    """
    import concurrent.futures as _cf

    ports_to_probe = dict(_resolved_printer_ports())
    for p in (extra_ports or []):
        ports_to_probe.setdefault(int(p), f'Custom({p})')

    open_set: Set[int] = set()

    # nmap first — better on WAN/filtered targets
    for p in _scan_ports_nmap(host, timeout=max(timeout, 4.0)):
        open_set.add(p)

    def _probe(port: int) -> Optional[int]:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port
        except OSError:
            return None

    workers = min(32, max(8, len(ports_to_probe)))
    with _cf.ThreadPoolExecutor(max_workers=workers) as pool:
        for port in pool.map(_probe, ports_to_probe.keys()):
            if port is not None:
                open_set.add(port)

    return sorted(open_set)


def _verify_ftp_port(host: str, port: int, timeout: float) -> bool:
    """True only if the port speaks FTP (220 banner)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(256).decode('latin-1', errors='replace').strip()
            return banner.startswith('220')
    except OSError:
        return False


# ── Individual protocol grabbers ──────────────────────────────────────────────

def _grab_ftp(host: str, timeout: float) -> dict:
    """Read FTP welcome banner (port 21)."""
    from utils.ports import PortConfig
    port = PortConfig.resolve('ftp')
    result: dict = {}
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(512).decode('latin-1', errors='replace').strip()
            if banner:
                result['ftp_banner'] = banner
    except OSError:
        pass
    return result


def _parse_hp_server_header(server: str) -> dict:
    """
    Parse HP Embedded Web Server 'Server' header.

    Example:
      HP HTTP Server; HP DeskJet 2600 series - V1N05A; Serial Number: CN85...; Built:... {TJP1FN2237AR}
    """
    out: dict = {}
    if not server or 'hp' not in server.lower():
        return out
    out['make'] = 'HP'
    m = re.search(
        r'HP HTTP Server;\s*HP\s+(.+?)\s*-\s*([A-Z0-9]+)\s*;',
        server, re.I,
    )
    if m:
        out['model'] = m.group(1).strip()
        out['product_number'] = m.group(2).strip()
    m = re.search(r'Serial Number:\s*([A-Z0-9]+)', server, re.I)
    if m:
        out['serial'] = m.group(1)
    m = re.search(r'Built:[^{]*\{([^}]+)\}', server)
    if m:
        out['firmware'] = m.group(1).strip()
    m = re.search(r'Built:\s*(.+?)\s*\{', server)
    if m and 'firmware_date' not in out:
        out['firmware_date'] = m.group(1).strip()
    return out


def _vendor_from_banner(text: str) -> tuple:
    """Extract (make, model) hints from a protocol banner string."""
    if not text:
        return '', ''
    hp = _parse_hp_server_header(text)
    if hp.get('make'):
        return hp['make'], hp.get('model', '')
    m = re.search(
        r'(EPSON|HP|Hewlett-Packard|Brother|Kyocera|Ricoh|Xerox|Canon|Lexmark|OKI|Samsung|Konica)'
        r'[\s_/-]*([\w\s./-]{2,40})?',
        text, re.I,
    )
    if m:
        make = m.group(1).replace('Hewlett-Packard', 'HP').title()
        model = (m.group(2) or '').strip()
        return make, model
    return '', ''


def _grab_http(host: str, timeout: float,
               probe_ports: Optional[List[int]] = None) -> dict:
    """
    Probe HP/EWS and generic HTTP on printer web ports.

    HP inkjets often expose the same EWS on 80, 443, 631, 8080 and even 9100.
    """
    from utils.ports import PortConfig

    candidates: List[Tuple[str, int]] = []
    seen: Set[Tuple[str, int]] = set()

    def _add(scheme: str, port: int) -> None:
        key = (scheme, port)
        if key not in seen and port > 0:
            seen.add(key)
            candidates.append(key)

    _add('http', PortConfig.resolve('http'))
    _add('https', PortConfig.resolve('https'))
    for port in (631, 8080, 9100, 80, 443):
        _add('http', port)
        _add('https', port)
    for port in (probe_ports or []):
        _add('http', int(port))

    result: dict = {'http_open_ports': []}
    best_hp: dict = {}

    for scheme, port in candidates:
        try:
            url = f'{scheme}://{host}:{port}/'
            r = requests.get(
                url, timeout=timeout, verify=False,
                allow_redirects=True,
                headers={'User-Agent': 'PrinterXPL-Forge/6.2'},
            )
            server = r.headers.get('Server', '')
            title = re.findall(r'<title[^>]*>(.*?)</title>', r.text, re.I | re.S)
            key = 'https' if scheme == 'https' else 'http'

            if r.status_code < 500:
                if port not in result['http_open_ports']:
                    result['http_open_ports'].append(port)

            if not result.get(f'{key}_server') and server:
                result[f'{key}_server'] = server
            if not result.get(f'{key}_title') and title:
                result[f'{key}_title'] = title[0].strip()
            result[f'{key}_status_{port}'] = str(r.status_code)
            if server:
                result[f'server_{port}'] = server

            hp = _parse_hp_server_header(server)
            if hp and (not best_hp or len(str(hp)) > len(str(best_hp))):
                best_hp = hp

            # HP DevMgmt JSON (common on DeskJet/OfficeJet)
            if 'hp' in server.lower() or 'embedded web server' in r.text.lower():
                for api_path in (
                    '/DevMgmt/ProductConfigDyn.xml',
                    '/DevMgmt/ProductStatusDyn.xml',
                    '/hp/device/info',
                ):
                    try:
                        api = requests.get(
                            f'{scheme}://{host}:{port}{api_path}',
                            timeout=timeout, verify=False,
                        )
                        if api.status_code != 200 or not api.text:
                            continue
                        txt = api.text
                        for tag, field in (
                            (r'<SerialNumber>([^<]+)', 'serial'),
                            (r'<ProductNumber>([^<]+)', 'product_number'),
                            (r'<FirmwareRevision>([^<]+)', 'firmware'),
                            (r'<ProductName>([^<]+)', 'model'),
                            (r'<UUID>([^<]+)', 'uuid'),
                        ):
                            m = re.search(tag, txt, re.I)
                            if m and field not in best_hp:
                                best_hp[field] = m.group(1).strip()
                    except Exception:
                        pass
        except Exception as exc:
            result.setdefault('http_errors', []).append(f'{scheme}:{port}:{str(exc)[:40]}')

    if best_hp:
        result['hp_ews'] = best_hp
    return result


def _grab_ipp(host: str, timeout: float) -> dict:
    """
    Send IPP 1.1 GET-PRINTER-ATTRIBUTES to the printer and parse the response.

    Tries HTTP:631 first, then HTTPS:631 (some printers require TLS).
    """

    def _build_ipp_request(printer_uri: str) -> bytes:
        def attr(tag: int, name: str, value: str) -> bytes:
            nb = name.encode()
            vb = value.encode()
            return (bytes([tag]) +
                    struct.pack('>H', len(nb)) + nb +
                    struct.pack('>H', len(vb)) + vb)

        body = b'\x01\x01'                      # IPP 1.1
        body += struct.pack('>H', 0x000B)        # Get-Printer-Attributes
        body += struct.pack('>I', 1)             # request-id
        body += b'\x01'                          # operation-attributes-tag
        body += attr(0x47, 'attributes-charset', 'utf-8')
        body += attr(0x48, 'attributes-natural-language', 'en')
        body += attr(0x45, 'printer-uri', printer_uri)
        body += attr(0x44, 'requested-attributes', 'all')
        body += b'\x03'                          # end-of-attributes
        return body

    from utils.ports import PortConfig
    _ipp_port = PortConfig.resolve('ipp')
    result = {}
    candidates = [
        ('http',  _ipp_port, '/ipp/'),
        ('http',  _ipp_port, '/ipp/print'),
        ('https', _ipp_port, '/ipp/print'),
        ('https', _ipp_port, '/ipp/'),
    ]
    for scheme, port, path in candidates:
        try:
            uri  = f'ipp://{host}{path}'
            body = _build_ipp_request(uri)
            r = requests.post(
                f'{scheme}://{host}:{port}{path}',
                data=body,
                headers={'Content-type': 'application/ipp'},
                timeout=timeout, verify=False,
            )
            if r.status_code == 200 and len(r.content) > 8:
                raw = r.content.decode('latin-1', errors='replace')
                result['ipp_raw'] = raw[:2000]
                result['ipp_endpoint'] = f'{scheme}:{port}{path}'

                # Extract key attributes using regex on the decoded response
                for pattern, key in [
                    (r'MDL:([^;]+);', 'model'),
                    (r'MFG:([^;]+);', 'make'),
                    (r'CMD:([^;]+);', 'langs'),
                    (r'DES:([^;]+);', 'description'),
                    (r'CID:([^;]+);', 'color_id'),
                    (r'FID:([^;]+);', 'feature_id'),
                    (r'RID:([^;]+);', 'res_id'),
                ]:
                    m = re.search(pattern, raw)
                    if m:
                        result[f'ipp_{key}'] = m.group(1).strip()

                # Parse text attributes (e.g. printer-make-and-model)
                for attr_name in ['printer-make-and-model', 'printer-name',
                                   'printer-info', 'printer-location',
                                   'printer-firmware-version',
                                   'printer-device-id', 'printer-uuid',
                                   'printer-dns-sd-name', 'printer-state']:
                    idx = raw.find(attr_name)
                    if idx >= 0:
                        chunk = raw[idx:idx+200]
                        printable = ''.join(c if 32 <= ord(c) < 127 else '|' for c in chunk)
                        result[f'ipp_attr_{attr_name.replace("-","_")}'] = printable[:80]

                # Document formats — extract only valid MIME types from binary response
                fmts = re.findall(
                    r'(application/(?:postscript|pdf|pcl|vnd\.epson\.\w+|octet-stream)|'
                    r'image/(?:pwg-raster|jpeg|png|urf)|text/plain)',
                    raw, re.I,
                )
                # Filter to printable MIME types only (no binary artifacts)
                clean_fmts = [f for f in dict.fromkeys(fmts)
                              if all(32 <= ord(c) <= 127 for c in f) and len(f) < 60]
                if clean_fmts:
                    result['ipp_doc_formats'] = clean_fmts

                # IPP version
                result['ipp_version_raw'] = f'{r.content[0]}.{r.content[1]}'
                break
        except Exception as exc:
            _log.debug("IPP %s:%d%s failed: %s", scheme, port, path, exc)

    return result


def _grab_pjl(host: str, timeout: float) -> dict:
    """Send PJL INFO ID to the RAW/JetDirect port and capture the response."""
    from utils.ports import PortConfig
    result = {}
    try:
        s = socket.create_connection((host, PortConfig.resolve('raw')), timeout=timeout)
        s.settimeout(timeout)
        uel = b'\x1b%-12345X'
        s.sendall(uel + b'@PJL INFO ID\r\n' + uel)
        time.sleep(min(timeout, 2.0))
        data = b''
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 8192:
                    break
        except (socket.timeout, BlockingIOError):
            pass
        s.close()
        if data:
            text = data.decode('latin-1', errors='replace')
            result['pjl_response'] = text[:500]
            m = re.search(r'INFO ID\s*\r?\n(.+)', text)
            if m:
                result['pjl_id'] = m.group(1).strip()
    except Exception as exc:
        result['pjl_error'] = str(exc)[:60]
    return result


def _grab_lpd(host: str, timeout: float) -> dict:
    """Probe LPD port for queue names and capabilities."""
    from utils.ports import PortConfig
    result = {}
    try:
        s = socket.create_connection((host, PortConfig.resolve('lpd')), timeout=timeout)
        s.settimeout(timeout)
        # LPD: receive any banner, then request queue status
        s.sendall(b'\x03default\n')   # receive queue state
        time.sleep(0.5)
        data = b''
        try:
            data = s.recv(1024)
        except socket.timeout:
            pass
        s.close()
        if data:
            text = data.decode('latin-1', errors='replace')
            result['lpd_response'] = text[:300]
            # Extract queue names from the response
            queues = re.findall(r'Printer:\s*(\S+)', text)
            if queues:
                result['lpd_queues'] = queues
    except Exception as exc:
        result['lpd_error'] = str(exc)[:60]
    return result


def _grab_wsd(host: str, timeout: float) -> dict:
    """Probe WSD (Web Services for Devices) endpoint for device metadata."""
    result = {}
    import uuid as _uuid
    soap = f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <s:Header>
    <a:To>http://{host}/WSD/DEVICE</a:To>
    <a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>
    <a:MessageID>urn:uuid:{_uuid.uuid4()}</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
  </s:Header>
  <s:Body/>
</s:Envelope>"""
    for path in ('/WSD/DEVICE', '/wsd/device', '/WSD/PRINTER'):
        try:
            r = requests.post(
                f'http://{host}{path}', data=soap.encode(),
                headers={'Content-Type': 'application/soap+xml; charset=utf-8',
                         'SOAPAction': '""'},
                timeout=timeout,
            )
            if r.status_code == 200:
                text = r.text
                for tag in ['Manufacturer', 'ModelName', 'FriendlyName',
                             'FirmwareVersion', 'SerialNumber', 'PresentationUrl',
                             'XAddrs', 'Types']:
                    m = re.search(f'<[^>]*{tag}[^>]*>(.*?)</', text, re.I | re.S)
                    if m:
                        val = re.sub(r'<[^>]+>', '', m.group(1)).strip()[:80]
                        result[f'wsd_{tag.lower()}'] = val
                result['wsd_raw'] = text[:500]
                break
        except Exception as exc:
            _log.debug("WSD %s failed: %s", path, exc)
    return result


def _grab_snmp(host: str, timeout: float) -> dict:
    """Query SNMP for device description and language support."""
    result = {}
    try:
        from pysnmp.hlapi import (
            getCmd, nextCmd, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity, SnmpEngine,
        )
        from utils.ports import PortConfig
        engine    = SnmpEngine()
        community = CommunityData('public', mpModel=0)
        transport = UdpTransportTarget((host, PortConfig.resolve('snmp')), timeout=timeout, retries=0)
        context   = ContextData()

        oids = {
            '1.3.6.1.2.1.1.1.0':          'sys_descr',
            '1.3.6.1.2.1.1.5.0':          'sys_name',
            '1.3.6.1.2.1.25.3.2.1.3.1':   'hr_device_descr',
            '1.3.6.1.2.1.43.5.1.1.16.1':  'prt_console_display',
        }
        for oid, key in oids.items():
            for err_ind, err_stat, _, binds in getCmd(
                engine, community, transport, context,
                ObjectType(ObjectIdentity(oid)),
            ):
                if not err_ind and not err_stat and binds:
                    result[f'snmp_{key}'] = str(binds[0][1])[:200]

    except ImportError:
        result['snmp_error'] = 'pysnmp not installed'
    except Exception as exc:
        result['snmp_error'] = str(exc)[:80]

    if not result.get('snmp_sys_descr') and not result.get('snmp_hr_device_descr'):
        import shutil
        import subprocess
        snmpget = shutil.which('snmpget')
        if snmpget:
            from utils.ports import PortConfig
            port = PortConfig.resolve('snmp')
            for oid, key in (
                ('1.3.6.1.2.1.1.1.0', 'sys_descr'),
                ('1.3.6.1.2.1.25.3.2.1.3.1', 'hr_device_descr'),
            ):
                try:
                    out = subprocess.check_output(
                        [snmpget, '-v1', '-c', 'public', '-Oqv', '-t', '2', '-r', '1',
                         f'{host}:{port}', oid],
                        stderr=subprocess.DEVNULL, text=True,
                    ).strip()
                    if out:
                        result[f'snmp_{key}'] = out[:200]
                except Exception:
                    pass
    return result


# ── Attack surface assessment ─────────────────────────────────────────────────

def _assess_attack_surface(fp: PrinterFingerprint) -> Dict[str, str]:
    """
    Derive the attack surface from the fingerprint.

    Returns a dict of {attack_vector: 'high'/'medium'/'low'/'not_applicable'}.
    """
    surface: Dict[str, str] = {}
    open_p = set(fp.open_ports)
    langs  = [l.upper() for l in fp.printer_langs]
    fmts   = [f.lower() for f in fp.doc_formats]

    # PJL attacks (requires port 9100 + PJL language)
    if 9100 in open_p and 'PJL' in langs:
        surface['pjl_info_disclosure']   = 'high'
        surface['pjl_path_traversal']    = 'high'
        surface['pjl_eeprom_access']     = 'medium'
        surface['pjl_factory_reset']     = 'medium'
        surface['pjl_dos_infinite_loop'] = 'medium'
        surface['pjl_print_job_sniff']   = 'low'
    elif 9100 in open_p:
        surface['raw_print_flooding']    = 'medium'
        surface['raw_dos']               = 'medium'

    # PostScript attacks
    if 'PS' in langs or 'POSTSCRIPT' in langs or 'BR-SCRIPT' in langs:
        surface['ps_code_execution']     = 'high'
        surface['ps_file_read']          = 'high'
        surface['ps_exfiltration']       = 'medium'
        surface['ps_dos_loop']           = 'medium'

    # IPP attacks
    if 631 in open_p:
        surface['ipp_job_manipulation']  = 'medium'
        surface['ipp_queue_listing']     = 'low'
        if 'application/postscript' in fmts:
            surface['ipp_ps_job_exec']   = 'high'
        if any('epson' in f for f in fmts):
            surface['ipp_escpr_job']     = 'low'   # send raw ESC/P-R print job

    # LPD attacks
    if 515 in open_p:
        surface['lpd_queue_manipulation']= 'medium'
        surface['lpd_dos']               = 'low'

    # Web interface attacks
    if 80 in open_p or 443 in open_p:
        surface['web_default_creds']     = 'medium'
        surface['web_path_traversal']    = 'medium'
        surface['web_info_disclosure']   = 'low'
        surface['web_csrf']              = 'low'

    # SMB attacks (rare on modern printers)
    if 445 in open_p:
        surface['smb_null_session']      = 'medium'
        surface['smb_share_access']      = 'low'

    # WSD attacks
    if 3702 in open_p or 5357 in open_p or 'WSD' in langs:
        surface['wsd_ssrf_probe']        = 'low'

    # Information disclosure (always available)
    surface['banner_info_leak']          = 'info'
    surface['snmp_public_community']     = 'info' if 161 in open_p else 'not_applicable'

    return surface


# ── Main entry point ──────────────────────────────────────────────────────────

def grab_all(
    host:    str,
    timeout: float = 5.0,
    verbose: bool  = False,
    vendor_hint: str = '',
) -> PrinterFingerprint:
    """
    Probe *host* with every available protocol and return a PrinterFingerprint.

    Args:
        host:    Printer IP address or hostname.
        timeout: Per-connection timeout in seconds.
        verbose: Print progress to stdout.

    Returns:
        A fully populated PrinterFingerprint instance.
    """
    fp = PrinterFingerprint(host=host)

    if verbose:
        print(f"[*] Banner grabbing {host} ...")

    # 1. Port scan (parallel; slightly longer timeout for WAN targets)
    scan_timeout = max(timeout, 4.0)
    if verbose:
        import shutil
        nm = 'yes' if shutil.which('nmap') else 'no'
        print(f"    Scanning ports (nmap={nm}) ...", end='', flush=True)
    fp.open_ports = scan_ports(host, timeout=scan_timeout)
    if verbose:
        print(f" open: {fp.open_ports}")

    # 1b. Drop port 21 unless it speaks FTP (avoid tcpwrapped false positives)
    if 21 in fp.open_ports and not _verify_ftp_port(host, 21, scan_timeout):
        fp.open_ports = [p for p in fp.open_ports if p != 21]

    _core_print = {23, 80, 443, 515, 631, 8080, 8443, 9100, 9101, 9102, 9150}
    if not _core_print.intersection(fp.open_ports):
        fp.attack_surface['printer_service_ports'] = (
            'NONE — no standard print ports open from this network '
            '(HTTP/IPP/RAW/LPD). Host may be offline, filtered, or not a printer.'
        )

    # 2. HTTP / HTTPS / EWS — probe even when port scan missed slow/filtered ports
    if verbose:
        print("    Grabbing HTTP/HTTPS/EWS ...", end='', flush=True)
    http_data = _grab_http(host, timeout=max(timeout, 4.0), probe_ports=fp.open_ports)
    fp.http_title   = http_data.get('http_title', '')
    fp.http_server  = http_data.get('http_server', '') or http_data.get('server_80', '')
    fp.https_server = http_data.get('https_server', '') or http_data.get('server_443', '')
    fp.raw_banners['http'] = str(http_data)
    for p in http_data.get('http_open_ports', []):
        if p not in fp.open_ports:
            fp.open_ports.append(p)
    fp.open_ports.sort()
    hp = http_data.get('hp_ews', {})
    if hp:
        fp.make = hp.get('make', fp.make) or fp.make
        fp.model = hp.get('model', fp.model) or fp.model
        fp.serial = hp.get('serial', fp.serial) or fp.serial
        fp.firmware = hp.get('firmware', fp.firmware) or fp.firmware
        fp.uuid = hp.get('uuid', fp.uuid) or fp.uuid
        if hp.get('product_number') and not fp.model:
            fp.model = hp['product_number']
        if 'DeskJet' in fp.model or 'OfficeJet' in fp.model or 'HP' in fp.make:
            for lang in ('IPP', 'PCL', 'AirPrint'):
                if lang not in fp.printer_langs:
                    fp.printer_langs.append(lang)
    if verbose:
        print(f" server={fp.http_server or fp.https_server} model={fp.make} {fp.model}")

    # 3. IPP
    if 631 in fp.open_ports:
        if verbose:
            print("    Grabbing IPP ...", end='', flush=True)
        ipp_data = _grab_ipp(host, timeout)
        fp.ipp_attrs = ipp_data
        fp.raw_banners['ipp'] = str(ipp_data)
        # Extract identification from IPP
        if 'ipp_make' in ipp_data:
            fp.make = ipp_data['ipp_make']
        if 'ipp_model' in ipp_data:
            fp.model = ipp_data['ipp_model']
        if 'ipp_langs' in ipp_data:
            fp.printer_langs = [l.strip() for l in ipp_data['ipp_langs'].split(',')]
        if 'ipp_doc_formats' in ipp_data:
            fp.doc_formats = ipp_data['ipp_doc_formats']
        # Firmware from header attributes
        fw_val = ipp_data.get('ipp_attr_printer_firmware_version', '')
        if fw_val:
            fp.firmware = re.sub(r'[|.]+', '', fw_val).strip()[:30]
        if verbose:
            print(f" model={fp.model or '?'} langs={fp.printer_langs}")

    # 4. PJL (RAW / port 9100)
    if 9100 in fp.open_ports:
        if verbose:
            print("    Grabbing PJL ...", end='', flush=True)
        pjl_data = _grab_pjl(host, timeout)
        fp.pjl_id = pjl_data.get('pjl_id', '')
        fp.raw_banners['pjl'] = str(pjl_data)
        # If PJL responds, add PJL to langs if not already there
        if fp.pjl_id and 'PJL' not in fp.printer_langs:
            fp.printer_langs.append('PJL')
        if verbose:
            print(f" pjl_id={fp.pjl_id[:40] or 'none'!r}")

    # 5. LPD
    if 515 in fp.open_ports:
        if verbose:
            print("    Grabbing LPD ...", end='', flush=True)
        lpd_data = _grab_lpd(host, timeout)
        fp.lpd_queues = lpd_data.get('lpd_queues', [])
        fp.raw_banners['lpd'] = str(lpd_data)
        if verbose:
            print(f" queues={fp.lpd_queues}")

    # 5b. FTP welcome banner
    if 21 in fp.open_ports:
        if verbose:
            print("    Grabbing FTP ...", end='', flush=True)
        ftp_data = _grab_ftp(host, timeout)
        fp.ftp_banner = ftp_data.get('ftp_banner', '')
        fp.raw_banners['ftp'] = str(ftp_data)
        if fp.ftp_banner and not fp.make:
            mk, md = _vendor_from_banner(fp.ftp_banner)
            if mk:
                fp.make, fp.model = mk, md
        if verbose:
            print(f" banner={fp.ftp_banner[:40] or 'none'!r}")

    # 6. WSD
    if 80 in fp.open_ports:
        if verbose:
            print("    Grabbing WSD ...", end='', flush=True)
        wsd_data = _grab_wsd(host, timeout)
        fp.wsd_info = wsd_data
        fp.raw_banners['wsd'] = str(wsd_data)
        # Fill model/make if not already set
        if not fp.make and wsd_data.get('wsd_manufacturer'):
            fp.make = wsd_data['wsd_manufacturer']
        if not fp.model and wsd_data.get('wsd_modelname'):
            fp.model = wsd_data['wsd_modelname']
        if verbose:
            print(f" model={wsd_data.get('wsd_modelname','?')}")

    # 7. SNMP (UDP — probe even if port 161 not in TCP list)
    if verbose:
        print("    Grabbing SNMP ...", end='', flush=True)
    snmp_data = _grab_snmp(host, timeout)
    fp.snmp_descr = snmp_data.get('snmp_sys_descr', snmp_data.get('snmp_hr_device_descr', ''))
    fp.raw_banners['snmp'] = str(snmp_data)
    if fp.snmp_descr:
        if not fp.make and 'hp' in fp.snmp_descr.lower():
            fp.make = 'HP'
        if 161 not in fp.open_ports:
            fp.open_ports.append(161)
            fp.open_ports.sort()
    if verbose:
        print(f" descr={fp.snmp_descr[:40] or 'none'!r}")

    # 8. Fallback: extract make/model from banners
    if not fp.model:
        for src in (fp.http_server, fp.https_server, fp.snmp_descr, fp.ftp_banner, fp.pjl_id):
            mk, md = _vendor_from_banner(src)
            if mk:
                fp.make, fp.model = mk, md or fp.model
                break
        if not fp.model:
            for src in (fp.http_server, fp.https_server, fp.snmp_descr):
                m = re.search(r'(EPSON|HP|Brother|Kyocera|Ricoh|Xerox|Canon|Lexmark)'
                              r'[\s_/-]*([\w\s-]{2,30})', src, re.I)
                if m:
                    fp.make  = m.group(1).title()
                    fp.model = m.group(2).strip()
                    break

    # 9. Attack surface assessment
    fp.attack_surface = _assess_attack_surface(fp)

    # 10. Manual vendor hint (workflow / --vendor-hint) when auto-detect failed
    if vendor_hint and not fp.make:
        from utils.vendor_profile import normalize_vendor
        slug = normalize_vendor(vendor_hint)
        fp.make = vendor_hint.strip().upper() if slug == 'generic' else slug.upper()
        if slug == 'hp' and not fp.printer_langs:
            fp.printer_langs = ['IPP', 'PCL', 'AirPrint']

    if verbose:
        print(f"[+] Fingerprint: {fp.summary()}")
        high_vectors = [k for k, v in fp.attack_surface.items() if v == 'high']
        if high_vectors:
            print(f"[!] High-risk attack vectors: {', '.join(high_vectors)}")

    return fp


def print_fingerprint(fp: PrinterFingerprint) -> None:
    """Pretty-print a PrinterFingerprint to stdout."""
    print(f"\n{'='*65}")
    print(f"  PRINTER FINGERPRINT — {fp.host}")
    print(f"{'='*65}")
    print(f"  Make/Model : {fp.make} {fp.model}")
    print(f"  Firmware   : {fp.firmware or '?'}")
    print(f"  Serial     : {fp.serial or '?'}")
    print(f"  UUID       : {fp.uuid or '?'}")
    print(f"  Open ports : {fp.open_ports}")
    print(f"  Languages  : {', '.join(fp.printer_langs) or 'none detected'}")
    print(f"  Doc formats: {', '.join(fp.doc_formats) or 'none'}")
    print(f"  HTTP server: {fp.http_server or fp.https_server or '?'}")
    print(f"  SNMP descr : {fp.snmp_descr[:60] or '?'}")
    if fp.ftp_banner:
        print(f"  FTP banner : {fp.ftp_banner[:60]}")
    if fp.pjl_id:
        print(f"  PJL ID     : {fp.pjl_id[:60]}")

    if fp.lpd_queues:
        print(f"  LPD queues : {fp.lpd_queues}")

    if fp.wsd_info.get('wsd_friendlyname'):
        print(f"  WSD name   : {fp.wsd_info['wsd_friendlyname']}")

    if fp.attack_surface:
        from utils.normalize import as_str
        print(f"\n  {'Attack surface':30s} {'Risk'}")
        print(f"  {'-'*50}")
        _risk_order = {'high': 0, 'medium': 1, 'low': 2, 'info': 3, 'not_applicable': 4}
        for vec, risk in sorted(fp.attack_surface.items(), key=lambda x: (
                _risk_order.get(as_str(x[1], 'info').lower(), 5), x[0])):
            risk_s = as_str(risk, 'info').lower()
            color = {
                'high':          '\033[1;31m',
                'medium':        '\033[1;33m',
                'low':           '\033[1;34m',
                'info':          '\033[0;37m',
                'not_applicable':'\033[2;37m',
            }.get(risk_s, '')
            reset = '\033[0m'
            print(f"  {color}{vec:<35}{risk_s.upper():<12}{reset}")
    print()


def print_protocol_hints(fp: PrinterFingerprint) -> None:
    """Suggest next steps when RAW/PJL shell is unavailable."""
    ports = set(fp.open_ports or [])
    if 9100 in ports and fp.pjl_id:
        return
    print("  ── Passive mode ─────────────────────────────────────────")
    if not ports:
        print("  No printer ports detected. Check IP, routing and firewall.")
    else:
        print(f"  Open ports: {sorted(ports)} — RAW/9100 "
              f"{'closed' if 9100 not in ports else 'open but PJL silent'}.")
        print("  PJL/PS/PCL shell commands require RAW (9100). Try instead:")
        if 631 in ports:
            print("    • python pxf.py <IP> --ipp")
        if 21 in ports:
            print("    • storage command (FTP) or --storage")
        if 80 in ports or 443 in ports:
            print("    • --bruteforce  (web default credentials)")
        print("    • --scan        (full fingerprint + CVE audit)")
    print()
