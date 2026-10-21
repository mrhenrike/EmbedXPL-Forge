#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — Base Printer Simulator
=====================================
Base class for all protocol simulators. Provides:
  - Thread-safe TCP/UDP server lifecycle
  - Connection logging
  - Vulnerability toggle (each vuln can be enabled/disabled per profile)
  - Stats counter (connections, commands, attacks detected)
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import logging
import socket
import socketserver
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

_LOG_DIR = Path(__file__).parent.parent / '.log'
_LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler(_LOG_DIR / 'lab.log', encoding='utf-8'),
        logging.StreamHandler(),
    ],
)


# ── Printer profile dataclass ─────────────────────────────────────────────────

@dataclass
class PrinterProfile:
    """
    Defines all characteristics of a simulated printer.
    Each simulator reads this to determine how to respond.
    """
    # Identity
    make:         str = 'Generic'
    model:        str = 'Printer 1000'
    firmware:     str = '1.0.0'
    serial:       str = 'SN00000001'
    uuid:         str = 'urn:uuid:00000000-0000-0000-0000-000000000001'
    location:     str = 'Lab Room 1'
    contact:      str = 'admin@lab.local'

    # Protocol support
    languages:    List[str] = field(default_factory=lambda: ['PJL', 'PCL', 'PS'])
    doc_formats:  List[str] = field(default_factory=lambda: [
        'application/pdf', 'application/postscript',
        'application/vnd.hp-PCL', 'application/octet-stream'
    ])

    # Auth
    admin_user:   str = 'admin'
    admin_pass:   str = ''          # blank by default (intentionally insecure)
    pjl_password: str = ''          # '' = no password on PJL
    snmp_read:    str = 'public'
    snmp_write:   str = 'private'
    ftp_user:     str = 'admin'
    ftp_pass:     str = ''

    # Intentional vulnerabilities (all enabled = maximum attack surface)
    vuln: Dict[str, bool] = field(default_factory=lambda: {
        'pjl_traversal':      True,   # EDB-15631 CVE-2010-4107
        'pjl_password_leak':  True,   # INFO VARIABLES leaks password
        'anon_ipp_jobs':      True,   # anonymous print job accepted
        'ipp_purge_anon':     True,   # purge-jobs without auth
        'lpd_unauthenticated':True,   # no LPD auth
        'lpd_bof_probe':      True,   # oversized control file → crash (CVE-2019-14308 style)
        'default_creds':      True,   # admin/blank on web
        'snmp_public_write':  False,  # public community allows SET (dangerous)
        'snmp_factory_reset': True,   # prtGeneralReset via SNMP writable
        'ftp_open':           True,   # FTP accessible
        'web_traversal':      True,   # path traversal in web UI
        'web_default_creds':  True,   # admin/blank accepted
        'wsd_enabled':        True,   # WSD discovery
        'ssrf_capable':       True,   # IPP Print-URI SSRF
        'firmware_upload':    True,   # firmware upload endpoint exists
        'nvram_rw':           True,   # NVRAM read/write via PJL
    })

    # Simulated filesystem (for PJL/FTP access)
    filesystem: Dict[str, str] = field(default_factory=lambda: {
        '0:/webServer/default.xml': '<config><admin_pass></admin_pass></config>',
        '0:/etc/passwd':            'root::0:0::/:/bin/sh\nadmin::1000:1000::/home/admin:/bin/sh',
        '0:/etc/shadow':            'root:$1$lab$hashed:18000:0:99999:7:::\nadmin::18000:0:99999:7:::',
        '0:/.profile':              '# HP JetDirect .profile\nexport PATH=/hp/bin:$PATH\n',
        '0:/tmp/jobs/job001.prn':   '%!PS-Adobe-3.0\n%%Title: Confidential Q4 Report\n%%EOF',
        '0:/tmp/jobs/job002.prn':   '%!PS-Adobe-3.0\n%%Title: Employee Salary Data\n%%EOF',
        '0:/hpmnt/etc/passwd':      'root::0:0::/:/bin/dlsh\n',
    })

    # Simulated SNMP MIB values
    snmp_mibs: Dict[str, str] = field(default_factory=lambda: {
        '1.3.6.1.2.1.1.1.0':       'HP LaserJet Pro M404n; SW=FutureSmart 4.11',
        '1.3.6.1.2.1.1.5.0':       'HPLAB-PRINTER-01',
        '1.3.6.1.2.1.1.6.0':       'Lab Room 1',
        '1.3.6.1.2.1.43.5.1.1.3.1': '3',    # prtGeneralReset = notResetting
        '1.3.6.1.2.1.43.5.1.1.1.1': 'HP LaserJet Pro M404n',
    })

    # Port assignments (can be overridden per instance)
    port_raw:   int = 9100
    port_ipp:   int = 631
    port_lpd:   int = 515
    port_http:  int = 80
    port_snmp:  int = 161
    port_ftp:   int = 21
    port_wsd:   int = 3702

    # State
    job_counter: int = 0


# ── Base simulator class ──────────────────────────────────────────────────────

class BaseSimulator:
    """
    Abstract base for protocol simulators.
    Subclasses implement `_make_server()` and handle their protocol.
    """

    PROTOCOL = 'BASE'

    def __init__(self, host: str, port: int, profile: PrinterProfile) -> None:
        self.host    = host
        self.port    = port
        self.profile = profile
        self.log     = logging.getLogger(
            f"{profile.make}.{profile.model}.{self.PROTOCOL}"
        )
        self._server: Optional[socketserver.BaseServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self.stats: Dict[str, int] = {
            'connections': 0,
            'commands':    0,
            'attacks':     0,
        }

    def _make_server(self) -> socketserver.BaseServer:
        raise NotImplementedError

    def start(self) -> 'BaseSimulator':
        if self._running:
            return self
        try:
            self._server = self._make_server()
            self._server.allow_reuse_address = True
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                daemon=True, name=f"{self.PROTOCOL}-{self.port}"
            )
            self._thread.start()
            self._running = True
            self.log.info("Started %s simulator on %s:%d", self.PROTOCOL, self.host, self.port)
        except OSError as exc:
            self.log.error("Failed to start %s on %d: %s", self.PROTOCOL, self.port, exc)
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
        self._running = False
        self.log.info("Stopped %s simulator on port %d", self.PROTOCOL, self.port)

    @property
    def is_running(self) -> bool:
        return self._running

    def _log_attack(self, client_addr: tuple, description: str) -> None:
        self.stats['attacks'] += 1
        self.log.warning(
            "ATTACK DETECTED from %s:%d — %s",
            client_addr[0], client_addr[1], description
        )
        with open(_LOG_DIR / 'attacks.log', 'a', encoding='utf-8') as f:
            f.write(
                f"{datetime.now().isoformat()} "
                f"{self.PROTOCOL} {self.profile.make} {self.profile.model} "
                f"from {client_addr[0]}:{client_addr[1]} — {description}\n"
            )
