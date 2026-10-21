#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — PJL/RAW Simulator (TCP port 9100)
===============================================
Simulates HP JetDirect / PJL printer on TCP port 9100.

Intentionally vulnerable configurations (per profile):
  - pjl_traversal:     FSDIRLIST/FSUPLOAD with directory traversal
  - pjl_password_leak: INFO VARIABLES leaks admin password
  - nvram_rw:          SET/DEFAULT commands modify NVRAM (simulated)
  - pjl_dos:           PS infinite loop and NVRAM damage accepted
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import re
import socketserver
import time
from typing import Optional

from simulators.base_printer import BaseSimulator, PrinterProfile

UEL = b'\x1b%-12345X'


class _PJLHandler(socketserver.BaseRequestHandler):
    """Handles a single TCP connection to the PJL simulator."""

    def setup(self) -> None:
        self.sim: 'PJLSimulator' = self.server.simulator
        self.profile: PrinterProfile = self.sim.profile
        self.sim.stats['connections'] += 1
        self.sim.log.info("PJL connection from %s:%d", *self.client_address)

    def handle(self) -> None:
        self.request.settimeout(10)
        buf = b''
        try:
            while True:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                buf += chunk
                # Process complete PJL block on UEL or after short pause
                if UEL in buf or b'@PJL' in buf:
                    resp = self._process(buf)
                    if resp:
                        self.request.sendall(resp)
                    buf = b''
        except (ConnectionResetError, OSError, TimeoutError):
            pass

    def _process(self, data: bytes) -> bytes:
        """Parse and respond to PJL commands."""
        self.sim.stats['commands'] += 1
        text = data.decode('latin-1', errors='replace').upper()
        out  = b''

        # INFO ID — printer identification
        if 'INFO ID' in text:
            out += self._pjl_resp(
                f'"{self.profile.make} {self.profile.model}"\r\n'
            )

        # INFO STATUS
        if 'INFO STATUS' in text:
            out += self._pjl_resp(
                'CODE=10001\r\nDISPLAY="Ready"\r\nONLINE=TRUE\r\n'
            )

        # INFO VARIABLES — intentionally leaks password if vuln enabled
        if 'INFO VARIABLES' in text:
            pwd = self.profile.pjl_password if self.profile.vuln.get('pjl_password_leak') else '***'
            out += self._pjl_resp(
                f'COPIES=1 [2 RANGE 1 999]\r\n'
                f'PAPER=LETTER [17 ENUMERATED]\r\n'
                f'PASSWORD={pwd} [8 STRING]\r\n'
                f'TIMEOUT=90 [2 RANGE 5 300]\r\n'
                f'HOSTNAME="{self.profile.model.replace(" ", "-")}"\r\n'
                f'USERNAME="admin"\r\n'
                f'IPADDRESS=127.0.0.1\r\n'
                f'SUBNET=255.255.255.0\r\n'
                f'GATEWAY=127.0.0.1\r\n'
                f'SMTPSERVER=\r\n'
                f'DNSSERVER=\r\n'
                f'SNMPWRITECOMMUNITY="{self.profile.snmp_write}"\r\n'
            )
            if not self.profile.vuln.get('pjl_password_leak'):
                pass
            else:
                self.sim._log_attack(self.client_address, 'INFO VARIABLES — password leak')

        # FSDIRLIST — directory listing (traversal check)
        m = re.search(r'FSDIRLIST NAME="([^"]+)"', data.decode('latin-1','replace'), re.I)
        if m:
            path = m.group(1)
            if self.profile.vuln.get('pjl_traversal') and '..' in path:
                self.sim._log_attack(self.client_address, f'PJL directory traversal: {path}')
            out += self._dir_listing(path)

        # FSUPLOAD — file download
        m = re.search(r'FSUPLOAD NAME="([^"]+)" OFFSET=(\d+) SIZE=(\d+)',
                      data.decode('latin-1','replace'), re.I)
        if m:
            path, offset, size = m.group(1), int(m.group(2)), int(m.group(3))
            if '..' in path and self.profile.vuln.get('pjl_traversal'):
                self.sim._log_attack(self.client_address, f'PJL traversal file read: {path}')
            out += self._file_upload(path, offset, size)

        # FSDOWNLOAD — file write
        m = re.search(r'FSDOWNLOAD.*NAME="([^"]+)"', data.decode('latin-1','replace'), re.I)
        if m:
            path = m.group(1)
            self.sim._log_attack(self.client_address, f'PJL FSDOWNLOAD (file write): {path}')
            out += self._pjl_resp('')  # accept silently

        # DMINFO — memory access (info disclosure)
        if 'DMINFO' in text or 'DMCMD' in text:
            self.sim._log_attack(self.client_address, 'PJL DMINFO/DMCMD — memory/control access')
            out += self._pjl_resp('RESULT CODE=0\r\n')

        # SET / DEFAULT — NVRAM modification
        m = re.search(r'@PJL (SET|DEFAULT) (\w+)=(.+)', data.decode('latin-1','replace'), re.I)
        if m:
            cmd, var, val = m.groups()
            if self.profile.vuln.get('nvram_rw'):
                self.sim._log_attack(self.client_address,
                                     f'PJL {cmd} {var}={val.strip()} — NVRAM write')
            out += self._pjl_resp('')

        # DISPLAY / RDYMSG — LCD panel modification
        if 'RDYMSG' in text or '@PJL DISPLAY' in text:
            self.sim._log_attack(self.client_address, 'PJL DISPLAY/RDYMSG — panel manipulation')
            out += self._pjl_resp('')

        # PostScript jobs — DoS probe
        if text.strip().startswith('%!') or ('SHOWPAGE' in text and 'PS' in text):
            self.sim._log_attack(self.client_address, 'PostScript job received (DoS/RCE probe)')

        return out if out else b''

    def _pjl_resp(self, body: str) -> bytes:
        return UEL + b'@PJL\r\n@PJL ' + body.encode('latin-1') + b'\r\n' + UEL

    def _dir_listing(self, path: str) -> bytes:
        """Return simulated filesystem directory listing."""
        entries = []
        prefix = path.rstrip('/\\')

        # Build listing from simulated filesystem
        seen_dirs: set = set()
        for fpath, content in self.profile.filesystem.items():
            norm = fpath.replace('\\', '/')
            # Match files under the requested path
            if '..' in path or path in ('0:/', '0:\\', '0:'):
                parts = norm.split('/')
                if len(parts) >= 2:
                    top = parts[1] if len(parts) > 1 else parts[0]
                    if top not in seen_dirs:
                        seen_dirs.add(top)
                        entries.append(f'{top} TYPE=DIR')
                entries.append(f'{parts[-1]} TYPE=FILE SIZE={len(content)}')

        if not entries:
            entries = ['. TYPE=DIR', '.. TYPE=DIR', 'tmp TYPE=DIR', 'etc TYPE=DIR']

        body = f'@PJL FSDIRLIST NAME="{path}" ENTRY=1\r\n'
        body += '\r\n'.join(entries[:50]) + '\r\n'
        return UEL + body.encode('latin-1') + UEL

    def _file_upload(self, path: str, offset: int, size: int) -> bytes:
        """Return simulated file content."""
        norm = path.replace('\\', '/').replace('0:/', '0:/')
        content = ''

        for fpath, fcontent in self.profile.filesystem.items():
            if fpath.replace('\\', '/').endswith(norm.split('/')[-1]) or norm in fpath:
                content = fcontent
                break

        if not content:
            # Generate plausible content based on filename
            fname = norm.split('/')[-1].lower()
            if 'passwd' in fname:
                content = 'root::0:0::/:/bin/sh\noperator::2:2::/:/bin/false\n'
            elif '.profile' in fname:
                content = '# device profile\nexport JOBNAME=PrinterLab\n'
            else:
                content = f'# file: {path}\n# size: simulated\n'

        chunk = content[offset:offset+size]
        header = f'@PJL FSUPLOAD FORMAT:BINARY SIZE={len(chunk)} NAME="{path}"\r\n'
        return UEL + header.encode('latin-1') + chunk.encode('latin-1') + b'\r\n' + UEL


class PJLSimulator(BaseSimulator):
    """PJL/RAW printer simulator on TCP port 9100."""

    PROTOCOL = 'PJL'

    def _make_server(self) -> socketserver.TCPServer:
        server = socketserver.ThreadingTCPServer((self.host, self.port), _PJLHandler)
        server.simulator = self
        return server
