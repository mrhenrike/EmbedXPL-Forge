#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SMB Protocol Support for PrinterXPL-Forge
========================================
Server Message Block printing on ports 445 / 139.

Two backends are tried in priority order:
  1. pysmb  (pure-Python, SMB1 / SMB2)
  2. smbclient system binary (fallback via subprocess)

Both IPv4 and IPv6 are supported.

Usage example::

    with SMBProtocol('192.168.1.5', share='print$') as smb:
        if smb.connect():
            shares = smb.list_shares()
            printers = smb.list_printers()
            smb.print_file('payload.ps', b'%!PS ...')
"""

# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import io
import os
import shutil
import socket
import subprocess
import tempfile
import uuid
from typing import Dict, List, Optional

# ── Optional pysmb backend ───────────────────────────────────────────────────
try:
    from smb.SMBConnection import SMBConnection as _SMBConnection
    from smb.smb_structs import OperationFailure as _SMBOpFail
    _PYSMB_AVAILABLE = True
except ImportError:
    _PYSMB_AVAILABLE = False
    _SMBOpFail = Exception  # type: ignore


class SMBProtocol:
    """
    SMB protocol implementation for printer enumeration and file printing.

    Supports:
      - Share enumeration
      - Printer share discovery
      - File printing via SMB
      - SMB printer fingerprinting (OS, machine name)
    """

    DEFAULT_PORT = 445
    ALT_PORT     = 139

    def __init__(
        self,
        host:     str,
        port:     Optional[int]  = None,
        timeout:  float          = 30.0,
        share:    str            = 'print$',
        username: str            = 'guest',
        password: str            = '',
        domain:   str            = '',
    ):
        self.host     = host.strip('[]')
        self.port     = port or self.DEFAULT_PORT
        self.timeout  = timeout
        self.share    = share
        self.username = username
        self.password = password
        self.domain   = domain

        self._conn: Optional[_SMBConnection] = None
        self._connected: bool = False
        self._server_name: str = ''
        self._os_info: str = ''
        self._backend: str = 'none'

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """
        Attempt SMB connection using pysmb (preferred) or a TCP probe.

        Returns True on success, False on failure.
        """
        if _PYSMB_AVAILABLE:
            return self._connect_pysmb()
        return self._connect_raw_tcp()

    def _connect_pysmb(self) -> bool:
        """Connect using pysmb library (SMB1/SMB2)."""
        client_name = 'PrinterXPL-Forge-' + uuid.uuid4().hex[:6]
        try:
            # Resolve server NetBIOS name (use hostname or IP as fallback)
            server_name = self._resolve_netbios_name() or self.host
            self._conn = _SMBConnection(
                self.username,
                self.password,
                client_name,
                server_name,
                domain        = self.domain,
                use_ntlm_v2   = True,
                is_direct_tcp = (self.port == 445),
            )
            connected = self._conn.connect(self.host, self.port, timeout=int(self.timeout))
            if connected:
                self._connected = True
                self._backend   = 'pysmb'
                self._server_name = server_name
            return connected
        except Exception:
            self._conn = None
            return False

    def _connect_raw_tcp(self) -> bool:
        """Fallback: just probe whether the port is open."""
        for port in (self.port, self.ALT_PORT):
            try:
                s = socket.create_connection((self.host, port), timeout=self.timeout)
                s.close()
                self.port     = port
                self._backend = 'tcp-probe'
                self._connected = True
                return True
            except OSError:
                continue
        return False

    def _resolve_netbios_name(self) -> str:
        """Try to obtain the remote machine's NetBIOS / hostname."""
        try:
            return socket.gethostbyaddr(self.host)[0].split('.')[0].upper()
        except Exception:
            return ''

    # ------------------------------------------------------------------
    # Enumeration
    # ------------------------------------------------------------------

    def list_shares(self) -> List[Dict[str, str]]:
        """
        List all SMB shares on the target.

        Returns a list of dicts with keys: name, type, comments.
        """
        if not self._connected:
            raise RuntimeError("Not connected — call connect() first")

        if self._conn:
            try:
                raw = self._conn.listShares()
                return [
                    {
                        'name':     s.name,
                        'type':     str(s.type),
                        'comments': s.comments,
                    }
                    for s in raw
                ]
            except Exception as exc:
                raise RuntimeError(f"listShares failed: {exc}") from exc

        # No pysmb — try smbclient binary
        return self._smbclient_list_shares()

    def list_printers(self) -> List[Dict[str, str]]:
        """
        Filter shares that are printer shares (type 0x00000001 in SMB).

        Returns a list of printer share dicts.
        """
        shares = self.list_shares()
        printers = []
        for s in shares:
            # pysmb returns type as string; '1' or '65536' (print$ uses type 3)
            name = s.get('name', '').lower()
            if ('print' in name or s.get('type', '') in ('1', '65536', '3')):
                printers.append(s)
        return printers

    def list_files(self, path: str = '/') -> List[str]:
        """List files in a share path (requires an active pysmb connection)."""
        if not self._conn:
            raise RuntimeError("pysmb backend required for file listing")
        try:
            entries = self._conn.listPath(self.share, path)
            return [e.filename for e in entries if e.filename not in ('.', '..')]
        except _SMBOpFail as exc:
            raise PermissionError(f"Cannot list {self.share}{path}: {exc}") from exc

    # ------------------------------------------------------------------
    # Printing
    # ------------------------------------------------------------------

    def print_file(
        self,
        remote_filename: str,
        data: bytes,
        print_share: Optional[str] = None,
    ) -> bool:
        """
        Send *data* as a print job to the SMB printer share.

        Args:
            remote_filename: Spool filename on the share (e.g. 'job.ps').
            data:            Raw bytes to send (PostScript, PCL, etc.).
            print_share:     Share name to use; defaults to self.share.

        Returns True on success.
        """
        share = print_share or self.share

        if self._conn and self._backend == 'pysmb':
            return self._pysmb_print(share, remote_filename, data)

        return self._smbclient_print(share, data)

    def _pysmb_print(self, share: str, filename: str, data: bytes) -> bool:
        """Upload data to printer share using pysmb."""
        try:
            buf = io.BytesIO(data)
            self._conn.storeFile(share, filename, buf)
            return True
        except Exception as exc:
            raise RuntimeError(f"SMB store failed: {exc}") from exc

    def _smbclient_print(self, share: str, data: bytes) -> bool:
        """Print via smbclient binary (subprocess fallback)."""
        smbclient = shutil.which('smbclient')
        if not smbclient:
            raise RuntimeError(
                "pysmb not available and smbclient not found. "
                "Install with: apt install smbclient  |  brew install samba"
            )
        # Write data to a temp file, then spool via smbclient
        with tempfile.NamedTemporaryFile(delete=False, suffix='.prn') as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            cmd = [smbclient, f'//{self.host}/{share}',
                   '-U', f'{self.username}%{self.password}',
                   '-c', f'print {tmp_path}']
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=self.timeout)
            if result.returncode != 0:
                raise RuntimeError(f"smbclient error: {result.stderr.strip()}")
            return True
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Fingerprinting
    # ------------------------------------------------------------------

    def get_info(self) -> Dict[str, str]:
        """
        Return basic SMB session information.

        Includes: host, port, backend, connected, server_name, os_info, share.
        """
        return {
            'host':        self.host,
            'port':        str(self.port),
            'backend':     self._backend,
            'connected':   str(self._connected),
            'server_name': self._server_name,
            'os_info':     self._os_info,
            'share':       self.share,
            'pysmb':       str(_PYSMB_AVAILABLE),
        }

    def fingerprint(self) -> str:
        """
        Attempt to obtain OS/machine fingerprint from the SMB session.

        Returns a human-readable string.
        """
        if self._conn and self._backend == 'pysmb':
            try:
                # pysmb stores server OS info after a successful connection
                info = self._conn.getAttributes(self.share, '/')
                return f"Server: {self._server_name}"
            except Exception:
                pass
        return f"SMB host {self.host}:{self.port} [{self._backend}]"

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the SMB connection."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
        self._connected = False

    def __enter__(self) -> 'SMBProtocol':
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def __repr__(self) -> str:
        state = 'connected' if self._connected else 'disconnected'
        return (
            f"<SMBProtocol {self.host}:{self.port} "
            f"share={self.share!r} backend={self._backend!r} {state}>"
        )


# ── Module-level convenience function ─────────────────────────────────────────

def print_via_smb(
    host:     str,
    share:    str,
    data:     bytes,
    username: str = 'guest',
    password: str = '',
    port:     int = 445,
    timeout:  float = 30.0,
) -> bool:
    """
    One-shot SMB print helper.

    Args:
        host:     Printer IP or hostname.
        share:    SMB printer share name (e.g. 'print$').
        data:     Raw bytes to spool (PostScript, PJL, etc.).
        username: SMB username (default: guest).
        password: SMB password (default: empty).
        port:     SMB port (default: 445).
        timeout:  Connection timeout in seconds.

    Returns True on success.
    """
    with SMBProtocol(host, port=port, timeout=timeout,
                     share=share, username=username, password=password) as smb:
        if not smb._connected:
            raise ConnectionError(f"Cannot connect to SMB on {host}:{port}")
        return smb.print_file('printjob.prn', data)
