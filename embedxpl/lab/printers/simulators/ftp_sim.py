#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — FTP Simulator (TCP port 21)
=========================================
Simulates the FTP server embedded in network printers (HP JetDirect, Ricoh, etc.).

Supports:
  USER, PASS, PWD, CWD, LIST, RETR, STOR, DELE, QUIT

Intentional vulnerabilities:
  - ftp_open: anonymous and default creds accepted
  - web_traversal: CWD ../.. allows root traversal
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import socketserver
import socket
import io
from typing import Optional

from simulators.base_printer import BaseSimulator, PrinterProfile


class _FTPHandler(socketserver.StreamRequestHandler):

    def setup(self) -> None:
        super().setup()  # initializes self.rfile / self.wfile
        self.sim: 'FTPSimulator' = self.server.simulator
        self.profile: PrinterProfile = self.sim.profile
        self.sim.stats['connections'] += 1
        self.sim.log.info("FTP connection from %s:%d", *self.client_address)
        self._cwd = '/'
        self._authed = False
        self._user: Optional[str] = None
        self._data_sock: Optional[socket.socket] = None
        self._data_addr: Optional[tuple] = None

    def handle(self) -> None:
        self._send("220 " + self.profile.make + " " + self.profile.model + " FTP Server ready.")
        self.request.settimeout(30)
        try:
            while True:
                line = self.rfile.readline()
                if not line:
                    break
                line = line.decode('latin-1', errors='replace').strip()
                if not line:
                    continue
                self.sim.stats['commands'] += 1
                self.sim.log.debug("FTP << %s", line[:80])
                cmd = line.split(None, 1)
                verb = cmd[0].upper()
                arg  = cmd[1] if len(cmd) > 1 else ''
                self._dispatch(verb, arg)
        except (OSError, TimeoutError, ConnectionResetError):
            pass

    def _dispatch(self, verb: str, arg: str) -> None:
        if verb == 'USER':
            self._user = arg
            self._send(f"331 Password required for {arg}.")
        elif verb == 'PASS':
            self._handle_auth(self._user or '', arg)
        elif verb == 'QUIT':
            self._send("221 Goodbye.")
        elif verb == 'PWD':
            self._send(f'257 "{self._cwd}" is the current directory.')
        elif verb == 'CWD':
            self._handle_cwd(arg)
        elif verb == 'LIST':
            self._handle_list()
        elif verb == 'RETR':
            self._handle_retr(arg)
        elif verb == 'STOR':
            self._handle_stor(arg)
        elif verb == 'DELE':
            self.sim._log_attack(self.client_address, f'FTP DELE {arg} — file deletion')
            self._send("250 File deleted.")
        elif verb == 'PORT':
            self._handle_port(arg)
        elif verb == 'PASV':
            self._send("502 Passive mode not supported in lab simulator.")
        elif verb == 'TYPE':
            self._send("200 Type set.")
        elif verb == 'SYST':
            self._send("215 UNIX Type: L8")
        elif verb == 'FEAT':
            self._send("211-Features:\r\n SIZE\r\n211 End.")
        elif verb == 'NOOP':
            self._send("200 OK.")
        else:
            self._send(f"502 Command not implemented: {verb}")

    def _handle_auth(self, user: str, password: str) -> None:
        profile = self.profile
        anon_ok  = profile.vuln.get('ftp_open') and user.lower() in ('anonymous', 'ftp')
        cred_ok  = profile.vuln.get('ftp_open') and \
                   user == profile.ftp_user and password == profile.ftp_pass

        if anon_ok:
            self._authed = True
            self.sim._log_attack(self.client_address, f'FTP anonymous login accepted (user={user})')
            self._send("230 Anonymous login successful.")
        elif cred_ok:
            self._authed = True
            self.sim._log_attack(self.client_address, f'FTP default credential login: {user}:{password}')
            self._send(f"230 User {user} logged in.")
        else:
            self.sim._log_attack(self.client_address, f'FTP failed login: {user}:{password[:10]}')
            self._send("530 Login incorrect.")

    def _handle_cwd(self, path: str) -> None:
        if '..' in path and self.profile.vuln.get('web_traversal'):
            self.sim._log_attack(self.client_address, f'FTP CWD traversal: {path}')
        self._cwd = path if path.startswith('/') else '/' + path
        self._send(f"250 Directory changed to {self._cwd}")

    def _handle_list(self) -> None:
        if not self._authed:
            self._send("530 Not logged in.")
            return
        listing = self._build_listing()
        if self._data_addr:
            try:
                dsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dsock.settimeout(5)
                dsock.connect(self._data_addr)
                self._send("150 Here comes the directory listing.")
                dsock.sendall(listing.encode())
                dsock.close()
                self._send("226 Directory send OK.")
            except OSError:
                self._send("425 Can't open data connection.")
        else:
            self._send("425 Use PORT command first.")

    def _build_listing(self) -> str:
        lines = [
            'drwxr-xr-x  2 root root  4096 Jan 01 00:00 .',
            'drwxr-xr-x  2 root root  4096 Jan 01 00:00 ..',
        ]
        for fpath, content in self.profile.filesystem.items():
            fname = fpath.split('/')[-1]
            fsize = len(content)
            lines.append(f'-rw-r--r--  1 admin admin {fsize:6d} Jan 01 00:00 {fname}')
        return '\r\n'.join(lines) + '\r\n'

    def _handle_retr(self, path: str) -> None:
        if not self._authed:
            self._send("530 Not logged in.")
            return
        if '..' in path and self.profile.vuln.get('web_traversal'):
            self.sim._log_attack(self.client_address, f'FTP RETR traversal: {path}')

        content = ''
        fname = path.split('/')[-1]
        for fpath, fcontent in self.profile.filesystem.items():
            if fpath.endswith(fname):
                content = fcontent
                break
        if not content:
            self._send("550 File not found.")
            return

        if self._data_addr:
            try:
                dsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dsock.settimeout(5)
                dsock.connect(self._data_addr)
                self._send(f"150 Opening data connection for {path} ({len(content)} bytes).")
                dsock.sendall(content.encode())
                dsock.close()
                self.sim._log_attack(self.client_address, f'FTP file download: {path}')
                self._send("226 Transfer complete.")
            except OSError:
                self._send("425 Can't open data connection.")
        else:
            self._send("425 Use PORT command first.")

    def _handle_stor(self, path: str) -> None:
        if not self._authed:
            self._send("530 Not logged in.")
            return
        self.sim._log_attack(self.client_address, f'FTP file upload: {path}')
        if self._data_addr:
            try:
                dsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dsock.settimeout(5)
                dsock.connect(self._data_addr)
                self._send("150 Ok to send data.")
                data = b''
                while True:
                    chunk = dsock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                dsock.close()
                self.profile.filesystem[path] = data.decode('latin-1', errors='replace')
                self._send("226 Transfer complete.")
            except OSError:
                self._send("425 Can't open data connection.")
        else:
            self._send("425 Use PORT command first.")

    def _handle_port(self, arg: str) -> None:
        try:
            parts = [int(x) for x in arg.split(',')]
            ip   = '.'.join(str(x) for x in parts[:4])
            port = parts[4] * 256 + parts[5]
            self._data_addr = (ip, port)
            self._send(f"200 PORT command successful. ({ip}:{port})")
        except Exception:
            self._send("501 Bad PORT argument.")

    def _send(self, msg: str) -> None:
        self.wfile.write((msg + '\r\n').encode())
        self.wfile.flush()


class FTPSimulator(BaseSimulator):
    """FTP server simulator on TCP port 21."""

    PROTOCOL = 'FTP'

    def _make_server(self) -> socketserver.TCPServer:
        server = socketserver.ThreadingTCPServer((self.host, self.port), _FTPHandler)
        server.simulator = self
        return server
