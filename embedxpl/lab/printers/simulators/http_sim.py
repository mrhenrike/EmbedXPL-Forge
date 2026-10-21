#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — HTTP Web Management Simulator (TCP port 80)
=========================================================
Simulates the embedded web server of a network printer.

Pages exposed:
  GET  /                     → redirect to /hp/device/this.LCDispatcher (HP) or index.html
  GET  /hp/device/status     → status page (no auth)
  GET  /info_configuration   → full config dump (no auth if vuln enabled)
  GET  /admin                → requires auth; default creds bypass if vuln enabled
  GET  /general/status.html  → status with firmware version
  POST /firmware_update      → fake firmware upload endpoint
  GET  /../../etc/passwd     → path traversal if vuln enabled
  GET  /wsd/                 → WSD endpoint info

Intentional vulnerabilities:
  - web_default_creds:  admin/blank accepted
  - web_traversal:      GET /../../etc/passwd returns content
  - firmware_upload:    POST /firmware_update accepted without signature check
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import base64
import http.server
import json
import urllib.parse
from typing import Optional

from simulators.base_printer import BaseSimulator, PrinterProfile


def _basic_auth_ok(header: Optional[str], user: str, pwd: str) -> bool:
    if not header or not header.startswith('Basic '):
        return False
    try:
        decoded = base64.b64decode(header[6:]).decode()
        return decoded == f'{user}:{pwd}'
    except Exception:
        return False


class _HTTPHandler(http.server.BaseHTTPRequestHandler):

    server_version = 'HP-ChaiSOE/1.0'
    sys_version    = ''

    def log_message(self, fmt, *args) -> None:
        self.server.simulator.log.debug(fmt, *args)

    def do_GET(self) -> None:
        sim: 'HTTPSimulator' = self.server.simulator
        profile: PrinterProfile = sim.profile
        path = urllib.parse.unquote(self.path).split('?')[0]
        sim.stats['connections'] += 1

        # ── Path traversal ─────────────────────────────────────────────────
        if '..' in path and profile.vuln.get('web_traversal'):
            sim._log_attack(self.client_address, f'HTTP web path traversal: {path}')
            # Try to serve from simulated filesystem
            norm = path.replace('\\', '/').lstrip('/')
            content = ''
            for fpath, fcontent in profile.filesystem.items():
                if fpath.endswith(norm.split('/')[-1]):
                    content = fcontent
                    break
            if not content:
                content = f'# traversal target: {path}\nroot::0:0::/:/bin/sh\n'
            self._send(200, content, 'text/plain')
            return

        # ── Main routes ────────────────────────────────────────────────────
        if path in ('/', '/index.html', '/hp/device/this.LCDispatcher'):
            self._send_html(_page_root(profile))

        elif path in ('/general/status.html', '/hp/device/status', '/Status.htm'):
            self._send_html(_page_status(profile))

        elif path in ('/info_configuration', '/Configuration.htm', '/config'):
            if profile.vuln.get('web_default_creds') or profile.vuln.get('web_traversal'):
                sim._log_attack(self.client_address, 'HTTP unauthenticated config dump')
                self._send_html(_page_config(profile))
            else:
                self._send_401()

        elif path in ('/admin', '/admin/', '/manage', '/manage/'):
            auth = self.headers.get('Authorization')
            if profile.vuln.get('web_default_creds') and \
               _basic_auth_ok(auth, profile.admin_user, profile.admin_pass):
                sim._log_attack(self.client_address, 'HTTP admin access with default creds')
                self._send_html(_page_admin(profile))
            elif not auth:
                self._send_401()
            else:
                sim._log_attack(self.client_address, f'HTTP failed admin login attempt: {auth[:30]}')
                self._send_401()

        elif path in ('/wsd', '/wsd/', '/WSD/DEVICE'):
            self._send(200, _wsd_response(profile), 'application/xml')

        elif path in ('/api/v1/info', '/api/info'):
            info = {
                'make': profile.make,
                'model': profile.model,
                'firmware': profile.firmware,
                'serial': profile.serial,
                'location': profile.location,
                'languages': profile.languages,
            }
            self._send(200, json.dumps(info, indent=2), 'application/json')

        elif path == '/snmp':
            self._send_html(f'<html><body>SNMP Community: {profile.snmp_read}</body></html>')

        else:
            self._send(404, f'<html><body>404 Not Found: {path}</body></html>', 'text/html')

    def do_POST(self) -> None:
        sim: 'HTTPSimulator' = self.server.simulator
        profile: PrinterProfile = sim.profile
        path = urllib.parse.unquote(self.path).split('?')[0]
        length = int(self.headers.get('Content-Length', 0))
        body   = self.rfile.read(length) if length else b''

        if path in ('/firmware_update', '/update', '/firmware/update'):
            if profile.vuln.get('firmware_upload'):
                sim._log_attack(
                    self.client_address,
                    f'HTTP firmware upload ({len(body)} bytes) — no signature check'
                )
                self._send_html('<html><body>Firmware update accepted. Rebooting...</body></html>')
            else:
                self._send(403, 'Forbidden', 'text/plain')

        elif path in ('/admin/login', '/login'):
            # Parse basic form body
            try:
                params = dict(urllib.parse.parse_qsl(body.decode()))
                user = params.get('user', params.get('username', ''))
                pwd  = params.get('pass', params.get('password', ''))
                if profile.vuln.get('web_default_creds') and \
                   user == profile.admin_user and pwd == profile.admin_pass:
                    sim._log_attack(self.client_address, 'HTTP login with default creds — success')
                    self._send_html('<html><body>Login successful.</body></html>')
                else:
                    sim._log_attack(self.client_address, f'HTTP login attempt user="{user}"')
                    self._send_401()
            except Exception:
                self._send(400, 'Bad Request', 'text/plain')

        else:
            self._send(404, 'Not Found', 'text/plain')

    def _send_html(self, html: str) -> None:
        self._send(200, html, 'text/html')

    def _send(self, code: int, body: str, ctype: str) -> None:
        data = body.encode('utf-8', errors='replace') if isinstance(body, str) else body
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Server', f'{self.server.simulator.profile.make} Embedded Web Server')
        self.end_headers()
        self.wfile.write(data)

    def _send_401(self) -> None:
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Printer Admin"')
        self.send_header('Content-Length', '0')
        self.end_headers()


# ── Page generators ───────────────────────────────────────────────────────────

def _page_root(p: PrinterProfile) -> str:
    return f"""<html><head><title>{p.make} {p.model}</title></head><body>
<h2>{p.make} {p.model}</h2>
<p>Status: <b>Ready</b></p>
<p>Firmware: {p.firmware}</p>
<p>Serial: {p.serial}</p>
<ul>
  <li><a href="/general/status.html">Status</a></li>
  <li><a href="/info_configuration">Configuration</a></li>
  <li><a href="/admin">Admin</a></li>
  <li><a href="/firmware_update">Firmware Update</a></li>
</ul>
</body></html>"""


def _page_status(p: PrinterProfile) -> str:
    return f"""<html><head><title>Status — {p.make} {p.model}</title></head><body>
<h2>Device Status</h2>
<table border="1">
<tr><td>Make / Model</td><td>{p.make} {p.model}</td></tr>
<tr><td>Firmware</td><td>{p.firmware}</td></tr>
<tr><td>Serial Number</td><td>{p.serial}</td></tr>
<tr><td>UUID</td><td>{p.uuid}</td></tr>
<tr><td>Location</td><td>{p.location}</td></tr>
<tr><td>Admin Contact</td><td>{p.contact}</td></tr>
<tr><td>Languages</td><td>{', '.join(p.languages)}</td></tr>
<tr><td>Status</td><td>Ready</td></tr>
<tr><td>Jobs Processed</td><td>{p.job_counter}</td></tr>
</table>
</body></html>"""


def _page_config(p: PrinterProfile) -> str:
    return f"""<html><head><title>Config — {p.make} {p.model}</title></head><body>
<h2>Device Configuration (FULL DUMP)</h2>
<pre>
AdminUser:       {p.admin_user}
AdminPassword:   {p.admin_pass or '(blank)'}
PJLPassword:     {p.pjl_password or '(blank)'}
SNMPRead:        {p.snmp_read}
SNMPWrite:       {p.snmp_write}
FTPUser:         {p.ftp_user}
FTPPassword:     {p.ftp_pass or '(blank)'}
Firmware:        {p.firmware}
Serial:          {p.serial}
Languages:       {', '.join(p.languages)}
</pre>
</body></html>"""


def _page_admin(p: PrinterProfile) -> str:
    return f"""<html><head><title>Admin — {p.make} {p.model}</title></head><body>
<h2>Admin Panel</h2>
<form action="/firmware_update" method="POST" enctype="multipart/form-data">
  <p>Firmware Update: <input type="file" name="firmware"> <input type="submit" value="Upload"></p>
</form>
<form action="/admin/reset" method="POST">
  <p>Factory Reset: <input type="submit" value="Reset to Factory Defaults"></p>
</form>
</body></html>"""


def _wsd_response(p: PrinterProfile) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<wsdp:ThisModel xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof">
  <wsdp:Manufacturer>{p.make}</wsdp:Manufacturer>
  <wsdp:ManufacturerUrl>http://{p.make.lower()}.com</wsdp:ManufacturerUrl>
  <wsdp:ModelName>{p.model}</wsdp:ModelName>
  <wsdp:ModelNumber>{p.firmware}</wsdp:ModelNumber>
  <wsdp:ModelUrl>http://{p.make.lower()}.com/{p.model.replace(' ','-')}</wsdp:ModelUrl>
  <wsdp:PresentationUrl>http://127.0.0.1:{p.port_http}/</wsdp:PresentationUrl>
</wsdp:ThisModel>"""


class HTTPSimulator(BaseSimulator):
    """HTTP web management simulator on TCP port 80."""

    PROTOCOL = 'HTTP'

    def _make_server(self) -> http.server.HTTPServer:
        server = http.server.ThreadingHTTPServer((self.host, self.port), _HTTPHandler)
        server.simulator = self
        return server
