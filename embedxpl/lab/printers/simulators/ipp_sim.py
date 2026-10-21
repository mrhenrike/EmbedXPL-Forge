#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — IPP Simulator (TCP port 631)
==========================================
Implements a minimal IPP/1.1 server over HTTP.
Supports:
  - Get-Printer-Attributes (IPP op 0x000B)
  - Print-Job             (IPP op 0x0002) — anonymous accepted if vuln enabled
  - Get-Jobs              (IPP op 0x000A)
  - Cancel-Job            (IPP op 0x0008)
  - Purge-Jobs            (IPP op 0x0012) — no auth if vuln enabled
  - Print-URI / SSRF      (IPP op 0x0003) — if ssrf_capable enabled

IPP binary encoding is simplified: real parsers would use RFC 8010.
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import http.server
import io
import json
import struct
import time
import urllib.parse
from typing import Dict, List, Optional

from simulators.base_printer import BaseSimulator, PrinterProfile

# ── IPP operation codes ───────────────────────────────────────────────────────
IPP_GET_PRINTER_ATTRS = 0x000B
IPP_PRINT_JOB         = 0x0002
IPP_GET_JOBS          = 0x000A
IPP_CANCEL_JOB        = 0x0008
IPP_PURGE_JOBS        = 0x0012
IPP_PRINT_URI         = 0x0003

IPP_STATUS_OK                  = 0x0000
IPP_STATUS_CLIENT_FORBIDDEN    = 0x0401
IPP_STATUS_CLIENT_NOT_AUTH     = 0x0403
IPP_STATUS_SERVER_ERROR        = 0x0500


def _ipp_attr(tag: int, name: str, value: bytes) -> bytes:
    """Encode a single IPP attribute (simplified)."""
    name_b = name.encode()
    return struct.pack('>BHH', tag, len(name_b), len(name_b)) + name_b + struct.pack('>H', len(value)) + value


def _ipp_str(name: str, value: str, tag: int = 0x44) -> bytes:
    name_b = name.encode()
    value_b = value.encode()
    return struct.pack('>BH', tag, len(name_b)) + name_b + struct.pack('>H', len(value_b)) + value_b


def _build_ipp_response(op_id: int, req_id: int, status: int, attrs: bytes) -> bytes:
    """Build a minimal IPP response."""
    return struct.pack('>BBHH', 1, 1, status, req_id) + b'\x01' + attrs + b'\x03'


class _IPPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that processes IPP-over-HTTP requests."""

    server_version = 'IPP/1.1'
    sys_version    = ''

    def log_message(self, fmt: str, *args) -> None:
        self.server.simulator.log.debug(fmt, *args)

    def do_POST(self) -> None:
        sim: 'IPPSimulator' = self.server.simulator
        profile: PrinterProfile = sim.profile
        sim.stats['connections'] += 1

        length = int(self.headers.get('Content-Length', 0))
        body   = self.rfile.read(length) if length else b''

        if not body or len(body) < 8:
            self._send_ipp_error(0, 0x0400, "Bad Request")
            return

        version_major  = body[0]
        version_minor  = body[1]
        op_id          = struct.unpack('>H', body[2:4])[0]
        request_id     = struct.unpack('>I', body[4:8])[0]

        sim.stats['commands'] += 1
        sim.log.info("IPP op=0x%04X from %s", op_id, self.client_address[0])

        # ── Get-Printer-Attributes ─────────────────────────────────────────
        if op_id == IPP_GET_PRINTER_ATTRS:
            attrs = self._printer_attrs(profile)
            resp  = _build_ipp_response(op_id, request_id, IPP_STATUS_OK, attrs)
            self._send_ipp(resp)

        # ── Print-Job ──────────────────────────────────────────────────────
        elif op_id == IPP_PRINT_JOB:
            if not profile.vuln.get('anon_ipp_jobs'):
                self._send_ipp_error(request_id, IPP_STATUS_CLIENT_FORBIDDEN, "Authentication required")
                return
            sim._log_attack(self.client_address, 'IPP anonymous Print-Job accepted')
            profile.job_counter += 1
            job_id = profile.job_counter
            attrs  = _ipp_str('job-id', str(job_id), tag=0x21)
            attrs += _ipp_str('job-state', '3', tag=0x21)  # pending
            attrs += _ipp_str('job-state-reasons', 'none', tag=0x44)
            resp   = _build_ipp_response(op_id, request_id, IPP_STATUS_OK, attrs)
            self._send_ipp(resp)

        # ── Print-URI (SSRF vector) ────────────────────────────────────────
        elif op_id == IPP_PRINT_URI:
            if profile.vuln.get('ssrf_capable'):
                # Extract URI from body (simplified parse)
                uri_start = body.find(b'document-uri')
                uri = '(simulated SSRF target)'
                if uri_start != -1:
                    try:
                        uri_len = struct.unpack('>H', body[uri_start + 12 + 2:uri_start + 12 + 4])[0]
                        uri = body[uri_start + 12 + 4:uri_start + 12 + 4 + uri_len].decode('utf-8', errors='replace')
                    except Exception:
                        pass
                sim._log_attack(self.client_address, f'IPP Print-URI SSRF — target URI: {uri}')
            profile.job_counter += 1
            attrs = _ipp_str('job-id', str(profile.job_counter), tag=0x21)
            self._send_ipp(_build_ipp_response(op_id, request_id, IPP_STATUS_OK, attrs))

        # ── Get-Jobs ───────────────────────────────────────────────────────
        elif op_id == IPP_GET_JOBS:
            attrs = b''
            for jid in range(1, min(profile.job_counter + 1, 6)):
                attrs += _ipp_str('job-id', str(jid), tag=0x21)
                attrs += _ipp_str('job-name', f'Confidential-Job-{jid:03d}', tag=0x44)
                attrs += _ipp_str('job-state', '9', tag=0x21)  # completed
                attrs += _ipp_str('job-originating-user-name', 'jsmith', tag=0x44)
            self._send_ipp(_build_ipp_response(op_id, request_id, IPP_STATUS_OK, attrs))

        # ── Purge-Jobs (DoS) ───────────────────────────────────────────────
        elif op_id == IPP_PURGE_JOBS:
            if not profile.vuln.get('ipp_purge_anon'):
                self._send_ipp_error(request_id, IPP_STATUS_CLIENT_FORBIDDEN, "Forbidden")
                return
            sim._log_attack(self.client_address, 'IPP Purge-Jobs — all jobs deleted (DoS)')
            profile.job_counter = 0
            self._send_ipp(_build_ipp_response(op_id, request_id, IPP_STATUS_OK, b''))

        # ── Cancel-Job ─────────────────────────────────────────────────────
        elif op_id == IPP_CANCEL_JOB:
            sim._log_attack(self.client_address, 'IPP Cancel-Job')
            self._send_ipp(_build_ipp_response(op_id, request_id, IPP_STATUS_OK, b''))

        else:
            self._send_ipp_error(request_id, IPP_STATUS_SERVER_ERROR, "Unsupported operation")

    def do_GET(self) -> None:
        """Basic info endpoint."""
        sim: 'IPPSimulator' = self.server.simulator
        profile = sim.profile
        body = json.dumps({
            'make': profile.make,
            'model': profile.model,
            'firmware': profile.firmware,
            'serial': profile.serial,
            'ipp_endpoint': f'ipp://{self.server.server_address[0]}:{self.server.server_address[1]}/ipp/print',
        }).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _printer_attrs(self, profile: PrinterProfile) -> bytes:
        """Build IPP printer-attributes group (simplified)."""
        a  = _ipp_str('printer-name', f'{profile.make} {profile.model}')
        a += _ipp_str('printer-make-and-model', f'{profile.make} {profile.model}')
        a += _ipp_str('printer-info', f'{profile.make} {profile.model} — Lab Simulator')
        a += _ipp_str('printer-location', profile.location)
        a += _ipp_str('printer-firmware-string-version', profile.firmware, tag=0x44)
        a += _ipp_str('printer-serial-number', profile.serial, tag=0x44)
        a += _ipp_str('printer-state', '3', tag=0x21)  # idle
        a += _ipp_str('printer-state-reasons', 'none', tag=0x44)
        a += _ipp_str('printer-uuid', profile.uuid, tag=0x44)

        # document-format-supported
        for fmt in profile.doc_formats:
            a += _ipp_str('document-format-supported', fmt, tag=0x49)

        # printer-uri-supported
        host, port = self.server.server_address
        a += _ipp_str('printer-uri-supported', f'ipp://{host}:{port}/ipp/print', tag=0x45)

        return a

    def _send_ipp(self, data: bytes) -> None:
        self.send_response(200)
        self.send_header('Content-Type', 'application/ipp')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_ipp_error(self, req_id: int, status: int, msg: str) -> None:
        resp = _build_ipp_response(0, req_id, status,
                                   _ipp_str('status-message', msg, tag=0x41))
        self._send_ipp(resp)


class IPPSimulator(BaseSimulator):
    """IPP printer simulator over HTTP on TCP port 631."""

    PROTOCOL = 'IPP'

    def _make_server(self) -> http.server.HTTPServer:
        server = http.server.ThreadingHTTPServer((self.host, self.port), _IPPHandler)
        server.simulator = self
        return server
