#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — SNMP Simulator (UDP port 161)
==========================================
Minimal SNMPv1/v2c agent supporting:
  - GetRequest (0xA0): returns MIB values from profile
  - GetNextRequest (0xA1): walks the MIB table
  - SetRequest (0xA3): writes NVRAM / triggers reset if vuln enabled

Uses raw UDP socket (no pysnmp dependency) with simplified BER encoding.
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import socket
import threading
from typing import Dict, Optional, Tuple

from simulators.base_printer import BaseSimulator, PrinterProfile


# ── Minimal BER helpers ───────────────────────────────────────────────────────

def _tlv(tag: int, value: bytes) -> bytes:
    """Encode TLV (tag-length-value) in BER."""
    length = len(value)
    if length < 0x80:
        return bytes([tag, length]) + value
    elif length < 0x100:
        return bytes([tag, 0x81, length]) + value
    else:
        return bytes([tag, 0x82, (length >> 8) & 0xFF, length & 0xFF]) + value


def _ber_int(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b'\x00')
    out = b''
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    if out[0] & 0x80:
        out = b'\x00' + out
    return _tlv(0x02, out)


def _ber_string(s: str) -> bytes:
    return _tlv(0x04, s.encode('latin-1', errors='replace'))


def _ber_oid(oid_str: str) -> bytes:
    parts = [int(x) for x in oid_str.strip('.').split('.')]
    if len(parts) < 2:
        parts = [1, 3] + parts
    first = parts[0] * 40 + parts[1]
    out   = bytes([first])
    for n in parts[2:]:
        if n < 0x80:
            out += bytes([n])
        else:
            enc = []
            while n:
                enc.append(n & 0x7F)
                n >>= 7
            enc.reverse()
            out += bytes([(b | 0x80) for b in enc[:-1]] + [enc[-1]])
    return _tlv(0x06, out)


def _decode_oid(data: bytes, offset: int) -> Tuple[str, int]:
    """Decode BER OID, return (oid_string, next_offset)."""
    tag = data[offset]
    assert tag == 0x06, f"Expected OID tag 0x06, got 0x{tag:02X}"
    offset += 1
    length = data[offset]
    offset += 1
    oid_bytes = data[offset:offset+length]
    offset += length

    oid_parts = []
    first = oid_bytes[0]
    oid_parts += [str(first // 40), str(first % 40)]
    n = 0
    for b in oid_bytes[1:]:
        n = (n << 7) | (b & 0x7F)
        if not (b & 0x80):
            oid_parts.append(str(n))
            n = 0
    return '.'.join(oid_parts), offset


def _decode_community(pkt: bytes) -> Optional[str]:
    """Extract community string from SNMPv1/v2c packet."""
    try:
        if pkt[0] != 0x30:
            return None
        offset = 2 if pkt[1] < 0x80 else 4
        # version integer
        if pkt[offset] != 0x02:
            return None
        vlen = pkt[offset+1]
        offset += 2 + vlen
        # community string
        if pkt[offset] != 0x04:
            return None
        clen = pkt[offset+1]
        offset += 2
        return pkt[offset:offset+clen].decode('latin-1', errors='replace')
    except Exception:
        return None


class SNMPSimulator(BaseSimulator):
    """
    SNMPv1/v2c agent using raw UDP socket.
    Simulates printer MIBs and detects SET attacks.
    """

    PROTOCOL = 'SNMP'

    def start(self) -> 'SNMPSimulator':
        if self._running:
            return self
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.settimeout(1.0)
            self._sock.bind((self.host, self.port))
            self._running = True
            self._thread = threading.Thread(target=self._serve, daemon=True,
                                            name=f"SNMP-{self.port}")
            self._thread.start()
            self.log.info("Started SNMP simulator on %s:%d (UDP)", self.host, self.port)
        except OSError as exc:
            self.log.error("Failed to start SNMP on %d: %s", self.port, exc)
        return self

    def stop(self) -> None:
        self._running = False
        if hasattr(self, '_sock'):
            self._sock.close()

    def _serve(self) -> None:
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
                resp = self._handle_packet(data, addr)
                if resp:
                    self._sock.sendto(resp, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_packet(self, data: bytes, addr: tuple) -> Optional[bytes]:
        community = _decode_community(data)
        if community is None:
            return None

        self.stats['connections'] += 1
        self.stats['commands'] += 1
        self.log.info("SNMP from %s:%d community='%s'", addr[0], addr[1], community)

        # Find PDU type
        try:
            offset = 2 if data[1] < 0x80 else 4  # skip SEQUENCE
            # skip version
            v_len = data[offset+1]
            offset += 2 + v_len
            # skip community
            c_len = data[offset+1]
            offset += 2 + c_len
            pdu_type = data[offset]
        except IndexError:
            return None

        if pdu_type == 0xA0:  # GetRequest
            return self._handle_get(data, addr, community, offset)
        elif pdu_type == 0xA1:  # GetNextRequest
            return self._handle_getnext(data, addr, community, offset)
        elif pdu_type == 0xA3:  # SetRequest
            return self._handle_set(data, addr, community, offset)
        return None

    def _handle_get(self, data: bytes, addr: tuple, community: str, pdu_offset: int) -> bytes:
        """Return MIB values for requested OIDs."""
        profile = self.profile

        # Check community
        if community not in (profile.snmp_read, profile.snmp_write):
            self.log.warning("SNMP unknown community '%s' from %s", community, addr[0])

        resp_vars = b''
        try:
            pdu_len  = data[pdu_offset+1]
            pdu_body = data[pdu_offset+2:pdu_offset+2+pdu_len]
            req_id   = pdu_body[2:4]  # simplified: just grab bytes

            # Find variable-bindings SEQUENCE
            vb_offset = 0
            while vb_offset < len(pdu_body):
                if pdu_body[vb_offset] == 0x30:  # VarBindList
                    vb_offset += 2
                    break
                vb_offset += 1

            while vb_offset < len(pdu_body):
                if pdu_body[vb_offset] != 0x30:
                    break
                vb_len = pdu_body[vb_offset+1]
                vb_body = pdu_body[vb_offset+2:vb_offset+2+vb_len]
                vb_offset += 2 + vb_len

                try:
                    oid_str, _ = _decode_oid(vb_body, 0)
                except Exception:
                    continue

                value = profile.snmp_mibs.get(oid_str, '')
                if not value:
                    # Try to match any suffix
                    for k, v in profile.snmp_mibs.items():
                        if k.endswith(oid_str) or oid_str.endswith(k):
                            value = v
                            break

                if value:
                    resp_vars += _tlv(0x30, _ber_oid(oid_str) + _ber_string(value))
                else:
                    resp_vars += _tlv(0x30, _ber_oid(oid_str) + _tlv(0x05, b''))  # Null

        except Exception as exc:
            self.log.debug("SNMP GET parse error: %s", exc)
            resp_vars = _tlv(0x30, _ber_oid('1.3.6.1.2.1.1.1.0') +
                             _ber_string(f'{profile.make} {profile.model}'))

        return self._build_response(community, 0xA2, resp_vars)

    def _handle_getnext(self, data: bytes, addr: tuple, community: str, pdu_offset: int) -> bytes:
        """Walk MIB: return first MIB entry."""
        profile  = self.profile
        mibs     = list(profile.snmp_mibs.items())
        resp_vars = b''
        for oid, val in mibs[:5]:  # return first 5 for simplicity
            resp_vars += _tlv(0x30, _ber_oid(oid) + _ber_string(val))
        self._log_attack(addr, 'SNMP GetNext — MIB walk')
        return self._build_response(community, 0xA2, resp_vars)

    def _handle_set(self, data: bytes, addr: tuple, community: str, pdu_offset: int) -> bytes:
        """Handle SetRequest — detect factory reset and NVRAM writes."""
        profile = self.profile

        if community != profile.snmp_write:
            self.log.warning("SNMP SET with wrong community '%s' from %s", community, addr[0])
            if not profile.vuln.get('snmp_public_write'):
                return self._build_response(community, 0xA2, b'')

        # Factory reset OID: 1.3.6.1.2.1.43.5.1.1.3.1 = 4 (resetToNVRAM)
        if b'\x2b\x06\x01\x02\x01\x2b\x05\x01\x01\x03\x01' in data:
            if profile.vuln.get('snmp_factory_reset'):
                self._log_attack(addr, 'SNMP SET prtGeneralReset=4 — factory reset triggered!')
        else:
            self._log_attack(addr, 'SNMP SET — NVRAM write attempt')

        return self._build_response(community, 0xA2, b'')

    def _build_response(self, community: str, pdu_type: int, var_binds: bytes) -> bytes:
        pdu_body = (
            _ber_int(1234)    # request-id
            + _ber_int(0)     # error-status: noError
            + _ber_int(0)     # error-index
            + _tlv(0x30, var_binds)  # VarBindList
        )
        pdu  = _tlv(pdu_type, pdu_body)
        msg  = (
            _ber_int(1)             # version: SNMPv2c
            + _ber_string(community)
            + pdu
        )
        return _tlv(0x30, msg)
