#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterXPL-Forge — Vulnerability Scanner
=======================================
Matches printer fingerprints against known CVEs with strict specificity levels:

  Level 0 — Exact:   make + model + firmware match
  Level 1 — Model:   make + model match (any firmware)
  Level 2 — Series:  make + model-family/series match
  Level 3 — Vendor:  make only — clearly labelled as generic vendor advisory
  Level 4 — Generic: applies to all printers regardless of vendor (PJL, SNMP…)

Results are presented separately by specificity level.
If nothing is found for levels 0–2, the report says so explicitly.
Generic (vendor-wide and protocol) advisories are shown in a separate section.

NVD API v2 queries use targeted CPE-style keywords to reduce false positives.
Only CVEs whose description or references mention the specific model/series
are promoted to the model-specific section; the rest are shown as "related vendor
advisories" with a clear note.
"""

# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

import requests
import urllib3

urllib3.disable_warnings()

# Local CVE catalog — consulted before NVD API for offline / faster lookups
try:
    from utils.cve_loader import lookup as _local_cve_lookup, filter_by as _local_filter
except ImportError:
    try:
        from cve_loader import lookup as _local_cve_lookup, filter_by as _local_filter
    except ImportError:
        _local_cve_lookup = None  # type: ignore
        _local_filter = None  # type: ignore

_log = logging.getLogger(__name__)

NVD_API   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY = 0.7   # rate-limit: 5 req/30 s without key


# ── Specificity levels ────────────────────────────────────────────────────────

class Specificity(IntEnum):
    EXACT         = 0   # make + model + firmware
    MODEL         = 1   # make + model
    SERIES        = 2   # make + model family (e.g. "L-series EcoTank")
    VENDOR        = 3   # make only
    GENERIC       = 4   # any printer (PJL, SNMP, IPP, …)


SPECIFICITY_LABEL = {
    Specificity.EXACT:   'exact match (make+model+firmware)',
    Specificity.MODEL:   'model match (make+model)',
    Specificity.SERIES:  'series match (product family)',
    Specificity.VENDOR:  'vendor advisory (make only — may not affect this model)',
    Specificity.GENERIC: 'generic printer advisory (protocol-level)',
}


# ── CVE dataclasses ───────────────────────────────────────────────────────────

@dataclass
class CVEEntry:
    """A single CVE record with specificity context."""
    cve_id:          str
    description:     str
    cvss_score:      float
    cvss_version:    str
    severity:        str
    published:       str
    modified:        str
    specificity:     Specificity    = Specificity.GENERIC
    references:      List[str]      = field(default_factory=list)
    source:          str            = 'nvd'
    exploitable:     bool           = False
    exploit_info:    str            = ''
    affected_product:str            = ''

    def __str__(self) -> str:
        return (f"{self.cve_id} [{self.severity} {self.cvss_score}] "
                f"[{SPECIFICITY_LABEL[self.specificity]}] "
                f"{self.description[:80]}")


@dataclass
class VulnReport:
    """Complete vulnerability report for a printer target."""
    host:       str
    make:       str
    model:      str
    firmware:   str

    # CVEs grouped by specificity level
    specific_cves: List[CVEEntry]  = field(default_factory=list)  # levels 0–2
    vendor_cves:   List[CVEEntry]  = field(default_factory=list)  # level 3
    generic_cves:  List[CVEEntry]  = field(default_factory=list)  # level 4
    misconfigs:    List[str]       = field(default_factory=list)
    risk_score:    float           = 0.0
    summary:       str             = ''

    @property
    def all_cves(self) -> List[CVEEntry]:
        return self.specific_cves + self.vendor_cves + self.generic_cves

    @property
    def critical(self) -> List[CVEEntry]:
        return [c for c in self.all_cves if c.severity.upper() in ('CRITICAL', 'HIGH')]

    @property
    def exploitable(self) -> List[CVEEntry]:
        return [c for c in self.all_cves if c.exploitable]


# ── Built-in CVE database ─────────────────────────────────────────────────────
# Schema:
#   make_pattern  : regex matched against printer make ('' = any)
#   model_pattern : regex matched against printer model ('' = any)
#   fw_pattern    : regex matched against firmware version ('' = any)
#   specificity   : Specificity enum level
#   cve_id        : CVE or internal ID
#   cvss          : CVSS base score
#   severity      : 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
#   description   : One-line description
#   exploitable   : bool
#   exploit_info  : PoC / exploitation notes (if exploitable)

_BUILTIN: List[Tuple] = [
    # ── EPSON L-series / EcoTank (L3250 family) ─────────────────────────────
    ('EPSON', r'L3\d{3}|L[34][12]\d{2}|EcoTank', '',
     Specificity.SERIES,
     'CVE-2021-26598', 6.1, 'MEDIUM',
     'EPSON EcoTank / L-series: CSRF in web management allows printer '
     'configuration change without user interaction.',
     False, ''),

    ('EPSON', r'L3\d{3}|L[34][12]\d{2}|EcoTank', '',
     Specificity.SERIES,
     'CVE-2022-3426', 5.4, 'MEDIUM',
     'EPSON EcoTank / L-series: unauthenticated access to device information '
     'page exposes IP, MAC, serial number, and firmware version.',
     True, 'HTTP GET /PRESENTATION/HTML/TOP/PRTINFO.HTML — no auth required'),

    ('EPSON', r'L3\d{3}|L[34][12]\d{2}|EcoTank', '',
     Specificity.SERIES,
     'CVE-2023-27516', 7.5, 'HIGH',
     'EPSON EcoTank L-series: LPD port 515 accepts unauthenticated print jobs '
     'with no size or content validation (DoS + data exfiltration vector).',
     True, 'Send arbitrary data to TCP 515 — no credentials required'),

    # ── EPSON general ────────────────────────────────────────────────────────
    ('EPSON', '', '',
     Specificity.VENDOR,
     'CVE-2019-3948', 9.8, 'CRITICAL',
     'EPSON network printers: unauthenticated arbitrary command execution via '
     'crafted LPD (port 515) print job. Affects multiple EPSON WorkForce and '
     'EcoTank models across multiple firmware generations.',
     True, 'Craft malicious LPD job to port 515; no authentication required'),

    ('EPSON', '', '',
     Specificity.VENDOR,
     'CVE-2019-3949', 7.5, 'HIGH',
     'EPSON printers: stored XSS in web admin interface via printer name or '
     'location field. Affects most EPSON models with a web management page.',
     False, 'Requires write access to web admin (may need default credentials)'),

    ('EPSON', '', '',
     Specificity.VENDOR,
     'CVE-2021-44228', 10.0, 'CRITICAL',
     'Log4Shell (Log4j RCE): EPSON EcoTank cloud services backend may be '
     'affected; embedded printer firmware itself is typically NOT vulnerable '
     'as it does not run Java. Assess the cloud/remote management service.',
     False, 'Unlikely on the printer device itself; assess EPSON cloud backend'),

    # ── HP LaserJet ─────────────────────────────────────────────────────────
    ('HP', r'LaserJet', '',
     Specificity.SERIES,
     'CVE-2011-4161', 10.0, 'CRITICAL',
     'HP LaserJet: PJL FSDOWNLOAD allows unauthenticated arbitrary file read '
     'from the printer filesystem (passwords, configs).',
     True, '@PJL FSDOWNLOAD FORMAT:BINARY SIZE=<n> NAME="0:/file"'),

    ('HP', r'LaserJet', '',
     Specificity.SERIES,
     'CVE-2023-1329', 9.8, 'CRITICAL',
     'HP LaserJet Pro: buffer overflow via PJL allows unauthenticated RCE. '
     'Affected: firmware < 20230209.',
     True, 'HPSEC-2023-002; send crafted PJL to port 9100'),

    ('HP', '', '',
     Specificity.VENDOR,
     'CVE-2017-2741', 9.8, 'CRITICAL',
     'HP PageWide and OfficeJet Pro: arbitrary code execution via malformed '
     'print job. PoC: Exploit-DB EDB-44292.',
     True, 'EDB-44292; crafted job to port 9100'),

    # ── Brother ──────────────────────────────────────────────────────────────
    ('Brother', '', '',
     Specificity.VENDOR,
     'CVE-2017-16249', 9.1, 'CRITICAL',
     'Brother network printers: unauthenticated LPD print job allows PostScript '
     'execution via port 515.',
     True, 'Send PS payload via LPD to port 515 — no credentials'),

    # ── Ricoh ────────────────────────────────────────────────────────────────
    ('Ricoh', r'Aficio|MP', '',
     Specificity.SERIES,
     'CVE-2019-14318', 9.8, 'CRITICAL',
     'Ricoh Aficio/MP series: command injection via device management web API.',
     True, 'Craft HTTP request to management REST API endpoint'),

    # ── Xerox ────────────────────────────────────────────────────────────────
    ('Xerox', r'WorkCentre|Phaser', '',
     Specificity.SERIES,
     'CVE-2018-9071', 7.5, 'HIGH',
     'Xerox WorkCentre/Phaser: directory traversal in web server (port 80) '
     'allows reading arbitrary files.',
     True, 'GET /../../etc/passwd on port 80'),

    # ── Generic PJL (any printer supporting PJL) ──────────────────────────
    ('', '', '',
     Specificity.GENERIC,
     'CVE-2014-3741', 7.8, 'HIGH',
     'Generic PJL: path traversal via FSDOWNLOAD/FSUPLOAD allows reading '
     'printer filesystem (admin passwords, certificates, configs). '
     'Applicable to any printer that responds to @PJL commands on port 9100.',
     True, '@PJL FSDOWNLOAD FORMAT:BINARY SIZE=<n> NAME="0:/../../../etc/passwd"'),

    # ── Generic SNMP (any printer with SNMP public community) ────────────────
    ('', '', '',
     Specificity.GENERIC,
     'CWE-284-SNMP', 6.5, 'MEDIUM',
     'Generic SNMP: default "public" community string (SNMP v1/v2c) allows '
     'unauthenticated read of full MIB — device info, interface table, job '
     'counters, and sometimes print spooler data.',
     False, 'snmpwalk -v2c -c public <host>'),

    # ── Generic IPP (AirPrint / IPP-Everywhere) ───────────────────────────
    ('', '', '',
     Specificity.GENERIC,
     'CVE-2017-18190', 7.5, 'HIGH',
     'Generic IPP/AirPrint: unauthenticated job submission to CUPS/IPP port 631 '
     'when IPP-Everywhere or AirPrint is enabled with no access control. '
     'Allows printing arbitrary content without credentials.',
     True, 'Send IPP Print-Job to port 631; no credentials — RFC 8011 §4.2.1'),
]


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


# ── CPE / keyword normalization ───────────────────────────────────────────────

def _build_nvd_queries(
    make: str, model: str, firmware: str,
) -> List[Tuple[str, Specificity]]:
    """
    Build a list of (keyword, specificity) pairs for NVD API queries.

    Returns queries ordered from most specific to least specific.
    Only queries that have enough information are included.
    """
    queries: List[Tuple[str, Specificity]] = []
    m  = make.strip()
    mo = model.strip()
    fw = firmware.strip()

    # Level 0: exact — make + model + firmware
    if m and mo and fw:
        queries.append((f"{m} {mo} {fw}", Specificity.EXACT))

    # Level 1: model — make + model
    if m and mo:
        # Remove trailing "Series" and extra spaces for cleaner search
        mo_clean = re.sub(r'\s+series\s*$', '', mo, flags=re.I).strip()
        queries.append((f"{m} {mo_clean}", Specificity.MODEL))

    # Level 2: series — extract family identifier (e.g. "L3250" → "L3 series")
    if m and mo:
        family = _extract_model_family(mo)
        if family and family.lower() != mo_clean.lower() if 'mo_clean' in dir() else True:
            queries.append((f"{m} {family}", Specificity.SERIES))

    return queries


def _extract_model_family(model: str) -> str:
    """
    Extract a product family/series name from a model string.

    Examples:
      'L3250 Series' → 'L3 EcoTank'
      'LaserJet P3015' → 'LaserJet'
      'WorkCentre 7845' → 'WorkCentre'
      'MFC-L8900CDW' → 'MFC-L'
    """
    # EPSON L-series EcoTank: L3250, L3150, L4260, etc.
    m = re.match(r'L([0-9])[0-9]{2,3}', model)
    if m:
        return f"L{m.group(1)} EcoTank"

    # HP: LaserJet, OfficeJet, PageWide, DeskJet, DesignJet
    m = re.match(r'(LaserJet|OfficeJet|PageWide|DeskJet|DesignJet|Photosmart)', model, re.I)
    if m:
        return m.group(1)

    # Brother: MFC-L, HL-L, DCP-
    m = re.match(r'(MFC-L|HL-L|DCP-|MFC-J)', model, re.I)
    if m:
        return m.group(1)

    # Xerox: WorkCentre, Phaser, VersaLink
    m = re.match(r'(WorkCentre|Phaser|VersaLink|AltaLink)', model, re.I)
    if m:
        return m.group(1)

    # Ricoh: MP, Aficio, SP
    m = re.match(r'(Aficio MP|MP C|SP C|SP [0-9])', model, re.I)
    if m:
        return m.group(1)

    # Kyocera: FS, ECOSYS, TASKalfa
    m = re.match(r'(ECOSYS|TASKalfa|FS-)', model, re.I)
    if m:
        return m.group(1)

    return ''


def _cve_mentions_model(desc: str, make: str, model: str) -> bool:
    """
    Return True if a CVE description/text explicitly mentions the target model.

    Uses a loose match: any of the significant tokens from make/model must
    appear near each other in the description.
    """
    text  = desc.lower()
    make  = make.lower().strip()
    model = model.lower().strip()

    # Extract significant model tokens (skip 'series', 'series', numbers only)
    model_parts = [p for p in re.split(r'[\s\-_/]+', model)
                   if len(p) >= 2 and not p.isdigit() and p not in ('series', 'printer')]

    if make and make in text:
        if not model_parts:
            return True
        for part in model_parts:
            if part in text:
                return True

    return False


def _catalog_applies_to_model(entry: dict, make: str, model: str) -> bool:
    """Skip enterprise-only catalog entries on consumer inkjet/MFP models."""
    product = entry.get('product', '').lower()
    model_l = f"{make} {model}".lower()
    if not product or not model_l.strip():
        return True

    consumer_kw = ('deskjet', 'officejet', 'envy', 'photosmart', 'smart tank')
    enterprise_kw = (
        'laserjet enterprise', 'pagewide', 'futuresmart', 'laserjet managed',
        'enterprise mfp', 'color laserjet enterprise',
    )

    is_consumer = any(k in model_l for k in consumer_kw)
    is_enterprise_product = any(k in product for k in enterprise_kw)

    if is_consumer and is_enterprise_product:
        return False
    return True


# ── NVD API ───────────────────────────────────────────────────────────────────

def _query_nvd(
    keyword: str,
    specificity: Specificity,
    make: str,
    model: str,
    api_key: str = '',
    max_results: int = 15,
) -> List[CVEEntry]:
    """
    Query NVD API v2 and return CVEEntry list filtered by model relevance.

    CVEs whose description mentions the specific model are promoted to the
    given specificity; others are demoted to VENDOR or skipped entirely.
    """
    headers = {'Accept': 'application/json'}
    if api_key:
        headers['apiKey'] = api_key

    params = {
        'keywordSearch': keyword,
        'resultsPerPage': max_results,
        'startIndex': 0,
    }
    entries: List[CVEEntry] = []
    try:
        r = requests.get(NVD_API, params=params, headers=headers, timeout=15)
        if r.status_code == 403:
            _log.warning("NVD rate limit — add nvd.api_key to config.json for higher limits")
            return []
        if r.status_code != 200:
            _log.debug("NVD returned %d for %r", r.status_code, keyword)
            return []

        for vuln in r.json().get('vulnerabilities', []):
            item   = vuln.get('cve', {})
            cve_id = item.get('id', 'CVE-?')
            descs  = item.get('descriptions', [])
            desc   = next((d['value'] for d in descs if d.get('lang') == 'en'), '')

            # CVSS scoring (v3.1 → v3.0 → v2.0)
            metrics    = item.get('metrics', {})
            cvss_score = 0.0
            cvss_ver   = 'N/A'
            severity   = 'UNKNOWN'
            for v_key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                v_list = metrics.get(v_key, [])
                if v_list:
                    cv         = v_list[0].get('cvssData', {})
                    cvss_score = float(cv.get('baseScore', 0))
                    cvss_ver   = cv.get('version', '')
                    severity   = (cv.get('baseSeverity') or
                                  v_list[0].get('baseSeverity', 'UNKNOWN'))
                    break

            refs = [ref['url'] for ref in item.get('references', [])[:4]]

            # Determine effective specificity for this NVD result:
            # If the description mentions the specific model → keep requested level
            # Otherwise → demote to VENDOR (generic vendor advisory)
            if specificity <= Specificity.MODEL and not _cve_mentions_model(desc, make, model):
                effective_specificity = Specificity.VENDOR
            else:
                effective_specificity = specificity

            entries.append(CVEEntry(
                cve_id           = cve_id,
                description      = desc[:300],
                cvss_score       = cvss_score,
                cvss_version     = cvss_ver,
                severity         = severity.upper(),
                published        = item.get('published', '')[:10],
                modified         = item.get('lastModified', '')[:10],
                specificity      = effective_specificity,
                references       = refs,
                source           = 'nvd',
                affected_product = f"{make} {model}".strip(),
            ))

    except requests.Timeout:
        _log.warning("NVD API timed out for %r", keyword)
    except Exception as exc:
        _log.warning("NVD query error for %r: %s", keyword, exc)

    return entries


# ── Built-in CVE matching ─────────────────────────────────────────────────────

def _match_builtin(
    make: str, model: str, firmware: str,
) -> Tuple[List[CVEEntry], List[CVEEntry], List[CVEEntry]]:
    """
    Match built-in CVE entries.

    Returns (specific_cves, vendor_cves, generic_cves).
    """
    specific: List[CVEEntry] = []
    vendor:   List[CVEEntry] = []
    generic:  List[CVEEntry] = []

    for row in _BUILTIN:
        (make_pat, model_pat, fw_pat, spec,
         cve_id, cvss, severity, desc, exploitable, exploit_info) = row

        # Empty pattern = matches anything
        if make_pat  and not re.search(make_pat,  make,     re.I): continue
        if model_pat and not re.search(model_pat, model,    re.I): continue
        if fw_pat    and not re.search(fw_pat,    firmware, re.I): continue

        entry = CVEEntry(
            cve_id           = cve_id,
            description      = desc,
            cvss_score       = cvss,
            cvss_version     = '3.1',
            severity         = severity,
            published        = '',
            modified         = '',
            specificity      = spec,
            source           = 'builtin',
            exploitable      = exploitable,
            exploit_info     = exploit_info,
            affected_product = f"{make} {model}".strip(),
        )

        if spec <= Specificity.SERIES:
            specific.append(entry)
        elif spec == Specificity.VENDOR:
            vendor.append(entry)
        else:
            generic.append(entry)

    return specific, vendor, generic


# ── Misconfiguration checks ───────────────────────────────────────────────────

def _check_misconfigs(
    open_ports:    List[int],
    printer_langs: List[str],
    snmp_descr:    str,
    doc_formats:   List[str],
) -> List[str]:
    """Return list of detected misconfiguration advisory strings."""
    mc    = []
    ports = set(open_ports)
    langs = [l.upper() for l in printer_langs]

    if 161 in ports:
        mc.append(
            "[SNMP] Default 'public' community string likely active — "
            "exposes device MIB (run: snmpwalk -v2c -c public <host>)"
        )
    if 9100 in ports and 'PJL' in langs:
        mc.append(
            "[PJL] Port 9100 + PJL active — no authentication; "
            "@PJL FSDOWNLOAD/FSUPLOAD can read/write printer filesystem"
        )
    if 9100 in ports and any(l in langs for l in ('PS', 'POSTSCRIPT', 'BR-SCRIPT')):
        mc.append(
            "[PostScript] Port 9100 + PS active — unauthenticated code "
            "execution via crafted PS payload"
        )
    if 515 in ports:
        mc.append(
            "[LPD] Port 515 open — unauthenticated print jobs accepted; "
            "DoS and data exfiltration vector"
        )
    if 631 in ports:
        mc.append(
            "[IPP] Port 631 open — verify authentication is enforced; "
            "AirPrint/IPP-Everywhere may allow anonymous job submission"
        )
    if 80 in ports or 443 in ports:
        mc.append(
            "[WEB] Web management interface exposed — verify default "
            "credentials changed (common: admin/admin, admin/<blank>)"
        )
    if snmp_descr:
        mc.append(f"[SNMP] Device info disclosed: {snmp_descr[:80]}")
    return mc


def _filter_generic_cves(
    generic:       List[CVEEntry],
    open_ports:    List[int],
    printer_langs: List[str],
    snmp_descr:    str = '',
) -> List[CVEEntry]:
    """Drop protocol-level advisories when the required port/lang is absent."""
    ports = set(open_ports or [])
    langs = {l.upper() for l in (printer_langs or [])}
    if not ports and not snmp_descr:
        return []

    out: List[CVEEntry] = []
    for cve in generic:
        blob = f"{cve.cve_id} {cve.description}".lower()
        if 'pjl' in blob or 'fsdownload' in blob:
            if 9100 in ports and ('PJL' in langs or not langs):
                out.append(cve)
        elif 'ipp' in blob or 'airprint' in blob:
            if 631 in ports:
                out.append(cve)
        elif 'snmp' in blob:
            if 161 in ports or snmp_descr:
                out.append(cve)
        elif 'lpd' in blob or 'port 515' in blob:
            if 515 in ports:
                out.append(cve)
        elif ports:
            out.append(cve)
    return out


# ── Risk scoring ──────────────────────────────────────────────────────────────

def _compute_risk(
    specific: List[CVEEntry],
    vendor:   List[CVEEntry],
    generic:  List[CVEEntry],
    misconfigs: List[str],
) -> float:
    """
    Compute risk score 0.0–10.0.

    Weights:
      - Specific CVEs (model/series): full weight
      - Vendor CVEs:                  50% weight (may not apply)
      - Generic CVEs:                 30% weight
      - Misconfigs:                   +0.3 each, capped at 2.0
    """
    def _top3_avg(cves: List[CVEEntry], weight: float) -> float:
        scores = sorted([c.cvss_score for c in cves], reverse=True)[:3]
        if not scores:
            return 0.0
        return (scores[0] * 0.60 + (scores[1] if len(scores) > 1 else 0) * 0.30 +
                (scores[2] if len(scores) > 2 else 0) * 0.10) * weight

    base = (_top3_avg(specific, 1.00) +
            _top3_avg(vendor,   0.50) +
            _top3_avg(generic,  0.30))
    bonus = min(len(misconfigs) * 0.3, 2.0)
    return min(round(base + bonus, 1), 10.0)


# ── Main entry point ──────────────────────────────────────────────────────────

def scan(
    host:          str,
    make:          str       = '',
    model:         str       = '',
    firmware:      str       = '',
    open_ports:    List[int] = None,
    printer_langs: List[str] = None,
    snmp_descr:    str       = '',
    doc_formats:   List[str] = None,
    nvd_api_key:   str       = '',
    use_nvd:       bool      = True,
    use_builtin:   bool      = True,
    verbose:       bool      = False,
) -> VulnReport:
    """
    Run a complete, specificity-aware vulnerability scan for the given printer.

    Results are divided into:
      - specific_cves: CVEs that specifically mention this make+model+firmware
      - vendor_cves:   CVEs for this vendor that may or may not apply
      - generic_cves:  Protocol-level advisories (PJL, SNMP, IPP)

    Args:
        host:          Printer IP/hostname.
        make:          Manufacturer string (e.g. 'EPSON').
        model:         Model string (e.g. 'L3250 Series').
        firmware:      Firmware version string.
        open_ports:    Open TCP port list.
        printer_langs: Supported printer language list.
        snmp_descr:    SNMP sysDescr value.
        doc_formats:   IPP document-format-supported list.
        nvd_api_key:   NVD API key for higher rate limits.
        use_nvd:       Query the NVD API.
        use_builtin:   Check built-in CVE database.
        verbose:       Print progress.
    """
    open_ports    = open_ports    or []
    printer_langs = printer_langs or []
    doc_formats   = doc_formats   or []

    spec_cves: List[CVEEntry] = []
    vend_cves: List[CVEEntry] = []
    gen_cves:  List[CVEEntry] = []

    # ── Built-in database ─────────────────────────────────────────────────────
    if use_builtin:
        s, v, g = _match_builtin(make, model, firmware)
        if verbose and (s or v):
            print(f"  [+] Built-in DB: {len(s)} specific, {len(v)} vendor, {len(g)} generic")
        spec_cves.extend(s)
        vend_cves.extend(v)
        gen_cves.extend(g)

    # ── Local CVE catalog (cve_catalog.json) ──────────────────────────────────
    if _local_filter is not None and (make or model):
        catalog_hits = _local_filter(vendor=make or None, poc_only=False)
        seen_local: set = {e.cve_id for e in spec_cves + vend_cves + gen_cves}
        for entry in catalog_hits:
            cid = entry.get("id", "")
            if cid in seen_local:
                continue
            if not _catalog_applies_to_model(entry, make, model):
                continue
            seen_local.add(cid)
            cvss_v = float(entry.get("cvss", 0.0))
            catalog_entry = CVEEntry(
                cve_id=cid,
                description=entry.get("description", ""),
                cvss_score=cvss_v,
                cvss_version="3.1",
                severity=_cvss_to_severity(cvss_v),
                published=f"{entry.get('year', 0)}-01-01T00:00:00.000",
                modified=f"{entry.get('year', 0)}-01-01T00:00:00.000",
                specificity=Specificity.VENDOR,
                references=entry.get("references", []),
                source="local_catalog",
                exploitable=bool(entry.get("poc_available")),
                exploit_info=f"xpl: {entry.get('xpl_module', '')}  msf: {entry.get('msf_module', '')}",
                affected_product=entry.get("product", ""),
            )
            vend_cves.append(catalog_entry)
        if verbose:
            print(f"  [+] Local Catalog: {len(catalog_hits)} entries for vendor '{make}'")

    # ── NVD API ───────────────────────────────────────────────────────────────
    if use_nvd and (make or model):
        queries = _build_nvd_queries(make, model, firmware)
        seen_ids: set = set()

        for keyword, spec_level in queries:
            if verbose:
                print(f"  [*] NVD query [{spec_level.name}]: {keyword!r}", end='', flush=True)
            results = _query_nvd(keyword, spec_level, make, model, nvd_api_key)
            if verbose:
                print(f" → {len(results)} results")

            for cve in results:
                if cve.cve_id in seen_ids:
                    continue
                seen_ids.add(cve.cve_id)
                if cve.specificity <= Specificity.SERIES:
                    spec_cves.append(cve)
                elif cve.specificity == Specificity.VENDOR:
                    vend_cves.append(cve)
                else:
                    gen_cves.append(cve)

            time.sleep(NVD_DELAY)

    # Deduplicate within each group (prefer builtin over NVD for exploit info)
    def _dedup(lst: List[CVEEntry]) -> List[CVEEntry]:
        seen: Dict[str, CVEEntry] = {}
        for e in lst:
            if e.cve_id not in seen or e.source == 'builtin':
                seen[e.cve_id] = e
        return sorted(seen.values(), key=lambda c: c.cvss_score, reverse=True)

    spec_cves = _dedup(spec_cves)
    vend_cves = _dedup(vend_cves)
    gen_cves  = _dedup(gen_cves)
    gen_cves  = _filter_generic_cves(gen_cves, open_ports, printer_langs, snmp_descr)

    # ── Misconfigurations ──────────────────────────────────────────────────────
    misconfigs = _check_misconfigs(open_ports, printer_langs, snmp_descr, doc_formats)

    # ── Risk score ─────────────────────────────────────────────────────────────
    risk = _compute_risk(spec_cves, vend_cves, gen_cves, misconfigs)

    # ── Summary ─────────────────────────────────────────────────────────────
    target_str = ' '.join(filter(None, [make, model, firmware])) or host
    if spec_cves:
        spec_note = f"{len(spec_cves)} specific to {target_str}"
    else:
        spec_note = f"NONE specific to {target_str}"

    summary = (f"{target_str} | {spec_note} | "
               f"{len(vend_cves)} vendor advisory | "
               f"{len(gen_cves)} generic | "
               f"risk={risk}/10 | {len(misconfigs)} misconfigs")

    return VulnReport(
        host          = host,
        make          = make,
        model         = model,
        firmware      = firmware,
        specific_cves = spec_cves,
        vendor_cves   = vend_cves,
        generic_cves  = gen_cves,
        misconfigs    = misconfigs,
        risk_score    = risk,
        summary       = summary,
    )


# ── Pretty print ─────────────────────────────────────────────────────────────

def print_report(report: VulnReport) -> None:
    """Pretty-print a VulnReport to stdout with clear specificity sections."""
    SEV_COLOR = {
        'CRITICAL': '\033[1;31m',
        'HIGH':     '\033[0;31m',
        'MEDIUM':   '\033[1;33m',
        'LOW':      '\033[1;34m',
        'UNKNOWN':  '\033[2;37m',
    }
    R = '\033[0m'

    def _section(title: str, cves: List[CVEEntry], note: str = '') -> None:
        if not cves:
            return
        print(f"\n  ── {title} {'─'*(55 - len(title))}")
        if note:
            print(f"  \033[2;37m{note}{R}")
        print(f"  {'CVE ID':<22} {'Score':>5}  {'Sev':<9} {'Expl.'}")
        print(f"  {'-'*60}")
        for cve in cves[:20]:
            sev   = cve.severity.upper()
            color = SEV_COLOR.get(sev, '')
            exp   = '\033[1;31mYES *\033[0m' if cve.exploitable else 'no'
            print(f"  {color}{cve.cve_id:<22} {cve.cvss_score:>5.1f}  {sev:<9}{R} {exp}")
            print(f"     {cve.description[:80]}")
            if cve.exploitable and cve.exploit_info:
                print(f"     \033[1;31m>> {cve.exploit_info[:78]}\033[0m")

    target = ' '.join(filter(None, [report.make, report.model, report.firmware]))
    print(f"\n{'='*65}")
    print(f"  VULNERABILITY REPORT — {report.host}")
    print(f"{'='*65}")
    print(f"  Target   : {target or report.host}")
    print(f"  Risk     : {report.risk_score}/10.0")
    print(f"  Summary  : {report.summary}")

    # ── Model-specific CVEs ─────────────────────────────────────────────────
    if report.specific_cves:
        _section(
            f"CVEs specific to {target}",
            report.specific_cves,
        )
    else:
        target_str = target or report.host
        print(f"\n  \033[0;32m[OK]\033[0m No CVEs found specifically for {target_str!r} "
              f"in the built-in DB or NVD.")
        print("       (Vendor advisories and generic advisories may still apply — see below.)")

    # ── Vendor advisories ───────────────────────────────────────────────────
    if report.vendor_cves:
        _section(
            f"Vendor advisories ({report.make} — may not affect this specific model)",
            report.vendor_cves,
            note="These CVEs affect some models from this vendor but "
                 "applicability to this specific model was not confirmed.",
        )

    # ── Generic advisories ──────────────────────────────────────────────────
    if report.generic_cves:
        _section(
            "Protocol/generic advisories (apply based on open ports and languages)",
            report.generic_cves,
            note="These advisories apply to any printer supporting the identified "
                 "protocols (PJL, SNMP, IPP, LPD). Verify which are active.",
        )

    # ── Misconfigurations ────────────────────────────────────────────────────
    if report.misconfigs:
        print(f"\n  ── Misconfigurations ({len(report.misconfigs)}) {'─'*35}")
        for mc in report.misconfigs:
            print(f"  \033[1;33m[!]\033[0m {mc}")

    print()
