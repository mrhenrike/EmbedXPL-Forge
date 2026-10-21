#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterXPL-Forge — Online Discovery Module
========================================
Structured dork-based discovery of exposed printers via 5 search engines:
  Shodan, Censys, FOFA, ZoomEye, Netlas.

Printer context is always implicit — user does not need to specify "printer".
At least one filter parameter is REQUIRED in all cases.
No engine will run a broad (unfiltered) search — ever.
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)

# ── Optional engine library imports ───────────────────────────────────────────

try:
    import shodan as _shodan_lib
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

try:
    from censys.search import CensysHosts
    CENSYS_AVAILABLE = True
except ImportError:
    CENSYS_AVAILABLE = False

try:
    import requests as _requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# FOFA — uses requests (no dedicated package required)
FOFA_AVAILABLE = REQUESTS_AVAILABLE

# ZoomEye — uses requests
ZOOMEYE_AVAILABLE = REQUESTS_AVAILABLE

# Netlas — official SDK or requests fallback
try:
    import netlas as _netlas_sdk
    NETLAS_SDK_AVAILABLE = True
except ImportError:
    NETLAS_SDK_AVAILABLE = False
NETLAS_AVAILABLE = REQUESTS_AVAILABLE or NETLAS_SDK_AVAILABLE


# ── Geographic region → ISO-3166-1 alpha-2 code map ─────────────────────────

_REGION_COUNTRIES: Dict[str, List[str]] = {
    'latin_america':   ['AR', 'BO', 'BR', 'CL', 'CO', 'CR', 'CU', 'DO', 'EC',
                        'GT', 'HN', 'MX', 'NI', 'PA', 'PE', 'PR', 'SV', 'UY', 'VE'],
    'south_america':   ['AR', 'BO', 'BR', 'CL', 'CO', 'EC', 'GY', 'PE', 'PY', 'SR', 'UY', 'VE'],
    'central_america': ['CR', 'GT', 'HN', 'MX', 'NI', 'PA', 'SV', 'BZ'],
    'north_america':   ['US', 'CA', 'MX'],
    'europe':          ['GB', 'DE', 'FR', 'IT', 'ES', 'PT', 'NL', 'BE', 'CH',
                        'AT', 'SE', 'NO', 'DK', 'FI', 'PL', 'CZ', 'HU', 'RO',
                        'BG', 'HR', 'GR', 'IE', 'SK', 'SI', 'EE', 'LT', 'LV'],
    'asia':            ['CN', 'JP', 'KR', 'IN', 'SG', 'MY', 'TH', 'VN', 'ID',
                        'PH', 'TW', 'HK', 'BD', 'PK', 'LK', 'MM'],
    'middle_east':     ['SA', 'AE', 'IL', 'TR', 'EG', 'IR', 'IQ', 'JO', 'KW', 'LB', 'QA', 'OM', 'BH', 'YE'],
    'africa':          ['ZA', 'NG', 'EG', 'KE', 'MA', 'TN', 'GH', 'ET', 'CI', 'TZ', 'SN', 'UG', 'CM'],
    'oceania':         ['AU', 'NZ', 'FJ', 'PG', 'WS', 'SB'],
    'north_africa':    ['EG', 'MA', 'TN', 'LY', 'DZ', 'SD'],
    'southeast_asia':  ['SG', 'MY', 'TH', 'VN', 'ID', 'PH', 'MM', 'KH', 'LA', 'BN'],
    'eastern_europe':  ['PL', 'CZ', 'HU', 'RO', 'BG', 'SK', 'UA', 'BY', 'MD', 'RS', 'BA', 'AL', 'MK'],
}

# Country name → ISO code (pt-BR and en-US)
_COUNTRY_NAME_TO_CODE: Dict[str, str] = {
    # Portuguese / Spanish
    'brasil': 'BR', 'brazil': 'BR',
    'argentina': 'AR',
    'mexico': 'MX', 'méxico': 'MX',
    'colombia': 'CO',
    'chile': 'CL',
    'peru': 'PE', 'perú': 'PE',
    'venezuela': 'VE',
    'equador': 'EC', 'ecuador': 'EC',
    'bolivia': 'BO',
    'paraguai': 'PY', 'paraguay': 'PY',
    'uruguai': 'UY', 'uruguay': 'UY',
    'cuba': 'CU',
    'costa rica': 'CR',
    'panama': 'PA', 'panamá': 'PA',
    'guatemala': 'GT',
    'honduras': 'HN',
    'el salvador': 'SV',
    'nicaragua': 'NI',
    'republica dominicana': 'DO', 'dominican republic': 'DO',
    # English
    'united states': 'US', 'usa': 'US', 'united states of america': 'US',
    'estados unidos': 'US',
    'canada': 'CA', 'canadá': 'CA',
    'united kingdom': 'GB', 'uk': 'GB', 'england': 'GB',
    'reino unido': 'GB',
    'germany': 'DE', 'alemanha': 'DE', 'deutschland': 'DE',
    'france': 'FR', 'franca': 'FR', 'frança': 'FR',
    'italy': 'IT', 'italia': 'IT', 'itália': 'IT',
    'spain': 'ES', 'espanha': 'ES', 'españa': 'ES',
    'portugal': 'PT',
    'netherlands': 'NL', 'holanda': 'NL', 'holland': 'NL',
    'belgium': 'BE', 'bélgica': 'BE',
    'switzerland': 'CH', 'suíça': 'CH',
    'austria': 'AT', 'áustria': 'AT',
    'sweden': 'SE', 'suécia': 'SE',
    'norway': 'NO', 'noruega': 'NO',
    'denmark': 'DK', 'dinamarca': 'DK',
    'finland': 'FI', 'finlândia': 'FI',
    'poland': 'PL', 'polônia': 'PL',
    'russia': 'RU', 'rússia': 'RU',
    'china': 'CN',
    'japan': 'JP', 'japão': 'JP',
    'south korea': 'KR', 'coreia do sul': 'KR',
    'india': 'IN',
    'australia': 'AU', 'austrália': 'AU',
    'new zealand': 'NZ', 'nova zelândia': 'NZ',
    'south africa': 'ZA', 'africa do sul': 'ZA',
    'nigeria': 'NG',
    'egypt': 'EG', 'egito': 'EG',
    'turkey': 'TR', 'turquia': 'TR',
    'israel': 'IL',
    'saudi arabia': 'SA', 'arabia saudita': 'SA',
    'united arab emirates': 'AE', 'emirates': 'AE', 'emirados arabes': 'AE',
    'singapore': 'SG', 'singapura': 'SG',
}

# Vendor name → canonical Shodan/Censys search strings
_VENDOR_SEARCH_TERMS: Dict[str, List[str]] = {
    'hp':            ['"HP LaserJet"', '"HP OfficeJet"', '"HP DeskJet"', '"HP Color LaserJet"', '"Hewlett-Packard"'],
    'epson':         ['"EPSON"', '"Epson"'],
    'ricoh':         ['"Ricoh"', '"Aficio"', '"RICOH"'],
    'xerox':         ['"Xerox"', '"Phaser"', '"WorkCentre"'],
    'brother':       ['"Brother"', '"BROTHER"'],
    'canon':         ['"Canon"', '"imageRUNNER"', '"CANON"'],
    'kyocera':       ['"Kyocera"', '"TASKalfa"', '"FS-"', '"KYOCERA"'],
    'konica':        ['"Konica Minolta"', '"bizhub"', '"KONICA MINOLTA"'],
    'samsung':       ['"Samsung"', '"SAMSUNG"'],
    'lexmark':       ['"Lexmark"', '"LEXMARK"'],
    'sharp':         ['"Sharp"', '"SHARP"', '"MX-"'],
    'oki':           ['"OKI"', '"OKIDATA"'],
    'toshiba':       ['"Toshiba"', '"TOSHIBA"', '"e-Studio"'],
    'fujifilm':      ['"Fujifilm"', '"Fuji Xerox"', '"FUJIFILM"'],
    'zebra':         ['"Zebra"', '"ZEBRA"'],
    'pantum':        ['"Pantum"', '"PANTUM"'],
    'sindoh':        ['"Sindoh"'],
    'develop':       ['"Develop"', '"ineo"'],
    'utax':          ['"UTAX"', '"Triumph-Adler"'],
    'dell':          ['"Dell"', '"DELL"'],
}

# Implicit printer-related Shodan filter terms (always appended)
_SHODAN_PRINTER_PORTS = '80,8080,9100,631,515,443,21'
_SHODAN_PRINTER_BASE = f'port:{_SHODAN_PRINTER_PORTS}'
_CENSYS_PRINTER_BASE = '(services.port=9100 OR services.port=515 OR services.port=631)'

# Port → protocol label
_PORT_LABELS = {9100: 'RAW/PJL', 515: 'LPD', 631: 'IPP', 80: 'HTTP-EWS', 443: 'HTTPS-EWS', 8080: 'HTTP-EWS', 21: 'FTP-PRINT'}

_PRINTER_PORTS = frozenset({21, 80, 443, 515, 631, 8080, 9100})

_PRINTER_BANNER_RE = re.compile(
    r'@PJL|HP HTTP Server|HP Printer|Epson_IPP|FTP Print Server|'
    r'LaserJet|DeskJet|OfficeJet|Officejet|RICOH|Aficio|EPSON|Epson|'
    r'Ready to Print|JetDirect|Embedded Web Server|_ipp\._tcp|_printer\._tcp|'
    r'Print Server|PJL INFO|IPP-Server',
    re.I,
)


@dataclass
class DiscoveryParams:
    """Structured parameters for a targeted online printer search."""
    vendors:   List[str]       = field(default_factory=list)   # e.g. ['epson', 'ricoh']
    model:     Optional[str]   = None                           # e.g. "deskjet pro 5500"
    countries: List[str]       = field(default_factory=list)   # ISO codes e.g. ['BR', 'AR']
    cities:    List[str]       = field(default_factory=list)   # e.g. ['Sao Paulo', 'Belem'] — single country only
    regions:   List[str]       = field(default_factory=list)   # e.g. ['latin_america']
    ports:     List[int]       = field(default_factory=list)   # e.g. [515, 9100]
    org:       Optional[str]   = None                           # e.g. "Telefonica"
    cpe:       Optional[str]   = None                           # Censys CPE e.g. "cpe:/h:hp:laserjet"
    limit:     int             = 100

    # ── backwards-compat shim: accept legacy `city` kwarg ──────────────────
    def __post_init__(self) -> None:
        """Normalise optional list fields that may arrive as None."""
        if self.vendors is None:
            self.vendors = []
        if self.countries is None:
            self.countries = []
        if self.cities is None:
            self.cities = []
        if self.regions is None:
            self.regions = []
        if self.ports is None:
            self.ports = []

    def has_filters(self) -> bool:
        """Returns True if at least one discovery filter was provided."""
        return bool(
            self.vendors or self.model or self.countries or
            self.cities or self.regions or self.ports or
            self.org or self.cpe
        )

    def resolve_country_codes(self) -> List[str]:
        """Resolve names to ISO codes and expand regions."""
        codes: Set[str] = set()
        for c in self.countries:
            normalized = c.strip().lower()
            if len(c) == 2 and c.upper() == c:
                codes.add(c.upper())
            elif normalized in _COUNTRY_NAME_TO_CODE:
                codes.add(_COUNTRY_NAME_TO_CODE[normalized])
            else:
                # Try partial match
                for name, code in _COUNTRY_NAME_TO_CODE.items():
                    if normalized in name or name in normalized:
                        codes.add(code)
                        break
        for region in self.regions:
            region_key = region.lower().replace('-', '_').replace(' ', '_')
            codes.update(_REGION_COUNTRIES.get(region_key, []))
        return sorted(codes)


class DorkQueryBuilder:
    """
    Builds structured Shodan and Censys dork queries from DiscoveryParams.

    Printer context is always implicit — user only provides filtering criteria.
    Supports multi-vendor, multi-country, region expansion, and CPE filtering.
    """

    def __init__(self, params: DiscoveryParams) -> None:
        self.params = params

    # ── Shodan ────────────────────────────────────────────────────────────────

    def build_shodan_queries(self) -> List[Dict[str, str]]:
        """
        Returns a list of Shodan query dicts: {query, description}.

        Each vendor generates its own query (API-efficient).
        If no vendor is specified, uses generic printer banner terms.
        Country/region/port/city are always appended as Shodan filters.
        """
        geo_part   = self._shodan_geo_part()
        port_part  = self._shodan_port_part()
        city_part  = self._shodan_city_part()
        org_part   = f' org:"{self.params.org}"' if self.params.org else ''
        model_part = f' "{self.params.model}"' if self.params.model else ''
        suffix     = f"{geo_part}{city_part}{org_part}{model_part}{port_part}"

        queries: List[Dict[str, str]] = []

        if self.params.vendors:
            for vendor in self.params.vendors:
                vendor_key = vendor.lower()
                search_terms = _VENDOR_SEARCH_TERMS.get(vendor_key, [f'"{vendor}"'])
                # Use the first 2 search terms per vendor to avoid too many queries
                for term in search_terms[:2]:
                    query = f"{term}{suffix}"
                    if not port_part:
                        query += f" {_SHODAN_PRINTER_BASE}"
                    queries.append({
                        'query': query,
                        'description': f"{vendor.title()} printers{self._geo_label()}",
                        'vendor': vendor,
                    })
        else:
            # Generic: use printer banner signatures
            generic_terms = [
                '"@PJL INFO"',
                '"@PJL USTATUS"',
                '"READY" port:9100',
                '"PJL"',
            ]
            for term in generic_terms:
                query = f"{term}{suffix}"
                if not port_part:
                    query += f" {_SHODAN_PRINTER_BASE}"
                queries.append({
                    'query': query.strip(),
                    'description': f"Generic printers{self._geo_label()}",
                    'vendor': None,
                })

        return queries

    def _shodan_geo_part(self) -> str:
        codes = self.params.resolve_country_codes()
        if not codes:
            return ''
        if len(codes) == 1:
            return f' country:{codes[0]}'
        # Multiple countries → join with OR in Shodan
        return ' (' + ' OR '.join(f'country:{c}' for c in codes) + ')'

    def _shodan_port_part(self) -> str:
        if not self.params.ports:
            return ''
        if len(self.params.ports) == 1:
            return f' port:{self.params.ports[0]}'
        return ' (' + ' OR '.join(f'port:{p}' for p in self.params.ports) + ')'

    def _shodan_city_part(self) -> str:
        if not self.params.cities:
            return ''
        if len(self.params.cities) == 1:
            return f' city:"{self.params.cities[0]}"'
        return ' (' + ' OR '.join(f'city:"{c}"' for c in self.params.cities) + ')'

    # ── Censys ────────────────────────────────────────────────────────────────

    def build_censys_queries(self) -> List[Dict[str, str]]:
        """Returns a list of Censys query dicts: {query, description}."""
        geo_part  = self._censys_geo_part()
        port_part = self._censys_port_part()
        city_part = self._censys_city_part()
        org_part  = f' AND autonomous_system.name="{self.params.org}"' if self.params.org else ''
        cpe_part  = f' AND services.software.uniform_resource_identifier="{self.params.cpe}"' if self.params.cpe else ''
        model_part = f' AND services.banner="{self.params.model}"' if self.params.model else ''
        suffix     = f"{geo_part}{city_part}{org_part}{cpe_part}{model_part}{port_part}"

        queries: List[Dict[str, str]] = []

        if self.params.vendors:
            for vendor in self.params.vendors:
                vendor_key = vendor.lower()
                raw_terms  = _VENDOR_SEARCH_TERMS.get(vendor_key, [f'"{vendor}"'])
                # Strip Shodan quoting style → Censys banner search
                censys_terms = [t.strip('"') for t in raw_terms[:2]]
                for term in censys_terms:
                    query = f'services.banner="{term}"{suffix}'
                    if not port_part:
                        # Append implicit printer port filter
                        query += f' AND ({_CENSYS_PRINTER_BASE.lstrip("(")}'
                    queries.append({
                        'query': query,
                        'description': f"{vendor.title()} printers (Censys){self._geo_label()}",
                        'vendor': vendor,
                    })
        else:
            generic_censys = [
                'services.banner="@PJL"',
                'services.banner="READY"',
            ]
            for term in generic_censys:
                query = f"{term}{suffix}"
                if not port_part:
                    query += f' AND {_CENSYS_PRINTER_BASE}'
                queries.append({
                    'query': query,
                    'description': f"Generic printers (Censys){self._geo_label()}",
                    'vendor': None,
                })

        return queries

    def _censys_geo_part(self) -> str:
        codes = self.params.resolve_country_codes()
        if not codes:
            return ''
        if len(codes) == 1:
            return f' AND location.country_code="{codes[0]}"'
        return ' AND (' + ' OR '.join(f'location.country_code="{c}"' for c in codes) + ')'

    def _censys_port_part(self) -> str:
        if not self.params.ports:
            return ''
        if len(self.params.ports) == 1:
            return f' AND services.port={self.params.ports[0]}'
        return ' AND (' + ' OR '.join(f'services.port={p}' for p in self.params.ports) + ')'

    def _censys_city_part(self) -> str:
        if not self.params.cities:
            return ''
        if len(self.params.cities) == 1:
            return f' AND location.city="{self.params.cities[0]}"'
        return ' AND (' + ' OR '.join(f'location.city="{c}"' for c in self.params.cities) + ')'

    # ── FOFA ──────────────────────────────────────────────────────────────────

    def build_fofa_queries(self) -> List[Dict[str, str]]:
        """
        Builds FOFA query strings.

        FOFA syntax: field="value" && field="value" || field="value"
        Fields: port, country, region, city, org, banner, header, protocol, app, product
        Query is base64-encoded before sending to the API.
        Implicit printer filter: at minimum port="9100" or banner="@PJL".
        """
        geo_part   = self._fofa_geo_part()
        port_part  = self._fofa_port_part()
        city_part  = self._fofa_city_part()
        org_part   = f' && org="{self.params.org}"' if self.params.org else ''
        model_part = f' && banner="{self.params.model}"' if self.params.model else ''
        suffix     = f"{geo_part}{city_part}{org_part}{model_part}{port_part}"

        queries: List[Dict[str, str]] = []

        if self.params.vendors:
            for vendor in self.params.vendors:
                vendor_key = vendor.lower()
                raw_terms  = _VENDOR_SEARCH_TERMS.get(vendor_key, [f'"{vendor}"'])
                # FOFA uses banner field for string matching
                fofa_terms = [t.strip('"') for t in raw_terms[:2]]
                for term in fofa_terms:
                    q = f'banner="{term}"{suffix}'
                    if not port_part:
                        q += ' && (port="9100" || port="515" || port="631")'
                    queries.append({
                        'query':       q,
                        'query_b64':   base64.b64encode(q.encode()).decode(),
                        'description': f"{vendor.title()} printers (FOFA){self._geo_label()}",
                        'vendor':      vendor,
                    })
        else:
            generic_terms = ['banner="@PJL"', 'banner="PJL READY"']
            for term in generic_terms:
                q = f'{term}{suffix}'
                if not port_part:
                    q += ' && (port="9100" || port="515")'
                queries.append({
                    'query':       q,
                    'query_b64':   base64.b64encode(q.encode()).decode(),
                    'description': f"Generic PJL printers (FOFA){self._geo_label()}",
                    'vendor':      None,
                })
        return queries

    def _fofa_geo_part(self) -> str:
        codes = self.params.resolve_country_codes()
        if not codes:
            return ''
        if len(codes) == 1:
            return f' && country="{codes[0]}"'
        return ' && (' + ' || '.join(f'country="{c}"' for c in codes) + ')'

    def _fofa_port_part(self) -> str:
        if not self.params.ports:
            return ''
        if len(self.params.ports) == 1:
            return f' && port="{self.params.ports[0]}"'
        return ' && (' + ' || '.join(f'port="{p}"' for p in self.params.ports) + ')'

    def _fofa_city_part(self) -> str:
        if not self.params.cities:
            return ''
        if len(self.params.cities) == 1:
            return f' && city="{self.params.cities[0]}"'
        return ' && (' + ' || '.join(f'city="{c}"' for c in self.params.cities) + ')'

    # ── ZoomEye ───────────────────────────────────────────────────────────────

    def build_zoomeye_queries(self) -> List[Dict[str, str]]:
        """
        Builds ZoomEye query strings.

        ZoomEye syntax: field:value +field:value (AND), -field:value (NOT)
        Fields: port, country, city, hostname, asn, org, app, ver, os, ssl, banner
        Note: country field uses full name or ISO code.
        """
        geo_part   = self._zoomeye_geo_part()
        port_part  = self._zoomeye_port_part()
        city_part  = self._zoomeye_city_part()
        org_part   = f' +org:"{self.params.org}"' if self.params.org else ''
        model_part = f' +banner:"{self.params.model}"' if self.params.model else ''
        suffix     = f"{geo_part}{city_part}{org_part}{model_part}{port_part}"

        queries: List[Dict[str, str]] = []

        if self.params.vendors:
            for vendor in self.params.vendors:
                vendor_key = vendor.lower()
                raw_terms  = _VENDOR_SEARCH_TERMS.get(vendor_key, [f'"{vendor}"'])
                zy_terms   = [t.strip('"') for t in raw_terms[:2]]
                for term in zy_terms:
                    q = f'banner:"{term}"{suffix}'
                    if not port_part:
                        q += ' +(port:9100 port:515 port:631)'
                    queries.append({
                        'query':       q,
                        'description': f"{vendor.title()} printers (ZoomEye){self._geo_label()}",
                        'vendor':      vendor,
                    })
        else:
            generic_terms = ['banner:"@PJL"', 'banner:"PJL READY"']
            for term in generic_terms:
                q = f'{term}{suffix}'
                if not port_part:
                    q += ' +(port:9100 port:515)'
                queries.append({
                    'query':       q,
                    'description': f"Generic PJL printers (ZoomEye){self._geo_label()}",
                    'vendor':      None,
                })
        return queries

    def _zoomeye_geo_part(self) -> str:
        codes = self.params.resolve_country_codes()
        if not codes:
            return ''
        if len(codes) == 1:
            return f' +country:"{codes[0]}"'
        # ZoomEye supports OR with multiple country: filters
        return ' +(' + ' '.join(f'country:"{c}"' for c in codes) + ')'

    def _zoomeye_port_part(self) -> str:
        if not self.params.ports:
            return ''
        if len(self.params.ports) == 1:
            return f' +port:{self.params.ports[0]}'
        return ' +(' + ' '.join(f'port:{p}' for p in self.params.ports) + ')'

    def _zoomeye_city_part(self) -> str:
        if not self.params.cities:
            return ''
        if len(self.params.cities) == 1:
            return f' +city:"{self.params.cities[0]}"'
        return ' +(' + ' '.join(f'city:"{c}"' for c in self.params.cities) + ')'

    # ── Netlas ────────────────────────────────────────────────────────────────

    def build_netlas_queries(self) -> List[Dict[str, str]]:
        """
        Builds Netlas Lucene queries.

        Verified field names (Netlas API 2026-03):
          port              port number
          geo.country       ISO-2 country code (e.g. "BR")
          geo.city          city name (string)
          isp               ISP/org name
          http.title        HTTP page title (for web-exposed printers)
          protocol          protocol name (e.g. "raw_tcp", "http")

        Note: raw TCP ports (9100, 515) have no text banner — vendor matching
        is done via http.title for web printers, or port-only for raw TCP.
        Ref: https://docs.netlas.io/knowledge-base/field-reference/responses/
        """
        geo_part   = self._netlas_geo_part()
        port_part  = self._netlas_port_part()
        city_part  = self._netlas_city_part()
        org_part   = f' AND isp:"{self.params.org}"' if self.params.org else ''
        # Model search uses http.title (web-exposed printers) when model specified
        model_part = f' AND http.title:"{self.params.model}"' if self.params.model else ''
        suffix     = f"{geo_part}{city_part}{org_part}{model_part}{port_part}"

        queries: List[Dict[str, str]] = []

        if self.params.vendors:
            for vendor in self.params.vendors:
                vendor_key = vendor.lower()
                raw_terms  = _VENDOR_SEARCH_TERMS.get(vendor_key, [f'"{vendor}"'])
                nl_terms   = [t.strip('"') for t in raw_terms[:1]]   # 1 term per vendor in Netlas
                for term in nl_terms:
                    # Try http.title (web-exposed printers) first, then pure port filter
                    q_web = f'http.title:"{term}"{suffix}'
                    if not port_part:
                        q_web += ' AND (port:80 OR port:443 OR port:631)'
                    queries.append({
                        'query':       q_web,
                        'description': f"{vendor.title()} printers via web (Netlas){self._geo_label()}",
                        'vendor':      vendor,
                    })
                    # Also add a port-only fallback (broader, for raw TCP printers)
                    q_port = f'(port:9100 OR port:515){suffix}'
                    queries.append({
                        'query':       q_port,
                        'description': f"{vendor.title()} raw-TCP printers (Netlas){self._geo_label()}",
                        'vendor':      vendor,
                    })
        else:
            # No vendor: just search by printer ports
            generic_terms = [
                ('(port:9100 OR port:515)',  'RAW/LPD printers'),
                ('(port:631 OR port:9100)',  'IPP/RAW printers'),
            ]
            for q_base, desc in generic_terms:
                q = f'{q_base}{suffix}'
                queries.append({
                    'query':       q,
                    'description': f"{desc} (Netlas){self._geo_label()}",
                    'vendor':      None,
                })
        return queries

    def _netlas_geo_part(self) -> str:
        codes = self.params.resolve_country_codes()
        if not codes:
            return ''
        if len(codes) == 1:
            return f' AND geo.country:{codes[0]}'
        return ' AND (' + ' OR '.join(f'geo.country:{c}' for c in codes) + ')'

    def _netlas_port_part(self) -> str:
        if not self.params.ports:
            return ''
        if len(self.params.ports) == 1:
            return f' AND port:{self.params.ports[0]}'
        return ' AND (' + ' OR '.join(f'port:{p}' for p in self.params.ports) + ')'

    def _netlas_city_part(self) -> str:
        if not self.params.cities:
            return ''
        if len(self.params.cities) == 1:
            return f' AND geo.city:"{self.params.cities[0]}"'
        return ' AND (' + ' OR '.join(f'geo.city:"{c}"' for c in self.params.cities) + ')'

    # ── Labels ────────────────────────────────────────────────────────────────

    def _geo_label(self) -> str:
        parts = []
        codes = self.params.resolve_country_codes()
        if codes:
            parts.append('/'.join(codes[:4]) + ('...' if len(codes) > 4 else ''))
        if self.params.cities:
            cities_label = '/'.join(self.params.cities[:3])
            if len(self.params.cities) > 3:
                cities_label += '...'
            parts.append(cities_label)
        if self.params.regions:
            parts.append('+'.join(self.params.regions))
        return (', ' + ', '.join(parts)) if parts else ''

    def describe(self) -> str:
        """Human-readable summary of the query being built."""
        parts = []
        if self.params.vendors:
            parts.append(f"vendors={','.join(self.params.vendors)}")
        if self.params.model:
            parts.append(f"model={self.params.model!r}")
        codes = self.params.resolve_country_codes()
        if codes:
            label = ','.join(codes[:6]) + ('...' if len(codes) > 6 else '')
            parts.append(f"countries=[{label}]")
        if self.params.cities:
            parts.append(f"cities=[{','.join(self.params.cities)}]")
        if self.params.regions:
            parts.append(f"regions={','.join(self.params.regions)}")
        if self.params.ports:
            labels = [_PORT_LABELS.get(p, str(p)) for p in self.params.ports]
            parts.append(f"ports={','.join(labels)}")
        if self.params.org:
            parts.append(f"org={self.params.org!r}")
        if self.params.cpe:
            parts.append(f"cpe={self.params.cpe!r}")
        return ' | '.join(parts) if parts else 'generic (all printers)'


# ── Result model ─────────────────────────────────────────────────────────────

@dataclass
class PrinterHit:
    """A single discovered printer from Shodan or Censys."""
    ip:           str
    port:         int
    source:       str
    country:      str  = ''
    country_code: str  = ''
    city:         str  = ''
    org:          str  = ''
    hostnames:    List[str] = field(default_factory=list)
    banner:       str  = ''
    product:      str  = ''
    version:      str  = ''
    vendor:       str  = ''
    timestamp:    str  = ''

    def to_dict(self) -> Dict:
        return self.__dict__.copy()


# ── Shodan search ─────────────────────────────────────────────────────────────

class ShodanSearcher:
    """Thin wrapper around the Shodan API with structured-query support."""

    def __init__(self, api_key: str) -> None:
        if not SHODAN_AVAILABLE:
            raise ImportError("shodan package not installed — pip install shodan")
        self._api = _shodan_lib.Shodan(api_key)

    def plan_info(self) -> Dict:
        try:
            return self._api.info()
        except Exception:
            return {}

    def search(self, query: str, limit: int = 100, vendor: str = '') -> List[PrinterHit]:
        hits: List[PrinterHit] = []
        try:
            _log.debug("Shodan query: %s", query)
            result = self._api.search(query, limit=limit)
            for m in result.get('matches', []):
                loc  = m.get('location', {})
                hits.append(PrinterHit(
                    ip           = m.get('ip_str', ''),
                    port         = m.get('port', 9100),
                    source       = 'shodan',
                    country      = loc.get('country_name', ''),
                    country_code = loc.get('country_code', ''),
                    city         = loc.get('city', ''),
                    org          = m.get('org', ''),
                    hostnames    = m.get('hostnames') or [],
                    banner       = (m.get('data', '') or '')[:600],
                    product      = m.get('product', ''),
                    version      = m.get('version', ''),
                    vendor       = vendor,
                    timestamp    = m.get('timestamp', ''),
                ))
        except _shodan_lib.APIError as exc:
            _log.warning("Shodan API error: %s", exc)
        except Exception as exc:
            _log.warning("Shodan search error: %s", exc)
        return hits


# ── Censys search ─────────────────────────────────────────────────────────────

class CensysSearcher:
    """Thin wrapper around Censys Hosts API with structured-query support."""

    def __init__(self, api_id: str, api_secret: str) -> None:
        if not CENSYS_AVAILABLE:
            raise ImportError("censys package not installed — pip install censys")
        self._api = CensysHosts(api_id, api_secret)

    def search(self, query: str, limit: int = 100, vendor: str = '') -> List[PrinterHit]:
        hits: List[PrinterHit] = []
        count = 0
        try:
            _log.debug("Censys query: %s", query)
            for page in self._api.search(query, per_page=min(100, limit), pages=-1):
                for host in page:
                    if count >= limit:
                        break
                    loc = host.get('location', {})
                    asn = host.get('autonomous_system', {})
                    svcs = host.get('services', [{}])
                    port = svcs[0].get('port', 9100) if svcs else 9100
                    hits.append(PrinterHit(
                        ip           = host.get('ip', ''),
                        port         = port,
                        source       = 'censys',
                        country      = loc.get('country', ''),
                        country_code = loc.get('country_code', ''),
                        city         = loc.get('city', ''),
                        org          = asn.get('name', ''),
                        hostnames    = host.get('names', []),
                        banner       = str(svcs[0])[:600] if svcs else '',
                        product      = '',
                        version      = '',
                        vendor       = vendor,
                        timestamp    = host.get('last_updated_at', ''),
                    ))
                    count += 1
                if count >= limit:
                    break
        except Exception as exc:
            _log.warning("Censys search error: %s", exc)
        return hits


# ── FOFA Searcher ─────────────────────────────────────────────────────────────

class FOFASearcher:
    """
    Wraps the FOFA API (fofa.info) for structured printer searches.

    API endpoint: GET https://fofa.info/api/v1/search/all
    Auth: API key only (email field was deprecated by FOFA in December 2023).
    Query must be base64-encoded.
    Docs: https://en.fofa.info/api
    """

    _BASE = "https://fofa.info/api/v1/search/all"
    _FIELDS = "ip,port,country,region,city,org,host,os,banner,server,product,version"

    def __init__(self, api_key: str, email: str = "") -> None:
        """Initialize FOFASearcher.

        Args:
            api_key: FOFA API key (required).
            email:   Ignored — FOFA deprecated email auth in December 2023.
        """
        if not REQUESTS_AVAILABLE:
            raise RuntimeError("'requests' library required for FOFA — pip install requests")
        self._api_key = api_key.strip()
        import requests as _r
        self._session = _r.Session()

    def search(self, params: 'DiscoveryParams', builder: 'DorkQueryBuilder') -> List['PrinterHit']:
        """Execute all FOFA dork queries derived from params."""
        hits:  List[PrinterHit] = []
        seen:  set              = set()
        limit  = params.limit
        queries = builder.build_fofa_queries()

        for qd in queries:
            if len(hits) >= limit:
                break
            q_b64 = qd.get('query_b64', base64.b64encode(qd['query'].encode()).decode())
            _log.debug("FOFA query: %s", qd['query'])
            try:
                resp = self._session.get(
                    self._BASE,
                    params={
                        'key':     self._api_key,
                        'qbase64': q_b64,
                        'fields':  self._FIELDS,
                        'size':    min(limit - len(hits), 100),
                        'page':    1,
                        'full':    'false',
                    },
                    timeout=20,
                )
                resp.raise_for_status()
                data = resp.json()
                if data.get('error'):
                    _log.warning("FOFA API error: %s", data.get('errmsg', 'unknown'))
                    continue
                for item in data.get('results') or []:
                    if len(hits) >= limit:
                        break
                    if not item:
                        continue
                    # results: [ip, port, country, region, city, org, host, os, banner, server, product, version]
                    ip = item[0] if len(item) > 0 else ''
                    if not ip or ip in seen:
                        continue
                    seen.add(ip)
                    hits.append(PrinterHit(
                        ip           = ip,
                        port         = int(item[1]) if len(item) > 1 and item[1] else 9100,
                        source       = 'fofa',
                        country      = item[2] if len(item) > 2 else '',
                        country_code = item[2] if len(item) > 2 else '',
                        city         = item[4] if len(item) > 4 else '',
                        org          = item[5] if len(item) > 5 else '',
                        hostnames    = [item[6]] if len(item) > 6 and item[6] else [],
                        banner       = item[8] if len(item) > 8 else '',
                        product      = item[10] if len(item) > 10 else '',
                        version      = item[11] if len(item) > 11 else '',
                        vendor       = qd.get('vendor'),
                        timestamp    = '',
                    ))
            except Exception as exc:
                _log.warning("FOFA search error (%s): %s", qd['query'][:60], exc)
        return hits


# ── ZoomEye Searcher ──────────────────────────────────────────────────────────

class ZoomEyeSearcher:
    """
    Wraps the ZoomEye API for structured printer searches.

    API endpoint: GET https://api.zoomeye.ai/host/search
    Auth: API-KEY header (preferred over deprecated JWT since 2025).
    Note: api.zoomeye.org redirects non-CN users to api.zoomeye.ai.
    Docs: https://www.zoomeye.ai/doc
    """

    _BASE = "https://api.zoomeye.ai/host/search"

    def __init__(self, api_key: str) -> None:
        if not REQUESTS_AVAILABLE:
            raise RuntimeError("'requests' library required for ZoomEye — pip install requests")
        self._api_key = api_key.strip()
        import requests as _r
        self._session = _r.Session()
        self._session.headers.update({
            'API-KEY':      self._api_key,
            'Content-Type': 'application/json',
        })

    def search(self, params: 'DiscoveryParams', builder: 'DorkQueryBuilder') -> List['PrinterHit']:
        """Execute all ZoomEye dork queries derived from params."""
        hits:  List[PrinterHit] = []
        seen:  set              = set()
        limit  = params.limit
        queries = builder.build_zoomeye_queries()

        for qd in queries:
            if len(hits) >= limit:
                break
            _log.debug("ZoomEye query: %s", qd['query'])
            try:
                page = 1
                while len(hits) < limit:
                    resp = self._session.get(
                        self._BASE,
                        params={
                            'query':    qd['query'],
                            'page':     page,
                            'pagesize': 20,
                        },
                        timeout=20,
                    )
                    resp.raise_for_status()
                    data  = resp.json()
                    items = data.get('matches', [])
                    if not items:
                        break
                    for item in items:
                        if len(hits) >= limit:
                            break
                        if not item:
                            continue
                        ip = item.get('ip', '')
                        if not ip or ip in seen:
                            continue
                        seen.add(ip)
                        geo   = item.get('geoinfo', {})
                        pinfo = item.get('portinfo', {})
                        hits.append(PrinterHit(
                            ip           = ip,
                            port         = int(pinfo.get('port', 9100)),
                            source       = 'zoomeye',
                            country      = geo.get('country', {}).get('name', ''),
                            country_code = geo.get('country', {}).get('code', ''),
                            city         = geo.get('city', {}).get('name', ''),
                            org          = geo.get('organization', ''),
                            hostnames    = [item.get('rdns', '')] if item.get('rdns') else [],
                            banner       = pinfo.get('banner', '')[:600],
                            product      = pinfo.get('app', ''),
                            version      = pinfo.get('ver', ''),
                            vendor       = qd.get('vendor'),
                            timestamp    = item.get('timestamp', ''),
                        ))
                    # ZoomEye free plan limited; stop after first page unless we have quota
                    if len(items) < 20:
                        break
                    page += 1
            except Exception as exc:
                msg = str(exc)
                if '402' in msg or 'credits' in msg.lower():
                    _log.warning("ZoomEye: insufficient API credits — upgrade plan at https://www.zoomeye.ai")
                    break
                _log.warning("ZoomEye search error (%s): %s", qd['query'][:60], exc)
        return hits


# ── Netlas Searcher ───────────────────────────────────────────────────────────

class NetlasSearcher:
    """
    Wraps the Netlas API (netlas.io) for structured printer searches.

    API endpoint: GET https://app.netlas.io/api/responses/
    Auth: X-API-Key header.
    Query syntax: Lucene (Elasticsearch-based).
    Docs: https://docs.netlas.io/
    """

    _BASE = "https://app.netlas.io/api/responses/"

    def __init__(self, api_key: str) -> None:
        if not REQUESTS_AVAILABLE:
            raise RuntimeError("'requests' library required for Netlas — pip install requests")
        self._api_key = api_key.strip()
        import requests as _r
        self._session = _r.Session()
        self._session.headers.update({'X-API-Key': self._api_key})

    def search(self, params: 'DiscoveryParams', builder: 'DorkQueryBuilder') -> List['PrinterHit']:
        """Execute all Netlas Lucene queries derived from params.

        Netlas field reference (verified 2026-03):
          geo.country        ISO-2 country code (e.g. "BR")
          geo.city           city name (string)
          port               port number (integer)
          isp                ISP name
          host               hostname/IP string
          @timestamp         scan timestamp
        """
        hits:  List[PrinterHit] = []
        seen:  set              = set()
        limit  = params.limit
        queries = builder.build_netlas_queries()

        for qd in queries:
            if len(hits) >= limit:
                break
            _log.debug("Netlas query: %s", qd['query'])
            try:
                resp = self._session.get(
                    self._BASE,
                    params={
                        'q':    qd['query'],
                        'size': min(limit - len(hits), 100),
                    },
                    timeout=60,    # Netlas can be slow on country-filtered queries
                )
                resp.raise_for_status()
                data  = resp.json()
                items = data.get('items', [])
                for item in items:
                    if len(hits) >= limit:
                        break
                    if not item:
                        continue
                    attrs = item.get('data') or {}
                    ip    = attrs.get('ip', '')
                    if not ip or ip in seen:
                        continue
                    seen.add(ip)
                    geo = attrs.get('geo', {})
                    hits.append(PrinterHit(
                        ip           = ip,
                        port         = int(attrs.get('port', 9100)),
                        source       = 'netlas',
                        country      = geo.get('country', ''),
                        country_code = geo.get('country', ''),
                        city         = geo.get('city', '') if isinstance(geo.get('city'), str) else '',
                        org          = attrs.get('isp', ''),
                        hostnames    = [attrs.get('host', '')] if attrs.get('host') else [],
                        banner       = '',        # raw TCP has no banner; HTTP captured separately
                        product      = '',
                        version      = '',
                        vendor       = qd.get('vendor'),
                        timestamp    = attrs.get('@timestamp', ''),
                    ))
            except Exception as exc:
                _log.warning("Netlas search error (%s): %s", qd['query'][:60], exc)
        return hits


# ── Manager (main public API) ─────────────────────────────────────────────────

class OnlineDiscoveryManager:
    """
    Orchestrates dork-based printer discovery across Shodan, Censys, FOFA, ZoomEye, Netlas.

    Usage:
        params = DiscoveryParams(vendors=['epson'], regions=['latin_america'], ports=[515])
        mgr    = OnlineDiscoveryManager()          # loads keys from config.json
        hits   = mgr.targeted_search(params, engines=['shodan','fofa'])
        mgr.print_results(hits)
    """

    # ── ANSI colours ──────────────────────────────────────────────────────────
    _GRN = '\033[0;32m'
    _YEL = '\033[1;33m'
    _CYN = '\033[1;36m'
    _RED = '\033[1;31m'
    _DIM = '\033[2;37m'
    _RST = '\033[0m'

    _ALL_ENGINES = ('shodan', 'censys', 'fofa', 'zoomeye', 'netlas')

    def __init__(self,
                 shodan_key:     Optional[str] = None,
                 censys_id:      Optional[str] = None,
                 censys_secret:  Optional[str] = None,
                 fofa_key:       Optional[str] = None,
                 zoomeye_key:    Optional[str] = None,
                 netlas_key:     Optional[str] = None) -> None:

        # Load credentials from config when not passed directly
        try:
            from utils.config import (load_config, shodan_key as _sk, censys_credentials,
                                       fofa_key as _fk, zoomeye_key as _zk, netlas_key as _nk)
            load_config()
            if not shodan_key:
                shodan_key = _sk()
            if not (censys_id and censys_secret):
                censys_id, censys_secret = censys_credentials()
            if not fofa_key:
                fofa_key = _fk()
            if not zoomeye_key:
                zoomeye_key = _zk()
            if not netlas_key:
                netlas_key = _nk()
        except Exception:
            pass

        self._shodan:   Optional[ShodanSearcher]   = None
        self._censys:   Optional[CensysSearcher]   = None
        self._fofa:     Optional[FOFASearcher]     = None
        self._zoomeye:  Optional[ZoomEyeSearcher]  = None
        self._netlas:   Optional[NetlasSearcher]   = None
        self._hits:     List[PrinterHit]            = []

        if shodan_key:
            try:
                self._shodan = ShodanSearcher(shodan_key)
                _log.info("Shodan API initialized")
            except Exception as exc:
                print(f"  {self._YEL}[!]{self._RST} Shodan init failed: {exc}")

        if censys_id and censys_secret:
            try:
                self._censys = CensysSearcher(censys_id, censys_secret)
                _log.info("Censys API initialized")
            except Exception as exc:
                print(f"  {self._YEL}[!]{self._RST} Censys init failed: {exc}")

        if fofa_key:
            try:
                self._fofa = FOFASearcher(api_key=fofa_key)
                _log.info("FOFA API initialized")
            except Exception as exc:
                print(f"  {self._YEL}[!]{self._RST} FOFA init failed: {exc}")

        if zoomeye_key:
            try:
                self._zoomeye = ZoomEyeSearcher(zoomeye_key)
                _log.info("ZoomEye API initialized")
            except Exception as exc:
                print(f"  {self._YEL}[!]{self._RST} ZoomEye init failed: {exc}")

        if netlas_key:
            try:
                self._netlas = NetlasSearcher(netlas_key)
                _log.info("Netlas API initialized")
            except Exception as exc:
                print(f"  {self._YEL}[!]{self._RST} Netlas init failed: {exc}")

    # ── Public entry points ───────────────────────────────────────────────────

    def _available_engines(self) -> Dict[str, object]:
        """Return a dict of engine_name -> searcher for all initialized engines."""
        return {k: v for k, v in {
            'shodan':  self._shodan,
            'censys':  self._censys,
            'fofa':    self._fofa,
            'zoomeye': self._zoomeye,
            'netlas':  self._netlas,
        }.items() if v is not None}

    @staticmethod
    def _is_printer_hit(hit: 'PrinterHit') -> bool:
        """Drop Shodan noise (SQL, SMB, random honeypots) unless banner looks like a printer."""
        if hit.port in _PRINTER_PORTS:
            return bool(_PRINTER_BANNER_RE.search(hit.banner or hit.product or ''))
        if hit.port == 5353:
            return bool(_PRINTER_BANNER_RE.search(hit.banner or ''))
        return bool(_PRINTER_BANNER_RE.search(hit.banner or hit.product or ''))

    def targeted_search(self,
                        params:  DiscoveryParams,
                        engines: Optional[List[str]] = None) -> List['PrinterHit']:
        """
        Run a structured dork search using provided parameters.

        Args:
            params:  Filter criteria (vendor, country, port, etc.).
            engines: Whitelist of engine names to use, e.g. ['shodan','fofa'].
                     Defaults to all initialized engines.

        Raises:
            ValueError: if params.has_filters() returns False.
        Returns:
            Deduplicated list of PrinterHit, sorted by country + IP.
        """
        if not params.has_filters():
            raise ValueError(
                "At least one discovery filter is required: --dork-vendor, --dork-country, "
                "--dork-city, --dork-region, --dork-port, --dork-org, --dork-cpe, or --dork-model\n"
                "When searching without geographic/vendor filters, provide a direct IP target instead."
            )

        active = self._available_engines()
        if engines:
            active = {k: v for k, v in active.items()
                      if k in [e.lower().strip() for e in engines]}

        builder = DorkQueryBuilder(params)
        print(f"\n  {self._CYN}{'='*68}{self._RST}")
        print(f"  {self._CYN}Online Printer Discovery — Dork Mode{self._RST}")
        print(f"  Filter : {builder.describe()}")
        print(f"  Engines: {', '.join(active.keys()) or 'none configured'}")
        print(f"  Limit  : {params.limit} results per query")
        print(f"  {self._CYN}{'='*68}{self._RST}\n")

        all_hits: List[PrinterHit] = []
        delay = 1.2  # seconds between API calls

        _ENGINE_DISPATCH = {
            'shodan':  self._run_shodan,
            'censys':  self._run_censys,
            'fofa':    self._run_fofa,
            'zoomeye': self._run_zoomeye,
            'netlas':  self._run_netlas,
        }

        for eng_name, _searcher in active.items():
            hits = _ENGINE_DISPATCH[eng_name](builder, params)
            all_hits.extend(hits)
            time.sleep(delay)

        if not active:
            print(f"  {self._RED}[!]{self._RST} No API credentials configured.")
            print("      Add keys to config.json — see: python pxf.py --check-config")
            return []

        # Deduplicate by IP:port and drop non-printer noise
        seen: Set[Tuple[str, int]] = set()
        unique: List[PrinterHit] = []
        dropped = 0
        for h in all_hits:
            if not self._is_printer_hit(h):
                dropped += 1
                continue
            key = (h.ip, h.port)
            if key not in seen:
                seen.add(key)
                unique.append(h)

        if dropped:
            print(f"  {self._DIM}Filtered {dropped} non-printer hit(s){self._RST}")

        unique.sort(key=lambda h: (h.country_code, h.ip))
        self._hits = unique
        return unique

    # ── Per-engine runners ────────────────────────────────────────────────────

    def _run_shodan(self, builder: 'DorkQueryBuilder', params: DiscoveryParams) -> List['PrinterHit']:
        if not self._shodan:
            return []
        queries = builder.build_shodan_queries()
        print(f"  {self._GRN}[Shodan]{self._RST} {len(queries)} quer{'y' if len(queries)==1 else 'ies'}")
        hits: List[PrinterHit] = []
        for idx, q in enumerate(queries, 1):
            print(f"    [{idx}/{len(queries)}] {q['description']}")
            print(f"           {self._DIM}{q['query']}{self._RST}")
            h = self._shodan.search(q['query'], limit=params.limit, vendor=q.get('vendor', ''))
            print(f"           Found: {self._GRN}{len(h)}{self._RST}")
            hits.extend(h)
            if idx < len(queries):
                time.sleep(1.2)
        return hits

    def _run_censys(self, builder: 'DorkQueryBuilder', params: DiscoveryParams) -> List['PrinterHit']:
        if not self._censys:
            return []
        queries = builder.build_censys_queries()
        print(f"  {self._GRN}[Censys]{self._RST} {len(queries)} quer{'y' if len(queries)==1 else 'ies'}")
        hits: List[PrinterHit] = []
        for idx, q in enumerate(queries, 1):
            print(f"    [{idx}/{len(queries)}] {q['description']}")
            print(f"           {self._DIM}{q['query']}{self._RST}")
            h = self._censys.search(q['query'], limit=params.limit, vendor=q.get('vendor', ''))
            print(f"           Found: {self._GRN}{len(h)}{self._RST}")
            hits.extend(h)
            if idx < len(queries):
                time.sleep(1.2)
        return hits

    def _run_fofa(self, builder: 'DorkQueryBuilder', params: DiscoveryParams) -> List['PrinterHit']:
        if not self._fofa:
            return []
        queries = builder.build_fofa_queries()
        print(f"  {self._GRN}[FOFA]{self._RST} {len(queries)} quer{'y' if len(queries)==1 else 'ies'}")
        hits = self._fofa.search(params, builder)
        print(f"         Found: {self._GRN}{len(hits)}{self._RST}")
        for q in queries:
            print(f"    Query: {self._DIM}{q['query']}{self._RST}")
        return hits

    def _run_zoomeye(self, builder: 'DorkQueryBuilder', params: DiscoveryParams) -> List['PrinterHit']:
        if not self._zoomeye:
            return []
        queries = builder.build_zoomeye_queries()
        print(f"  {self._GRN}[ZoomEye]{self._RST} {len(queries)} quer{'y' if len(queries)==1 else 'ies'}")
        hits = self._zoomeye.search(params, builder)
        print(f"           Found: {self._GRN}{len(hits)}{self._RST}")
        for q in queries:
            print(f"    Query: {self._DIM}{q['query']}{self._RST}")
        return hits

    def _run_netlas(self, builder: 'DorkQueryBuilder', params: DiscoveryParams) -> List['PrinterHit']:
        if not self._netlas:
            return []
        queries = builder.build_netlas_queries()
        print(f"  {self._GRN}[Netlas]{self._RST} {len(queries)} quer{'y' if len(queries)==1 else 'ies'}")
        hits = self._netlas.search(params, builder)
        print(f"          Found: {self._GRN}{len(hits)}{self._RST}")
        for q in queries:
            print(f"    Query: {self._DIM}{q['query']}{self._RST}")
        return hits

    def print_results(self, hits: List[PrinterHit]) -> None:
        """Print a formatted table of discovered printers."""
        if not hits:
            print(f"  {self._YEL}[!]{self._RST} No printers found matching the given filters.")
            return

        print(f"\n  {self._CYN}{'='*68}{self._RST}")
        print(f"  {self._CYN}Results — {len(hits)} unique printer(s) found{self._RST}")
        print(f"  {self._CYN}{'='*68}{self._RST}")
        print(f"  {'IP':<16} {'Port':<6} {'CC':<4} {'City':<18} {'Org':<28} {'Src':<8}")
        print(f"  {'-'*68}")

        for h in hits:
            port_label = _PORT_LABELS.get(h.port, str(h.port))
            org_short  = (h.org[:26] + '..') if len(h.org) > 28 else h.org
            city_short = (h.city[:16] + '..') if len(h.city) > 18 else h.city
            print(f"  {self._GRN}{h.ip:<16}{self._RST} {port_label:<6} {h.country_code:<4} "
                  f"{city_short:<18} {org_short:<28} {h.source}")

        print()
        # Country stats
        by_cc: Dict[str, int] = defaultdict(int)
        for h in hits:
            by_cc[h.country_code or '??'] += 1
        stat_line = '  '.join(f"{cc}:{n}" for cc, n in sorted(by_cc.items(), key=lambda x: -x[1])[:10])
        print(f"  Distribution: {stat_line}")
        print()

    def export_results(self, hits: List[PrinterHit], output_path: Optional[str] = None) -> Optional[str]:
        """Export results to JSON. Returns path to saved file."""
        if not hits:
            return None
        ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
        path = output_path or f'.log/discovery_{ts}.json'
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        data = {
            'generated': datetime.now().isoformat(),
            'total':     len(hits),
            'results':   [h.to_dict() for h in hits],
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        print(f"  {self._GRN}[+]{self._RST} Results saved to {path}")
        return path

    # ── Legacy compatibility shim (for old --discover-online without dorks) ───

    def discover(self, max_results_per_query: int = 100,
                 delay_between_queries: float = 1.2,
                 use_shodan: bool = True,
                 use_censys: bool = True) -> Dict:
        """
        Legacy broad discovery (no filters).
        Deprecated — use targeted_search(DiscoveryParams(...)) instead.
        """
        params = DiscoveryParams(
            vendors=list(_VENDOR_SEARCH_TERMS.keys())[:6],
            ports=[9100],
            limit=max_results_per_query,
        )
        hits = self.targeted_search(params)
        self.print_results(hits)
        self.export_results(hits)
        return {'total_devices': len(hits), 'timestamp': datetime.now().isoformat()}
