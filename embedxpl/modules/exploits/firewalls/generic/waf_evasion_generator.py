#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""WAF evasion generator from Apache and Nginx bad-bot blocklist analysis.

Parses the Apache Ultimate Bad Bot Blocker and Nginx Ultimate Bad Bot Blocker
blocklist configuration files to extract blocked user-agents and referrers,
then generates safe / non-blocked user-agent rotation candidates for WAF
evasion research and red-team engagements.

Blocklist sources auto-discovered from the SOC submodule path:
    submodules/SOC/apache-ultimate-bad-bot-blocker/Apache_2.4/custom.d/globalblacklist.conf
    submodules/SOC/nginx-ultimate-bad-bot-blocker/conf.d/globalblacklist.conf

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from embedxpl.core.exploit import (
    Exploit,
    OptBool,
    OptString,
    print_error,
    print_info,
    print_status,
    print_success,
    print_table,
)

logger = logging.getLogger(__name__)

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# SOC submodule auto-discovery anchored to the repo root
# ---------------------------------------------------------------------------
_MODULE_FILE = Path(__file__).resolve()
# Walk up to find the firewallxpl package root, then the workspace root
_REPO_ROOT = _MODULE_FILE.parent
for _ in range(8):
    if (_REPO_ROOT / "firewallxpl").is_dir():
        break
    _REPO_ROOT = _REPO_ROOT.parent

_SOC_ROOT = _REPO_ROOT.parent.parent / "SOC"

_APACHE_DEFAULT = (
    _SOC_ROOT
    / "apache-ultimate-bad-bot-blocker"
    / "Apache_2.4"
    / "custom.d"
    / "globalblacklist.conf"
)
_NGINX_DEFAULT = (
    _SOC_ROOT
    / "nginx-ultimate-bad-bot-blocker"
    / "conf.d"
    / "globalblacklist.conf"
)

# ---------------------------------------------------------------------------
# Curated safe / benign user-agents that are never blocked by the lists
# These represent real production browsers and well-known safe crawlers.
# ---------------------------------------------------------------------------
_SAFE_BROWSER_UAS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Googlebot-Image/1.0; +http://www.google.com/bot.html)",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Slurp; http://help.yahoo.com/help/us/ysearch/slurp",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Twitterbot/1.0",
    "LinkedInBot/1.0 (compatible; Mozilla/5.0; Jakarta Commons-HttpClient/3.1 +http://www.linkedin.com)",
    "python-requests/2.31.0",
    "curl/7.88.1",
    "Wget/1.21.4 (linux-gnu)",
    "Go-http-client/2.0",
    "Java/17.0.11",
    "Apache-HttpClient/4.5.14 (Java/17.0.11)",
    "okhttp/4.12.0",
]

# ---------------------------------------------------------------------------
# Data container
# ---------------------------------------------------------------------------

@dataclass
class BlocklistData:
    """Parsed blocklist data from Apache or Nginx configuration.

    Attributes:
        source_path: Absolute path of the parsed configuration file.
        blocked_uas: Set of exact or regex-pattern user-agent strings marked as bad.
        blocked_referrers: Set of referrer patterns marked as spam.
        good_uas: Set of user-agent strings explicitly allowed (good_bot / whitelist).
        raw_line_count: Total number of non-comment, non-empty lines parsed.
        server: Server type detected ("apache" or "nginx").
    """

    source_path: Path
    blocked_uas: Set[str] = field(default_factory=set)
    blocked_referrers: Set[str] = field(default_factory=set)
    good_uas: Set[str] = field(default_factory=set)
    raw_line_count: int = 0
    server: str = "unknown"

    @property
    def blocked_ua_count(self) -> int:
        return len(self.blocked_uas)

    @property
    def blocked_ref_count(self) -> int:
        return len(self.blocked_referrers)

    @property
    def good_ua_count(self) -> int:
        return len(self.good_uas)


# ---------------------------------------------------------------------------
# Apache parser
# ---------------------------------------------------------------------------

# Matches: SetEnvIfNoCase User-Agent ~*<pattern> bad_bot
_APACHE_UA_BAD_RE = re.compile(
    r'(?i)SetEnvIfNoCase\s+User-Agent\s+~\*(?P<pattern>[^\s]+)\s+bad_bot', re.MULTILINE
)
# Matches: BrowserMatchNoCase "..." good_bot
_APACHE_UA_GOOD_RE = re.compile(
    r'(?i)BrowserMatchNoCase\s+"(?P<pattern>[^"]+)"\s+good_bot', re.MULTILINE
)
# Matches: SetEnvIfNoCase Referer ~*<pattern> spam_ref
_APACHE_REF_RE = re.compile(
    r'(?i)SetEnvIfNoCase\s+Referer\s+~\*(?P<pattern>[^\s]+)\s+spam_ref', re.MULTILINE
)


def parse_apache_blocklist(path: Path) -> BlocklistData:
    """Parse an Apache Ultimate Bad Bot Blocker globalblacklist.conf.

    Extracts:
        - Blocked UA patterns (SetEnvIfNoCase User-Agent ~* ... bad_bot)
        - Allowed UA patterns (BrowserMatchNoCase "..." good_bot)
        - Blocked referrers (SetEnvIfNoCase Referer ~* ... spam_ref)

    Args:
        path: Absolute path to the Apache globalblacklist.conf file.

    Returns:
        Populated BlocklistData instance.

    Raises:
        FileNotFoundError: If the configuration file does not exist.
        OSError: If the file cannot be read.
    """
    path = Path(path).resolve()
    if not path.exists():
        raise FileNotFoundError("Apache blocklist not found: {}".format(path))

    text = path.read_text(encoding="utf-8", errors="replace")
    data = BlocklistData(source_path=path, server="apache")
    data.raw_line_count = sum(1 for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#"))

    for m in _APACHE_UA_BAD_RE.finditer(text):
        raw = m.group("pattern").strip()
        data.blocked_uas.add(_clean_pattern(raw))

    for m in _APACHE_UA_GOOD_RE.finditer(text):
        raw = m.group("pattern").strip()
        data.good_uas.add(_clean_pattern(raw))

    for m in _APACHE_REF_RE.finditer(text):
        raw = m.group("pattern").strip()
        data.blocked_referrers.add(_clean_pattern(raw))

    return data


# ---------------------------------------------------------------------------
# Nginx parser
# ---------------------------------------------------------------------------

# Matches: "~*(?:\b)SomeThing(?:\b)"   3;
_NGINX_MAP_ENTRY_RE = re.compile(
    r'"~\*\(\?:\\b\)(?P<pattern>[^(]+)\(\?:\\b\)"\s+(?P<score>\d+);'
)

# Also capture simple entries without word boundaries: "~*SomeThing"  <score>;
_NGINX_SIMPLE_ENTRY_RE = re.compile(
    r'"~\*(?P<pattern>[A-Za-z0-9._\-\s]+)"\s+(?P<score>\d+);'
)

# Referrer entries in Nginx use a separate map block typically named bad_referrer
_NGINX_REF_RE = re.compile(
    r'"~\*\(\?:\\b\)(?P<pattern>[^(]+)\(\?:\\b\)"\s+1;'
)


def parse_nginx_blocklist(path: Path) -> BlocklistData:
    """Parse an Nginx Ultimate Bad Bot Blocker globalblacklist.conf.

    Extracts:
        - Blocked UA patterns from map blocks (score > 0 = blocked)
        - Blocked referrer patterns (score = 1 in referrer map blocks)

    The Nginx config uses map {} blocks; this parser identifies entries
    with a numeric score >= 1 as blocked, score = 0 as allowed.

    Args:
        path: Absolute path to the Nginx globalblacklist.conf file.

    Returns:
        Populated BlocklistData instance.

    Raises:
        FileNotFoundError: If the configuration file does not exist.
        OSError: If the file cannot be read.
    """
    path = Path(path).resolve()
    if not path.exists():
        raise FileNotFoundError("Nginx blocklist not found: {}".format(path))

    text = path.read_text(encoding="utf-8", errors="replace")
    data = BlocklistData(source_path=path, server="nginx")
    data.raw_line_count = sum(1 for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#"))

    for m in _NGINX_MAP_ENTRY_RE.finditer(text):
        pattern = _clean_pattern(m.group("pattern"))
        score = int(m.group("score"))
        if score > 0:
            data.blocked_uas.add(pattern)

    for m in _NGINX_SIMPLE_ENTRY_RE.finditer(text):
        pattern = _clean_pattern(m.group("pattern"))
        score = int(m.group("score"))
        if score > 0 and pattern:
            data.blocked_uas.add(pattern)

    return data


# ---------------------------------------------------------------------------
# Pattern utilities
# ---------------------------------------------------------------------------

def _clean_pattern(raw: str) -> str:
    """Strip common regex anchors and escape artifacts from a blocklist pattern."""
    cleaned = raw.strip()
    cleaned = re.sub(r'\(\?:\\b\)', '', cleaned)
    cleaned = re.sub(r'\(\?:(?:.*?)\)', '', cleaned)
    cleaned = cleaned.replace(r'\.', '.')
    cleaned = cleaned.replace(r'\-', '-')
    cleaned = cleaned.replace(r'\/', '/')
    cleaned = cleaned.strip(".* ")
    return cleaned


def _ua_matches_blocked(ua: str, blocked_patterns: Set[str]) -> bool:
    """Return True if *ua* matches any blocked pattern (case-insensitive substring)."""
    ua_lower = ua.lower()
    for pat in blocked_patterns:
        if pat and pat.lower() in ua_lower:
            return True
    return False


# ---------------------------------------------------------------------------
# Evasion generators
# ---------------------------------------------------------------------------

def generate_allowed_uas(
    apache_data: Optional[BlocklistData] = None,
    nginx_data: Optional[BlocklistData] = None,
) -> List[str]:
    """Return list of user-agents confirmed not to match any blocked pattern.

    Cross-references the curated safe UA list against both blocklist datasets.
    A UA is included only if it does not contain any blocked pattern token as
    a case-insensitive substring.

    Args:
        apache_data: Parsed Apache blocklist (optional).
        nginx_data: Parsed Nginx blocklist (optional).

    Returns:
        List of safe, non-blocked user-agent strings.
    """
    blocked: Set[str] = set()
    if apache_data:
        blocked.update(apache_data.blocked_uas)
    if nginx_data:
        blocked.update(nginx_data.blocked_uas)

    allowed: List[str] = []
    for ua in _SAFE_BROWSER_UAS:
        if not _ua_matches_blocked(ua, blocked):
            allowed.append(ua)

    return allowed


def generate_evasion_variants(ua: str) -> List[str]:
    """Generate case-variation evasion candidates for a given user-agent string.

    Produces variants that may bypass naive exact-string or case-sensitive WAF
    rules while remaining plausible for application-level fingerprinting.

    Args:
        ua: Base user-agent string to mutate.

    Returns:
        List of variant user-agent strings (deduped, original excluded).
    """
    variants: List[str] = []

    # 1. Title-case the entire UA
    title = ua.title()
    if title != ua:
        variants.append(title)

    # 2. Uppercase all letters
    upper = ua.upper()
    if upper not in (ua, title):
        variants.append(upper)

    # 3. Lowercase all letters
    lower = ua.lower()
    if lower not in (ua, title, upper):
        variants.append(lower)

    # 4. Swap casing of keyword tokens (Mozilla, Chrome, Safari, Firefox, etc.)
    swapped = _swap_keywords(ua)
    if swapped and swapped not in variants and swapped != ua:
        variants.append(swapped)

    # 5. Insert harmless zero-width space after the product token (obfuscates naive regex)
    # Note: some WAFs normalize this; it is a research data point.
    zws = ua.replace("/", "/\u200b", 1)
    if zws != ua and zws not in variants:
        variants.append(zws)

    return list(dict.fromkeys(variants))  # preserve order, dedup


def _swap_keywords(ua: str) -> str:
    """Swap casing of known UA product tokens for evasion research."""
    keywords = ["Mozilla", "Chrome", "Safari", "Firefox", "AppleWebKit", "Gecko", "Trident", "Edge"]
    result = ua
    for kw in keywords:
        if kw in result:
            result = result.replace(kw, kw.swapcase(), 1)
    return result


# ---------------------------------------------------------------------------
# Exploit class
# ---------------------------------------------------------------------------

class Exploit(Exploit):
    """WAF evasion generator from Apache and Nginx bad-bot blocklist analysis.

    Parses the blocklist configuration files from the SOC submodule, extracts
    blocked user-agent patterns, and generates safe / evasion-candidate UAs
    for WAF bypass research and perimeter assessment.
    """

    __info__ = {
        "name": "WAF Evasion Generator",
        "description": (
            "Parses Apache and Nginx bad-bot blocklist configs to extract blocked "
            "user-agents and referrers, then generates safe UA rotation candidates "
            "and case-variant evasion strings for WAF bypass research."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
        ),
        "devices": (
            "Apache 2.4 with mod_setenvif",
            "Nginx with map module",
            "Any host behind WAF/reverse proxy",
        ),
    }

    apache_conf = OptString(str(_APACHE_DEFAULT), "Path to Apache globalblacklist.conf")
    nginx_conf = OptString(str(_NGINX_DEFAULT), "Path to Nginx globalblacklist.conf")
    target_ua = OptString("", "UA string to generate evasion variants for (optional)")
    show_blocked = OptBool(False, "Display sample blocked UAs from parsed blocklists")
    max_display = OptString("20", "Maximum entries to display in tables")

    def check(self) -> bool:
        """Verify blocklist files are accessible."""
        apache_path = Path(self.apache_conf)
        nginx_path = Path(self.nginx_conf)

        apache_ok = apache_path.exists()
        nginx_ok = nginx_path.exists()

        if apache_ok:
            print_status("Apache blocklist found: {}".format(apache_path))
        else:
            print_error("Apache blocklist not found: {}".format(apache_path))

        if nginx_ok:
            print_status("Nginx blocklist found: {}".format(nginx_path))
        else:
            print_error("Nginx blocklist not found: {}".format(nginx_path))

        return apache_ok or nginx_ok

    def run(self) -> None:
        """Parse blocklists, generate allowed UAs and evasion variants."""
        if not self.check():
            print_error("No blocklist files accessible. Adjust apache_conf / nginx_conf.")
            return

        apache_data: Optional[BlocklistData] = None
        nginx_data: Optional[BlocklistData] = None
        max_rows = int(self.max_display) if self.max_display.isdigit() else 20

        apache_path = Path(self.apache_conf)
        nginx_path = Path(self.nginx_conf)

        if apache_path.exists():
            try:
                apache_data = parse_apache_blocklist(apache_path)
                print_status(
                    "Apache blocklist: {} blocked UAs | {} blocked refs | {} allowed UAs".format(
                        apache_data.blocked_ua_count,
                        apache_data.blocked_ref_count,
                        apache_data.good_ua_count,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                print_error("Apache parse error: {}".format(exc))

        if nginx_path.exists():
            try:
                nginx_data = parse_nginx_blocklist(nginx_path)
                print_status(
                    "Nginx blocklist: {} blocked UAs | {} blocked refs".format(
                        nginx_data.blocked_ua_count,
                        nginx_data.blocked_ref_count,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                print_error("Nginx parse error: {}".format(exc))

        if not apache_data and not nginx_data:
            print_error("Failed to parse any blocklist.")
            return

        # Generate safe allowed UAs
        allowed = generate_allowed_uas(apache_data, nginx_data)
        print_status("Safe (non-blocked) UAs from curated list: {}".format(len(allowed)))

        if allowed:
            headers = ("#", "User-Agent (safe / allowed tier)")
            rows = [(str(i + 1), ua) for i, ua in enumerate(allowed[:max_rows])]
            print_success("Safe user-agents for rotation:")
            print_table(headers, *rows)

        # Evasion variants for a specific UA if provided
        target_ua = self.target_ua.strip()
        if target_ua:
            variants = generate_evasion_variants(target_ua)
            print_status("Evasion variants for target UA ({} variants):".format(len(variants)))
            if variants:
                headers = ("#", "Variant")
                rows = [(str(i + 1), v) for i, v in enumerate(variants)]
                print_table(headers, *rows)
            else:
                print_info("No distinct case-variants generated for the provided UA.")

        # Optionally display blocked UA samples
        if str(self.show_blocked).lower() == "true" or self.show_blocked is True:
            all_blocked: List[str] = []
            if apache_data:
                all_blocked.extend(sorted(apache_data.blocked_uas)[:max_rows // 2])
            if nginx_data:
                all_blocked.extend(sorted(nginx_data.blocked_uas)[:max_rows // 2])

            if all_blocked:
                headers = ("#", "Blocked pattern")
                rows = [(str(i + 1), pat) for i, pat in enumerate(all_blocked[:max_rows])]
                print_info("Sample blocked UA patterns:")
                print_table(headers, *rows)
