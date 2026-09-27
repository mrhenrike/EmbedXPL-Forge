"""WAF Evasion User-Agent Generator.

Generates non-blocked user-agent strings for WAF evasion by analyzing
blocklist configurations from Apache/Nginx bad-bot blocker projects.
Useful for red-team engagements and WAF bypass research.

Original research / PoC credits
--------------------------------
Title   : WAF Evasion Generator
Source  : FirewallXPL-Forge firewallxpl/modules/generic/waf_evasion_generator.py
          Apache Ultimate Bad Bot Blocker (mitchellkrogza)
          Nginx Ultimate Bad Bot Blocker (mitchellkrogza)
Author  : Andre Henrique (@mrhenrike) | Uniao Geek

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

import random
import re
from pathlib import Path
from typing import List

from embedxpl.core.exploit import *


# Known benign user-agents unlikely to be in blocklists
_BENIGN_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "curl/8.7.1",
    "Go-http-client/2.0",
    "python-httpx/0.27.0",
]

# Known blocked UA keywords (from common blocklists)
_BLOCKED_KEYWORDS = (
    "sqlmap", "nikto", "masscan", "zgrab", "nmap", "hydra", "gobuster",
    "dirbuster", "burpsuite", "openvas", "metasploit", "nuclei",
    "ZmEu", "harvester", "havij", "libwww-perl/5",
)


def _extract_blocked_uas_from_blocklist(blocklist_path: Path) -> List[str]:
    """Extract blocked UA patterns from Apache/Nginx blocklist config."""
    blocked = []
    if not blocklist_path.exists():
        return blocked
    try:
        text = blocklist_path.read_text(encoding="utf-8", errors="replace")
        # Apache blocklist pattern: BotAgent
        for match in re.finditer(r'"([^"]+)"', text):
            ua = match.group(1)
            if len(ua) > 5 and not ua.startswith("http"):
                blocked.append(ua)
    except Exception:
        pass
    return blocked[:200]


class Exploit(Exploit):
    """WAF Evasion User-Agent Generator."""

    __info__ = {
        "name": "WAF Evasion User-Agent Generator",
        "description": (
            "Generates non-blocked user-agent strings by analyzing bad-bot blocklist "
            "configurations. Useful for WAF bypass in authorized red-team engagements. "
            "Optionally reads Apache/Nginx blocklist files to filter candidates."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/mitchellkrogza/apache-ultimate-bad-bot-blocker",
            "https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker",
        ),
        "devices": ("Web application firewalls (WAF)", "IDS/IPS with UA-based detection"),
    }

    blocklist_path = OptString("", "Path to blocklist config file (optional)")
    count = OptInteger(10, "Number of UA strings to generate")

    @mute
    def check(self) -> bool:
        return True

    def run(self) -> None:
        count = int(self.count)
        bl_path_str = str(self.blocklist_path)
        blocked: list[str] = list(_BLOCKED_KEYWORDS)

        if bl_path_str:
            bl_path = Path(bl_path_str)
            extra = _extract_blocked_uas_from_blocklist(bl_path)
            blocked.extend(extra)
            print_info(f"Loaded {len(extra)} blocked patterns from {bl_path}")

        # Filter benign pool
        candidates = [
            ua for ua in _BENIGN_UA_POOL
            if not any(kw.lower() in ua.lower() for kw in blocked)
        ]

        if not candidates:
            candidates = _BENIGN_UA_POOL

        print_status(f"Generating {count} WAF-evasion user-agent candidates")
        for i in range(min(count, len(candidates))):
            ua = random.choice(candidates)
            print_success(f"[{i+1:02d}] {ua}")
        print_info(
            "Usage: inject into requests as 'User-Agent' header during authorized testing. "
            "Combine with payload encoding for full WAF evasion."
        )
