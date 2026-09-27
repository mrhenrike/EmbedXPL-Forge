"""Sigma Perimeter Rule Validator for EmbedXPL.

Applies Sigma detection rules targeting firewall/network perimeter activity
to log files in syslog, CEF, JSON-lines, or key=value format.
No external sigma-cli or SIEM required.

Original research / PoC credits
--------------------------------
Title   : Native Sigma Perimeter Rule Validator
Source  : FirewallXPL-Forge firewallxpl/modules/generic/sigma_perimeter_validator.py
Author  : Andre Henrique (@mrhenrike) | Uniao Geek

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

import collections
import json
import logging
import re
from pathlib import Path
from typing import Any

from embedxpl.core.exploit import *

logger = logging.getLogger(__name__)

_VERSION = "1.0.0"

# Built-in lightweight Sigma-like detection patterns for common perimeter threats
_BUILTIN_RULES = {
    "cleartext_http_outbound": {
        "description": "Outbound HTTP (unencrypted) to non-standard ports",
        "pattern": re.compile(r"(dstport=(?!443|80)\d+.*action=accept|proto=TCP.*dstport=80)"),
        "severity": "medium",
    },
    "ssl_vpn_brute_force": {
        "description": "SSL-VPN multiple authentication failures",
        "pattern": re.compile(r"(subtype=vpn.*action=ssl-vpn-login-fail|type=event.*ssl.*fail.*fail.*fail)"),
        "severity": "high",
    },
    "firewall_policy_bypass": {
        "description": "Traffic bypassing firewall policy (policy=0 or implicit deny override)",
        "pattern": re.compile(r"policyid=0\b|policy.?id=0\b"),
        "severity": "high",
    },
    "admin_login_success": {
        "description": "Administrative login to firewall",
        "pattern": re.compile(r"(action=login.*status=success|logdesc=.?Admin.?login.?successful)"),
        "severity": "low",
    },
    "config_change": {
        "description": "Configuration change detected",
        "pattern": re.compile(r"(subtype=system.*action=.*change|logdesc=.?Configuration.?changed)"),
        "severity": "medium",
    },
    "large_outbound_transfer": {
        "description": "Unusually large outbound data transfer",
        "pattern": re.compile(r"sentbyte=(\d{8,})"),
        "severity": "medium",
    },
    "blocked_c2_pattern": {
        "description": "Outbound connection to suspicious port (common C2: 4444, 8888, 1337)",
        "pattern": re.compile(r"dstport=(4444|8888|1337|9999|31337)\b.*action=accept"),
        "severity": "high",
    },
    "rip_ripv2_detected": {
        "description": "RIP routing protocol traffic detected on perimeter",
        "pattern": re.compile(r"(proto=UDP.*dstport=520|app=RIP|service=RIP)"),
        "severity": "low",
    },
}


class Exploit(Exploit):
    """Sigma Perimeter Log Validator — applies built-in detection rules."""

    __info__ = {
        "name": "Sigma Perimeter Rule Validator",
        "description": (
            "Applies lightweight Sigma-style detection rules against firewall/perimeter "
            "logs (FortiGate, pfSense, generic syslog). Detects: cleartext traffic, "
            "VPN brute-force, policy bypass, admin logins, config changes, C2 patterns. "
            "No external sigma-cli required."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://github.com/SigmaHQ/sigma",),
        "devices": ("FortiGate", "pfSense", "OPNsense", "Generic syslog sources"),
    }

    log_file = OptString("", "Path to firewall log file to analyze")
    max_lines = OptInteger(50000, "Maximum log lines to process")

    @mute
    def check(self) -> bool:
        p = Path(str(self.log_file))
        return p.exists() and p.is_file()

    def run(self) -> None:
        log_path = Path(str(self.log_file))
        max_lines = int(self.max_lines)

        if not log_path.exists():
            print_error(f"Log file not found: {log_path}")
            print_info("Usage: set log_file=/var/log/firewall.log")
            return

        print_status(f"Analyzing {log_path} with {len(_BUILTIN_RULES)} built-in rules")

        findings: dict[str, list[int]] = collections.defaultdict(list)
        line_count = 0

        try:
            with open(log_path, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    if lineno > max_lines:
                        print_info(f"Stopping at {max_lines} lines (limit reached)")
                        break
                    for rule_name, rule in _BUILTIN_RULES.items():
                        if rule["pattern"].search(line):
                            findings[rule_name].append(lineno)
                    line_count += 1
        except OSError as exc:
            print_error(f"Cannot read log file: {exc}")
            return

        print_success(f"Processed {line_count:,} lines")

        if not findings:
            print_info("No rule matches found")
            return

        for rule_name, lines in sorted(findings.items(), key=lambda x: len(x[1]), reverse=True):
            rule = _BUILTIN_RULES[rule_name]
            sev = rule["severity"].upper()
            desc = rule["description"]
            hits = len(lines)
            sample = f"lines {', '.join(str(l) for l in lines[:5])}"
            if sev == "HIGH":
                print_success(f"[{sev}] {rule_name}: {hits} hits — {desc} ({sample})")
            else:
                print_info(f"[{sev}] {rule_name}: {hits} hits — {desc} ({sample})")
