#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""Native Sigma perimeter rule validator for firewall log analysis.

Applies Sigma detection rules targeting firewall/network perimeter activity
to log files in syslog, CEF, JSON-lines, or key=value format. No external
sigma-cli or SIEM required.

Detection scope:
    - Cleartext protocol usage (HTTP, FTP, Telnet, unencrypted DB ports)
    - Suspicious outbound connections (known malicious ports, C2 patterns)
    - Policy violations (blocked traffic patterns, rate anomalies)
    - Firewall rule bypass indicators
    - DNS anomalies (coin mining, C2 beacons via DNS)
    - Cisco ACL/AAA audit events

Sigma rules sourced from:
    submodules/FraudDetection/sigma/rules/network/

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import collections
import glob
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from embedxpl.core.exploit import *

logger = logging.getLogger(__name__)

__version__ = "1.0.0"

_SEV_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Perimeter-relevant Sigma logsource categories
_PERIMETER_LOGSOURCE_CATS = frozenset([
    "firewall", "dns", "proxy", "network",
    "cisco", "fortinet", "paloalto", "juniper", "huawei",
    "windows",
])


def _yaml_safe_load(text: str) -> Dict[str, Any]:
    """YAML subset parser for Sigma rules (no PyYAML dependency fallback).

    Prefers PyYAML if installed, falls back to manual parser.
    """
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text) or {}
    except ImportError:
        pass
    return _yaml_parse_manual(text)


def _yaml_parse_manual(text: str) -> Dict[str, Any]:
    """Minimal manual YAML parser for Sigma rule structure."""
    result: Dict[str, Any] = {}
    lines = text.splitlines()
    _parse_block(lines, result, 0)
    return result


def _parse_block(
    lines: List[str],
    container: Dict[str, Any],
    base_indent: int,
) -> None:
    """Recursive block parser."""
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.rstrip()
        i += 1
        if not stripped.strip() or stripped.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent < base_indent:
            break
        line = stripped.strip()
        if ":" in line and not line.startswith("-"):
            sep = line.index(":")
            key = line[:sep].strip()
            val_raw = line[sep + 1:].strip()
            if val_raw in ("|", ">", ""):
                # Peek ahead to determine list or dict
                child_lines: List[str] = []
                while i < len(lines):
                    nxt = lines[i]
                    nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                    if nxt.strip() and nxt_indent <= indent:
                        break
                    child_lines.append(nxt)
                    i += 1
                first = next((c.strip() for c in child_lines if c.strip() and not c.strip().startswith("#")), "")
                if first.startswith("- "):
                    lst = [_coerce(c.strip()[2:]) for c in child_lines if c.strip().startswith("- ")]
                    container[key] = lst
                elif val_raw == "|":
                    container[key] = " ".join(c.strip() for c in child_lines if c.strip())
                else:
                    nested: Dict[str, Any] = {}
                    container[key] = nested
                    _parse_block(child_lines, nested, indent + 1)
            elif val_raw.startswith("[") and val_raw.endswith("]"):
                container[key] = [_coerce(v.strip().strip("'\"")) for v in val_raw[1:-1].split(",") if v.strip()]
            else:
                container[key] = _coerce(val_raw)


def _coerce(v: str) -> Any:
    if v in ("true", "True", "yes"): return True
    if v in ("false", "False", "no"): return False
    if v in ("null", "~", ""): return None
    try: return int(v)
    except ValueError: pass
    try: return float(v)
    except ValueError: pass
    return v.strip("'\"")


def load_perimeter_rules(rules_dir: str) -> List[Dict[str, Any]]:
    """Load Sigma rules relevant to perimeter/firewall contexts.

    Filters rules by logsource category to network/firewall/proxy only.

    Args:
        rules_dir: Root directory containing Sigma .yml rule files.

    Returns:
        List of parsed rule dicts with detection sections.
    """
    rules = []
    for path in glob.glob(str(Path(rules_dir) / "**" / "*.yml"), recursive=True):
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
            rule = _yaml_safe_load(text)
            if not rule.get("title") or not rule.get("detection"):
                continue
            # Filter to perimeter-relevant logsources
            logsource = rule.get("logsource", {})
            category = str(logsource.get("category", "")).lower()
            product = str(logsource.get("product", "")).lower()
            service = str(logsource.get("service", "")).lower()
            relevant = (
                any(k in category for k in _PERIMETER_LOGSOURCE_CATS)
                or any(k in product for k in _PERIMETER_LOGSOURCE_CATS)
                or any(k in service for k in _PERIMETER_LOGSOURCE_CATS)
                or category == ""  # no category = generic, include
            )
            if not relevant:
                continue
            rule["_source_path"] = path
            rules.append(rule)
        except Exception as exc:
            logger.debug("Failed to load %s: %s", path, exc)
    return rules


def _match_field(entry: Dict[str, Any], field: str, expected: Any) -> bool:
    actual = entry.get(field)
    if actual is None:
        actual = next((v for k, v in entry.items() if k.lower() == field.lower()), None)
    if actual is None:
        return False
    if isinstance(expected, list):
        return any(_match_val(actual, e) for e in expected)
    return _match_val(actual, expected)


def _match_val(actual: Any, expected: Any) -> bool:
    if expected is None:
        return actual is None
    a, e = str(actual).lower(), str(expected).lower()
    if "*" in e:
        return bool(re.search(re.escape(e).replace(r"\*", ".*"), a))
    return a == e


def _eval_selection(entry: Dict[str, Any], sel: Any) -> bool:
    if not isinstance(sel, dict):
        return False
    return all(_match_field(entry, f, v) for f, v in sel.items())


def _eval_detection(entry: Dict[str, Any], detection: Any) -> bool:
    if not isinstance(detection, dict):
        return False
    condition = str(detection.get("condition", "selection")).lower().strip()
    blocks = {k: v for k, v in detection.items() if k != "condition"}

    def eval_b(name: str) -> bool:
        b = blocks.get(name)
        return _eval_selection(entry, b) if isinstance(b, dict) else False

    def eval_glob(prefix: str, all_: bool) -> bool:
        matching = [k for k in blocks if k.startswith(prefix)]
        if not matching:
            return False
        results = [eval_b(k) for k in matching]
        return all(results) if all_ else any(results)

    if "1 of " in condition:
        return eval_glob(condition.replace("1 of ", "").rstrip("*").strip(), False)
    if "all of " in condition:
        return eval_glob(condition.replace("all of ", "").rstrip("*").strip(), True)
    if " and " in condition:
        for part in (p.strip() for p in condition.split(" and ")):
            if "1 of " in part:
                if not eval_glob(part.replace("1 of ", "").rstrip("*").strip(), False):
                    return False
            elif part.startswith("not "):
                if eval_b(part[4:].strip()):
                    return False
            else:
                if not eval_b(part):
                    return False
        return True
    if " or " in condition:
        return any(eval_b(p.strip()) for p in condition.split(" or "))
    if condition.startswith("not "):
        return not eval_b(condition[4:].strip())
    return eval_b(condition)


def parse_firewall_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a firewall/syslog line into a structured dict.

    Handles:
        - JSON lines
        - Key=value embedded fields
        - Cisco ACL syslog patterns (permitted/denied, src/dst)
        - CEF format basics
    """
    line = line.strip()
    if not line:
        return None

    entry: Dict[str, Any] = {"_raw": line}

    # JSON lines
    try:
        parsed = json.loads(line)
        if isinstance(parsed, dict):
            return parsed
    except ValueError:
        pass

    # Key=value pairs
    for m in re.finditer(r'([\w_-]+)=([^\s,;"]+)', line):
        entry[m.group(1).lower()] = _coerce(m.group(2))

    # Port extraction
    for pattern in (r'\b(?:dstport|dst_port|d?port|destinationPort)\s*[=:]\s*(\d+)',
                    r':(\d{1,5})\b'):
        m = re.search(pattern, line, re.IGNORECASE)
        if m and "dst_port" not in entry:
            entry["dst_port"] = int(m.group(1))
            break

    # Action extraction
    m = re.search(r'\b(permit|deny|allow|block|forward|accept|drop|reject|reset)\b', line, re.IGNORECASE)
    if m and "action" not in entry:
        entry["action"] = m.group(1).lower()

    # Protocol
    m = re.search(r'\b(tcp|udp|icmp|http|ftp|telnet|ssh|smtp|dns)\b', line, re.IGNORECASE)
    if m and "protocol" not in entry:
        entry["protocol"] = m.group(1).lower()

    # Blocked field (common in Fortinet/Cisco logs)
    if "blocked: true" in line.lower() or "action=deny" in line.lower() or "deny" in line.lower():
        entry.setdefault("blocked", "true")
    elif "blocked: false" in line.lower() or "action=allow" in line.lower() or "permit" in line.lower():
        entry.setdefault("blocked", "false")

    return entry


def match_against_rules(
    rules: List[Dict[str, Any]],
    entries: List[Dict[str, Any]],
    min_severity: str = "low",
) -> List[Dict[str, Any]]:
    """Apply Sigma rules to log entries and return filtered matches.

    Args:
        rules: Parsed Sigma rules.
        entries: Structured log records.
        min_severity: Minimum level to include.

    Returns:
        Sorted match list (highest severity first).
    """
    min_sev = _SEV_ORDER.get(min_severity.lower(), 1)
    matches = []

    for idx, entry in enumerate(entries):
        for rule in rules:
            if _eval_detection(entry, rule.get("detection", {})):
                severity = rule.get("level", "medium").lower()
                if _SEV_ORDER.get(severity, 0) >= min_sev:
                    matches.append({
                        "rule_title": rule.get("title", "Unknown"),
                        "rule_id": rule.get("id", ""),
                        "severity": severity,
                        "tags": rule.get("tags", []),
                        "description": rule.get("description", "")[:200],
                        "entry_index": idx,
                        "entry": entry,
                    })

    matches.sort(key=lambda m: _SEV_ORDER.get(m["severity"], 0), reverse=True)
    return matches


class Exploit(Exploit):
    """Native Sigma perimeter rule validator for firewall log analysis.

    Loads Sigma rules from the sigma submodule (network/firewall subset)
    and applies them to a provided log file without any SIEM or sigma-cli
    dependency. Pure Python matching engine.

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    """

    __info__ = {
        "name": "Sigma Perimeter Rule Validator",
        "description": (
            "Applies Sigma network/firewall detection rules against log files "
            "(syslog, CEF, JSON-lines, key=value). Detects cleartext protocols, "
            "C2 DNS patterns, policy violations, Cisco AAA events. "
            "No sigma-cli or SIEM required."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "submodules/FraudDetection/sigma/rules/network/",
            "https://github.com/SigmaHQ/sigma",
        ),
        "devices": ("firewall", "ngfw", "utm", "waf", "network"),
        "platform": ("linux", "macos", "windows"),
    }

    log_file = OptString("", "Path to firewall/syslog/proxy log file")
    rules_dir = OptString("", "Sigma rules directory (auto-discovers sigma submodule if empty)")
    min_severity = OptString("low", "Minimum severity: informational/low/medium/high/critical")
    max_lines = OptInteger(100_000, "Maximum log lines to read")
    dry_run = OptBool(False, "Load and count rules without matching")

    def _find_sigma_dir(self) -> Optional[Path]:
        """Locate the Sigma rules directory.

        Searches in order:
        1. Packaged resources (firewallxpl/resources/sigma/), including
           the windows/ subdirectory.
        2. FraudDetection sigma submodule (legacy path).
        3. Harpia purple-sigma-rules (superproject path).

        Returns:
            Path to a sigma rules directory, or None if not found.
        """
        # Packaged resources: resources/sigma/ is shipped with FXF
        pkg_sigma = Path(__file__).resolve().parents[2] / "resources" / "sigma"
        if pkg_sigma.is_dir():
            return pkg_sigma

        # Packaged resources fallback: one more level up (installed egg layout)
        pkg_sigma2 = Path(__file__).resolve().parents[3] / "resources" / "sigma"
        if pkg_sigma2.is_dir():
            return pkg_sigma2

        fxf_root = Path(__file__).resolve().parents[5]
        for candidate in [
            # Harpia purple-sigma-rules (superproject layout)
            fxf_root.parent / "Safelabs-Harpia" / "purple-sigma-rules" / "sigma",
            fxf_root / "Safelabs-Harpia" / "purple-sigma-rules" / "sigma",
            # Legacy FraudDetection path
            fxf_root / "FraudDetection" / "sigma" / "rules" / "network",
            fxf_root.parent / "FraudDetection" / "sigma" / "rules" / "network",
        ]:
            if candidate.is_dir():
                return candidate
        return None

    def check(self) -> bool:
        log = str(self.log_file).strip()
        if not log:
            logger.error("Set log_file to a log file path.")
            return False
        if not Path(log).exists():
            logger.error("Log file not found: %s", log)
            return False
        return True

    def run(self) -> None:
        rules_dir = str(self.rules_dir).strip()
        if not rules_dir:
            found = self._find_sigma_dir()
            if found:
                rules_dir = str(found)
            else:
                logger.error(
                    "Sigma rules not found. Set rules_dir or run: "
                    "git submodule update --init submodules/FraudDetection/sigma"
                )
                return

        rules = load_perimeter_rules(rules_dir)
        if not rules:
            logger.error("No perimeter-relevant Sigma rules loaded from: %s", rules_dir)
            return

        logger.info("Loaded %d perimeter Sigma rules", len(rules))

        if self.dry_run:
            print(f"[dry-run] Loaded {len(rules)} perimeter rules from {rules_dir}")
            for r in sorted(rules, key=lambda x: x.get("title", "")):
                ls = r.get("logsource", {})
                src = ls.get("category") or ls.get("product") or "generic"
                print(f"  [{r.get('level','?')}] {r.get('title','?')} [{src}]")
            return

        # Parse log
        log_path = Path(str(self.log_file).strip())
        max_l = int(self.max_lines)
        entries: List[Dict[str, Any]] = []
        line_count = 0

        with open(log_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line_count >= max_l:
                    break
                line_count += 1
                parsed = parse_firewall_line(line)
                if parsed:
                    entries.append(parsed)

        logger.info("Parsed %d entries from %d lines", len(entries), line_count)

        matches = match_against_rules(rules, entries, str(self.min_severity))

        print()
        print("=" * 70)
        print(f"  Sigma Perimeter Validator - {log_path.name}")
        print(f"  Rules: {len(rules)}  Log entries: {len(entries)}  Matches: {len(matches)}")
        print("=" * 70)
        print()

        if not matches:
            print("[+] No rule matches above configured threshold.")
            return

        # Group by rule for summary
        by_rule: Dict[str, List[int]] = collections.defaultdict(list)
        for m in matches:
            by_rule[m["rule_title"]].append(m["entry_index"])

        print("Detections by rule:")
        print("-" * 70)
        for rule_title, indices in sorted(by_rule.items()):
            # Find severity for this rule
            sev = next((m["severity"] for m in matches if m["rule_title"] == rule_title), "?")
            tags = next((m.get("tags", [])[:3] for m in matches if m["rule_title"] == rule_title), [])
            tag_str = ", ".join(tags) if tags else ""
            print(f"  [{sev.upper()}] {rule_title} - {len(indices)} hit(s)")
            if tag_str:
                print(f"         Tags: {tag_str}")
            # Show first match example
            first_idx = indices[0]
            first_entry = matches[next(i for i, m in enumerate(matches) if m["entry_index"] == first_idx)]["entry"]
            raw = str(first_entry.get("_raw", ""))[:100]
            if raw:
                print(f"         Example: {raw}")
            print()

        counts = collections.Counter(m["severity"] for m in matches)
        parts = [f"{s.upper()}={counts[s]}" for s in ["critical", "high", "medium", "low", "informational"] if s in counts]
        print(f"Total: {len(matches)} match(es) | {', '.join(parts)}")
        print()
