"""
embedxpl/modules/parsers/fortinet_syslog.py - FortiGate Syslog Log Parser.

Native Python parser for Fortinet FortiGate syslog messages in key=value format.
No Logstash, Filebeat, or external pipeline required.

Supports FortiGate log formats:
  - System events (type=event subtype=system): admin login, config change
  - Traffic logs (type=traffic): firewall policy actions
  - VPN logs (type=event subtype=vpn): SSL-VPN, IPsec events
  - User logs (type=event subtype=user): user authentication

Sources:
  - Harpia purple-sigma-rules/sigma/network/fortinet/fortigate/ (13 Sigma rules)
  - FortiOS Log Message Reference 7.6.1

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import re
import shlex
from typing import Any, Dict, List, Optional

__version__ = "1.0.0"

# FortiGate field aliases -> ECS-like normalized names
_FIELD_MAP: Dict[str, str] = {
    "devname": "device.name",
    "devid": "device.id",
    "date": "event.date",
    "time": "event.time",
    "logid": "fortigate.logid",
    "type": "fortigate.type",
    "subtype": "fortigate.subtype",
    "level": "log.level",
    "vd": "fortigate.vdom",
    "eventtime": "event.created",
    "srcip": "source.ip",
    "dstip": "destination.ip",
    "srcport": "source.port",
    "dstport": "destination.port",
    "srcmac": "source.mac",
    "dstmac": "destination.mac",
    "action": "event.action",
    "status": "event.outcome",
    "msg": "message",
    "reason": "event.reason",
    "user": "user.name",
    "remip": "source.ip",
    "policyid": "rule.id",
    "policyname": "rule.name",
    "interface": "observer.ingress.interface.name",
    "dstinterface": "observer.egress.interface.name",
    "proto": "network.transport",
    "app": "network.application",
    "sentbyte": "network.bytes",
    "rcvdbyte": "network.bytes",
    "duration": "event.duration",
}

# FortiGate log ID categories
_LOGID_CATEGORIES: Dict[str, str] = {
    "01": "system",
    "02": "traffic",
    "04": "ips",
    "05": "anomaly",
    "06": "viruses",
    "10": "admin",
    "12": "email",
    "20": "webfilter",
    "32": "dlp",
}


def parse_fortigate_kv(raw: str) -> Dict[str, Any]:
    """Parse a FortiGate key=value syslog line.

    FortiGate logs use space-separated key=value format.
    Values may be quoted with double quotes.

    Args:
        raw: Raw syslog line from FortiGate.

    Returns:
        Dict of parsed fields with normalized ECS-like names.
    """
    result: Dict[str, Any] = {"_raw": raw}

    # Extract key=value pairs (handle quoted values)
    kv_pattern = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|[^ ]+)')
    for m in kv_pattern.finditer(raw):
        key = m.group(1).lower()
        val = m.group(2).strip('"')
        # Numeric coercion (but NOT for IDs that may start with 0)
        if val.isdigit() and not val.startswith("0"):
            val = int(val)
        # Map to ECS name
        ecs_key = _FIELD_MAP.get(key, f"fortigate.{key}")
        result[ecs_key] = val
        # Also keep original key for Sigma rule matching
        result[key] = val

    return result


def parse_fortinet_log_batch(log_lines: List[str]) -> List[Dict[str, Any]]:
    """Parse a batch of FortiGate log lines.

    Args:
        log_lines: List of raw syslog lines.

    Returns:
        List of parsed event dicts.
    """
    events = []
    for line in log_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Handle syslog header: <priority>timestamp hostname process:
        if line.startswith("<"):
            m = re.match(r"<\d+>.*?:\s+(.*)", line)
            if m:
                line = m.group(1)
        parsed = parse_fortigate_kv(line)
        if len(parsed) > 1:  # has at least one field besides _raw
            events.append(parsed)
    return events


def classify_fortigate_event(event: Dict[str, Any]) -> str:
    """Classify a FortiGate event by category.

    Args:
        event: Parsed FortiGate event dict.

    Returns:
        Category string: "admin", "traffic", "vpn", "threat", "config", "other".
    """
    subtype = str(event.get("subtype", "")).lower()
    event_type = str(event.get("type", event.get("fortigate.type", ""))).lower()
    logid = str(event.get("logid", event.get("fortigate.logid", "")))

    if logid.startswith("01"):
        return "system"
    if subtype in ("admin", "system") and "login" in str(event.get("message", "")).lower():
        return "admin"
    if subtype == "vpn" or "vpn" in subtype:
        return "vpn"
    if event_type == "traffic":
        return "traffic"
    if subtype in ("ips", "anomaly", "virus", "webfilter"):
        return "threat"
    if "config" in str(event.get("message", event.get("action", ""))).lower():
        return "config"
    return "other"


class FortigateSyslogParser:
    """High-level FortiGate syslog parser for XPL-Forge.

    Usage:
        parser = FortigateSyslogParser()
        events = parser.parse_file("/var/log/fortigate.log")
        admin_events = parser.filter_by_category(events, "admin")
    """

    def parse_file(
        self,
        path: str,
        max_lines: int = 50_000,
        encoding: str = "utf-8",
    ) -> List[Dict[str, Any]]:
        """Parse a FortiGate log file.

        Args:
            path: Path to log file.
            max_lines: Maximum lines to parse.
            encoding: File encoding.

        Returns:
            List of parsed event dicts.
        """
        lines = []
        with open(path, encoding=encoding, errors="replace") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                lines.append(line)
        return parse_fortinet_log_batch(lines)

    def filter_by_category(
        self,
        events: List[Dict[str, Any]],
        category: str,
    ) -> List[Dict[str, Any]]:
        """Filter events by category.

        Args:
            events: Parsed event list.
            category: Category to filter ("admin", "traffic", "vpn", etc.)

        Returns:
            Filtered event list.
        """
        return [e for e in events if classify_fortigate_event(e) == category]

    def extract_admin_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract admin authentication events (login/logout/lockout)."""
        return [
            e for e in events
            if e.get("action") in ("login", "logout") or "login" in str(e.get("message", "")).lower()
        ]

    def extract_config_changes(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract configuration change events."""
        return [
            e for e in events
            if "config" in str(e.get("message", "")).lower()
            or e.get("action") in ("set", "unset", "add", "delete", "edit")
        ]
