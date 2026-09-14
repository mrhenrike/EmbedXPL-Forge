"""pfSense / OPNsense Syslog Parser — EmbedXPL port of FirewallXPL-Forge.

Original research / PoC credits
--------------------------------
Title   : pfSense/OPNsense Syslog Parser
Source  : FirewallXPL-Forge firewallxpl/modules/parsers/pfsense_syslog.py
Author  : Andre Henrique (@mrhenrike) | Uniao Geek
Version : 1.0.0

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

__version__ = "1.0.0"

# pfSense filterlog CSV field order (CSV format)
_FILTERLOG_FIELDS = [
    "rule_number", "sub_rule_number", "anchor", "tracker",
    "interface", "reason", "action", "direction", "ip_version",
    "tos", "ecn", "ttl", "id", "offset", "flags", "protocol_id", "protocol",
    "length", "src_ip", "dst_ip",
    # TCP/UDP
    "src_port", "dst_port", "data_length",
    # TCP specific
    "tcp_flags", "sequence", "ack", "window", "urg", "tcp_options",
]

# Regex for pfSense syslog header
_PFSENSE_HEADER = re.compile(
    r"(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)", re.S
)


def parse_pfsense_line(raw: str) -> Optional[Dict[str, Any]]:
    
    result: Dict[str, Any] = {"_raw": raw.strip()}

    m = _PFSENSE_HEADER.match(raw.strip())
    if not m:
        # Try inline format
        kv_pairs = re.findall(r'(\w+)=([^\s,]+)', raw)
        for k, v in kv_pairs:
            result[k.lower()] = v
        return result if len(result) > 1 else None

    timestamp, host, program, pid, message = m.groups()
    result["timestamp"] = timestamp.strip()
    result["host"] = host
    result["program"] = program
    result["pid"] = pid
    result["message"] = message

    program_lower = program.lower()

    if "filterlog" in program_lower:
        result["log_type"] = "firewall"
        _parse_filterlog_message(result, message)

    elif "sshd" in program_lower:
        result["log_type"] = "ssh"
        _parse_sshd_message(result, message)

    elif "sudo" in program_lower:
        result["log_type"] = "sudo"
        _parse_sudo_message(result, message)

    elif "php" in program_lower:
        result["log_type"] = "webgui"

    else:
        result["log_type"] = "other"

    return result


def _parse_filterlog_message(event: Dict[str, Any], message: str) -> None:
    
    parts = message.split(",")
    if len(parts) >= 20:
        field_names = _FILTERLOG_FIELDS[:len(parts)]
        for i, name in enumerate(field_names):
            event[name] = parts[i]

        # Normalize key fields
        event["action"] = event.get("action", "pass").lower()
        event["source.ip"] = event.get("src_ip", "")
        event["destination.ip"] = event.get("dst_ip", "")
        event["source.port"] = event.get("src_port", "")
        event["destination.port"] = event.get("dst_port", "")
        event["network.direction"] = event.get("direction", "in")


def _parse_sshd_message(event: Dict[str, Any], message: str) -> None:
    
    # Accepted/Failed password/publickey for user X from IP port N
    m = re.search(
        r"(Accepted|Failed|Invalid|error:)\s+(\w+).*for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)",
        message, re.I
    )
    if m:
        event["event.outcome"] = "success" if m.group(1) == "Accepted" else "failure"
        event["auth.method"] = m.group(2)
        event["user.name"] = m.group(3)
        event["source.ip"] = m.group(4)
        event["source.port"] = m.group(5)
    elif "Disconnected" in message:
        event["event.action"] = "disconnect"


def _parse_sudo_message(event: Dict[str, Any], message: str) -> None:
    
    # user1 : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/sh
    m = re.match(r"(\S+)\s*:\s*TTY=(\S+).*USER=(\S+)\s*;.*COMMAND=(.+)", message, re.I)
    if m:
        event["user.name"] = m.group(1)
        event["user.target"] = m.group(3)
        event["process.command_line"] = m.group(4).strip()
        event["event.action"] = "sudo"


class PfsenseSyslogParser:
    

    def parse_file(
        self,
        path: str,
        max_lines: int = 50_000,
        log_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        
        events = []
        with open(path, encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                parsed = parse_pfsense_line(line)
                if parsed and len(parsed) > 1:
                    if log_types is None or parsed.get("log_type") in log_types:
                        events.append(parsed)
        return events
