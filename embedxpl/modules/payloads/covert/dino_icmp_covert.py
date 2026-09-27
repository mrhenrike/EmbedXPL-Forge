"""Dino ICMP Covert Channel Assessment (Animal Farm APT).

# Original: Behavioral analysis of Dino (ESET Animal Farm 2015)
# Reference: docs/malware-research/by-tool/FirewallXPL.md#6-dino
# Dino persists in corporate firewalls using ICMP as covert C2 channel
# MITRE: T1095 (Non-Application Layer Protocol), T1205 (Traffic Signaling)
"""
# ============================================================
# AUTHORIZED USE ONLY — See docs/malware-research/DISCLAIMER.md
# Use only against systems you own or have WRITTEN authorization
# to test. Operator assumes full legal responsibility for use.
# simulate=True by default — set False only for authorized tests.
# ============================================================

from __future__ import annotations

import os
import socket
import struct
import time
from typing import Optional

try:
    from embedxpl.core.base import BaseExploit
    _Base = BaseExploit
except ImportError:
    class _Base:  # type: ignore[no-redef]
        pass

METADATA = {
    "name":           "Dino ICMP Covert Channel Assessment",
    "type":           "assessment",
    "cvss":           6.0,
    "platform":       "linux,windows,macos",
    "author":         "Andre Henrique (@mrhenrike) | Uniao Geek",
    "description":    (
        "Assesses whether ICMP can be used as a covert C2 channel — "
        "the technique used by the Dino implant (Animal Farm APT, "
        "attributed to DGSE France). "
        "Dino encoded C2 commands in ICMP Echo payload, using the "
        "firewall itself as the C2 relay (since firewall processes ICMP). "
        "Assessment: (1) ICMP reachability, (2) ICMP payload size limits, "
        "(3) outbound ICMP filtering (can data exfil via ICMP Echo?)."
    ),
    "references":     [
        "docs/malware-research/by-tool/FirewallXPL.md#6-dino",
        "https://www.welivesecurity.com/wp-content/uploads/2018/09/ESET-OperationBugdrop.pdf",
        "https://securelist.com/i-am-dino/69630/",
    ],
    "malware_family": "Dino (Animal Farm APT)",
    "mitre":          ["T1095", "T1205"],
    "destructive":    False,
}

_PROBE_TAG = b"XPL-DINO-PROBE"
_ICMP_ECHO_REQUEST = 8
_ICMP_ECHO_REPLY = 0


def _checksum(data: bytes) -> int:
    """Calculate ICMP checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_icmp_echo(payload: bytes, seq: int = 1) -> bytes:
    """Build ICMP echo request packet."""
    pid = os.getpid() & 0xFFFF
    header = struct.pack("!BBHHH", _ICMP_ECHO_REQUEST, 0, 0, pid, seq)
    chk = _checksum(header + payload)
    header = struct.pack("!BBHHH", _ICMP_ECHO_REQUEST, 0, chk, pid, seq)
    return header + payload


class Exploit(_Base):
    def __init__(self) -> None:
        self.target: str = ""
        self.payload_size: int = 64    # probe payload size
        self.timeout: float = 5.0
        self.simulate: bool = True

    def check(self) -> bool:
        if self.simulate:
            return True
        # Quick reachability check via socket
        try:
            s = socket.create_connection((self.target, 80), timeout=2.0)
            s.close()
            return True
        except Exception:
            # Host may not have port 80 but still respond to ICMP
            return True

    def run(self) -> None:
        if self.simulate:
            print(f"[SIMULATE] Dino ICMP covert channel assessment: {self.target}")
            print("  Dino technique:")
            print("  - Implant runs inside firewall process")
            print("  - Encodes C2 commands in ICMP Echo payload")
            print("  - Firewall processes ICMP -> data reaches implant without network log")
            print("  - Response encoded in ICMP Echo Reply payload")
            print()
            print("  Assessment would test:")
            print("  1. ICMP Echo reachability (basic ping)")
            print("  2. Large ICMP payloads (data exfil capacity)")
            print("  3. Non-standard ICMP ID/sequence patterns")
            print(f"  4. Outbound ICMP filtering detection")
            return

        print(f"[*] Dino ICMP covert channel assessment: {self.target}")

        # Need raw socket for ICMP — check privileges
        try:
            if os.name == "nt":
                # Windows: use ICMP.dll style
                print("  [*] Using OS-level ping for ICMP probe")
                import subprocess
                result = subprocess.run(
                    ["ping", "-n", "1", "-l", str(self.payload_size), self.target],
                    capture_output=True, text=True, timeout=self.timeout + 2
                )
                if "Reply from" in result.stdout:
                    print(f"  [+] ICMP Echo reply received ({self.payload_size}B payload)")
                    print("  [!] ICMP reachable — covert channel via payload possible")
                else:
                    print("  [-] No ICMP reply")
            else:
                # Linux: raw socket
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    sock.settimeout(self.timeout)
                    payload = _PROBE_TAG + b"\x00" * max(0, self.payload_size - len(_PROBE_TAG))
                    packet = _build_icmp_echo(payload)
                    sock.sendto(packet, (self.target, 0))
                    try:
                        resp, addr = sock.recvfrom(1024)
                        icmp_data = resp[20:]  # skip IP header
                        if icmp_data[0] == _ICMP_ECHO_REPLY:
                            resp_payload = icmp_data[8:]
                            print(f"  [+] ICMP Echo reply from {addr[0]} ({len(resp_payload)}B payload)")
                            if _PROBE_TAG in resp_payload:
                                print("  [+] Probe payload echoed back — ICMP data channel confirmed")
                                print("  [!] DINO-style ICMP covert channel is POSSIBLE on this host")
                    except socket.timeout:
                        print("  [-] No ICMP reply (filtered or host down)")
                    sock.close()
                except PermissionError:
                    print("  [!] Raw socket requires root/Administrator")
                    print("  Retry with: sudo python -m embedxpl")

        except Exception as e:
            print(f"  Error: {e}")

        print()
        print("  Dino C2 channel mitigation:")
        print("  - Implement deep packet inspection of ICMP payloads")
        print("  - Block ICMP Echo with non-standard payload patterns")
        print("  - Monitor for ICMP packets with large payloads (>100 bytes)")


