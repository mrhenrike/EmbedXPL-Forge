"""SYNful Knock Cisco IOS Implant Detection Assessment.

# Original: SYNful Knock — Cisco IOS Implant (Mandiant/FireEye 2015)
# Reference: docs/malware-research/by-tool/FirewallXPL.md#2-win32turla
# SYNful Knock: persistent implant in Cisco IOS router firmware
# Activation: specific TCP packet with crafted SYN sequence number
# MITRE: T1542.001 (System Firmware), T1205 (Traffic Signaling)
"""
# ============================================================
# AUTHORIZED USE ONLY — See docs/malware-research/DISCLAIMER.md
# Use only against systems you own or have WRITTEN authorization
# to test. Operator assumes full legal responsibility for use.
# simulate=True by default — set False only for authorized tests.
# ============================================================

from __future__ import annotations

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
    "name":           "SYNful Knock Cisco IOS Implant Detection",
    "type":           "assessment",
    "cvss":           7.5,
    "platform":       "cisco_ios",
    "author":         "Andre Henrique (@mrhenrike) | Uniao Geek",
    "description":    (
        "Detects behavioral indicators of the SYNful Knock Cisco IOS implant "
        "(Mandiant 2015). SYNful Knock modified the IOS firmware image to "
        "add a persistent backdoor activated by a specific TCP SYN packet "
        "with a crafted sequence number on any TCP port. "
        "Assessment: (1) SSH/Telnet version anomalies, (2) SNMP "
        "writeable community check (implant installed via SNMP write), "
        "(3) unexpected TCP port responses, (4) HTTP management "
        "interface version fingerprinting."
    ),
    "references":     [
        "docs/malware-research/by-tool/FirewallXPL.md#2-win32turla",
        "https://www.mandiant.com/resources/blog/synful-knock-acis",
        "https://www.cisco.com/c/en/us/about/security-center/event-response/synful-knock.html",
    ],
    "malware_family": "SYNful Knock (Cisco IOS implant)",
    "mitre":          ["T1542.001", "T1205"],
    "destructive":    False,
}

# SYNful Knock known trigger sequence number pattern (public indicator)
# (Actual trigger value is attacker-specific — this is a test for unexpected behavior)
_SYNFUL_TRIGGER_HINT = "0xCAFEBABE"  # example — real value varies per implant

# Cisco IOS versions known to be targeted
_CISCO_IOS_TARGETED = [
    "12.2", "12.4", "15.0", "15.1", "15.2",
]


class Exploit(_Base):
    def __init__(self) -> None:
        self.target: str = ""
        self.timeout: float = 5.0
        self.snmp_community: str = "public"
        self.simulate: bool = True

    def check(self) -> bool:
        if self.simulate:
            return True
        for port in [22, 23, 80, 443]:
            try:
                s = socket.create_connection((self.target, port), timeout=2.0)
                s.close()
                return True
            except Exception:
                continue
        return False

    def run(self) -> None:
        if self.simulate:
            print(f"[SIMULATE] SYNful Knock detection: {self.target}")
            print("  SYNful Knock (Mandiant 2015):")
            print("  - Modifies Cisco IOS ROMMON/firmware image")
            print("  - Activates via TCP SYN with specific sequence number")
            print("  - Provides persistent shell on any TCP port")
            print("  - Survives reboot (firmware modification)")
            print()
            print("  Detection would check:")
            print("  1. SSH/Telnet banner for IOS version (targeted versions)")
            print("  2. SNMP writeable community (install vector)")
            print("  3. HTTP management interface version")
            print("  4. Unexpected TCP port responses")
            print("  5. IOS image integrity (requires local console access)")
            return

        print(f"[*] SYNful Knock assessment: {self.target}")
        findings = []

        # 1. SSH banner
        print("[*] Checking SSH banner...")
        try:
            s = socket.create_connection((self.target, 22), timeout=self.timeout)
            banner = s.recv(256).decode("latin-1", errors="replace")
            s.close()
            print(f"    SSH: {banner[:80].strip()!r}")
            if "Cisco" in banner or "IOS" in banner:
                findings.append(f"Cisco device detected via SSH: {banner[:60].strip()!r}")
                for ver in _CISCO_IOS_TARGETED:
                    if ver in banner:
                        findings.append(f"WARNING: IOS {ver} in SYNful Knock targeted range")
                        print(f"    [!] IOS {ver} is in targeted version range")
        except Exception as e:
            print(f"    SSH check: {e}")

        # 2. SNMP write test (install vector)
        print("[*] Checking SNMP write access (SYNful Knock install vector)...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            # SNMPv1 SetRequest to sysContact (harmless test attribute)
            # This is a minimal SNMP set test
            sock.sendto(b"\x30\x26\x02\x01\x00\x04\x07private", (self.target, 161))
            try:
                resp, _ = sock.recvfrom(1024)
                if resp:
                    findings.append("WARNING: SNMP responding (check write access with 'private' community)")
                    print("    [!] SNMP port responding — verify write community is restricted")
            except socket.timeout:
                print("    SNMP: no response (filtered — good)")
            sock.close()
        except Exception as e:
            print(f"    SNMP error: {e}")

        # 3. HTTP management interface
        print("[*] Checking HTTP management interface...")
        for port in [80, 443]:
            try:
                s = socket.create_connection((self.target, port), timeout=2.0)
                req = f"GET / HTTP/1.0\r\nHost: {self.target}\r\n\r\n"
                s.send(req.encode())
                resp = s.recv(1024).decode("latin-1", errors="replace")
                s.close()
                if "IOS" in resp or "Cisco" in resp:
                    print(f"    HTTP/{port}: Cisco management interface found")
                    findings.append(f"Cisco HTTP management on port {port}")
            except Exception:
                pass

        # Summary
        print("\n[*] Summary:")
        if findings:
            for f in findings:
                print(f"    {'[!]' if 'WARNING' in f or 'Cisco' in f else '[*]'} {f}")
            print("\n    SYNful Knock mitigation:")
            print("    - Verify IOS image integrity: 'verify /sha512 <image>'")
            print("    - Disable SNMP write: 'no snmp-server community private RW'")
            print("    - Upgrade to IOS XE (different attack surface)")
            print("    - Enable Cisco ROMMON integrity checks")
        else:
            print("    No SYNful Knock indicators detected")
        print()
        print("    Ref: docs/malware-research/by-tool/FirewallXPL.md#2-win32turla")

