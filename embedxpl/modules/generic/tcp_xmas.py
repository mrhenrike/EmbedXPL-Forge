"""TCP Xmas scan — firewall/IDS evasion fingerprinting.

Sends TCP packets with FIN, URG, and PSH flags set simultaneously
(the "Xmas tree" pattern). RFC-compliant stacks should respond with
RST for closed ports and drop the packet for open ports, allowing
port state inference. Useful for firewall rule testing and OS fingerprinting.

Requires root/administrator privileges for raw socket access.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

__info__ = {
    "name": "TCP Xmas Scan (Firewall/IDS Evasion)",
    "description": (
        "Sends TCP Xmas packets (FIN+URG+PSH flags) to probe port states. "
        "Closed ports return RST; open/filtered ports are silent. "
        "Bypasses some stateless ACL-based firewalls. "
        "Requires root/admin for raw socket access."
    ),
    "authors": ("André Henrique (@mrhenrike)",),
    "references": (
        "https://nmap.org/book/scan-methods-null-fin-xmas-scan.html",
        "https://www.exploit-db.com/papers/35487",
    ),
}

_DEFAULT_PORTS = [22, 23, 80, 443, 8080, 8443, 161, 1900, 7547, 37215]


class Exploit(HTTPClient):
    """TCP Xmas scan for port state inference."""

    target  = OptIP("", "Target IPv4 address")
    ports   = OptString("22,23,80,443,8080,161,1900,7547", "Comma-separated ports to scan")
    timeout = OptPort(2, "Per-port response timeout (seconds)")

    def run(self) -> None:
        """Send Xmas packets to specified ports."""
        try:
            from scapy.all import IP, TCP, sr1, conf
            conf.verb = 0
        except ImportError:
            print_error("scapy not installed — run: pip install scapy")
            return

        try:
            port_list = [int(p.strip()) for p in self.ports.split(",") if p.strip()]
        except ValueError:
            print_error("Invalid port list — use comma-separated integers")
            return

        print_status(f"TCP Xmas scan: {self.target} ({len(port_list)} ports)...")
        open_filtered = []
        closed = []

        for port in port_list:
            try:
                # FIN=1, URG=1, PSH=1 = Xmas flags
                pkt = IP(dst=self.target) / TCP(dport=port, flags="FPU")
                resp = sr1(pkt, timeout=int(self.timeout), verbose=0)
                if resp is None:
                    open_filtered.append(port)
                    print_success(f"  Port {port}: OPEN|FILTERED (no response)")
                elif resp.haslayer(TCP) and resp[TCP].flags & 0x04:  # RST
                    closed.append(port)
                    print_status(f"  Port {port}: closed (RST received)")
            except Exception as e:
                print_error(f"  Port {port}: error — {e}")

        print_status(f"\nSummary: {len(open_filtered)} open/filtered, {len(closed)} closed")
        if open_filtered:
            print_success(f"Open/filtered ports: {open_filtered}")

    @mute
    def check(self) -> bool:
        """Quick check — scapy available and target is reachable."""
        try:
            from scapy.all import IP, ICMP, sr1, conf
            conf.verb = 0
            pkt = IP(dst=self.target) / ICMP()
            resp = sr1(pkt, timeout=2, verbose=0)
            if resp:
                print_success(f"Target {self.target} is reachable")
                return True
        except ImportError:
            print_error("scapy not available")
        except Exception as e:
            print_error(f"Check error: {e}")
        return False
