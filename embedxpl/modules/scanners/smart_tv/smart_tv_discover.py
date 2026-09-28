# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Generic Smart TV LAN Discovery Scanner.

Probes all 15+ known Smart TV service ports to fingerprint the platform
(Roku, LG WebOS, Samsung Tizen, Android TV, Fire TV, VIDAA, etc.).

Version: 1.0.0
"""

import socket
import threading
from typing import Dict, List, Optional, Tuple

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_SMART_TV_PORTS: List[Tuple[int, str, str]] = [
    (3000, "tcp",  "LG WebOS SSAP (WebSocket)"),
    (3001, "tcp",  "LG WebOS SSAP TLS (WebSocket)"),
    (8001, "tcp",  "Samsung Tizen REST API"),
    (8002, "tcp",  "Samsung Tizen REST API TLS"),
    (8060, "tcp",  "Roku ECP (HTTP)"),
    (8008, "tcp",  "Android TV / Chromecast / Fire TV DIAL"),
    (8009, "tcp",  "Android TV DIAL TLS"),
    (8085, "tcp",  "Roku BrightScript dev console"),
    (5555, "tcp",  "ADB TCP (Android TV / Fire TV)"),
    (7989, "tcp",  "TCL Android TV file server"),
    (7983, "tcp",  "TCL Android TV secondary"),
    (9080, "tcp",  "LG SuperSign CMS"),
    (36866, "tcp", "LG Smart TV (legacy)"),
    (5600, "tcp",  "Samsung legacy web server"),
    (55000, "udp", "Samsung AllShare / DLNA"),
    (1925, "tcp",  "Philips JointSpace API"),
    (4444, "tcp",  "Hisense VIDAA API"),
    (8081, "tcp",  "Hisense VIDAA / WATTrouter alt"),
    (18888, "tcp", "LG WebOS TyphoonPWN port"),
]


def _tcp_probe(host: str, port: int, timeout: float = 1.5) -> Optional[str]:
    """Attempt a TCP connection and grab a banner.

    Args:
        host: Target hostname or IP.
        port: TCP port number.
        timeout: Connection timeout in seconds.

    Returns:
        Banner string if connected, None otherwise.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner = s.recv(256).decode("utf-8", errors="replace").strip()
            except Exception:
                banner = ""
            return banner if banner else "(connected, no banner)"
    except Exception:
        return None


def _udp_probe(host: str, port: int, timeout: float = 1.5) -> bool:
    """Send a UDP probe and check for any response.

    Args:
        host: Target hostname or IP.
        port: UDP port number.
        timeout: Wait timeout in seconds.

    Returns:
        True if a response was received.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x00", (host, port))
        data, _ = sock.recvfrom(256)
        sock.close()
        return bool(data)
    except Exception:
        return False


class Exploit(BaseExploit):
    """Generic Smart TV LAN Discovery Scanner.

    Probes all known Smart TV service ports and fingerprints the platform.
    Identifies Roku, LG WebOS, Samsung Tizen, Android TV, Amazon Fire TV,
    Hisense VIDAA, Philips JointSpace, and other embedded TV platforms.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Smart TV LAN Discovery Scanner",
        "description": (
            "Probes 15+ Smart TV service ports to fingerprint the platform. "
            "Identifies Roku ECP, LG WebOS SSAP, Samsung Tizen REST, Android TV ADB/DIAL, "
            "Fire TV, Hisense VIDAA, LG SuperSign, Philips JointSpace, TCL file server, "
            "and Samsung AllShare. Safe read-only enumeration."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://developer.roku.com/docs/developer-program/dev-tools/external-control-api.md",
            "https://webostv.developer.lge.com/develop/app-development/",
            "https://developer.samsung.com/smarttv/develop/",
        ),
        "devices": (
            "Roku", "LG Smart TV", "Samsung Smart TV", "Android TV",
            "Amazon Fire TV", "Hisense", "Sony Bravia", "Vizio",
            "Philips Android TV", "TCL", "Toshiba",
        ),
    }

    target = OptIP("", "Target IPv4 address")
    timeout = OptInteger(2, "TCP connection timeout (seconds)")
    threads = OptInteger(20, "Concurrent probe threads")

    def run(self) -> None:
        print_status("Scanning {} for Smart TV services...".format(self.target))
        results: Dict[int, str] = {}
        lock = threading.Lock()

        def probe(port: int, proto: str, label: str) -> None:
            if proto == "tcp":
                banner = _tcp_probe(self.target, port, float(self.timeout))
                if banner is not None:
                    with lock:
                        results[port] = "[TCP/{:5d}] {} — {}".format(
                            port, label, banner[:80] if banner != "(connected, no banner)" else ""
                        )
                        print_success(results[port])
            else:
                if _udp_probe(self.target, port, float(self.timeout)):
                    with lock:
                        results[port] = "[UDP/{:5d}] {}".format(port, label)
                        print_success(results[port])

        workers = []
        for port, proto, label in _SMART_TV_PORTS:
            t = threading.Thread(target=probe, args=(port, proto, label), daemon=True)
            t.start()
            workers.append(t)

        for t in workers:
            t.join(timeout=float(self.timeout) + 2)

        if not results:
            print_error("No Smart TV services found on {}".format(self.target))
        else:
            print_status(
                "Found {} open Smart TV port(s) on {}".format(len(results), self.target)
            )

    @mute
    def check(self) -> bool:
        for port, proto, _ in _SMART_TV_PORTS:
            if proto == "tcp" and _tcp_probe(self.target, port, 1.0) is not None:
                return True
        return False
