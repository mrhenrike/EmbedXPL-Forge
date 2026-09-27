# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""ADB Mass Scanner — Port 5555 LAN Sweep.

Scans a subnet for devices with open Android Debug Bridge (ADB)
TCP port 5555 and no-auth configurations.

Version: 1.0.0
"""

import ipaddress
import socket
import threading
from typing import List

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """ADB Mass Scanner — LAN Sweep Port 5555.

    Sweeps a subnet for devices with open ADB TCP port 5555 and no
    authentication required. Identifies Android TV, Fire TV, and other
    Android devices exposed on the local network.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "ADB Mass Scanner Port 5555",
        "description": (
            "Sweeps a subnet for Android Debug Bridge (ADB) devices on TCP port 5555. "
            "Identifies Android TV, Fire TV, Roku, and other Android devices with ADB "
            "exposed on the local network. Safe read-only port probe."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://developer.android.com/tools/adb",
        ),
        "devices": (
            "Android TV", "Amazon Fire TV", "Xiaomi Mi Box",
            "TCL Android TV", "Android IoT devices",
        ),
    }

    target = OptIP("", "Target network in CIDR notation (e.g. 192.168.1.0/24)")
    port = OptPort(5555, "ADB TCP port")
    threads = OptInteger(50, "Concurrent scan threads")
    timeout = OptInteger(1, "Connection timeout per host (seconds)")

    def run(self) -> None:
        network = self.target
        if "/" not in network:
            network = "{}/32".format(network)

        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            print_error("Invalid network: {}".format(e))
            return

        hosts = list(net.hosts())
        print_status(
            "Scanning {} hosts for ADB on port {}...".format(len(hosts), self.port)
        )

        found: List[str] = []
        lock = threading.Lock()
        semaphore = threading.Semaphore(int(self.threads))

        def scan_host(ip: str) -> None:
            with semaphore:
                try:
                    with socket.create_connection((ip, self.port), timeout=float(self.timeout)):
                        with lock:
                            found.append(ip)
                            print_success("ADB open: {}:{}".format(ip, self.port))
                except Exception:
                    pass

        workers = []
        for ip in hosts:
            t = threading.Thread(target=scan_host, args=(str(ip),), daemon=True)
            t.start()
            workers.append(t)

        for t in workers:
            t.join(timeout=float(self.timeout) + 5)

        print_status(
            "Scan complete. {} ADB-accessible device(s) found.".format(len(found))
        )
        if found:
            for ip in found:
                print_success("  {}:{} — try: adb connect {}:{}".format(
                    ip, self.port, ip, self.port
                ))

    @mute
    def check(self) -> bool:
        ip = self.target.split("/")[0]
        try:
            with socket.create_connection((ip, self.port), timeout=3):
                return True
        except Exception:
            return False
