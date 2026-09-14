"""MediaTek MT7622 Access Point Unauthenticated Heap Overflow (2026).

Pre-auth heap overflow in the MediaTek MT7622 embedded Wi-Fi/Bluetooth SoC
access point management daemon (hostapd variant).  A crafted association
request or management frame triggers the overflow without requiring any
authentication or client credentials.

Original research / PoC credits
--------------------------------
Source  : WirelessXPL-Forge wirelessxpl/modules/generic/access_points/
          mt7622_heap_overflow_preauth.py
          WirelessXPL-Forge CVE catalog

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

import socket
import struct

from embedxpl.core.exploit import *


_CVE = "N/A (2026 research; CVE assignment pending)"


def _port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _http_get(host: str, port: int, path: str, timeout: float) -> str:
    for scheme in ("http", "https"):
        try:
            import urllib.request, ssl
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}{path}",
                headers={"User-Agent": "EmbedXPL/3.9"},
            )
            kw = {"timeout": timeout}
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                kw["context"] = ctx
            with urllib.request.urlopen(req, **kw) as r:
                return r.read(4096).decode("utf-8", errors="replace")
        except Exception:
            continue
    return ""


class Exploit(Exploit):
    """MediaTek MT7622 AP Pre-Auth Heap Overflow."""

    __info__ = {
        "name": "MediaTek MT7622 AP Pre-Auth Heap Overflow",
        "description": (
            "Pre-authentication heap buffer overflow in the MediaTek MT7622 SoC "
            "access point management daemon. Triggered via crafted 802.11 management "
            "frame or association request. No credentials required. "
            "Affects routers/APs using MT7622 chipset (Asus, Netgear, and others). "
            "CVE pending — 2026 research."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/mrhenrike/WirelessXPL-Forge",
            "https://www.mediatek.com/products/broadbandWifi/mt7622",
        ),
        "devices": ("MediaTek MT7622-based routers and APs",),
    }

    target = OptIP("", "Target AP management IP")
    port = OptPort(80, "AP management web port")
    timeout = OptInteger(8, "Timeout in seconds")

    @mute
    def check(self) -> bool:
        host, port, timeout = str(self.target), int(self.port), float(self.timeout)
        if not host:
            return False
        if not _port_open(host, port, timeout):
            return False
        body = _http_get(host, port, "/", timeout)
        return "mt7622" in body.lower() or "mediatek" in body.lower() or len(body) > 100

    def run(self) -> None:
        host, port, timeout = str(self.target), int(self.port), float(self.timeout)
        print_status(f"MediaTek MT7622 pre-auth heap overflow probe")
        if not host:
            print_error("No target IP specified")
            return
        if not _port_open(host, port, timeout):
            print_error(f"Port {port} not reachable")
            return
        body = _http_get(host, port, "/", timeout)
        if body:
            print_success(f"AP web UI reachable ({len(body)} bytes)")
            if "mt7622" in body.lower() or "mediatek" in body.lower():
                print_success("MediaTek MT7622 banner detected — potentially vulnerable")
            else:
                print_info("Chipset not confirmed via web banner — check via 802.11 probe frames")
        print_info(
            "Full pre-auth overflow exploitation requires: monitor-mode NIC + scapy "
            "to craft 802.11 association request frames. "
            "Use WirelessXPL-Forge mt7622_heap_overflow_preauth module."
        )
