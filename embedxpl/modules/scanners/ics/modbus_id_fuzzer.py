# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Modbus Unit ID Fuzzer — brute-force slave ID discovery on TCP/502.

Scans all 256 possible Modbus Unit IDs (slave addresses) on a target
Modbus gateway or multi-drop converter. Many Modbus-to-TCP gateways bridge
multiple serial Modbus devices, each identified by a unique Unit ID (1-255).

This fuzzer sends a minimal Modbus read request for each Unit ID and checks
if the device responds with valid Modbus data (not an exception or silence).
Unit IDs that respond indicate a physical device at that slave address.

Default Unit ID is typically 1, but in multi-device installations you may
find PLCs, RTUs, and energy meters scattered across IDs 1-255.

Protocol: Modbus/TCP, port 502
References:
  - Modbus Application Protocol Specification V1.1b3
  - MITRE ATT&CK ICS: T0846 (Remote System Discovery)
  - Ported from ModBusSploit auxiliary/scanner/id_fuzzer.py

Version: 1.0.0
"""

import socket
import struct
import time
from typing import List

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit


def _probe_unit_id(host: str, port: int, unit_id: int, timeout: float) -> bool:
    """Send a minimal Modbus read request and check for valid response on given Unit ID."""
    # Diagnostic query: XID=0x1821, ProtocolID=0x0000, Length=2, UnitID=<id>, FC=1 (ReadCoils null)
    request = b"\x18\x21\x00\x00\x00\x02" + bytes([unit_id]) + b"\x01"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(request)
        resp = sock.recv(256)
        sock.close()
        # Valid response: starts with our XID and has data
        if len(resp) > 0 and resp[0:4] == b"\x18\x21\x00\x00":
            return True
        return False
    except Exception:
        return False


class Exploit(BaseExploit):
    """Modbus Unit ID Fuzzer — discover all active Modbus slaves on a gateway.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Modbus Unit ID Fuzzer (Slave Discovery)",
        "description": (
            "Probes all 256 Modbus Unit IDs on a target to discover which slave IDs "
            "have active Modbus devices. Useful for mapping Modbus-to-TCP gateways "
            "that bridge multiple serial PLCs/RTUs. "
            "Ported from ModBusSploit auxiliary/scanner/id_fuzzer.py."
        ),
        "authors": (
            "ModBusSploit contributors",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge port",
        ),
        "references": (
            "https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf",
            "https://attack.mitre.org/techniques/T0846/",
        ),
        "devices": (
            "Modbus-to-TCP gateway",
            "Modbus multi-drop serial network bridge",
            "Any Modbus/TCP server with multiple slave IDs",
        ),
    }

    target = OptIP("", "Target Modbus gateway IPv4 address")
    port = OptPort(502, "Modbus TCP port (default 502)")
    start_id = OptInteger(0, "Starting Unit ID (0-255)")
    end_id = OptInteger(255, "Ending Unit ID (0-255)")
    delay = OptFloat(0.2, "Delay between probes in seconds")
    timeout = OptFloat(1.0, "Socket timeout per probe (seconds)")

    def run(self) -> None:
        """Fuzz all Unit IDs and report responding devices."""
        print_status(f"[Modbus ID Fuzzer] Scanning {self.target}:{self.port} Unit IDs {self.start_id}–{self.end_id}...")

        found: List[int] = []
        total = self.end_id - self.start_id + 1

        for unit_id in range(self.start_id, self.end_id + 1):
            progress = unit_id - self.start_id + 1
            print(f"\r[*] Testing ID: {unit_id:3d} ({progress}/{total})", end="", flush=True)
            if _probe_unit_id(self.target, self.port, unit_id, self.timeout):
                found.append(unit_id)
                print(f"\r                              ")
                print_success(f"[Modbus ID Fuzzer] Active Unit ID: {unit_id}")
            time.sleep(self.delay)

        print()
        if found:
            print_success(f"[Modbus ID Fuzzer] Found {len(found)} active Unit ID(s): {found}")
        else:
            print_error(f"[Modbus ID Fuzzer] No active Modbus devices found on {self.target}:{self.port}")

    @mute
    def check(self) -> bool:
        """Return True if TCP/502 is reachable."""
        try:
            sock = socket.create_connection((self.target, self.port), timeout=3)
            sock.close()
            return True
        except Exception:
            return False
