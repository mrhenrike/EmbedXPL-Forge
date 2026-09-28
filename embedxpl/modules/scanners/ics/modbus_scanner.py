# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Modbus/TCP Scanner — Fingerprint PLCs, RTUs and HMIs via Modbus Function Codes.

Scans for Modbus/TCP capable devices on port 502 using standard Modbus function
codes to identify and fingerprint industrial control system components:

  - Function Code 43 / MEI Type 14 (Read Device Identification)
    Reports device vendor, product name, firmware version, and serial number.
  - Function Code 1  (Read Coils) — probes coil status registers.
  - Function Code 3  (Read Holding Registers) — reads holding register values.

Modbus/TCP has no built-in authentication; any device reachable on TCP/502 is
accessible.

References:
  - Modbus Application Protocol Specification V1.1b3
  - ICS-CERT Advisory: Exposed Modbus services are a critical risk (ICS-CERT-2016-0001)
  - MITRE ATT&CK ICS: T0846 (Remote System Discovery)

Version: 1.0.0
"""

import socket
import struct
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_MODBUS_PORT = 502

# Modbus/TCP ADU (Application Data Unit):
# Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1) + PDU
_TRANSACTION = 0x0001
_PROTOCOL_ID = 0x0000
_UNIT_ID = 0x01

# Function Code 43 sub-function 14 (MEI — Read Device Identification)
_MEI_REQ = struct.pack(">HHHBBBB", _TRANSACTION, _PROTOCOL_ID, 4, _UNIT_ID, 0x2B, 0x0E, 0x01, 0x00)

# FC1 — Read Coils (address 0, quantity 8)
_FC1_REQ = struct.pack(">HHHBBBBB", _TRANSACTION, _PROTOCOL_ID, 6, _UNIT_ID, 0x01, 0x00, 0x00, 0x00, 0x08)

# FC3 — Read Holding Registers (address 0, quantity 10)
_FC3_REQ = struct.pack(">HHHBBBBB", _TRANSACTION, _PROTOCOL_ID, 6, _UNIT_ID, 0x03, 0x00, 0x00, 0x00, 0x0A)


def _modbus_query(host: str, port: int, request: bytes, timeout: int = 5) -> Optional[bytes]:
    """Send a Modbus/TCP request and return the response bytes."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.sendall(request)
        data = sock.recv(256)
        sock.close()
        return data
    except Exception:
        return None


def _parse_mei_response(data: bytes) -> dict:
    """Parse FC43/MEI Type 14 response into a dict of object values."""
    result = {}
    if len(data) < 8:
        return result
    # Skip MBAP header (6 bytes) + unit ID (1) + function code (1) + MEI type (1) + ...
    offset = 9
    try:
        conformity = data[offset]
        more = data[offset + 1]
        obj_count = data[offset + 2]
        offset += 3
        obj_labels = {0x00: "VendorName", 0x01: "ProductCode", 0x02: "MajorMinorRevision",
                      0x03: "VendorURL", 0x04: "ProductName", 0x05: "ModelName"}
        for _ in range(obj_count):
            if offset + 2 > len(data):
                break
            obj_id = data[offset]
            obj_len = data[offset + 1]
            obj_val = data[offset + 2: offset + 2 + obj_len].decode("ascii", errors="replace")
            label = obj_labels.get(obj_id, "Object_0x{:02X}".format(obj_id))
            result[label] = obj_val
            offset += 2 + obj_len
    except Exception:
        pass
    return result


class Exploit(BaseExploit):
    """Modbus/TCP ICS Scanner — Device identification and register enumeration.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Modbus/TCP ICS Scanner",
        "description": (
            "Scans for Modbus/TCP devices on port 502. Uses FC43/MEI Type 14 for "
            "device identification (vendor, product, firmware version), FC1 for coil "
            "status, and FC3 for holding register values. Modbus/TCP has no "
            "authentication — any reachable device is accessible."
        ),
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",
            "Shodan ICS Research",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "references": (
            "https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf",
            "https://attack.mitre.org/techniques/T0846/",
        ),
        "devices": (
            "PLC", "RTU", "HMI", "Modbus gateway", "Industrial switch",
            "Schneider Modicon", "Siemens", "Rockwell Allen-Bradley", "ABB",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(_MODBUS_PORT, "Modbus/TCP port (default 502)")
    unit_id = OptInteger(1, "Modbus Unit ID / Slave ID (1–247)")
    timeout = OptInteger(5, "Socket timeout in seconds")

    def run(self) -> None:
        print_status("Probing Modbus/TCP on {}:{}...".format(self.target, self.port))

        # FC43 — Device Identification
        resp = _modbus_query(self.target, self.port, _MEI_REQ, self.timeout)
        if resp and len(resp) > 8 and resp[7] == 0x2B:
            device_info = _parse_mei_response(resp)
            print_success("Modbus/TCP device identified on {}:{}".format(self.target, self.port))
            for key, val in device_info.items():
                print_success("  {}: {}".format(key, val))
        elif resp and len(resp) > 7 and resp[7] & 0x80:
            exc_code = resp[8] if len(resp) > 8 else "unknown"
            print_status("FC43 exception code {} (device may not support MEI)".format(exc_code))
            print_success("Modbus/TCP device present (FC43 not supported)")
        elif resp:
            print_success("Modbus/TCP response received — device confirmed")
        else:
            print_error("No Modbus/TCP response on {}:{}".format(self.target, self.port))
            return

        # FC1 — Read Coils
        coil_resp = _modbus_query(self.target, self.port, _FC1_REQ, self.timeout)
        if coil_resp and len(coil_resp) > 8 and coil_resp[7] == 0x01:
            coil_byte = coil_resp[9] if len(coil_resp) > 9 else 0
            coils = "{:08b}".format(coil_byte)
            print_status("FC1 Coils (addr 0-7): {}".format(coils))

        # FC3 — Read Holding Registers
        reg_resp = _modbus_query(self.target, self.port, _FC3_REQ, self.timeout)
        if reg_resp and len(reg_resp) > 9 and reg_resp[7] == 0x03:
            byte_count = reg_resp[8]
            regs = []
            for i in range(0, byte_count - 1, 2):
                val = struct.unpack(">H", reg_resp[9 + i: 11 + i])[0]
                regs.append(str(val))
            print_status("FC3 Holding Registers (addr 0-9): [{}]".format(", ".join(regs)))

    @mute
    def check(self) -> bool:
        resp = _modbus_query(self.target, self.port, _FC1_REQ, 4)
        return resp is not None and len(resp) >= 7
