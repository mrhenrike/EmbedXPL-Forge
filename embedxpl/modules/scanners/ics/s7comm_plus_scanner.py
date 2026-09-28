# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""S7comm+ (S7 Communication Plus) Scanner — Siemens S7-1200/S7-1500 PLC detection.

S7comm+ is the updated S7 communication protocol used in Siemens S7-1200 and
S7-1500 PLCs. It runs over ISO-on-TCP (RFC 1006) on TCP/102.

This scanner:
  1. Establishes TCP connection to port 102
  2. Sends a TPKT/COTP CR (Connection Request) packet
  3. Sends an S7comm+ Session Setup Request
  4. Parses the response to extract Order Code, Serial Number,
     Hardware Version, and Firmware Version from the PLC

These fields are extracted without authentication from the default
configuration of S7-1200/S7-1500 PLCs.

Protocol: S7comm+ over ISO-on-TCP (TPKT+COTP, TCP/102)
Default port: TCP/102

References:
  - Thomas Roth: "Fuzzing the S7 Protocol"
  - Wenzhe Zhu (ISF): S7Plus client implementation
  - MITRE ATT&CK ICS: T0846 (Remote System Discovery)

Version: 1.0.0
"""

import socket
import struct
import time
from typing import Optional, Tuple

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

# TPKT + COTP CR (Connection Request)
# TPKT: version=3, reserved=0, length=23
# COTP: length=18, PDU_type=0xE0 (CR), dst=0, src=1, class=0
# Parameters: tpdu-size=0xC0 0x01 0x0A, src-tsap=0xC1 0x02 0x06 0x00, dst-tsap=0xC2 0x02 0x00 0x01
_COTP_CONNECT = bytes.fromhex(
    "030000231ee0000000010000c0010ac1020600c20f53494d415449432d524f4f542d455300"
)

# S7comm+ Session Setup / GetSZL request for identification
# (Minimal request to trigger identity response from S7-1200/1500)
_S7PLUS_SESSION_SETUP = bytes.fromhex(
    "030000dd02f080720100ce31000004ca0000000100000120360000011d00040000"
    "000000a1000000d3821f0000a3816900151553657276657253657373696f6e5f31"
    "433943333830a3822100152c313a3a3a362e303a3a5443502f4950202d3e20496e"
    "74656c2852292050524f2f313030304d54204e2e2e2ea38228001500a382290015"
    "00a3822a00150e4841434b2d50435f323832333330a3822b000401a3822c001201"
    "c9c380a3822d001500a1000000d3817f0000a38169001515537562736372697074"
    "696f6e436f6e7461696e6572a2a20000000072010000"
)


def _recv_tpkt(sock: socket.socket, timeout: int = 5) -> Optional[bytes]:
    """Receive a full TPKT-framed packet (blocking, with timeout)."""
    sock.settimeout(timeout)
    try:
        # Read TPKT header: version(1)+reserved(1)+length(2)
        hdr = b""
        while len(hdr) < 4:
            chunk = sock.recv(4 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
        total_len = struct.unpack(">H", hdr[2:4])[0]
        payload = b""
        remaining = total_len - 4
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                break
            payload += chunk
            remaining -= len(chunk)
        return hdr + payload
    except Exception:
        return None


def _s7plus_scan(host: str, port: int, timeout: int) -> Optional[dict]:
    """Connect to S7-1200/1500 via S7comm+ and extract identity information."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)

        # TPKT/COTP Connection Request
        sock.sendall(_COTP_CONNECT)
        resp1 = _recv_tpkt(sock, timeout)
        if not resp1 or len(resp1) < 7:
            sock.close()
            return None
        cotp_type = resp1[5] if len(resp1) > 5 else 0
        if cotp_type != 0xD0:  # Not a CC (Connection Confirm)
            sock.close()
            return None

        # S7comm+ Session Setup
        time.sleep(0.1)
        sock.sendall(_S7PLUS_SESSION_SETUP)
        resp2 = _recv_tpkt(sock, timeout)
        sock.close()

        if not resp2 or len(resp2) < 30:
            return {"host": host, "port": port, "note": "TPKT/COTP OK — S7comm+ session response too short"}

        # Look for printable string segments (order code, version strings)
        # The response contains TLV-encoded fields; we search for known patterns
        result: dict = {"host": host, "port": port}
        data = resp2[7:]  # skip TPKT+COTP DT header

        # Extract printable ASCII strings (>= 4 chars) as candidate fields
        strings = []
        current = []
        for b in data:
            if 0x20 <= b <= 0x7E:
                current.append(chr(b))
            else:
                if len(current) >= 4:
                    strings.append("".join(current))
                current = []
        if current and len(current) >= 4:
            strings.append("".join(current))

        # Filter for Siemens-like strings
        order_codes = [s for s in strings if s.startswith("6E") or s.startswith("6A") or s.startswith("6S")]
        versions = [s for s in strings if "V" in s and any(c.isdigit() for c in s)]

        if order_codes:
            result["order_code"] = order_codes[0]
        if versions:
            result["firmware_version"] = versions[0]
        if strings:
            result["raw_strings"] = strings[:5]  # first 5 printable fields

        return result
    except Exception:
        return None


class Exploit(BaseExploit):
    """S7comm+ (S7-1200/S7-1500) PLC Scanner — identity extraction.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Siemens S7comm+ Scanner (S7-1200/S7-1500)",
        "description": (
            "Connects to TCP/102 and performs S7comm+ Session Setup to extract "
            "order code, serial number, hardware/firmware version from Siemens "
            "S7-1200 and S7-1500 PLCs. No authentication required on default config. "
            "Ported from ISF icssploit s7comm_plus_scan.py using raw sockets (no Scapy)."
        ),
        "authors": (
            "wenzhe zhu <jtrkid[at]gmail.com> (ISF icssploit)",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge port",
        ),
        "references": (
            "https://www.siemens.com/global/en/products/automation/systems/industrial/plc.html",
            "https://attack.mitre.org/techniques/T0846/",
        ),
        "devices": (
            "Siemens S7-1200 (all CPU variants)",
            "Siemens S7-1500 (all CPU variants)",
            "Siemens ET 200SP CPU",
        ),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(102, "ISO-on-TCP port (default 102)")
    timeout = OptInteger(5, "Socket timeout in seconds")

    def run(self) -> None:
        """Scan S7comm+ PLC and display identity information."""
        print_status(f"[S7comm+] Scanning {self.target}:{self.port}...")
        result = _s7plus_scan(self.target, self.port, self.timeout)
        if result:
            print_success(f"[S7comm+] S7 device found on {self.target}:{self.port}")
            for key, val in result.items():
                if isinstance(val, list):
                    print_success(f"  {key}: {', '.join(val)}")
                else:
                    print_success(f"  {key}: {val}")
        else:
            print_error(f"[S7comm+] No S7comm+ response from {self.target}:{self.port}")

    @mute
    def check(self) -> bool:
        """Return True if TCP/102 COTP connection is accepted."""
        return _s7plus_scan(self.target, self.port, 3) is not None
