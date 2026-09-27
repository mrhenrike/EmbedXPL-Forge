# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Siemens S7 Communication Plus Scanner — Fingerprint S7 PLCs (Port 102/TCP).

Siemens S7 PLCs use the S7 Communication protocol (S7comm and S7comm-plus) over
ISO-TSAP/COTP on TCP port 102.  The scanner performs:

  1. COTP Connection Request (CR) — establishes transport connection.
  2. S7comm Setup Communication request — negotiates PDU size.
  3. Reads CPU identification (SZL ID 0x001C) — returns PLC order number,
     module name, plant identification, hardware/firmware version.

S7comm has no authentication; the PLC processes any valid S7 connection.
S7comm-plus (used by S7-1200/1500) has optional but often misconfigured
session-based authentication.

References:
  - Siemens PCS7 / TIA Portal
  - MITRE ATT&CK ICS: T0855 (Unauthorized Command Message)
  - Digitalbond Project Redpoint S7 Scanner
  - Stuxnet/INCONTROLLER used S7 protocol for PLC manipulation

Version: 1.0.0
"""

import socket
import struct
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_S7_PORT = 102

# ISO-TSAP COTP Connection Request (CR)
_COTP_CR = bytes([
    0x03, 0x00,        # TPKT version + reserved
    0x00, 0x16,        # TPKT length (22)
    0x11,              # COTP header length
    0xE0,              # CR TPDU
    0x00, 0x00,        # DST-REF
    0x00, 0x01,        # SRC-REF
    0x00,              # Class 0
    0xC0, 0x01, 0x0A,  # Proposed max TPDU size
    0xC1, 0x02, 0x01, 0x00,  # TSAP src (1.0)
    0xC2, 0x02, 0x01, 0x02,  # TSAP dst (1.2 = PLC rack 0 slot 2)
])

# S7comm Setup Communication request
_S7_SETUP_COMM = bytes([
    0x03, 0x00, 0x00, 0x19,  # TPKT
    0x02, 0xF0, 0x80,        # COTP DT
    0x32, 0x01, 0x00, 0x00,  # S7comm: protocol id, ROSCTR=1 (Job), reserved
    0x00, 0x00,              # PDU reference
    0x00, 0x08,              # Parameter length
    0x00, 0x00,              # Data length
    0xF0, 0x00,              # Function: Setup Communication
    0x00, 0x01,              # Reserved
    0x00, 0x01,              # Max AMQ calling
    0x00, 0x01,              # Max AMQ called
    0x03, 0xC0,              # PDU length (960)
])

# S7comm Read SZL (System Status List) ID 0x001C — CPU identification
_S7_READ_SZL = bytes([
    0x03, 0x00, 0x00, 0x21,  # TPKT
    0x02, 0xF0, 0x80,        # COTP DT
    0x32, 0x07, 0x00, 0x00,  # S7comm: UserData
    0x00, 0x00,              # PDU ref
    0x00, 0x08,              # Parameter length
    0x00, 0x08,              # Data length
    0x00, 0x01, 0x12,        # Parameter head
    0x04, 0x11, 0x44, 0x01, 0x00,  # Subfunc: SZL read, seq=1
    0xFF, 0x09, 0x00, 0x04,  # Data
    0x00, 0x1C, 0x00, 0x00,  # SZL ID 0x001C, index 0
])


def _recv_tpkt(sock: socket.socket) -> Optional[bytes]:
    """Receive a complete TPKT message from socket."""
    try:
        header = b""
        while len(header) < 4:
            chunk = sock.recv(4 - len(header))
            if not chunk:
                return None
            header += chunk
        if header[0] != 0x03:
            return header
        total_len = struct.unpack(">H", header[2:4])[0]
        body = b""
        remaining = total_len - 4
        while len(body) < remaining:
            chunk = sock.recv(remaining - len(body))
            if not chunk:
                break
            body += chunk
        return header + body
    except Exception:
        return None


class Exploit(BaseExploit):
    """Siemens S7 PLC Communication Scanner — CPU identification via S7comm.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Siemens S7 PLC Scanner",
        "description": (
            "Scans for Siemens S7 PLCs on TCP/102 using the S7 Communication protocol. "
            "Performs COTP connection request + S7comm Setup Communication + SZL read "
            "to extract CPU order number, module name, hardware/firmware versions. "
            "S7comm has no authentication — targets S7-300/400/1200/1500 series."
        ),
        "authors": (
            "Digitalbond / Project Redpoint",
            "Smod (scadastrangelove)",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "references": (
            "https://github.com/digitalbond/Redpoint",
            "https://attack.mitre.org/techniques/T0855/",
        ),
        "devices": (
            "Siemens S7-300", "Siemens S7-400", "Siemens S7-1200", "Siemens S7-1500",
            "Siemens S7-200", "LOGO! PLC",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(_S7_PORT, "S7 Communication port (default 102)")
    timeout = OptInteger(8, "Socket timeout in seconds")

    def run(self) -> None:
        print_status("Connecting to S7 PLC on {}:{}...".format(self.target, self.port))
        try:
            sock = socket.create_connection((self.target, self.port), timeout=self.timeout)
        except Exception as exc:
            print_error("Connection failed: {}".format(exc))
            return

        try:
            # Step 1: COTP Connection Request
            sock.sendall(_COTP_CR)
            cotp_resp = _recv_tpkt(sock)
            if not cotp_resp or len(cotp_resp) < 5 or cotp_resp[4] != 0x0B:
                print_error("COTP connection rejected — target may not be an S7 PLC")
                return
            print_success("COTP connected to {}:{}".format(self.target, self.port))

            # Step 2: S7comm Setup Communication
            sock.sendall(_S7_SETUP_COMM)
            setup_resp = _recv_tpkt(sock)
            if not setup_resp or len(setup_resp) < 17:
                print_error("S7comm setup failed")
                return

            # PDU size from negotiated response
            if len(setup_resp) >= 25:
                pdu_size = struct.unpack(">H", setup_resp[23:25])[0]
                print_status("PDU size negotiated: {} bytes".format(pdu_size))

            # Step 3: Read SZL CPU identification
            sock.sendall(_S7_READ_SZL)
            szl_resp = _recv_tpkt(sock)
            if szl_resp and len(szl_resp) > 30:
                # SZL data starts around offset 33; contains ASCII strings
                szl_data = szl_resp[33:]
                # Try to extract order number (typically 20 bytes ASCII at offset 2)
                try:
                    order_num = szl_data[2:22].decode("ascii", errors="replace").strip("\x00")
                    if order_num:
                        print_success("Order Number: {}".format(order_num))
                    module_name = szl_data[36:68].decode("ascii", errors="replace").strip("\x00") \
                        if len(szl_data) > 68 else ""
                    if module_name:
                        print_success("Module Name: {}".format(module_name))
                    plant_id = szl_data[22:32].decode("ascii", errors="replace").strip("\x00") \
                        if len(szl_data) > 32 else ""
                    if plant_id:
                        print_status("Plant ID: {}".format(plant_id))
                except Exception:
                    print_status("SZL data ({} bytes) — could not parse fields".format(len(szl_data)))
            else:
                print_status("No SZL response or insufficient data")
        finally:
            sock.close()

    @mute
    def check(self) -> bool:
        try:
            sock = socket.create_connection((self.target, self.port), timeout=5)
            sock.sendall(_COTP_CR)
            resp = _recv_tpkt(sock)
            sock.close()
            return resp is not None and len(resp) >= 5
        except Exception:
            return False
