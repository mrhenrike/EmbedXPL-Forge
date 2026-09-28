# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Modbus TCP Device Identification Scanner.

Scans Modbus TCP slaves using FC 17 (Report Server ID) and FC 43/14
(Read Device Identification) to extract vendor name, product code,
major/minor revision, and additional device metadata. Port 502.

Constructs Modbus ADU frames manually using struct.pack for each
function code probe.

References:
  - Modbus Application Protocol Specification V1.1b3
  - Modbus Implementation Guide (FC 43 MEI)

Version: 1.0.0
"""

import socket
import struct

from embedxpl.core.exploit import *


class Exploit(Exploit):
    """Modbus TCP Device Identification Scanner.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Modbus TCP Device Identification Scanner",
        "description": (
            "Probes Modbus TCP devices using FC 17 (Report Server ID) and "
            "FC 43/14 (Read Device Identification) to extract vendor, product "
            "code, revision, and device metadata. Identifies PLC/RTU models "
            "and firmware versions on TCP/502."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf",
        ),
        "devices": (
            "Any Modbus TCP device",
            "Schneider Electric Modicon",
            "Allen-Bradley MicroLogix/CompactLogix",
            "Siemens S7 (Modbus module)",
            "Wago 750 series",
            "ABB AC500",
        ),
        "severity": "info",
        "mitre": ["T0846"],
        "status": "confirmed",
    }

    target = OptIP("", "Target Modbus TCP device IP")
    port = OptPort(502, "Modbus TCP port")
    timeout = OptInteger(3, "Socket timeout in seconds")
    unit_id = OptInteger(1, "Modbus Unit ID (slave address)")
    scan_range = OptBool(False, "Scan unit IDs 1-247")

    _FC_REPORT_SERVER_ID = 0x11
    _FC_MEI = 0x2B
    _MEI_TYPE_READ_DEVICE_ID = 0x0E
    _PROTOCOL_ID = 0x0000

    def _next_tx_id(self) -> int:
        if not hasattr(self, "_tx_counter"):
            self._tx_counter = 0
        self._tx_counter = (self._tx_counter + 1) & 0xFFFF
        return self._tx_counter

    def _build_report_server_id(self, unit: int) -> bytes:
        """Build FC 17 (Report Server ID) request."""
        pdu = struct.pack(">B", self._FC_REPORT_SERVER_ID)
        mbap = struct.pack(
            ">HHHB", self._next_tx_id(), self._PROTOCOL_ID, len(pdu) + 1, unit
        )
        return mbap + pdu

    def _build_read_device_id(self, unit: int, obj_id: int = 0x00) -> bytes:
        """Build FC 43/14 (Read Device Identification) request.

        Object IDs:
          0x00 = VendorName
          0x01 = ProductCode
          0x02 = MajorMinorRevision
          0x03 = VendorUrl
          0x04 = ProductName
          0x05 = ModelName
          0x06 = UserApplicationName
        """
        pdu = struct.pack(
            ">BBB B",
            self._FC_MEI,
            self._MEI_TYPE_READ_DEVICE_ID,
            0x01,  # read device ID code: basic (objects 0x00-0x02)
            obj_id,
        )
        mbap = struct.pack(
            ">HHHB", self._next_tx_id(), self._PROTOCOL_ID, len(pdu) + 1, unit
        )
        return mbap + pdu

    def _send_modbus(self, frame: bytes) -> bytes:
        """Send Modbus TCP frame and return response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(self.timeout))
            sock.connect((self.target, self.port))
            sock.sendall(frame)
            resp = sock.recv(260)
            sock.close()
            return resp
        except (socket.error, OSError):
            return b""

    def _parse_server_id(self, resp: bytes) -> dict:
        """Parse FC 17 Report Server ID response."""
        result = {}
        if len(resp) < 9:
            return result

        fc = resp[7]
        if fc == self._FC_REPORT_SERVER_ID:
            byte_count = resp[8]
            if byte_count > 0 and len(resp) > 9:
                server_id = resp[9:9 + byte_count]
                result["server_id"] = server_id.decode("ascii", errors="replace").rstrip("\x00")
                # Run status is last byte
                if len(resp) > 9 + byte_count:
                    result["run_status"] = "ON" if resp[9 + byte_count] == 0xFF else "OFF"
        elif fc == (self._FC_REPORT_SERVER_ID | 0x80):
            exc = resp[8] if len(resp) > 8 else 0
            result["error"] = "Exception code {}".format(exc)

        return result

    def _parse_device_id(self, resp: bytes) -> dict:
        """Parse FC 43/14 Read Device Identification response."""
        result = {}
        if len(resp) < 14:
            return result

        fc = resp[7]
        if fc == self._FC_MEI:
            # Response: FC(1) + MEI_type(1) + DeviceIdCode(1) + ConformityLevel(1) +
            #           MoreFollows(1) + NextObjectId(1) + NumObjects(1) + objects...
            if len(resp) < 15:
                return result

            num_objects = resp[14]
            offset = 15
            obj_names = {
                0x00: "vendor_name",
                0x01: "product_code",
                0x02: "revision",
                0x03: "vendor_url",
                0x04: "product_name",
                0x05: "model_name",
                0x06: "user_app_name",
            }

            for _ in range(num_objects):
                if offset + 2 > len(resp):
                    break
                obj_id = resp[offset]
                obj_len = resp[offset + 1]
                offset += 2
                if offset + obj_len > len(resp):
                    break
                obj_val = resp[offset:offset + obj_len].decode("ascii", errors="replace")
                key = obj_names.get(obj_id, "object_0x{:02x}".format(obj_id))
                result[key] = obj_val
                offset += obj_len
        elif fc == (self._FC_MEI | 0x80):
            exc = resp[8] if len(resp) > 8 else 0
            result["error"] = "Exception code {}".format(exc)

        return result

    def _scan_unit(self, unit: int) -> dict:
        """Scan a single unit ID with both FC 17 and FC 43/14."""
        info = {"unit_id": unit}

        # FC 17: Report Server ID
        resp = self._send_modbus(self._build_report_server_id(unit))
        if resp:
            server_info = self._parse_server_id(resp)
            info.update(server_info)

        # FC 43/14: Read Device Identification (basic)
        resp = self._send_modbus(self._build_read_device_id(unit, 0x00))
        if resp:
            device_info = self._parse_device_id(resp)
            info.update(device_info)

        return info

    @mute
    def check(self) -> bool:
        """Verify Modbus TCP port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(self.timeout))
            sock.connect((self.target, self.port))
            sock.close()
            return True
        except (socket.error, OSError):
            return False

    @multi
    def run(self) -> None:
        """Execute Modbus device identification scan."""
        print_status(
            "Scanning Modbus TCP at {}:{}".format(self.target, self.port)
        )

        if not self.check():
            print_error("Modbus TCP port not accessible")
            return

        print_success("Modbus TCP port open")

        if self.scan_range:
            print_info("Scanning unit IDs 1-247...")
            found = 0
            for uid in range(1, 248):
                info = self._scan_unit(uid)
                if "vendor_name" in info or "server_id" in info:
                    found += 1
                    self._print_device_info(info)
            print_info("Scan complete: {} device(s) found".format(found))
        else:
            info = self._scan_unit(self.unit_id)
            if "error" in info and not any(
                k for k in info if k not in ("unit_id", "error")
            ):
                print_error("Unit ID {} - {}".format(self.unit_id, info["error"]))
            else:
                self._print_device_info(info)

    def _print_device_info(self, info: dict) -> None:
        """Format and print discovered device information."""
        print_success("Device at Unit ID {}:".format(info.get("unit_id", "?")))
        if "vendor_name" in info:
            print_info("  Vendor:   {}".format(info["vendor_name"]))
        if "product_code" in info:
            print_info("  Product:  {}".format(info["product_code"]))
        if "revision" in info:
            print_info("  Revision: {}".format(info["revision"]))
        if "model_name" in info:
            print_info("  Model:    {}".format(info["model_name"]))
        if "server_id" in info:
            print_info("  Server ID: {}".format(info["server_id"]))
        if "run_status" in info:
            print_info("  Status:   {}".format(info["run_status"]))
