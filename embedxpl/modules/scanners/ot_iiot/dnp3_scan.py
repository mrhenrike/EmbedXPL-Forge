# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""DNP3 Data Link Layer Scanner.

Scans for DNP3 outstations by sending Link Status Request frames at the
data link layer. Identifies valid master/outstation address pairs and
confirms DNP3 service presence on TCP/20000.

Constructs DNP3 data link layer frames with proper CRC-16 calculation
using struct.pack.

References:
  - IEEE 1815-2012 (DNP3 Specification)
  - DNP3 Data Link Layer Protocol

Version: 1.0.0
"""

import socket
import struct
import time

from embedxpl.core.exploit import *


class Exploit(Exploit):
    """DNP3 Data Link Layer Scanner.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "DNP3 Data Link Layer Scanner",
        "description": (
            "Scans for DNP3 outstations by sending Link Status Request "
            "frames. Identifies valid master/outstation address pairs by "
            "probing common address ranges. Confirms DNP3 presence on "
            "TCP/20000 and extracts link-layer configuration."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://www.ieee.org/",
            "https://www.dnp.org/",
        ),
        "devices": (
            "SEL protective relays",
            "GE Multilin relays",
            "ABB REF/RET series",
            "Schneider Electric Easergy",
            "Generic DNP3 outstations",
        ),
        "severity": "info",
        "mitre": ["T0846"],
        "status": "confirmed",
    }

    target = OptIP("", "Target DNP3 outstation IP")
    port = OptPort(20000, "DNP3 TCP port")
    timeout = OptInteger(3, "Socket timeout in seconds")
    master_addr = OptInteger(1, "Source (master) address for probes")
    scan_start = OptInteger(1, "First outstation address to scan")
    scan_end = OptInteger(20, "Last outstation address to scan")

    # DNP3 Data Link constants
    _DL_START = 0x0564
    _DL_DIR_MASTER = 0x80
    _DL_PRM_MASTER = 0x40
    _DL_FC_LINK_STATUS = 0x09
    _DL_FC_TEST_LINK = 0x02
    _DL_FC_RESET_LINK = 0x00

    def _crc16_dnp3(self, data: bytes) -> int:
        """Calculate DNP3 CRC-16 (polynomial 0x3D65, reflected)."""
        crc_table = []
        for i in range(256):
            crc = i
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA6BC
                else:
                    crc >>= 1
            crc_table.append(crc & 0xFFFF)

        crc = 0x0000
        for byte in data:
            idx = (crc ^ byte) & 0xFF
            crc = (crc >> 8) ^ crc_table[idx]
        return (~crc) & 0xFFFF

    def _build_link_status_request(self, dst_addr: int) -> bytes:
        """Build DNP3 Link Status Request frame."""
        control = self._DL_DIR_MASTER | self._DL_PRM_MASTER | self._DL_FC_LINK_STATUS
        length = 5  # minimum data link frame (no user data)

        header = struct.pack("<H", self._DL_START)
        header += struct.pack("<B", length)
        header += struct.pack("<B", control)
        header += struct.pack("<H", dst_addr & 0xFFFF)
        header += struct.pack("<H", self.master_addr & 0xFFFF)

        crc = self._crc16_dnp3(header)
        return header + struct.pack("<H", crc)

    def _build_test_link(self, dst_addr: int) -> bytes:
        """Build DNP3 Test Link States frame."""
        control = self._DL_DIR_MASTER | self._DL_PRM_MASTER | self._DL_FC_TEST_LINK
        length = 5

        header = struct.pack("<H", self._DL_START)
        header += struct.pack("<B", length)
        header += struct.pack("<B", control)
        header += struct.pack("<H", dst_addr & 0xFFFF)
        header += struct.pack("<H", self.master_addr & 0xFFFF)

        crc = self._crc16_dnp3(header)
        return header + struct.pack("<H", crc)

    def _parse_link_response(self, resp: bytes) -> dict:
        """Parse DNP3 data link layer response."""
        result = {}
        if len(resp) < 10:
            return result

        start = struct.unpack_from("<H", resp, 0)[0]
        if start != self._DL_START:
            return result

        length = resp[2]
        control = resp[3]
        dst_addr = struct.unpack_from("<H", resp, 4)[0]
        src_addr = struct.unpack_from("<H", resp, 6)[0]

        # Verify CRC
        header_data = resp[:8]
        expected_crc = self._crc16_dnp3(header_data)
        actual_crc = struct.unpack_from("<H", resp, 8)[0]

        result["valid_crc"] = expected_crc == actual_crc
        result["src_addr"] = src_addr
        result["dst_addr"] = dst_addr
        result["control"] = control
        result["length"] = length

        # Decode control byte
        result["dir"] = "secondary" if not (control & 0x80) else "primary"
        result["prm"] = bool(control & 0x40)
        result["fc"] = control & 0x0F

        fc_names = {
            0x00: "ACK",
            0x01: "NACK",
            0x0B: "LINK_STATUS",
            0x0F: "NOT_SUPPORTED",
        }
        result["fc_name"] = fc_names.get(result["fc"], "FC_0x{:02X}".format(result["fc"]))

        return result

    def _probe_address(self, sock: socket.socket, dst_addr: int) -> dict:
        """Probe a single outstation address."""
        frame = self._build_link_status_request(dst_addr)
        try:
            sock.sendall(frame)
            time.sleep(0.1)
            resp = sock.recv(292)
            if resp:
                return self._parse_link_response(resp)
        except socket.timeout:
            pass
        return {}

    @mute
    def check(self) -> bool:
        """Verify DNP3 TCP port is accessible."""
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
        """Scan for DNP3 outstations by probing address range."""
        print_status(
            "DNP3 link-layer scan on {}:{} (addresses {}-{})".format(
                self.target, self.port, self.scan_start, self.scan_end
            )
        )

        if not self.check():
            print_error("DNP3 TCP port not accessible")
            return

        print_success("TCP/{} open - starting DNP3 address scan".format(self.port))

        found_stations = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(self.timeout))
            sock.connect((self.target, self.port))

            for addr in range(self.scan_start, self.scan_end + 1):
                result = self._probe_address(sock, addr)
                if result and result.get("valid_crc"):
                    found_stations.append(result)
                    print_success(
                        "Outstation addr={} responded: {} (src={}, fc={})".format(
                            addr,
                            result.get("fc_name", "?"),
                            result.get("src_addr", "?"),
                            "0x{:02X}".format(result.get("fc", 0)),
                        )
                    )
                elif result:
                    print_info(
                        "Addr {} - response with invalid CRC".format(addr)
                    )

            sock.close()

        except socket.error as exc:
            print_error("Connection error: {}".format(exc))

        print_info(
            "Scan complete: {} active outstation(s) found".format(len(found_stations))
        )

        if found_stations:
            print_info("Summary:")
            for st in found_stations:
                print_info(
                    "  Address {} | Response: {} | Direction: {}".format(
                        st.get("src_addr", "?"),
                        st.get("fc_name", "?"),
                        st.get("dir", "?"),
                    )
                )
