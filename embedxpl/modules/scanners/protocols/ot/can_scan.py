# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""CAN Bus Sniffer - Arbitration ID and UDS PID Scanner.

Captures CAN bus frames to enumerate arbitration IDs, identify active
ECUs, and probe UDS (Unified Diagnostic Services) PIDs via ISO 14229.

References:
  - ISO 11898 (CAN protocol)
  - ISO 14229 (UDS - Unified Diagnostic Services)
  - ISO 15765 (CAN transport layer / ISO-TP)

Version: 1.0.0
"""

import struct
import socket
import time

from embedxpl.core.exploit import *


_CAN_EFF_FLAG = 0x80000000
_CAN_RTR_FLAG = 0x40000000
_CAN_ERR_FLAG = 0x20000000
_CAN_EFF_MASK = 0x1FFFFFFF
_CAN_SFF_MASK = 0x000007FF

_UDS_SID_DIAGNOSTIC_SESSION = 0x10
_UDS_SID_READ_DID = 0x22
_UDS_SID_TESTER_PRESENT = 0x3E
_UDS_SID_READ_DTC = 0x19

_COMMON_DIDS = {
    0xF186: "Active Diagnostic Session",
    0xF187: "Spare Part Number",
    0xF188: "ECU Software Version",
    0xF189: "ECU Software Number",
    0xF18A: "System Supplier ID",
    0xF18B: "ECU Manufacturing Date",
    0xF190: "VIN",
    0xF191: "Hardware Number",
    0xF192: "Supplier Hardware Version",
    0xF193: "Supplier Software Version",
    0xF194: "Supplier Manufacturing ID",
    0xF195: "ECU Serial Number",
    0xF197: "System Name",
    0xF19E: "Application Software ID",
}


class Exploit(Exploit):
    """CAN Bus Arbitration ID and UDS PID Scanner.

    Captures CAN frames via SocketCAN to enumerate active arbitration
    IDs and probe ECUs with UDS diagnostic requests.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "CAN Bus Arbitration ID and UDS Scanner",
        "description": (
            "Captures CAN bus traffic via SocketCAN to enumerate arbitration IDs, "
            "identify active ECUs, and probe UDS (ISO 14229) diagnostic services "
            "for VIN, software version, and DTC information."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://www.iso.org/standard/63648.html",
            "https://www.iso.org/standard/72439.html",
        ),
        "devices": ("Automotive ECUs", "CAN-enabled PLCs", "Industrial CAN nodes"),
        "severity": "info",
        "mitre": ["T0846"],
        "status": "confirmed",
        "required_hardware": ["can_bus_interface"],
    }

    target = OptString("", "Target arbitration ID filter (hex, empty for all)")
    timeout = OptInteger(10, "Passive capture duration in seconds")
    interface = OptString("can0", "SocketCAN interface name")
    uds_scan = OptBool(True, "Probe discovered IDs with UDS requests")
    uds_tx_id = OptString("7DF", "UDS broadcast request ID (hex)")
    uds_rx_base = OptInteger(0x7E8, "UDS response base ID")

    def _open_can_socket(self) -> socket.socket:
        """Open raw CAN socket on the specified interface."""
        try:
            sock = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
            sock.bind((str(self.interface),))
            sock.settimeout(1.0)
            return sock
        except (socket.error, OSError, AttributeError) as exc:
            raise RuntimeError(
                "Cannot open CAN socket on {}: {}".format(self.interface, exc)
            )

    def _recv_frame(self, sock: socket.socket) -> dict:
        """Receive and parse a single CAN frame."""
        data = sock.recv(16)
        if len(data) < 16:
            return {}
        can_id, dlc = struct.unpack("<IB", data[:5])
        payload = data[8:8 + (dlc & 0x0F)]
        is_extended = bool(can_id & _CAN_EFF_FLAG)
        is_rtr = bool(can_id & _CAN_RTR_FLAG)
        arb_id = can_id & (_CAN_EFF_MASK if is_extended else _CAN_SFF_MASK)
        return {
            "arb_id": arb_id,
            "arb_id_hex": "0x{:08X}".format(arb_id) if is_extended else "0x{:03X}".format(arb_id),
            "dlc": dlc & 0x0F,
            "data": payload,
            "extended": is_extended,
            "rtr": is_rtr,
        }

    def _send_frame(self, sock: socket.socket, arb_id: int, data: bytes) -> None:
        """Send a CAN frame."""
        dlc = len(data)
        padding = b"\x00" * (8 - dlc)
        frame = struct.pack("<IB3s", arb_id, dlc, b"\x00\x00\x00") + data + padding
        sock.send(frame)

    def _passive_capture(self, sock: socket.socket) -> dict:
        """Passively capture CAN traffic and aggregate by arbitration ID."""
        arb_ids = {}
        deadline = time.time() + float(self.timeout)
        while time.time() < deadline:
            try:
                frame = self._recv_frame(sock)
                if not frame:
                    continue
                aid = frame["arb_id"]
                if self.target:
                    try:
                        filter_id = int(str(self.target), 16)
                        if aid != filter_id:
                            continue
                    except ValueError:
                        pass

                if aid not in arb_ids:
                    arb_ids[aid] = {
                        "arb_id": aid,
                        "arb_id_hex": frame["arb_id_hex"],
                        "extended": frame["extended"],
                        "count": 0,
                        "dlc_set": set(),
                        "first_data": frame["data"],
                    }
                arb_ids[aid]["count"] += 1
                arb_ids[aid]["dlc_set"].add(frame["dlc"])
            except socket.timeout:
                continue
            except (socket.error, OSError):
                break
        return arb_ids

    def _uds_tester_present(self, sock: socket.socket) -> bool:
        """Send UDS Tester Present (broadcast) and check for response."""
        tx_id = int(str(self.uds_tx_id), 16)
        payload = struct.pack(">BB", 0x02, _UDS_SID_TESTER_PRESENT) + b"\x00"
        self._send_frame(sock, tx_id, payload)
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                frame = self._recv_frame(sock)
                if not frame:
                    continue
                rx_base = int(self.uds_rx_base)
                if rx_base <= frame["arb_id"] <= rx_base + 0x07:
                    if len(frame["data"]) >= 2 and frame["data"][1] == 0x7E:
                        return True
            except socket.timeout:
                continue
        return False

    def _uds_read_did(self, sock: socket.socket, did: int) -> str:
        """Send UDS Read Data By Identifier and return response string."""
        tx_id = int(str(self.uds_tx_id), 16)
        payload = struct.pack(">BBH", 0x03, _UDS_SID_READ_DID, did)
        self._send_frame(sock, tx_id, payload)
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                frame = self._recv_frame(sock)
                if not frame:
                    continue
                rx_base = int(self.uds_rx_base)
                if rx_base <= frame["arb_id"] <= rx_base + 0x07:
                    data = frame["data"]
                    if len(data) >= 4 and data[1] == 0x62:
                        resp_did = struct.unpack(">H", data[2:4])[0]
                        if resp_did == did:
                            return data[4:].decode("ascii", errors="replace").strip("\x00")
                    if len(data) >= 2 and data[1] == 0x7F:
                        return ""
            except socket.timeout:
                continue
        return ""

    def _probe_uds(self, sock: socket.socket) -> dict:
        """Probe standard UDS DIDs and collect responses."""
        results = {}
        if not self._uds_tester_present(sock):
            return results
        for did, name in _COMMON_DIDS.items():
            value = self._uds_read_did(sock, did)
            if value:
                results[name] = value
            time.sleep(0.05)
        return results

    @mute
    def check(self) -> bool:
        """Verify CAN interface is available."""
        try:
            sock = self._open_can_socket()
            sock.close()
            return True
        except RuntimeError:
            return False

    @multi
    def run(self) -> None:
        """Execute CAN bus capture and UDS scan."""
        print_status("Starting CAN bus capture on {} for {} seconds".format(
            self.interface, self.timeout
        ))

        try:
            sock = self._open_can_socket()
        except RuntimeError as exc:
            print_error("{}".format(exc))
            return

        try:
            arb_ids = self._passive_capture(sock)
        except Exception as exc:
            print_error("Capture error: {}".format(exc))
            sock.close()
            return

        if not arb_ids:
            print_warning("No CAN traffic captured")
            sock.close()
            return

        print_success("Captured {} unique arbitration ID(s)".format(len(arb_ids)))
        for entry in sorted(arb_ids.values(), key=lambda e: e["arb_id"]):
            dlc_str = "/".join(str(d) for d in sorted(entry["dlc_set"]))
            print_info("{} - {} frame(s), DLC: {}, {}".format(
                entry["arb_id_hex"],
                entry["count"],
                dlc_str,
                "extended" if entry["extended"] else "standard",
            ))

        if self.uds_scan:
            print_status("Probing UDS diagnostic services...")
            uds_results = self._probe_uds(sock)
            if uds_results:
                print_success("UDS data extracted:")
                for name, value in uds_results.items():
                    print_info("  {}: {}".format(name, value))
            else:
                print_info("No UDS responses received (no UDS-capable ECU or access denied)")

        sock.close()
