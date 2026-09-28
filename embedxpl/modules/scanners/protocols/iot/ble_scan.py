# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""BLE GATT Services and Advertising Data Scanner.

Scans Bluetooth Low Energy peripherals for advertising data,
GATT service UUIDs, characteristics, and device information.

References:
  - Bluetooth Core Specification v5.x
  - GATT Service Discovery (Bluetooth SIG)

Version: 1.0.0
"""

import struct
import socket
import time

from embedxpl.core.exploit import *


_COMMON_SERVICES = {
    "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
    "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "00001810-0000-1000-8000-00805f9b34fb": "Blood Pressure",
    "00001809-0000-1000-8000-00805f9b34fb": "Health Thermometer",
    "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate",
    "00001812-0000-1000-8000-00805f9b34fb": "Human Interface Device",
    "00001815-0000-1000-8000-00805f9b34fb": "Automation IO",
    "00001802-0000-1000-8000-00805f9b34fb": "Immediate Alert",
    "00001803-0000-1000-8000-00805f9b34fb": "Link Loss",
    "00001804-0000-1000-8000-00805f9b34fb": "Tx Power",
    "0000fee0-0000-1000-8000-00805f9b34fb": "Xiaomi Mi Band",
    "0000feaa-0000-1000-8000-00805f9b34fb": "Eddystone",
}

_AD_TYPES = {
    0x01: "Flags",
    0x02: "Incomplete 16-bit UUIDs",
    0x03: "Complete 16-bit UUIDs",
    0x06: "Incomplete 128-bit UUIDs",
    0x07: "Complete 128-bit UUIDs",
    0x08: "Shortened Local Name",
    0x09: "Complete Local Name",
    0x0A: "TX Power Level",
    0xFF: "Manufacturer Specific Data",
    0x16: "Service Data (16-bit UUID)",
}


class Exploit(Exploit):
    """BLE GATT Services and Advertising Data Scanner.

    Scans for BLE peripheral advertisements and enumerates GATT services,
    characteristics, and device information using HCI socket commands.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "BLE GATT Services and Advertising Scanner",
        "description": (
            "Scans Bluetooth Low Energy peripherals for advertising data, "
            "GATT service UUIDs, characteristics, and device information "
            "using HCI raw socket commands."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://www.bluetooth.com/specifications/specs/core-specification-5-4/",
        ),
        "devices": ("BLE Peripherals", "IoT Sensors", "Wearables", "Beacons"),
        "severity": "info",
        "mitre": ["T0846"],
        "status": "confirmed",
        "required_hardware": ["ble_adapter"],
    }

    target = OptString("", "Target BLE MAC address (empty for passive scan)")
    timeout = OptInteger(10, "Scan duration in seconds")
    hci_device = OptInteger(0, "HCI device index (hci0=0, hci1=1)")

    _OGF_LE = 0x08
    _OCF_SET_SCAN_PARAMS = 0x000B
    _OCF_SET_SCAN_ENABLE = 0x000C

    def _hci_open(self) -> socket.socket:
        """Open raw HCI socket for BLE operations."""
        try:
            sock = socket.socket(
                socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI
            )
            sock.bind((int(self.hci_device),))
            sock.settimeout(float(self.timeout))
            return sock
        except (socket.error, OSError, AttributeError) as exc:
            raise RuntimeError(
                "Cannot open HCI device hci{}: {}".format(self.hci_device, exc)
            )

    def _hci_send_cmd(self, sock: socket.socket, ogf: int, ocf: int,
                      params: bytes = b"") -> None:
        """Send HCI command via raw socket."""
        opcode = (ogf << 10) | ocf
        header = struct.pack("<BHB", 0x01, opcode, len(params))
        sock.sendall(header + params)

    def _enable_le_scan(self, sock: socket.socket) -> None:
        """Configure and enable LE passive scan."""
        scan_params = struct.pack("<BHHBB", 0x00, 0x0010, 0x0010, 0x00, 0x00)
        self._hci_send_cmd(sock, self._OGF_LE, self._OCF_SET_SCAN_PARAMS, scan_params)
        time.sleep(0.1)
        enable_params = struct.pack("<BB", 0x01, 0x00)
        self._hci_send_cmd(sock, self._OGF_LE, self._OCF_SET_SCAN_ENABLE, enable_params)

    def _disable_le_scan(self, sock: socket.socket) -> None:
        """Disable LE scan."""
        disable_params = struct.pack("<BB", 0x00, 0x00)
        self._hci_send_cmd(sock, self._OGF_LE, self._OCF_SET_SCAN_ENABLE, disable_params)

    def _parse_ad_structures(self, data: bytes) -> list:
        """Parse advertising data into AD type/value pairs."""
        structures = []
        offset = 0
        while offset < len(data):
            if offset >= len(data):
                break
            length = data[offset]
            if length == 0 or offset + 1 + length > len(data):
                break
            ad_type = data[offset + 1]
            ad_data = data[offset + 2:offset + 1 + length]
            type_name = _AD_TYPES.get(ad_type, "Type 0x{:02x}".format(ad_type))
            structures.append({
                "type": ad_type,
                "type_name": type_name,
                "data": ad_data,
            })
            offset += 1 + length
        return structures

    def _format_mac(self, raw: bytes) -> str:
        """Format 6-byte address as MAC string."""
        return ":".join("{:02X}".format(b) for b in reversed(raw))

    def _uuid16_to_full(self, uuid16: int) -> str:
        """Expand 16-bit UUID to full 128-bit string."""
        return "{:08x}-0000-1000-8000-00805f9b34fb".format(uuid16)

    def _extract_uuids(self, ad_structures: list) -> list:
        """Extract service UUIDs from advertising structures."""
        uuids = []
        for ad in ad_structures:
            if ad["type"] in (0x02, 0x03):
                data = ad["data"]
                for i in range(0, len(data) - 1, 2):
                    uuid16 = struct.unpack("<H", data[i:i + 2])[0]
                    uuids.append(self._uuid16_to_full(uuid16))
            elif ad["type"] in (0x06, 0x07):
                data = ad["data"]
                for i in range(0, len(data) - 15, 16):
                    raw = data[i:i + 16]
                    parts = [
                        raw[3::-1].hex(),
                        raw[5:3:-1].hex(),
                        raw[7:5:-1].hex(),
                        raw[8:10].hex(),
                        raw[10:16].hex(),
                    ]
                    uuids.append("-".join(parts))
        return uuids

    def _extract_local_name(self, ad_structures: list) -> str:
        """Extract device local name from advertising data."""
        for ad in ad_structures:
            if ad["type"] in (0x08, 0x09):
                return ad["data"].decode("utf-8", errors="replace")
        return ""

    def _scan_advertisements(self) -> list:
        """Perform BLE passive scan and collect advertisement data."""
        devices = {}
        try:
            sock = self._hci_open()
        except RuntimeError as exc:
            print_error("{}".format(exc))
            return []

        try:
            self._enable_le_scan(sock)
            deadline = time.time() + float(self.timeout)
            while time.time() < deadline:
                try:
                    data = sock.recv(1024)
                    if not data or len(data) < 14:
                        continue
                    pkt_type = data[0]
                    if pkt_type != 0x04:
                        continue
                    evt_code = data[1]
                    if evt_code != 0x3E:
                        continue
                    sub_evt = data[3]
                    if sub_evt != 0x02:
                        continue
                    num_reports = data[4]
                    offset = 5
                    for _ in range(num_reports):
                        if offset + 9 > len(data):
                            break
                        addr_type = data[offset + 1]
                        addr_raw = data[offset + 2:offset + 8]
                        mac = self._format_mac(addr_raw)
                        ad_len = data[offset + 8]
                        ad_data = data[offset + 9:offset + 9 + ad_len]
                        rssi_offset = offset + 9 + ad_len
                        rssi = struct.unpack("b", bytes([data[rssi_offset]]))[0] if rssi_offset < len(data) else -127

                        if mac not in devices:
                            ad_structs = self._parse_ad_structures(ad_data)
                            devices[mac] = {
                                "mac": mac,
                                "addr_type": "public" if addr_type == 0 else "random",
                                "rssi": rssi,
                                "name": self._extract_local_name(ad_structs),
                                "uuids": self._extract_uuids(ad_structs),
                                "ad_structures": ad_structs,
                            }
                        offset = rssi_offset + 1
                except socket.timeout:
                    break
                except (socket.error, OSError):
                    break
            self._disable_le_scan(sock)
        finally:
            sock.close()

        return list(devices.values())

    @mute
    def check(self) -> bool:
        """Verify HCI device is available."""
        try:
            sock = self._hci_open()
            sock.close()
            return True
        except RuntimeError:
            return False

    @multi
    def run(self) -> None:
        """Execute BLE advertising scan."""
        print_status("Starting BLE scan on hci{} for {} seconds".format(
            self.hci_device, self.timeout
        ))

        if not self.check():
            print_error("HCI device hci{} not available".format(self.hci_device))
            return

        devices = self._scan_advertisements()
        if not devices:
            print_warning("No BLE devices discovered")
            return

        print_success("Discovered {} BLE device(s)".format(len(devices)))
        for dev in sorted(devices, key=lambda d: d["rssi"], reverse=True):
            name_str = dev["name"] or "(unknown)"
            print_info("{} [{}] RSSI: {} dBm - {}".format(
                dev["mac"], dev["addr_type"], dev["rssi"], name_str
            ))
            for uuid in dev["uuids"]:
                svc_name = _COMMON_SERVICES.get(uuid, "Custom Service")
                print_info("  Service: {} ({})".format(svc_name, uuid))
