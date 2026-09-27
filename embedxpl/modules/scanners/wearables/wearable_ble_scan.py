# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Wearable Device BLE Advertisement Scanner.

Scans Bluetooth Low Energy (BLE) advertisements to identify wearable
devices from major vendors. Detection criteria:

  - Bluetooth Company ID in manufacturer-specific AD type (0xFF):
      Xiaomi  = 0x038F
      Garmin  = 0x0087
      Samsung = 0x0075
      Fitbit  = 0x0224

  - Standard GATT service UUIDs in the advertisement:
      Heart Rate Service  = 0x180D
      Battery Service     = 0x180F
      Device Information  = 0x180A
      Current Time        = 0x1805

  - Device name pattern matching in complete/shortened local name AD
    types for model-specific identification.

The scanner passively listens to BLE advertisements using the HCI raw
interface and does not initiate any connections. Requires a compatible
BLE adapter (hci0 by default) and root/CAP_NET_ADMIN privileges.

References:
  - https://www.bluetooth.com/specifications/assigned-numbers/
  - https://www.bluetooth.com/specifications/specs/core-specification-5-3/

Version: 1.0.0
"""

import struct
import time
from collections import OrderedDict

from embedxpl.core.exploit import *


class Exploit(Exploit):
    """Wearable BLE Advertisement Scanner.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Wearable Device BLE Advertisement Scanner",
        "description": (
            "Passively scans BLE advertisements to identify wearable devices "
            "from Xiaomi, Garmin, Samsung, and Fitbit using Bluetooth Company "
            "IDs, GATT service UUIDs, and device name heuristics."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.bluetooth.com/specifications/assigned-numbers/",
            "https://www.bluetooth.com/specifications/specs/core-specification-5-3/",
        ),
        "devices": (
            "Xiaomi Mi Band 3-7 / Smart Band",
            "Garmin Forerunner / Fenix / Venu / Vivoactive",
            "Samsung Galaxy Watch / Gear",
            "Fitbit Charge / Versa / Sense / Inspire",
            "Generic BLE wearables with HR/Battery services",
        ),
        "status": "confirmed",
        "required_hardware": ["ble_adapter"],
    }

    adapter = OptString("hci0", "BLE adapter interface")
    scan_duration = OptInteger(10, "Scan duration in seconds")
    show_unknown = OptBool(False, "Show unidentified BLE devices")
    timeout = OptInteger(12, "Maximum scan timeout in seconds")

    _COMPANY_IDS = {
        0x038F: "Xiaomi",
        0x0157: "Xiaomi (legacy)",
        0x0087: "Garmin",
        0x0075: "Samsung",
        0x0224: "Fitbit",
        0x004C: "Apple",
        0x0006: "Microsoft",
        0x001D: "Qualcomm",
        0x0059: "Nordic Semiconductor",
    }

    _WEARABLE_VENDORS = {"Xiaomi", "Garmin", "Samsung", "Fitbit"}

    _SERVICE_UUIDS = {
        0x180D: "Heart Rate",
        0x180F: "Battery",
        0x180A: "Device Information",
        0x1805: "Current Time",
        0x1816: "Cycling Speed and Cadence",
        0x1814: "Running Speed and Cadence",
        0x181C: "User Data",
    }

    _NAME_PATTERNS = {
        "Xiaomi": [
            "MI Band", "Mi Smart Band", "Xiaomi Band",
            "Mi Watch", "Redmi Band", "Amazfit",
        ],
        "Garmin": [
            "Forerunner", "Fenix", "Venu", "Vivoactive",
            "Epix", "Instinct", "Enduro", "Lily",
        ],
        "Samsung": [
            "Galaxy Watch", "Gear S", "Gear Sport",
            "Galaxy Watch Active", "SM-R",
        ],
        "Fitbit": [
            "Charge", "Versa", "Sense", "Inspire",
            "Luxe", "Ionic", "Surge", "Blaze", "Alta",
        ],
    }

    def _start_ble_scan(self):
        """Configure HCI adapter for passive BLE scanning.

        Returns:
            Raw HCI socket or None on failure.
        """
        import socket as bt_socket
        try:
            sock = bt_socket.socket(
                bt_socket.AF_BLUETOOTH, bt_socket.SOCK_RAW,
                bt_socket.BTPROTO_HCI
            )
            hci_dev = int(str(self.adapter).replace("hci", ""))
            sock.bind((hci_dev,))
            sock.settimeout(1.0)

            scan_params = struct.pack("<BBHBHHBB",
                0x01, 0x0B, 0x20, 7,
                0x00, 0x0010, 0x0010, 0x00, 0x00,
            )
            sock.send(scan_params)

            enable = struct.pack("<BBHBB", 0x01, 0x0C, 0x20, 2, 0x01, 0x00)
            sock.send(enable)

            return sock
        except (OSError, PermissionError, ValueError) as exc:
            print_error("Cannot initialize BLE scan: {}".format(exc))
            return None

    def _stop_ble_scan(self, sock):
        """Disable BLE scanning and close the socket.

        Args:
            sock: Raw HCI socket.
        """
        try:
            disable = struct.pack("<BBHBB", 0x01, 0x0C, 0x20, 2, 0x00, 0x00)
            sock.send(disable)
            sock.close()
        except OSError:
            pass

    def _parse_adv_packet(self, pkt):
        """Parse a BLE advertisement packet into structured data.

        Extracts BD_ADDR, local name, company ID, advertised service
        UUIDs, RSSI, and performs vendor/model identification.

        Args:
            pkt: Raw HCI event bytes.

        Returns:
            Dict with parsed device data or None.
        """
        if len(pkt) < 12:
            return None

        try:
            addr_bytes = pkt[7:13] if len(pkt) > 13 else pkt[3:9]
            bdaddr = ":".join("{:02X}".format(b) for b in reversed(addr_bytes))
            name = ""
            company_id = None
            company_name = None
            services = []
            vendor = None
            model_hint = ""

            offset = 13 if len(pkt) > 14 else 9
            while offset < len(pkt) - 2:
                ad_len = pkt[offset]
                if ad_len == 0 or offset + ad_len >= len(pkt):
                    break
                ad_type = pkt[offset + 1]
                ad_data = pkt[offset + 2:offset + 1 + ad_len]

                if ad_type in (0x08, 0x09) and ad_data:
                    name = ad_data.decode("utf-8", errors="replace")

                if ad_type == 0xFF and len(ad_data) >= 2:
                    company_id = struct.unpack("<H", ad_data[:2])[0]
                    company_name = self._COMPANY_IDS.get(company_id)

                if ad_type in (0x02, 0x03) and len(ad_data) >= 2:
                    for i in range(0, len(ad_data) - 1, 2):
                        svc_uuid = struct.unpack_from("<H", ad_data, i)[0]
                        svc_name = self._SERVICE_UUIDS.get(svc_uuid)
                        if svc_name:
                            services.append(svc_name)

                offset += ad_len + 1

            if company_name and company_name in self._WEARABLE_VENDORS:
                vendor = company_name
            if not vendor:
                for vnd, patterns in self._NAME_PATTERNS.items():
                    for pattern in patterns:
                        if pattern.lower() in name.lower():
                            vendor = vnd
                            model_hint = pattern
                            break
                    if vendor:
                        break

            if not vendor and not self.show_unknown:
                return None

            rssi = struct.unpack("b", bytes([pkt[-1]]))[0] if pkt else -127

            return {
                "bdaddr": bdaddr,
                "name": name or "(no name)",
                "vendor": vendor or "Unknown",
                "company_id": "0x{:04X}".format(company_id) if company_id is not None else "-",
                "company": company_name or "-",
                "services": ", ".join(services) if services else "-",
                "model_hint": model_hint,
                "rssi": rssi,
            }
        except (IndexError, struct.error):
            return None

    @mute
    def check(self) -> bool:
        """Verify BLE adapter is available for scanning.

        Returns:
            True if the HCI socket can be opened.
        """
        sock = self._start_ble_scan()
        if sock:
            self._stop_ble_scan(sock)
            return True
        return False

    def run(self) -> None:
        """Execute BLE advertisement scan for wearable devices."""
        print_status("Wearable BLE Advertisement Scanner")
        print_info("Adapter: {} | Duration: {} sec".format(
            self.adapter, self.scan_duration
        ))

        sock = self._start_ble_scan()
        if not sock:
            print_error(
                "BLE scan initialization failed. Ensure adapter {} is "
                "available and run with appropriate privileges.".format(
                    self.adapter
                )
            )
            return

        devices = OrderedDict()
        print_status("Scanning BLE advertisements...")

        deadline = time.monotonic() + int(self.scan_duration)
        pkt_count = 0
        while time.monotonic() < deadline:
            try:
                pkt = sock.recv(260)
            except Exception:
                continue
            pkt_count += 1
            dev = self._parse_adv_packet(pkt)
            if dev:
                key = dev["bdaddr"]
                if key not in devices:
                    devices[key] = dev
                else:
                    existing = devices[key]
                    if dev["rssi"] > existing["rssi"]:
                        existing["rssi"] = dev["rssi"]
                    if dev["name"] != "(no name)" and existing["name"] == "(no name)":
                        existing["name"] = dev["name"]
                    if dev["vendor"] != "Unknown" and existing["vendor"] == "Unknown":
                        existing["vendor"] = dev["vendor"]

        self._stop_ble_scan(sock)
        print_info("Processed {} advertisement packets".format(pkt_count))

        wearables = {k: v for k, v in devices.items() if v["vendor"] != "Unknown"}
        unknown = {k: v for k, v in devices.items() if v["vendor"] == "Unknown"}

        if wearables:
            print_success("{} wearable device(s) identified:".format(len(wearables)))
            headers = ("BLE Address", "Vendor", "Name", "Company ID", "Services", "RSSI")
            rows = [
                (d["bdaddr"], d["vendor"], d["name"], d["company_id"],
                 d["services"][:30], "{}dBm".format(d["rssi"]))
                for d in sorted(wearables.values(), key=lambda x: x["rssi"], reverse=True)
            ]
            print_table(headers, *rows)

            vendor_counts = {}
            for d in wearables.values():
                vendor_counts[d["vendor"]] = vendor_counts.get(d["vendor"], 0) + 1
            summary_rows = [(v, str(c)) for v, c in sorted(vendor_counts.items())]
            print_table(("Vendor", "Count"), *summary_rows, title="Vendor Summary")

        else:
            print_warning("No identified wearable devices found")

        if unknown and self.show_unknown:
            print_info("{} unidentified BLE device(s):".format(len(unknown)))
            unk_headers = ("BLE Address", "Name", "Company ID", "RSSI")
            unk_rows = [
                (d["bdaddr"], d["name"], d["company_id"],
                 "{}dBm".format(d["rssi"]))
                for d in sorted(unknown.values(), key=lambda x: x["rssi"], reverse=True)[:20]
            ]
            print_table(unk_headers, *unk_rows)

        print_info(
            "Recommendation: disable BLE on wearables when not syncing, "
            "use randomized BLE MAC addresses where supported."
        )
