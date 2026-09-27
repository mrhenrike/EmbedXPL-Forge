# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""WiFi SSID/BSSID/Cipher/PMKID Scanner.

Captures 802.11 beacon and probe response frames in monitor mode to
enumerate wireless networks, cipher suites, and extract PMKID hashes
from EAPOL handshake initiation frames.

References:
  - IEEE 802.11-2020
  - WPA/WPA2/WPA3 security specifications

Version: 1.0.0
"""

import struct
import socket
import time

from embedxpl.core.exploit import *


_BEACON_TYPE = 0x80
_PROBE_RESP_TYPE = 0x50
_AUTH_CIPHER_SUITES = {
    b"\x00\x0f\xac\x01": "WEP-40",
    b"\x00\x0f\xac\x02": "TKIP",
    b"\x00\x0f\xac\x04": "CCMP",
    b"\x00\x0f\xac\x05": "WEP-104",
    b"\x00\x0f\xac\x06": "BIP-CMAC-128",
    b"\x00\x0f\xac\x08": "GCMP-128",
    b"\x00\x0f\xac\x09": "GCMP-256",
    b"\x00\x0f\xac\x0c": "BIP-GMAC-256",
}
_AKM_SUITES = {
    b"\x00\x0f\xac\x01": "802.1X",
    b"\x00\x0f\xac\x02": "PSK",
    b"\x00\x0f\xac\x06": "SAE (WPA3)",
    b"\x00\x0f\xac\x08": "SAE-FT",
    b"\x00\x0f\xac\x12": "OWE",
}
_TAG_SSID = 0
_TAG_RSN = 48
_TAG_VENDOR = 221
_WPA_OUI = b"\x00\x50\xf2\x01"


class Exploit(Exploit):
    """WiFi SSID/BSSID/Cipher/PMKID Scanner.

    Captures 802.11 management frames in monitor mode to enumerate
    wireless networks, security configurations, and PMKID hashes.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "WiFi SSID/BSSID/Cipher/PMKID Scanner",
        "description": (
            "Captures 802.11 beacon and probe response frames in monitor mode to "
            "enumerate SSIDs, BSSIDs, channel info, cipher suites (WEP/WPA/WPA2/WPA3), "
            "and attempt PMKID extraction from EAPOL association frames."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://standards.ieee.org/standard/802_11-2020.html",
        ),
        "devices": ("WiFi Access Points", "Wireless Routers", "IoT WiFi Devices"),
        "severity": "info",
        "mitre": ["T0846"],
        "status": "confirmed",
        "required_hardware": ["wifi_monitor_mode"],
    }

    target = OptString("", "Target BSSID filter (empty for all)")
    timeout = OptInteger(15, "Scan duration in seconds")
    interface = OptString("wlan0mon", "Monitor mode interface name")

    def _open_raw_socket(self) -> socket.socket:
        """Open raw 802.11 capture socket on monitor interface."""
        try:
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)
            )
            sock.bind((str(self.interface), 0))
            sock.settimeout(1.0)
            return sock
        except (socket.error, OSError) as exc:
            raise RuntimeError(
                "Cannot open monitor socket on {}: {}".format(self.interface, exc)
            )

    def _parse_radiotap_length(self, frame: bytes) -> int:
        """Extract Radiotap header length."""
        if len(frame) < 4:
            return 0
        return struct.unpack("<H", frame[2:4])[0]

    def _format_bssid(self, raw: bytes) -> str:
        """Format 6-byte address as BSSID string."""
        return ":".join("{:02X}".format(b) for b in raw)

    def _parse_tagged_params(self, data: bytes) -> dict:
        """Parse 802.11 tagged parameters (information elements)."""
        tags = {}
        offset = 0
        while offset + 2 <= len(data):
            tag_id = data[offset]
            tag_len = data[offset + 1]
            if offset + 2 + tag_len > len(data):
                break
            tag_data = data[offset + 2:offset + 2 + tag_len]
            if tag_id not in tags:
                tags[tag_id] = []
            tags[tag_id].append(tag_data)
            offset += 2 + tag_len
        return tags

    def _parse_rsn(self, data: bytes) -> dict:
        """Parse RSN (WPA2/WPA3) information element."""
        result = {"version": 0, "group_cipher": "", "pairwise": [], "akm": []}
        if len(data) < 10:
            return result
        result["version"] = struct.unpack("<H", data[0:2])[0]
        result["group_cipher"] = _AUTH_CIPHER_SUITES.get(data[2:6], "Unknown")

        pw_count = struct.unpack("<H", data[6:8])[0]
        offset = 8
        for _ in range(pw_count):
            if offset + 4 > len(data):
                break
            suite = _AUTH_CIPHER_SUITES.get(data[offset:offset + 4], "Unknown")
            result["pairwise"].append(suite)
            offset += 4

        if offset + 2 <= len(data):
            akm_count = struct.unpack("<H", data[offset:offset + 2])[0]
            offset += 2
            for _ in range(akm_count):
                if offset + 4 > len(data):
                    break
                akm = _AKM_SUITES.get(data[offset:offset + 4], "Unknown")
                result["akm"].append(akm)
                offset += 4

        return result

    def _parse_wpa(self, data: bytes) -> dict:
        """Parse WPA1 vendor-specific information element."""
        if len(data) < 14 or data[:4] != _WPA_OUI:
            return {}
        return self._parse_rsn(data[4:])

    def _parse_beacon(self, frame: bytes, rt_len: int) -> dict:
        """Parse 802.11 beacon/probe response frame."""
        dot11 = frame[rt_len:]
        if len(dot11) < 36:
            return {}

        fc = struct.unpack("<H", dot11[0:2])[0]
        subtype = (fc >> 4) & 0x0F
        if subtype not in (0x08, 0x05):
            return {}

        bssid = self._format_bssid(dot11[16:22])
        if self.target and bssid.upper() != str(self.target).upper():
            return {}

        fixed = dot11[24:36]
        if len(fixed) < 12:
            return {}
        cap_info = struct.unpack("<H", fixed[10:12])[0]

        tagged_data = dot11[36:]
        tags = self._parse_tagged_params(tagged_data)

        ssid = ""
        if _TAG_SSID in tags and tags[_TAG_SSID]:
            raw_ssid = tags[_TAG_SSID][0]
            ssid = raw_ssid.decode("utf-8", errors="replace")

        result = {
            "bssid": bssid,
            "ssid": ssid or "(hidden)",
            "privacy": bool(cap_info & 0x0010),
            "security": "Open",
            "pairwise": [],
            "akm": [],
        }

        if _TAG_RSN in tags:
            rsn = self._parse_rsn(tags[_TAG_RSN][0])
            result["pairwise"] = rsn.get("pairwise", [])
            result["akm"] = rsn.get("akm", [])
            if "SAE (WPA3)" in result["akm"] or "SAE-FT" in result["akm"]:
                result["security"] = "WPA3"
            else:
                result["security"] = "WPA2"

        if _TAG_VENDOR in tags:
            for vendor_data in tags[_TAG_VENDOR]:
                wpa = self._parse_wpa(vendor_data)
                if wpa and not result["akm"]:
                    result["security"] = "WPA"
                    result["pairwise"] = wpa.get("pairwise", [])
                    result["akm"] = wpa.get("akm", [])

        if result["privacy"] and result["security"] == "Open":
            result["security"] = "WEP"

        return result

    def _extract_pmkid(self, frame: bytes, rt_len: int) -> dict:
        """Extract PMKID from EAPOL Message 1 if present."""
        dot11 = frame[rt_len:]
        if len(dot11) < 30:
            return {}
        eapol_start = dot11.find(b"\x88\x8e")
        if eapol_start < 0:
            return {}
        eapol = dot11[eapol_start + 2:]
        if len(eapol) < 99:
            return {}
        key_info = struct.unpack(">H", eapol[5:7])[0]
        if not (key_info & 0x0008):
            return {}
        key_data_len = struct.unpack(">H", eapol[97:99])[0]
        key_data = eapol[99:99 + key_data_len]
        pmkid_tag = b"\x01\x00\x00\x0f\xac\x04"
        idx = key_data.find(pmkid_tag)
        if idx < 0:
            return {}
        pmkid = key_data[idx + len(pmkid_tag):idx + len(pmkid_tag) + 16]
        if len(pmkid) != 16:
            return {}
        ap_mac = self._format_bssid(dot11[16:22])
        sta_mac = self._format_bssid(dot11[10:16])
        return {
            "bssid": ap_mac,
            "station": sta_mac,
            "pmkid": pmkid.hex(),
        }

    @mute
    def check(self) -> bool:
        """Verify monitor mode interface is available."""
        try:
            sock = self._open_raw_socket()
            sock.close()
            return True
        except RuntimeError:
            return False

    @multi
    def run(self) -> None:
        """Execute WiFi scan in monitor mode."""
        print_status("Starting WiFi scan on {} for {} seconds".format(
            self.interface, self.timeout
        ))

        try:
            sock = self._open_raw_socket()
        except RuntimeError as exc:
            print_error("{}".format(exc))
            return

        networks = {}
        pmkids = []
        deadline = time.time() + float(self.timeout)

        try:
            while time.time() < deadline:
                try:
                    frame = sock.recv(4096)
                    if not frame or len(frame) < 10:
                        continue
                    rt_len = self._parse_radiotap_length(frame)
                    if rt_len == 0 or rt_len >= len(frame):
                        continue

                    result = self._parse_beacon(frame, rt_len)
                    if result and result["bssid"] not in networks:
                        networks[result["bssid"]] = result

                    pmkid_result = self._extract_pmkid(frame, rt_len)
                    if pmkid_result:
                        pmkids.append(pmkid_result)
                except socket.timeout:
                    continue
                except (socket.error, OSError):
                    break
        finally:
            sock.close()

        if not networks:
            print_warning("No wireless networks discovered")
            return

        print_success("Discovered {} network(s)".format(len(networks)))
        for net in sorted(networks.values(), key=lambda n: n["ssid"]):
            print_info("{} - BSSID: {} [{}]".format(
                net["ssid"], net["bssid"], net["security"]
            ))
            if net["pairwise"]:
                print_info("  Pairwise: {}".format(", ".join(net["pairwise"])))
            if net["akm"]:
                print_info("  AKM: {}".format(", ".join(net["akm"])))

        if pmkids:
            print_success("Captured {} PMKID(s):".format(len(pmkids)))
            for p in pmkids:
                print_info("  AP: {} STA: {} PMKID: {}".format(
                    p["bssid"], p["station"], p["pmkid"]
                ))
