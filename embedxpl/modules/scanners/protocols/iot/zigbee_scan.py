# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Zigbee PAN Discovery and Coordinator Identification Scanner.

Performs passive capture of Zigbee 802.15.4 frames to discover Personal
Area Networks (PANs), coordinator addresses, and network parameters.

References:
  - IEEE 802.15.4-2020
  - Zigbee Specification (Zigbee Alliance / CSA)

Version: 1.0.0
"""

import struct
import socket
import time

from embedxpl.core.exploit import *


_FRAME_TYPE_BEACON = 0x00
_FRAME_TYPE_DATA = 0x01
_FRAME_TYPE_ACK = 0x02
_FRAME_TYPE_CMD = 0x03

_ZIGBEE_PROFILES = {
    0x0104: "Home Automation",
    0x0109: "Smart Energy",
    0xC05E: "ZigBee Light Link",
    0xA1E0: "Green Power",
}

_CHANNELS = list(range(11, 27))


class Exploit(Exploit):
    """Zigbee PAN Discovery and Coordinator Identification Scanner.

    Captures 802.15.4 beacon frames and data traffic to identify Zigbee
    PANs, coordinators, routers, and end devices on channels 11-26.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Zigbee PAN Discovery Scanner",
        "description": (
            "Passively captures IEEE 802.15.4 beacon and data frames to discover "
            "Zigbee PANs, coordinator extended addresses, channel usage, and "
            "network parameters across channels 11-26."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://standards.ieee.org/standard/802_15_4-2020.html",
            "https://csa-iot.org/developer-resource/specifications-download-request/",
        ),
        "devices": ("Zigbee Coordinators", "Zigbee Routers", "Zigbee End Devices"),
        "severity": "info",
        "mitre": ["T0846"],
        "status": "confirmed",
        "required_hardware": ["ble_adapter"],
    }

    target = OptString("", "Target PAN ID filter (hex, e.g. 0x1A2B, empty for all)")
    timeout = OptInteger(15, "Total scan duration in seconds")
    channel = OptInteger(0, "Specific channel (11-26), 0 for all channels")
    interface = OptString("/dev/ttyUSB0", "Zigbee sniffer serial interface")
    baud_rate = OptInteger(115200, "Serial baud rate for sniffer adapter")

    def _open_sniffer(self):
        """Open serial connection to Zigbee sniffer adapter."""
        try:
            import serial
            ser = serial.Serial(
                port=str(self.interface),
                baudrate=int(self.baud_rate),
                timeout=2,
            )
            return ser
        except ImportError:
            raise RuntimeError("pyserial library required for Zigbee sniffing")
        except Exception as exc:
            raise RuntimeError("Cannot open sniffer at {}: {}".format(self.interface, exc))

    def _set_channel(self, sniffer, channel: int) -> None:
        """Send channel-set command to sniffer firmware."""
        cmd = struct.pack("<BBB", 0x01, 0x00, channel & 0xFF)
        sniffer.write(cmd)
        sniffer.flush()
        time.sleep(0.05)

    def _read_frame(self, sniffer, timeout_ms: int = 500) -> bytes:
        """Read a single 802.15.4 frame from the sniffer."""
        sniffer.timeout = timeout_ms / 1000.0
        header = sniffer.read(2)
        if len(header) < 2:
            return b""
        length = header[1]
        if length > 127 or length == 0:
            return b""
        frame = sniffer.read(length)
        return frame

    def _parse_frame_control(self, fc: int) -> dict:
        """Parse 802.15.4 Frame Control field."""
        return {
            "frame_type": fc & 0x07,
            "security": bool(fc & 0x08),
            "pending": bool(fc & 0x10),
            "ack_req": bool(fc & 0x20),
            "pan_compress": bool(fc & 0x40),
            "dst_mode": (fc >> 10) & 0x03,
            "src_mode": (fc >> 14) & 0x03,
        }

    def _parse_beacon(self, frame: bytes) -> dict:
        """Parse IEEE 802.15.4 beacon frame."""
        result = {}
        if len(frame) < 9:
            return result

        fc = struct.unpack("<H", frame[0:2])[0]
        info = self._parse_frame_control(fc)
        result["frame_type"] = "beacon"
        result["security"] = info["security"]

        seq = frame[2]
        result["sequence"] = seq

        src_pan = struct.unpack("<H", frame[3:5])[0]
        result["pan_id"] = "0x{:04X}".format(src_pan)

        if info["src_mode"] == 2:
            src_addr = struct.unpack("<H", frame[5:7])[0]
            result["coordinator_short"] = "0x{:04X}".format(src_addr)
            beacon_offset = 7
        elif info["src_mode"] == 3:
            src_addr = frame[5:13]
            result["coordinator_ext"] = ":".join("{:02X}".format(b) for b in reversed(src_addr))
            beacon_offset = 13
        else:
            return result

        if beacon_offset + 2 <= len(frame):
            sf = struct.unpack("<H", frame[beacon_offset:beacon_offset + 2])[0]
            result["beacon_order"] = sf & 0x0F
            result["superframe_order"] = (sf >> 4) & 0x0F
            result["pan_coordinator"] = bool(sf & 0x4000)
            result["association_permit"] = bool(sf & 0x8000)

        return result

    def _parse_data_header(self, frame: bytes) -> dict:
        """Parse 802.15.4 data frame header for PAN/address info."""
        result = {}
        if len(frame) < 5:
            return result

        fc = struct.unpack("<H", frame[0:2])[0]
        info = self._parse_frame_control(fc)
        result["frame_type"] = "data"
        result["security"] = info["security"]

        offset = 3
        if info["dst_mode"] == 2:
            if offset + 4 <= len(frame):
                dst_pan = struct.unpack("<H", frame[offset:offset + 2])[0]
                result["dst_pan"] = "0x{:04X}".format(dst_pan)
                dst_addr = struct.unpack("<H", frame[offset + 2:offset + 4])[0]
                result["dst_short"] = "0x{:04X}".format(dst_addr)
                offset += 4
        elif info["dst_mode"] == 3:
            if offset + 10 <= len(frame):
                dst_pan = struct.unpack("<H", frame[offset:offset + 2])[0]
                result["dst_pan"] = "0x{:04X}".format(dst_pan)
                offset += 10

        return result

    def _scan_channel(self, sniffer, channel: int, duration: float) -> list:
        """Scan a single channel for the given duration."""
        self._set_channel(sniffer, channel)
        frames = []
        deadline = time.time() + duration
        while time.time() < deadline:
            raw = self._read_frame(sniffer)
            if not raw or len(raw) < 3:
                continue
            fc = struct.unpack("<H", raw[0:2])[0]
            ft = fc & 0x07
            if ft == _FRAME_TYPE_BEACON:
                parsed = self._parse_beacon(raw)
                if parsed:
                    parsed["channel"] = channel
                    frames.append(parsed)
            elif ft == _FRAME_TYPE_DATA:
                parsed = self._parse_data_header(raw)
                if parsed:
                    parsed["channel"] = channel
                    frames.append(parsed)
        return frames

    def _aggregate_pans(self, all_frames: list) -> dict:
        """Aggregate captured frames by PAN ID."""
        pans = {}
        for f in all_frames:
            pan_id = f.get("pan_id") or f.get("dst_pan")
            if not pan_id:
                continue
            if self.target and pan_id.upper() != self.target.upper():
                continue
            if pan_id not in pans:
                pans[pan_id] = {
                    "pan_id": pan_id,
                    "channels": set(),
                    "coordinator_short": "",
                    "coordinator_ext": "",
                    "security": False,
                    "association_permit": False,
                    "frame_count": 0,
                }
            entry = pans[pan_id]
            entry["channels"].add(f.get("channel", 0))
            entry["frame_count"] += 1
            if f.get("coordinator_short"):
                entry["coordinator_short"] = f["coordinator_short"]
            if f.get("coordinator_ext"):
                entry["coordinator_ext"] = f["coordinator_ext"]
            if f.get("security"):
                entry["security"] = True
            if f.get("association_permit"):
                entry["association_permit"] = True
        return pans

    @mute
    def check(self) -> bool:
        """Verify sniffer adapter is accessible."""
        try:
            sniffer = self._open_sniffer()
            sniffer.close()
            return True
        except RuntimeError:
            return False

    @multi
    def run(self) -> None:
        """Execute Zigbee PAN discovery scan."""
        print_status("Starting Zigbee scan on {}".format(self.interface))

        try:
            sniffer = self._open_sniffer()
        except RuntimeError as exc:
            print_error("{}".format(exc))
            return

        channels = [int(self.channel)] if int(self.channel) in _CHANNELS else _CHANNELS
        per_channel = max(1.0, float(self.timeout) / len(channels))
        all_frames = []

        try:
            for ch in channels:
                print_status("Scanning channel {} ({:.1f}s)...".format(ch, per_channel))
                frames = self._scan_channel(sniffer, ch, per_channel)
                all_frames.extend(frames)
        finally:
            sniffer.close()

        pans = self._aggregate_pans(all_frames)
        if not pans:
            print_warning("No Zigbee PANs discovered")
            return

        print_success("Discovered {} PAN(s)".format(len(pans)))
        for pan in pans.values():
            ch_list = sorted(pan["channels"])
            print_info("PAN {} on channel(s) {}".format(
                pan["pan_id"], ", ".join(str(c) for c in ch_list)
            ))
            if pan["coordinator_short"]:
                print_info("  Coordinator (short): {}".format(pan["coordinator_short"]))
            if pan["coordinator_ext"]:
                print_info("  Coordinator (ext):   {}".format(pan["coordinator_ext"]))
            print_info("  Security enabled: {}".format(pan["security"]))
            print_info("  Association permit: {}".format(pan["association_permit"]))
            print_info("  Frames captured: {}".format(pan["frame_count"]))
