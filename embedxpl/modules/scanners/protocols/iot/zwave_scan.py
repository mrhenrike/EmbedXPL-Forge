# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Z-Wave HomeID/NodeID/Security Class Scanner.

Captures Z-Wave RF frames via SDR to discover Home IDs, Node IDs, and
security class information (S0/S2) from Z-Wave network traffic.

References:
  - ITU-T G.9959 (Z-Wave PHY/MAC)
  - Z-Wave Plus v2 Application Command Classes

Version: 1.0.0
"""

import struct
import time

from embedxpl.core.exploit import *


_ZWAVE_PREAMBLE = b"\x55\x55\x55"
_SOF_BYTE = 0x01
_ZWAVE_FREQ_US = 908.42
_ZWAVE_FREQ_EU = 868.42
_ZWAVE_FREQ_ANZ = 921.42

_COMMAND_CLASSES = {
    0x20: "Basic",
    0x25: "Switch Binary",
    0x26: "Switch Multilevel",
    0x30: "Sensor Binary",
    0x31: "Sensor Multilevel",
    0x62: "Door Lock",
    0x63: "User Code",
    0x70: "Configuration",
    0x71: "Alarm/Notification",
    0x72: "Manufacturer Specific",
    0x80: "Battery",
    0x84: "Wake Up",
    0x85: "Association",
    0x86: "Version",
    0x87: "Indicator",
    0x98: "Security S0",
    0x9F: "Security S2",
}


class Exploit(Exploit):
    """Z-Wave HomeID/NodeID/Security Class Scanner.

    Captures Z-Wave RF traffic via SDR transceiver to identify Home IDs,
    enumerate Node IDs, and detect security class (S0, S2, or none).

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Z-Wave HomeID/NodeID/Security Class Scanner",
        "description": (
            "Captures Z-Wave RF frames via SDR on 908.42/868.42 MHz to discover "
            "Home IDs, enumerate Node IDs, and identify security classes (S0/S2) "
            "from observed network traffic."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://www.itu.int/rec/T-REC-G.9959/en",
        ),
        "devices": ("Z-Wave Controllers", "Z-Wave Sensors", "Z-Wave Locks"),
        "severity": "info",
        "mitre": ["T0846"],
        "status": "confirmed",
        "required_hardware": ["sdr_tx_rx"],
    }

    target = OptString("", "Target Home ID filter (hex, e.g. A1B2C3D4, empty for all)")
    timeout = OptInteger(30, "Capture duration in seconds")
    frequency = OptFloat(908.42, "Z-Wave frequency in MHz (908.42 US, 868.42 EU)")
    sdr_device = OptString("", "SDR device string (empty for auto-detect)")
    sample_rate = OptFloat(2.0, "SDR sample rate in Msps")

    def _init_sdr(self):
        """Initialize SDR receiver for Z-Wave capture."""
        try:
            from rtlsdr import RtlSdr
            sdr = RtlSdr()
            sdr.sample_rate = float(self.sample_rate) * 1e6
            sdr.center_freq = float(self.frequency) * 1e6
            sdr.gain = 40
            return sdr
        except ImportError:
            raise RuntimeError("pyrtlsdr library required for SDR capture")
        except Exception as exc:
            raise RuntimeError("Cannot initialize SDR: {}".format(exc))

    def _demodulate_fsk(self, samples) -> bytes:
        """Demodulate 2-FSK Z-Wave signal from IQ samples."""
        import numpy as np
        phase = np.angle(samples)
        freq = np.diff(np.unwrap(phase))
        bits = (freq > 0).astype(np.uint8)
        byte_data = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte_val = 0
            for bit_idx in range(8):
                byte_val = (byte_val << 1) | bits[i + bit_idx]
            byte_data.append(byte_val)
        return bytes(byte_data)

    def _find_frames(self, raw_bytes: bytes) -> list:
        """Locate Z-Wave frame boundaries in demodulated data."""
        frames = []
        offset = 0
        while offset < len(raw_bytes) - 10:
            idx = raw_bytes.find(bytes([_SOF_BYTE]), offset)
            if idx < 0:
                break
            if idx + 1 >= len(raw_bytes):
                break
            length = raw_bytes[idx + 1]
            if length < 3 or length > 64:
                offset = idx + 1
                continue
            if idx + 2 + length > len(raw_bytes):
                break
            frame = raw_bytes[idx:idx + 2 + length]
            checksum = 0xFF
            for b in frame[1:-1]:
                checksum ^= b
            if checksum == frame[-1]:
                frames.append(frame)
            offset = idx + 2 + length
        return frames

    def _parse_frame(self, frame: bytes) -> dict:
        """Parse Z-Wave frame for Home ID, source/dest node, and command class."""
        result = {}
        if len(frame) < 9:
            return result

        home_id = frame[2:6]
        result["home_id"] = home_id.hex().upper()
        result["src_node"] = frame[6]
        result["frame_ctrl"] = frame[7]
        result["length"] = frame[8]

        if len(frame) > 10:
            result["dst_node"] = frame[9]

        if len(frame) > 11:
            cc = frame[10]
            result["command_class"] = cc
            result["cc_name"] = _COMMAND_CLASSES.get(cc, "0x{:02X}".format(cc))

        return result

    def _determine_security(self, frames: list, home_id: str) -> str:
        """Determine security class from observed command classes."""
        has_s2 = False
        has_s0 = False
        for f in frames:
            if f.get("home_id") != home_id:
                continue
            cc = f.get("command_class", 0)
            if cc == 0x9F:
                has_s2 = True
            elif cc == 0x98:
                has_s0 = True
        if has_s2:
            return "S2"
        if has_s0:
            return "S0"
        return "None"

    def _aggregate_network(self, parsed_frames: list) -> dict:
        """Aggregate parsed frames by Home ID."""
        networks = {}
        for f in parsed_frames:
            hid = f.get("home_id")
            if not hid:
                continue
            if self.target and hid.upper() != str(self.target).upper():
                continue
            if hid not in networks:
                networks[hid] = {
                    "home_id": hid,
                    "nodes": set(),
                    "command_classes": set(),
                    "frame_count": 0,
                }
            networks[hid]["nodes"].add(f.get("src_node", 0))
            if f.get("dst_node"):
                networks[hid]["nodes"].add(f["dst_node"])
            if f.get("cc_name"):
                networks[hid]["command_classes"].add(f["cc_name"])
            networks[hid]["frame_count"] += 1
        return networks

    @mute
    def check(self) -> bool:
        """Verify SDR hardware is available."""
        try:
            sdr = self._init_sdr()
            sdr.close()
            return True
        except RuntimeError:
            return False

    @multi
    def run(self) -> None:
        """Execute Z-Wave RF capture and analysis."""
        print_status("Starting Z-Wave capture at {:.2f} MHz for {} seconds".format(
            float(self.frequency), self.timeout
        ))

        try:
            sdr = self._init_sdr()
        except RuntimeError as exc:
            print_error("{}".format(exc))
            return

        all_frames = []
        chunk_size = 262144
        deadline = time.time() + float(self.timeout)

        try:
            while time.time() < deadline:
                try:
                    samples = sdr.read_samples(chunk_size)
                    raw_bytes = self._demodulate_fsk(samples)
                    frames = self._find_frames(raw_bytes)
                    for frame in frames:
                        parsed = self._parse_frame(frame)
                        if parsed:
                            all_frames.append(parsed)
                except Exception:
                    continue
        finally:
            sdr.close()

        networks = self._aggregate_network(all_frames)
        if not networks:
            print_warning("No Z-Wave networks discovered")
            return

        print_success("Discovered {} Z-Wave network(s)".format(len(networks)))
        for net in networks.values():
            security = self._determine_security(all_frames, net["home_id"])
            sorted_nodes = sorted(net["nodes"])
            print_info("Home ID: {}".format(net["home_id"]))
            print_info("  Nodes ({}): {}".format(
                len(sorted_nodes),
                ", ".join(str(n) for n in sorted_nodes)
            ))
            print_info("  Security: {}".format(security))
            print_info("  Command classes: {}".format(
                ", ".join(sorted(net["command_classes"]))
            ))
            print_info("  Frames captured: {}".format(net["frame_count"]))
