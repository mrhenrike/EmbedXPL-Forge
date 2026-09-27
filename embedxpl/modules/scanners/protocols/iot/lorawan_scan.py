# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""LoRaWAN Gateway Sniffer - DevEUI/AppEUI Discovery.

Captures LoRaWAN uplink and join-request frames via SDR to extract
DevEUI, AppEUI (JoinEUI), DevAddr, and gateway metadata.

References:
  - LoRaWAN Specification v1.0.4 (LoRa Alliance)
  - LoRa Modulation Basics (Semtech AN1200.22)

Version: 1.0.0
"""

import struct
import time

from embedxpl.core.exploit import *


_MTYPE_JOIN_REQUEST = 0x00
_MTYPE_JOIN_ACCEPT = 0x01
_MTYPE_UNCONF_UP = 0x02
_MTYPE_CONF_UP = 0x04
_MTYPE_UNCONF_DOWN = 0x03
_MTYPE_CONF_DOWN = 0x05

_MTYPE_NAMES = {
    _MTYPE_JOIN_REQUEST: "Join Request",
    _MTYPE_JOIN_ACCEPT: "Join Accept",
    _MTYPE_UNCONF_UP: "Unconfirmed Data Up",
    _MTYPE_CONF_UP: "Confirmed Data Up",
    _MTYPE_UNCONF_DOWN: "Unconfirmed Data Down",
    _MTYPE_CONF_DOWN: "Confirmed Data Down",
}

_EU868_CHANNELS = [868.1, 868.3, 868.5]
_US915_CHANNELS = [902.3 + i * 0.2 for i in range(64)]

_REGIONS = {
    "EU868": _EU868_CHANNELS,
    "US915": _US915_CHANNELS[:8],
}


class Exploit(Exploit):
    """LoRaWAN Gateway Sniffer.

    Captures LoRaWAN frames via SDR to discover gateways, extract DevEUI
    and AppEUI from join requests, and enumerate active DevAddrs.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "LoRaWAN Gateway Sniffer",
        "description": (
            "Captures LoRaWAN RF frames via SDR to extract DevEUI/AppEUI from "
            "join-request messages, enumerate active DevAddrs from uplink traffic, "
            "and identify gateway presence on EU868/US915 channels."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://lora-alliance.org/resource_hub/lorawan-specification-v1-0-4/",
        ),
        "devices": ("LoRaWAN Gateways", "LoRaWAN End Devices", "LoRa Sensors"),
        "severity": "info",
        "mitre": ["T0846"],
        "status": "confirmed",
        "required_hardware": ["sdr_tx_rx"],
    }

    target = OptString("", "Target DevEUI filter (hex, empty for all)")
    timeout = OptInteger(60, "Capture duration in seconds")
    region = OptString("EU868", "LoRaWAN region (EU868, US915)")
    sdr_device = OptString("", "SDR device string (empty for auto-detect)")
    spreading_factor = OptInteger(7, "LoRa spreading factor (7-12)")

    def _init_sdr(self, frequency: float):
        """Initialize SDR receiver for LoRa capture."""
        try:
            from rtlsdr import RtlSdr
            sdr = RtlSdr()
            sdr.sample_rate = 1e6
            sdr.center_freq = frequency * 1e6
            sdr.gain = 40
            return sdr
        except ImportError:
            raise RuntimeError("pyrtlsdr library required for SDR capture")
        except Exception as exc:
            raise RuntimeError("Cannot initialize SDR: {}".format(exc))

    def _detect_lora_preamble(self, samples) -> list:
        """Detect LoRa chirp preamble in IQ samples."""
        import numpy as np
        magnitude = np.abs(samples)
        threshold = np.mean(magnitude) + 3 * np.std(magnitude)
        peaks = np.where(magnitude > threshold)[0]
        bursts = []
        if len(peaks) == 0:
            return bursts

        start = peaks[0]
        for i in range(1, len(peaks)):
            if peaks[i] - peaks[i - 1] > 1000:
                bursts.append((start, peaks[i - 1]))
                start = peaks[i]
        bursts.append((start, peaks[-1]))
        return bursts

    def _extract_payload(self, samples, start: int, end: int) -> bytes:
        """Extract and demodulate LoRa payload from burst region."""
        import numpy as np
        burst = samples[start:end]
        phase = np.angle(burst)
        freq = np.diff(np.unwrap(phase))
        bits = (freq > 0).astype(np.uint8)
        byte_data = bytearray()
        for i in range(0, len(bits) - 7, 8):
            val = 0
            for bit_idx in range(8):
                val = (val << 1) | bits[i + bit_idx]
            byte_data.append(val)
        return bytes(byte_data)

    def _parse_mhdr(self, data: bytes) -> dict:
        """Parse LoRaWAN MHDR (MAC Header) byte."""
        if not data:
            return {}
        mhdr = data[0]
        mtype = (mhdr >> 5) & 0x07
        major = mhdr & 0x03
        return {
            "mtype": mtype,
            "mtype_name": _MTYPE_NAMES.get(mtype, "Unknown (0x{:02x})".format(mtype)),
            "major": major,
        }

    def _parse_join_request(self, data: bytes) -> dict:
        """Parse LoRaWAN Join Request payload."""
        if len(data) < 19:
            return {}
        app_eui = data[1:9]
        dev_eui = data[9:17]
        dev_nonce = struct.unpack("<H", data[17:19])[0]
        return {
            "app_eui": app_eui[::-1].hex().upper(),
            "dev_eui": dev_eui[::-1].hex().upper(),
            "dev_nonce": dev_nonce,
        }

    def _parse_data_frame(self, data: bytes) -> dict:
        """Parse LoRaWAN data frame header for DevAddr and FCnt."""
        if len(data) < 8:
            return {}
        dev_addr = struct.unpack("<I", data[1:5])[0]
        fctrl = data[5]
        fcnt = struct.unpack("<H", data[6:8])[0]
        return {
            "dev_addr": "{:08X}".format(dev_addr),
            "fctrl": fctrl,
            "fcnt": fcnt,
            "ack": bool(fctrl & 0x20),
            "adr": bool(fctrl & 0x80),
            "fopts_len": fctrl & 0x0F,
        }

    def _capture_channel(self, frequency: float, duration: float) -> list:
        """Capture and parse LoRaWAN frames on a single channel."""
        frames = []
        try:
            sdr = self._init_sdr(frequency)
        except RuntimeError:
            return frames

        chunk_size = 131072
        deadline = time.time() + duration

        try:
            while time.time() < deadline:
                try:
                    samples = sdr.read_samples(chunk_size)
                    bursts = self._detect_lora_preamble(samples)
                    for start, end in bursts:
                        payload = self._extract_payload(samples, start, end)
                        if len(payload) < 2:
                            continue
                        mhdr = self._parse_mhdr(payload)
                        if not mhdr:
                            continue
                        frame = {"frequency": frequency}
                        frame.update(mhdr)

                        if mhdr["mtype"] == _MTYPE_JOIN_REQUEST:
                            jr = self._parse_join_request(payload)
                            if jr:
                                frame.update(jr)
                        elif mhdr["mtype"] in (_MTYPE_UNCONF_UP, _MTYPE_CONF_UP,
                                                _MTYPE_UNCONF_DOWN, _MTYPE_CONF_DOWN):
                            df = self._parse_data_frame(payload)
                            if df:
                                frame.update(df)

                        frames.append(frame)
                except Exception:
                    continue
        finally:
            sdr.close()

        return frames

    def _aggregate_results(self, all_frames: list) -> dict:
        """Aggregate captured frames into devices and join requests."""
        devices = {}
        joins = []
        for f in all_frames:
            if "dev_eui" in f:
                dev_eui = f["dev_eui"]
                if self.target and dev_eui.upper() != str(self.target).upper():
                    continue
                joins.append(f)
                if dev_eui not in devices:
                    devices[dev_eui] = {
                        "dev_eui": dev_eui,
                        "app_eui": f.get("app_eui", ""),
                        "join_count": 0,
                        "frequencies": set(),
                    }
                devices[dev_eui]["join_count"] += 1
                devices[dev_eui]["frequencies"].add(f["frequency"])
            elif "dev_addr" in f:
                addr = f["dev_addr"]
                if addr not in devices:
                    devices[addr] = {
                        "dev_addr": addr,
                        "frame_count": 0,
                        "adr": f.get("adr", False),
                        "frequencies": set(),
                    }
                devices[addr]["frame_count"] = devices[addr].get("frame_count", 0) + 1
                devices[addr]["frequencies"].add(f["frequency"])
        return {"devices": devices, "joins": joins}

    @mute
    def check(self) -> bool:
        """Verify SDR hardware is available."""
        try:
            channels = _REGIONS.get(str(self.region), _EU868_CHANNELS)
            sdr = self._init_sdr(channels[0])
            sdr.close()
            return True
        except RuntimeError:
            return False

    @multi
    def run(self) -> None:
        """Execute LoRaWAN gateway capture and analysis."""
        channels = _REGIONS.get(str(self.region), _EU868_CHANNELS)
        print_status("Starting LoRaWAN capture ({} region, {} channels, {} seconds)".format(
            self.region, len(channels), self.timeout
        ))

        if not self.check():
            print_error("SDR hardware not available")
            return

        per_channel = max(2.0, float(self.timeout) / len(channels))
        all_frames = []

        for freq in channels:
            print_status("Listening on {:.1f} MHz ({:.0f}s)...".format(freq, per_channel))
            frames = self._capture_channel(freq, per_channel)
            all_frames.extend(frames)
            if frames:
                print_info("  Captured {} frame(s)".format(len(frames)))

        results = self._aggregate_results(all_frames)
        devices = results["devices"]
        joins = results["joins"]

        if not devices:
            print_warning("No LoRaWAN traffic captured")
            return

        print_success("Discovered {} device(s)/address(es)".format(len(devices)))

        if joins:
            print_success("Join requests captured: {}".format(len(joins)))
            for j in joins:
                print_info("  DevEUI: {} AppEUI: {} Nonce: {}".format(
                    j["dev_eui"], j["app_eui"], j["dev_nonce"]
                ))

        for dev in devices.values():
            if "dev_eui" in dev:
                print_info("DevEUI: {} (AppEUI: {}, {} join(s))".format(
                    dev["dev_eui"], dev.get("app_eui", "N/A"), dev.get("join_count", 0)
                ))
            elif "dev_addr" in dev:
                print_info("DevAddr: {} ({} frame(s), ADR: {})".format(
                    dev["dev_addr"], dev.get("frame_count", 0), dev.get("adr", False)
                ))
