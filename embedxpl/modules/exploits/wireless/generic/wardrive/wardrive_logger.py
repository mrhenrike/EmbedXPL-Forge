"""Wardrive Logger - GPS-tagged WiFi network discovery logger.

Records discovered WiFi networks with optional GPS coordinates and exports
to CSV, JSON, and KML formats for map visualization.

GPS source priority:
  1. gpsd daemon (via gpsd-py3 or gps3 library)
  2. NMEA file/serial port
  3. Graceful fallback to lat=None, lon=None

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import csv
import json
import logging
import math
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# GPS Backends
# ---------------------------------------------------------------------------

class _GpsPosition:
    """Current GPS fix container."""

    __slots__ = ("lat", "lon", "alt", "speed", "track", "ts", "fix")

    def __init__(self) -> None:
        self.lat: Optional[float] = None
        self.lon: Optional[float] = None
        self.alt: Optional[float] = None
        self.speed: Optional[float] = None
        self.track: Optional[float] = None
        self.ts: Optional[str] = None
        self.fix: bool = False

    def copy(self) -> "_GpsPosition":
        p = _GpsPosition()
        p.lat = self.lat
        p.lon = self.lon
        p.alt = self.alt
        p.speed = self.speed
        p.track = self.track
        p.ts = self.ts
        p.fix = self.fix
        return p


class _GpsdBackend:
    """Non-blocking gpsd reader thread."""

    def __init__(self, host: str = "127.0.0.1", port: int = 2947) -> None:
        self._host = host
        self._port = port
        self._pos = _GpsPosition()
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        """Attempt to start the gpsd reader thread.

        Returns:
            True if the library is available and the thread started.
        """
        try:
            import gpsd  # type: ignore
            gpsd.connect(host=self._host, port=self._port)
            self._running = True
            self._thread = threading.Thread(target=self._poll, args=(gpsd,), daemon=True)
            self._thread.start()
            logger.info("[Wardrive] gpsd backend started (%s:%d)", self._host, self._port)
            return True
        except ImportError:
            logger.debug("[Wardrive] gpsd-py3 not installed, gpsd backend unavailable")
        except Exception as exc:
            logger.debug("[Wardrive] gpsd connection failed: %s", exc)
        return False

    def _poll(self, gpsd: object) -> None:
        while self._running:
            try:
                packet = gpsd.get_current()  # type: ignore[attr-defined]
                if hasattr(packet, "lat") and packet.lat is not None:
                    with self._lock:
                        self._pos.lat = packet.lat
                        self._pos.lon = packet.lon
                        self._pos.alt = getattr(packet, "alt", None)
                        self._pos.speed = getattr(packet, "hspeed", None)
                        self._pos.track = getattr(packet, "track", None)
                        self._pos.ts = datetime.now(timezone.utc).isoformat()
                        self._pos.fix = True
            except Exception:
                pass
            time.sleep(1)

    def position(self) -> _GpsPosition:
        with self._lock:
            return self._pos.copy()

    def stop(self) -> None:
        self._running = False


class _NmeaBackend:
    """NMEA sentence file/serial reader."""

    def __init__(self, source: str) -> None:
        self._source = source
        self._pos = _GpsPosition()
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        src = Path(self._source)
        if not src.exists():
            # Try as serial port path on Linux
            try:
                import serial  # type: ignore
                self._serial = serial.Serial(self._source, 9600, timeout=1)
                self._running = True
                self._thread = threading.Thread(target=self._read_serial, daemon=True)
                self._thread.start()
                logger.info("[Wardrive] NMEA serial backend started (%s)", self._source)
                return True
            except Exception as exc:
                logger.debug("[Wardrive] NMEA serial failed: %s", exc)
                return False

        self._running = True
        self._thread = threading.Thread(target=self._read_file, daemon=True)
        self._thread.start()
        logger.info("[Wardrive] NMEA file backend started (%s)", self._source)
        return True

    def _parse_gga(self, sentence: str) -> None:
        parts = sentence.split(",")
        if len(parts) < 9:
            return
        try:
            lat_raw = parts[2]
            lat_dir = parts[3]
            lon_raw = parts[4]
            lon_dir = parts[5]
            fix_quality = int(parts[6]) if parts[6] else 0
            if fix_quality == 0 or not lat_raw or not lon_raw:
                return

            def _deg(raw: str, direction: str) -> float:
                d = int(float(raw) // 100)
                m = float(raw) - d * 100
                deg = d + m / 60.0
                if direction in ("S", "W"):
                    deg = -deg
                return deg

            with self._lock:
                self._pos.lat = _deg(lat_raw, lat_dir)
                self._pos.lon = _deg(lon_raw, lon_dir)
                self._pos.alt = float(parts[9]) if parts[9] else None
                self._pos.ts = datetime.now(timezone.utc).isoformat()
                self._pos.fix = True
        except (ValueError, IndexError):
            pass

    def _read_file(self) -> None:
        with suppress(Exception):
            with open(self._source, "r", errors="ignore") as fh:
                for line in fh:
                    if not self._running:
                        break
                    line = line.strip()
                    if line.startswith("$GPGGA") or line.startswith("$GNGGA"):
                        self._parse_gga(line)

    def _read_serial(self) -> None:
        while self._running:
            with suppress(Exception):
                line = self._serial.readline().decode("ascii", errors="ignore").strip()
                if line.startswith("$GPGGA") or line.startswith("$GNGGA"):
                    self._parse_gga(line)

    def position(self) -> _GpsPosition:
        with self._lock:
            return self._pos.copy()

    def stop(self) -> None:
        self._running = False


# ---------------------------------------------------------------------------
# Network record
# ---------------------------------------------------------------------------

@dataclass
class WardriveSighting:
    """A single wardrive observation of a WiFi network."""
    ssid: str
    bssid: str
    channel: int
    rssi: int
    security: str
    timestamp: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude: Optional[float] = None
    speed: Optional[float] = None
    vendor: Optional[str] = None
    band: str = ""
    hidden: bool = False


# ---------------------------------------------------------------------------
# OUI vendor lookup (top 20 prefixes)
# ---------------------------------------------------------------------------

_OUI_TABLE: dict[str, str] = {
    "00:1A:2B": "Cisco", "00:25:00": "Cisco",
    "30:B5:C2": "TP-Link", "50:C7:BF": "TP-Link", "EC:08:6B": "TP-Link",
    "00:1D:7E": "D-Link", "1C:7E:E5": "D-Link",
    "20:CF:30": "ASUS", "F8:32:E4": "ASUS",
    "00:14:BF": "Linksys", "00:18:F8": "Netgear",
    "20:0C:C8": "Netgear", "E4:F4:C6": "Netgear",
    "7C:61:66": "Huawei", "00:E0:FC": "Huawei",
    "C8:3A:35": "Tenda", "88:C6:26": "Google",
    "00:26:BB": "Apple", "3C:07:54": "Apple",
    "00:17:F2": "Apple",
}


def _resolve_vendor(bssid: str) -> Optional[str]:
    prefix = bssid[:8].upper()
    return _OUI_TABLE.get(prefix)


def _channel_to_band(channel: int) -> str:
    if channel <= 14:
        return "2.4 GHz"
    if channel < 133:
        return "5 GHz"
    return "6 GHz"


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

class WardriveLogger:
    """GPS-tagged WiFi network discovery logger.

    Collects WiFi sightings with optional GPS coordinates from gpsd or NMEA
    source. Exports to CSV, JSON, and KML formats for map visualization.

    Attributes:
        __info__: Module metadata.

    Args:
        output_dir: Directory where export files are saved.
        session_id: Optional session identifier; auto-generated if omitted.
        gps_source: GPS backend config:
            - None: no GPS (lat/lon always None)
            - "gpsd": use local gpsd daemon
            - "gpsd://host:port": use remote gpsd
            - "/dev/ttyUSB0" or path to .nmea file: NMEA source
        simulate: When True, sightings are recorded in memory only.
        on_sighting: Optional callback called with each new WardriveSighting.
    """

    __info__ = {
        "name": "Wardrive Logger",
        "category": "wardrive",
        "type": "logger",
        "description": (
            "GPS-tagged WiFi network discovery logger with CSV, JSON, KML export. "
            "Supports gpsd daemon, NMEA serial, or static coordinates. "
            "Integrate with Wigle, Google Maps, or custom heat-map tools."
        ),
        "hw_req": [
            "WiFi adapter with monitor-mode support",
            "Optional: GPS receiver (gpsd or NMEA serial)",
        ],
        "authors": ["Andre Henrique (@mrhenrike) | Uniao Geek"],
    }

    def __init__(
        self,
        output_dir: str | Path,
        session_id: Optional[str] = None,
        gps_source: Optional[str] = None,
        simulate: bool = True,
        on_sighting: Optional[Callable[[WardriveSighting], None]] = None,
    ) -> None:
        self.output_dir = Path(output_dir).resolve()
        self.session_id = session_id or str(uuid.uuid4())[:8]
        self.simulate = simulate
        self.on_sighting = on_sighting
        self._sightings: list[WardriveSighting] = []
        self._lock = threading.Lock()
        self._gps: Optional[_GpsdBackend | _NmeaBackend] = None

        if not self.simulate:
            self.output_dir.mkdir(parents=True, exist_ok=True)

        self._init_gps(gps_source)

    # ------------------------------------------------------------------
    # GPS init
    # ------------------------------------------------------------------

    def _init_gps(self, source: Optional[str]) -> None:
        if source is None:
            logger.info("[Wardrive] No GPS source - lat/lon will be None")
            return

        if source == "gpsd" or source.startswith("gpsd://"):
            host, port = "127.0.0.1", 2947
            if source.startswith("gpsd://"):
                rest = source[len("gpsd://"):]
                if ":" in rest:
                    host, p = rest.rsplit(":", 1)
                    with suppress(ValueError):
                        port = int(p)
                else:
                    host = rest
            backend = _GpsdBackend(host=host, port=port)
            if backend.start():
                self._gps = backend
            else:
                logger.warning("[Wardrive] gpsd unavailable - falling back to no GPS")
        else:
            backend = _NmeaBackend(source=source)
            if backend.start():
                self._gps = backend
            else:
                logger.warning("[Wardrive] NMEA source unavailable - falling back to no GPS")

    # ------------------------------------------------------------------
    # Current GPS fix
    # ------------------------------------------------------------------

    def _current_gps(self) -> _GpsPosition:
        if self._gps is None:
            return _GpsPosition()
        return self._gps.position()

    # ------------------------------------------------------------------
    # Record
    # ------------------------------------------------------------------

    def record(
        self,
        ssid: str,
        bssid: str,
        channel: int,
        rssi: int,
        security: str,
        hidden: bool = False,
        gps_override: Optional[tuple[float, float]] = None,
    ) -> WardriveSighting:
        """Record a WiFi network sighting.

        Args:
            ssid: Network SSID (empty string or '<hidden>' for hidden networks).
            bssid: AP MAC address.
            channel: WiFi channel number.
            rssi: Signal strength in dBm.
            security: Security type string (e.g. 'WPA2', 'Open').
            hidden: True if SSID is not broadcast.
            gps_override: Optional (lat, lon) tuple to bypass GPS backend.

        Returns:
            The created WardriveSighting record.
        """
        pos = self._current_gps()

        if gps_override is not None:
            lat, lon = gps_override
        elif pos.fix:
            lat, lon = pos.lat, pos.lon
        else:
            lat, lon = None, None

        sighting = WardriveSighting(
            ssid=ssid or "<hidden>",
            bssid=bssid.upper(),
            channel=channel,
            rssi=rssi,
            security=security,
            timestamp=datetime.now(timezone.utc).isoformat(),
            latitude=lat,
            longitude=lon,
            altitude=pos.alt if pos.fix else None,
            speed=pos.speed if pos.fix else None,
            vendor=_resolve_vendor(bssid),
            band=_channel_to_band(channel),
            hidden=hidden,
        )

        with self._lock:
            self._sightings.append(sighting)

        if self.on_sighting:
            with suppress(Exception):
                self.on_sighting(sighting)

        if self.simulate:
            logger.debug("[Wardrive] simulate record: %s (%s)", ssid, bssid)
        return sighting

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        """Return basic session statistics."""
        with self._lock:
            total = len(self._sightings)
            with_gps = sum(1 for s in self._sightings if s.latitude is not None)
            unique_bssid = len({s.bssid for s in self._sightings})

        return {
            "session": self.session_id,
            "total_sightings": total,
            "unique_aps": unique_bssid,
            "with_gps": with_gps,
            "without_gps": total - with_gps,
        }

    # ------------------------------------------------------------------
    # Export - CSV
    # ------------------------------------------------------------------

    def export_csv(self, path: Optional[str | Path] = None) -> str:
        """Export sightings to a CSV file.

        Args:
            path: Output file path. Defaults to output_dir/wardrive_<session>.csv.

        Returns:
            Absolute path to the written CSV file.
        """
        out = self._default_path(path, "csv")

        if self.simulate:
            logger.info("[Wardrive] simulate=True - skipping CSV export to %s", out)
            return str(out)

        with self._lock:
            records = [asdict(s) for s in self._sightings]

        with open(str(out), "w", newline="", encoding="utf-8") as fh:
            if records:
                writer = csv.DictWriter(fh, fieldnames=list(records[0].keys()))
                writer.writeheader()
                writer.writerows(records)

        logger.info("[Wardrive] CSV exported: %s (%d rows)", out, len(records))
        return str(out)

    # ------------------------------------------------------------------
    # Export - JSON
    # ------------------------------------------------------------------

    def export_json(self, path: Optional[str | Path] = None) -> str:
        """Export sightings to a JSON file.

        Args:
            path: Output file path. Defaults to output_dir/wardrive_<session>.json.

        Returns:
            Absolute path to the written JSON file.
        """
        out = self._default_path(path, "json")

        if self.simulate:
            logger.info("[Wardrive] simulate=True - skipping JSON export to %s", out)
            return str(out)

        with self._lock:
            data = {
                "session": self.session_id,
                "exported": datetime.now(timezone.utc).isoformat(),
                "sightings": [asdict(s) for s in self._sightings],
            }

        with open(str(out), "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)

        logger.info("[Wardrive] JSON exported: %s (%d sightings)", out, len(self._sightings))
        return str(out)

    # ------------------------------------------------------------------
    # Export - KML
    # ------------------------------------------------------------------

    def export_kml(self, path: Optional[str | Path] = None) -> str:
        """Export sightings with GPS coordinates to a KML file.

        Networks without GPS coordinates are skipped. The KML file can be
        loaded in Google Maps, Google Earth, or JOSM for map visualization.

        Args:
            path: Output file path. Defaults to output_dir/wardrive_<session>.kml.

        Returns:
            Absolute path to the written KML file.
        """
        out = self._default_path(path, "kml")

        if self.simulate:
            logger.info("[Wardrive] simulate=True - skipping KML export to %s", out)
            return str(out)

        with self._lock:
            geo_sightings = [s for s in self._sightings if s.latitude is not None]

        kml = ET.Element("kml", xmlns="http://www.opengis.net/kml/2.2")
        doc = ET.SubElement(kml, "Document")
        ET.SubElement(doc, "name").text = f"Wardrive Session {self.session_id}"

        style_ids = {
            "WPA3": ("#ff00aa00", "wpa3"),
            "WPA2": ("#ff0000ff", "wpa2"),
            "WPA": ("#ff00aaff", "wpa"),
            "Open": ("#ff0000cc", "open"),
        }
        for label, (color, sid) in style_ids.items():
            style = ET.SubElement(doc, "Style", id=sid)
            icon = ET.SubElement(style, "IconStyle")
            ET.SubElement(icon, "color").text = color
            ET.SubElement(icon, "scale").text = "1.0"

        for s in geo_sightings:
            pm = ET.SubElement(doc, "Placemark")
            ET.SubElement(pm, "name").text = s.ssid
            desc_lines = [
                f"BSSID: {s.bssid}",
                f"Security: {s.security}",
                f"Channel: {s.channel} ({s.band})",
                f"RSSI: {s.rssi} dBm",
                f"Vendor: {s.vendor or 'Unknown'}",
                f"Time: {s.timestamp}",
            ]
            ET.SubElement(pm, "description").text = "\n".join(desc_lines)

            style_ref = "wpa2"
            for key, (_, sid) in style_ids.items():
                if key in s.security:
                    style_ref = sid
                    break
            if s.security.lower() in ("open", ""):
                style_ref = "open"
            ET.SubElement(pm, "styleUrl").text = f"#{style_ref}"

            point = ET.SubElement(pm, "Point")
            alt = s.altitude or 0.0
            ET.SubElement(point, "coordinates").text = (
                f"{s.longitude},{s.latitude},{alt}"
            )

        tree = ET.ElementTree(kml)
        ET.indent(tree, space="  ")
        with open(str(out), "wb") as fh:
            fh.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
            tree.write(fh, encoding="utf-8", xml_declaration=False)

        logger.info("[Wardrive] KML exported: %s (%d geotagged)", out, len(geo_sightings))
        return str(out)

    # ------------------------------------------------------------------
    # Export - GeoJSON (bonus, for Leaflet/Folium)
    # ------------------------------------------------------------------

    def export_geojson(self, path: Optional[str | Path] = None) -> str:
        """Export geotagged sightings as GeoJSON for Leaflet/Folium maps.

        Args:
            path: Output file path. Defaults to output_dir/wardrive_<session>.geojson.

        Returns:
            Absolute path to the written GeoJSON file.
        """
        out = self._default_path(path, "geojson")

        if self.simulate:
            logger.info("[Wardrive] simulate=True - skipping GeoJSON export to %s", out)
            return str(out)

        with self._lock:
            geo = [s for s in self._sightings if s.latitude is not None]

        features = []
        for s in geo:
            features.append({
                "type": "Feature",
                "geometry": {
                    "type": "Point",
                    "coordinates": [s.longitude, s.latitude],
                },
                "properties": {
                    "ssid": s.ssid,
                    "bssid": s.bssid,
                    "security": s.security,
                    "channel": s.channel,
                    "rssi": s.rssi,
                    "band": s.band,
                    "vendor": s.vendor,
                    "timestamp": s.timestamp,
                },
            })

        geojson = {
            "type": "FeatureCollection",
            "metadata": {
                "session": self.session_id,
                "exported": datetime.now(timezone.utc).isoformat(),
                "count": len(features),
            },
            "features": features,
        }

        with open(str(out), "w", encoding="utf-8") as fh:
            json.dump(geojson, fh, indent=2)

        logger.info("[Wardrive] GeoJSON exported: %s (%d features)", out, len(features))
        return str(out)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _default_path(self, path: Optional[str | Path], ext: str) -> Path:
        if path is not None:
            return Path(path).resolve()
        return self.output_dir / f"wardrive_{self.session_id}.{ext}"

    def stop(self) -> None:
        """Stop GPS backends and flush data."""
        if self._gps:
            self._gps.stop()

    @property
    def sightings(self) -> list[WardriveSighting]:
        """Read-only snapshot of current sightings."""
        with self._lock:
            return list(self._sightings)
