"""Wireless Intrusion Detection System (WIDS) - native Python implementation.

Passive monitor-mode packet analysis using Scapy. Detects common 802.11
attacks and anomalies, emitting structured alerts via callback or MQTT.

Detected threat classes:
  - DEAUTH_FLOOD: excessive deauthentication frames targeting client/AP
  - BEACON_FLOOD: beacon frame flood (SSID flood attack)
  - PROBE_FLOOD: probe request/response flood
  - EVIL_TWIN: SSID seen with a different BSSID than previously observed
  - ROGUE_AP: new AP on monitored SSID with mismatched parameters
  - CHANNEL_HOP: AP BSSID hopping across multiple channels rapidly
  - SSID_CHANGE: known BSSID advertising different SSID
  - DISASSOC_FLOOD: excessive disassociation frames

Requires: scapy (graceful import error with clear message)
MQTT alerting: requires paho-mqtt (optional, graceful fallback)

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import defaultdict, deque
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

try:
    from scapy.layers.dot11 import (  # type: ignore
        Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas, Dot11Elt,
        Dot11ProbeReq, Dot11ProbeResp, RadioTap,
    )
    from scapy.all import AsyncSniffer  # type: ignore
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False
    logger.warning("[WIDS] scapy not installed - install with: pip install scapy")

try:
    import paho.mqtt.client as mqtt  # type: ignore
    _MQTT_AVAILABLE = True
except ImportError:
    _MQTT_AVAILABLE = False


# ---------------------------------------------------------------------------
# Alert types and structure
# ---------------------------------------------------------------------------

class AlertType(str, Enum):
    DEAUTH_FLOOD = "DEAUTH_FLOOD"
    BEACON_FLOOD = "BEACON_FLOOD"
    PROBE_FLOOD = "PROBE_FLOOD"
    EVIL_TWIN = "EVIL_TWIN"
    ROGUE_AP = "ROGUE_AP"
    CHANNEL_HOP = "CHANNEL_HOP"
    SSID_CHANGE = "SSID_CHANGE"
    DISASSOC_FLOOD = "DISASSOC_FLOOD"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


_SEVERITY_MAP: dict[AlertType, Severity] = {
    AlertType.DEAUTH_FLOOD: Severity.CRITICAL,
    AlertType.BEACON_FLOOD: Severity.HIGH,
    AlertType.PROBE_FLOOD: Severity.MEDIUM,
    AlertType.EVIL_TWIN: Severity.CRITICAL,
    AlertType.ROGUE_AP: Severity.HIGH,
    AlertType.CHANNEL_HOP: Severity.MEDIUM,
    AlertType.SSID_CHANGE: Severity.HIGH,
    AlertType.DISASSOC_FLOOD: Severity.HIGH,
}


@dataclass
class WIDSAlert:
    """A WIDS detection event."""
    alert_id: str
    alert_type: AlertType
    severity: Severity
    timestamp: str
    bssid: Optional[str]
    ssid: Optional[str]
    details: dict[str, Any] = field(default_factory=dict)
    simulated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-safe dict."""
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "details": self.details,
            "simulated": self.simulated,
        }


# ---------------------------------------------------------------------------
# Thresholds configuration
# ---------------------------------------------------------------------------

@dataclass
class WIDSThresholds:
    """Configurable detection thresholds.

    Args:
        deauth_per_second: Deauth frames per second before triggering alert.
        beacon_flood_per_second: Distinct beaconing SSIDs per second.
        probe_per_second: Probe frames per second per source MAC.
        disassoc_per_second: Disassoc frames per second before alert.
        channel_hop_window_seconds: Time window for channel-hop detection.
        channel_hop_count: Min channel changes in window to trigger alert.
        rate_window_seconds: Sliding window duration for rate calculations.
    """
    deauth_per_second: float = 5.0
    beacon_flood_per_second: float = 20.0
    probe_per_second: float = 10.0
    disassoc_per_second: float = 5.0
    channel_hop_window_seconds: float = 30.0
    channel_hop_count: int = 5
    rate_window_seconds: float = 5.0


# ---------------------------------------------------------------------------
# Rate tracker using sliding time window
# ---------------------------------------------------------------------------

class _RateCounter:
    """Sliding-window event rate tracker."""

    def __init__(self, window: float = 5.0) -> None:
        self._window = window
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    def record(self) -> float:
        """Record an event and return the current rate (events/sec)."""
        now = time.monotonic()
        with self._lock:
            self._events.append(now)
            cutoff = now - self._window
            while self._events and self._events[0] < cutoff:
                self._events.popleft()
            return len(self._events) / self._window


# ---------------------------------------------------------------------------
# Wireless IDS main class
# ---------------------------------------------------------------------------

class WirelessIDS:
    """Native Python Wireless Intrusion Detection System.

    Sniffs 802.11 management frames in monitor mode and emits structured
    alerts when attack patterns are detected. Requires the interface to
    already be in monitor mode.

    Attributes:
        __info__: Module metadata.

    Args:
        interface: Wireless interface in monitor mode (e.g. 'wlan0mon').
        thresholds: Detection threshold configuration.
        on_alert: Callback invoked with each WIDSAlert (may run in sniff thread).
        mqtt_broker: Optional MQTT broker host. If set and paho-mqtt is
            installed, alerts are also published to MQTT.
        mqtt_port: MQTT broker port (default 1883).
        mqtt_topic: MQTT topic for alert publication.
        simulate: When True, captures no real packets; runs a mock scenario
            instead showing what would be detected.
    """

    __info__ = {
        "name": "Wireless IDS (WIDS)",
        "category": "wids",
        "type": "detection",
        "description": (
            "Native Python passive 802.11 intrusion detection system. "
            "Detects deauth floods, beacon floods, evil twin, rogue AP, "
            "probe floods, and channel-hopping attacks. "
            "Optional MQTT alerting via paho-mqtt."
        ),
        "detected_attacks": [
            "DEAUTH_FLOOD", "BEACON_FLOOD", "PROBE_FLOOD",
            "EVIL_TWIN", "ROGUE_AP", "CHANNEL_HOP", "SSID_CHANGE", "DISASSOC_FLOOD",
        ],
        "hw_req": ["WiFi adapter in monitor mode"],
        "authors": ["Andre Henrique (@mrhenrike) | Uniao Geek"],
    }

    def __init__(
        self,
        interface: str = "wlan0mon",
        thresholds: Optional[WIDSThresholds] = None,
        on_alert: Optional[Callable[[WIDSAlert], None]] = None,
        mqtt_broker: Optional[str] = None,
        mqtt_port: int = 1883,
        mqtt_topic: str = "wids/alerts",
        simulate: bool = True,
    ) -> None:
        self.interface = interface
        self.thresholds = thresholds or WIDSThresholds()
        self.on_alert = on_alert
        self.simulate = simulate
        self.mqtt_topic = mqtt_topic

        self._alerts: list[WIDSAlert] = []
        self._lock = threading.Lock()
        self._running = False
        self._sniffer: Optional[Any] = None

        # Per-BSSID state
        self._known_ssids: dict[str, str] = {}       # bssid -> ssid
        self._known_channels: dict[str, list[tuple[float, int]]] = defaultdict(list)
        self._deauth_rate: dict[str, _RateCounter] = defaultdict(
            lambda: _RateCounter(thresholds.rate_window_seconds if thresholds else 5.0)
        )
        self._disassoc_rate: dict[str, _RateCounter] = defaultdict(
            lambda: _RateCounter(thresholds.rate_window_seconds if thresholds else 5.0)
        )
        self._beacon_rate = _RateCounter(thresholds.rate_window_seconds if thresholds else 5.0)
        self._probe_rate: dict[str, _RateCounter] = defaultdict(
            lambda: _RateCounter(thresholds.rate_window_seconds if thresholds else 5.0)
        )
        self._alert_cooldown: dict[str, float] = {}
        self._cooldown_seconds = 10.0

        self._mqtt: Optional[Any] = None
        if mqtt_broker and _MQTT_AVAILABLE and not simulate:
            self._init_mqtt(mqtt_broker, mqtt_port, mqtt_topic)

    # ------------------------------------------------------------------
    # MQTT
    # ------------------------------------------------------------------

    def _init_mqtt(self, host: str, port: int, topic: str) -> None:
        try:
            import json as _json
            client = mqtt.Client(client_id=f"wxf-wids-{uuid.uuid4().hex[:6]}")
            client.connect(host, port, keepalive=30)
            client.loop_start()
            self._mqtt = client
            logger.info("[WIDS] MQTT connected to %s:%d topic=%s", host, port, topic)
        except Exception as exc:
            logger.warning("[WIDS] MQTT init failed: %s", exc)

    def _publish_mqtt(self, alert: WIDSAlert) -> None:
        if self._mqtt is None:
            return
        import json as _json
        with suppress(Exception):
            self._mqtt.publish(self.mqtt_topic, _json.dumps(alert.to_dict()), qos=1)

    # ------------------------------------------------------------------
    # Alert emission
    # ------------------------------------------------------------------

    def _emit(
        self,
        alert_type: AlertType,
        bssid: Optional[str],
        ssid: Optional[str],
        details: dict[str, Any],
        simulated: bool = False,
    ) -> Optional[WIDSAlert]:
        """Build and dispatch a WIDSAlert, respecting per-type cooldown."""
        cooldown_key = f"{alert_type.value}:{bssid}:{ssid}"
        now = time.monotonic()

        with self._lock:
            if now - self._alert_cooldown.get(cooldown_key, 0.0) < self._cooldown_seconds:
                return None
            self._alert_cooldown[cooldown_key] = now

        alert = WIDSAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=alert_type,
            severity=_SEVERITY_MAP.get(alert_type, Severity.MEDIUM),
            timestamp=datetime.now(timezone.utc).isoformat(),
            bssid=bssid,
            ssid=ssid,
            details=details,
            simulated=simulated,
        )

        with self._lock:
            self._alerts.append(alert)

        logger.warning(
            "[WIDS] %s [%s] bssid=%s ssid=%s %s",
            alert.severity.value, alert.alert_type.value,
            bssid, ssid, details,
        )

        if self.on_alert:
            with suppress(Exception):
                self.on_alert(alert)

        if not simulated:
            self._publish_mqtt(alert)

        return alert

    # ------------------------------------------------------------------
    # Packet analysis
    # ------------------------------------------------------------------

    def _analyse(self, pkt: Any) -> None:
        """Process a single captured packet."""
        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt[Dot11]
        bssid = (dot11.addr3 or dot11.addr2 or "").upper()
        src = (dot11.addr2 or "").upper()

        # --- Deauth flood ---
        if pkt.haslayer(Dot11Deauth):
            rate = self._deauth_rate[src].record()
            if rate >= self.thresholds.deauth_per_second:
                self._emit(AlertType.DEAUTH_FLOOD, bssid=src, ssid=None,
                           details={"rate_per_sec": round(rate, 1), "src_mac": src})

        # --- Disassoc flood ---
        elif pkt.haslayer(Dot11Disas):
            rate = self._disassoc_rate[src].record()
            if rate >= self.thresholds.disassoc_per_second:
                self._emit(AlertType.DISASSOC_FLOOD, bssid=src, ssid=None,
                           details={"rate_per_sec": round(rate, 1), "src_mac": src})

        # --- Beacon analysis ---
        elif pkt.haslayer(Dot11Beacon):
            ssid = ""
            channel = 0
            with suppress(Exception):
                ssid = pkt[Dot11Elt].info.decode("utf-8", errors="replace")
            with suppress(Exception):
                channel = int(ord(pkt[Dot11Elt:3].info))

            # Beacon flood
            rate = self._beacon_rate.record()
            if rate >= self.thresholds.beacon_flood_per_second:
                self._emit(AlertType.BEACON_FLOOD, bssid=bssid, ssid=ssid,
                           details={"rate_per_sec": round(rate, 1)})

            # Evil twin / SSID change detection
            if bssid and ssid:
                with self._lock:
                    known = self._known_ssids.get(bssid)
                    if known is None:
                        self._known_ssids[bssid] = ssid
                    elif known != ssid:
                        self._emit(AlertType.SSID_CHANGE, bssid=bssid, ssid=ssid,
                                   details={"previous_ssid": known, "new_ssid": ssid})
                        self._known_ssids[bssid] = ssid

                # Evil twin: same SSID, different BSSID already seen for this SSID
                for known_bssid, known_ssid in list(self._known_ssids.items()):
                    if known_ssid == ssid and known_bssid != bssid:
                        self._emit(AlertType.EVIL_TWIN, bssid=bssid, ssid=ssid,
                                   details={"legitimate_bssid": known_bssid, "rogue_bssid": bssid})

            # Channel hop detection
            if bssid and channel:
                with self._lock:
                    hops = self._known_channels[bssid]
                    now = time.monotonic()
                    hops.append((now, channel))
                    cutoff = now - self.thresholds.channel_hop_window_seconds
                    self._known_channels[bssid] = [(t, c) for t, c in hops if t > cutoff]
                    distinct_ch = len({c for _, c in self._known_channels[bssid]})
                    if distinct_ch >= self.thresholds.channel_hop_count:
                        self._emit(AlertType.CHANNEL_HOP, bssid=bssid, ssid=ssid,
                                   details={"distinct_channels": distinct_ch,
                                            "window_seconds": self.thresholds.channel_hop_window_seconds})

        # --- Probe flood ---
        elif pkt.haslayer(Dot11ProbeReq) or pkt.haslayer(Dot11ProbeResp):
            rate = self._probe_rate[src].record()
            if rate >= self.thresholds.probe_per_second:
                self._emit(AlertType.PROBE_FLOOD, bssid=bssid, ssid=None,
                           details={"rate_per_sec": round(rate, 1), "src_mac": src})

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Start passive monitoring.

        Returns:
            True if monitoring started, False if scapy is unavailable or
            already running.
        """
        if self._running:
            logger.warning("[WIDS] Already running")
            return False

        if self.simulate:
            logger.info("[WIDS] simulate=True - starting mock scenario")
            self._running = True
            threading.Thread(target=self._simulate_scenario, daemon=True).start()
            return True

        if not _SCAPY_AVAILABLE:
            logger.error("[WIDS] scapy is not installed. Cannot start passive sniffing.")
            return False

        try:
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._analyse,
                store=False,
                filter="type mgt",
            )
            self._sniffer.start()
            self._running = True
            logger.info("[WIDS] Passive sniffing started on %s", self.interface)
            return True
        except Exception as exc:
            logger.error("[WIDS] Failed to start sniffer: %s", exc)
            return False

    def stop(self) -> None:
        """Stop monitoring and clean up."""
        self._running = False
        if self._sniffer:
            with suppress(Exception):
                self._sniffer.stop()
        if self._mqtt:
            with suppress(Exception):
                self._mqtt.loop_stop()
                self._mqtt.disconnect()
        logger.info("[WIDS] Stopped")

    # ------------------------------------------------------------------
    # Simulate mode
    # ------------------------------------------------------------------

    def _simulate_scenario(self) -> None:
        """Emit mock alerts for dry-run demonstration."""
        scenarios = [
            (2.0, AlertType.DEAUTH_FLOOD, "AA:BB:CC:11:22:33", None,
             {"rate_per_sec": 12.4, "src_mac": "AA:BB:CC:11:22:33"}),
            (4.0, AlertType.BEACON_FLOOD, "FF:FF:FF:FF:FF:FF", "FLOOD_TEST",
             {"rate_per_sec": 35.0}),
            (6.0, AlertType.EVIL_TWIN, "DE:AD:BE:EF:00:01", "CoffeeShop_WiFi",
             {"legitimate_bssid": "AA:AA:AA:AA:AA:AA", "rogue_bssid": "DE:AD:BE:EF:00:01"}),
            (8.0, AlertType.PROBE_FLOOD, None, None,
             {"rate_per_sec": 15.2, "src_mac": "11:22:33:44:55:66"}),
            (10.0, AlertType.SSID_CHANGE, "BB:CC:DD:EE:FF:00", "NewSSID",
             {"previous_ssid": "OldSSID", "new_ssid": "NewSSID"}),
        ]

        for delay, atype, bssid, ssid, details in scenarios:
            if not self._running:
                break
            time.sleep(delay)
            self._emit(atype, bssid=bssid, ssid=ssid, details=details, simulated=True)

        self._running = False
        logger.info("[WIDS] simulate scenario complete (%d alerts emitted)", len(self._alerts))

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def alerts(self) -> list[WIDSAlert]:
        """Read-only snapshot of all alerts emitted so far."""
        with self._lock:
            return list(self._alerts)

    def clear_alerts(self) -> None:
        """Clear accumulated alerts."""
        with self._lock:
            self._alerts.clear()

    def summary(self) -> dict[str, Any]:
        """Return a count summary grouped by alert type."""
        with self._lock:
            by_type: dict[str, int] = defaultdict(int)
            for a in self._alerts:
                by_type[a.alert_type.value] += 1
        return {
            "running": self._running,
            "interface": self.interface,
            "total_alerts": sum(by_type.values()),
            "by_type": dict(by_type),
            "simulate": self.simulate,
        }
