"""ESP8266 WIDS Bridge - Python receiver for ESP8266 hardware WIDS alerts.

Subscribes to MQTT topics published by an ESP8266 running the WIDS firmware
(based on wifi-arsenal_7 WIDS.ino). Decodes incoming alert JSON payloads into
typed WIDSAlert dataclasses and dispatches them to registered handlers.

Alert types from ESP8266 firmware:
  DEAUTH_DETECTED  - 802.11 deauthentication frame flood observed
  BEACON_FLOOD     - excessive beacon frames from multiple SSIDs
  PROBE_FLOOD      - high-rate probe request/response activity
  RSSI_ANOMALY     - signal-strength spike suggesting rogue AP proximity

Requires: paho-mqtt (graceful fallback with ImportError message if missing)
Simulate mode: generates mock alerts at a configurable interval.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import json
import logging
import random
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

try:
    import paho.mqtt.client as _mqtt_mod  # type: ignore
    _PAHO_AVAILABLE = True
except ImportError:
    _mqtt_mod = None  # type: ignore
    _PAHO_AVAILABLE = False
    logger.warning(
        "[ESP8266-WIDS] paho-mqtt not installed - "
        "install with: pip install paho-mqtt"
    )


# ---------------------------------------------------------------------------
# Alert types
# ---------------------------------------------------------------------------

class ESP8266AlertType(str, Enum):
    """Alert types emitted by the ESP8266 WIDS firmware."""
    DEAUTH_DETECTED = "DEAUTH_DETECTED"
    BEACON_FLOOD = "BEACON_FLOOD"
    PROBE_FLOOD = "PROBE_FLOOD"
    RSSI_ANOMALY = "RSSI_ANOMALY"
    UNKNOWN = "UNKNOWN"


_SEVERITY_MAP: dict[ESP8266AlertType, str] = {
    ESP8266AlertType.DEAUTH_DETECTED: "CRITICAL",
    ESP8266AlertType.BEACON_FLOOD: "HIGH",
    ESP8266AlertType.PROBE_FLOOD: "MEDIUM",
    ESP8266AlertType.RSSI_ANOMALY: "MEDIUM",
    ESP8266AlertType.UNKNOWN: "LOW",
}

_MOCK_ALERT_POOL: list[dict[str, Any]] = [
    {
        "type": "DEAUTH_DETECTED",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "channel": 6,
        "count": 47,
        "rate_per_sec": 9.4,
    },
    {
        "type": "BEACON_FLOOD",
        "ssid_count": 32,
        "rate_per_sec": 28.1,
    },
    {
        "type": "PROBE_FLOOD",
        "src_mac": "11:22:33:44:55:66",
        "target_ssid": "TargetNet",
        "rate_per_sec": 14.0,
    },
    {
        "type": "RSSI_ANOMALY",
        "bssid": "DE:AD:BE:EF:00:01",
        "rssi_delta_db": 22,
        "current_rssi": -38,
        "note": "possible AP proximity",
    },
]


# ---------------------------------------------------------------------------
# Alert dataclass
# ---------------------------------------------------------------------------

@dataclass
class WIDSAlert:
    """A structured alert received from the ESP8266 WIDS hardware.

    Attributes:
        alert_id: Unique identifier for this alert instance.
        alert_type: Classified alert type.
        severity: Severity level string ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        timestamp: ISO-8601 UTC timestamp of receipt.
        bssid: Relevant AP MAC address, if any.
        ssid: Relevant SSID, if any.
        channel: WiFi channel, if reported.
        details: Raw payload fields from the ESP8266.
        source_device: Identifier of the ESP8266 unit that sent the alert.
        simulated: True when generated in simulate mode.
    """
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    alert_type: ESP8266AlertType = ESP8266AlertType.UNKNOWN
    severity: str = "LOW"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    bssid: Optional[str] = None
    ssid: Optional[str] = None
    channel: Optional[int] = None
    details: dict[str, Any] = field(default_factory=dict)
    source_device: Optional[str] = None
    simulated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-safe dict."""
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type.value,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "details": self.details,
            "source_device": self.source_device,
            "simulated": self.simulated,
        }


# ---------------------------------------------------------------------------
# Payload decoder
# ---------------------------------------------------------------------------

def decode_payload(raw: str | bytes, source_device: Optional[str] = None) -> WIDSAlert:
    """Parse a raw MQTT payload into a WIDSAlert.

    Expected payload format (from ESP8266 firmware):
      {"type":"DEAUTH_DETECTED","bssid":"AA:BB:...","channel":6,"count":12}

    Unknown or malformed payloads produce an UNKNOWN-type alert with
    the raw data preserved in details.

    Args:
        raw: Raw MQTT payload bytes or string.
        source_device: Optional device identifier (e.g. MQTT client ID).

    Returns:
        Decoded WIDSAlert instance.
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")

    try:
        payload: dict[str, Any] = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        logger.warning("[ESP8266-WIDS] Malformed payload: %r", raw[:200])
        return WIDSAlert(
            alert_type=ESP8266AlertType.UNKNOWN,
            severity="LOW",
            details={"raw": raw[:500]},
            source_device=source_device,
        )

    type_str = str(payload.get("type", "")).upper()
    try:
        alert_type = ESP8266AlertType(type_str)
    except ValueError:
        alert_type = ESP8266AlertType.UNKNOWN

    return WIDSAlert(
        alert_type=alert_type,
        severity=_SEVERITY_MAP.get(alert_type, "LOW"),
        bssid=payload.get("bssid"),
        ssid=payload.get("ssid"),
        channel=payload.get("channel"),
        details={k: v for k, v in payload.items() if k not in ("type",)},
        source_device=source_device,
    )


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------

class ESP8266WIDSBridge:
    """Python bridge for ESP8266 hardware WIDS via MQTT.

    Connects to an MQTT broker and subscribes to the topic where the ESP8266
    firmware publishes intrusion alerts. Decoded alerts are dispatched to
    registered handler callbacks.

    In simulate mode, a background thread emits mock alerts at a configurable
    interval so the integration can be tested without physical hardware.

    Args:
        broker: MQTT broker hostname or IP.
        port: MQTT broker port (default 1883).
        topic: MQTT topic to subscribe to (default 'wids/alerts').
        client_id: MQTT client identifier; auto-generated if omitted.
        username: Optional MQTT username.
        password: Optional MQTT password.
        on_alert: Primary alert handler callback.
        simulate: When True, no MQTT connection is made; mock alerts are used.
        mock_interval_seconds: Interval between simulated alerts (simulate mode).
    """

    def __init__(
        self,
        broker: str = "127.0.0.1",
        port: int = 1883,
        topic: str = "wids/alerts",
        client_id: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        on_alert: Optional[Callable[[WIDSAlert], None]] = None,
        simulate: bool = True,
        mock_interval_seconds: float = 5.0,
    ) -> None:
        self.broker = broker
        self.port = port
        self.topic = topic
        self.simulate = simulate
        self.mock_interval = mock_interval_seconds
        self._handlers: list[Callable[[WIDSAlert], None]] = []
        self._alerts: list[WIDSAlert] = []
        self._lock = threading.Lock()
        self._running = False
        self._client_id = client_id or f"wxf-wids-bridge-{uuid.uuid4().hex[:8]}"
        self._username = username
        self._password = password
        self._mqtt_client: Any = None
        self._mock_thread: Optional[threading.Thread] = None

        if on_alert:
            self._handlers.append(on_alert)

    # ------------------------------------------------------------------
    # Handler registration
    # ------------------------------------------------------------------

    def add_handler(self, handler: Callable[[WIDSAlert], None]) -> None:
        """Register an additional alert handler.

        Args:
            handler: Callable that accepts a WIDSAlert instance.
        """
        self._handlers.append(handler)

    def remove_handler(self, handler: Callable[[WIDSAlert], None]) -> None:
        """Remove a previously registered handler."""
        with suppress_exc():
            self._handlers.remove(handler)

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, alert: WIDSAlert) -> None:
        with self._lock:
            self._alerts.append(alert)

        logger.warning(
            "[ESP8266-WIDS] %s [%s] bssid=%s ssid=%s ch=%s simulated=%s",
            alert.severity, alert.alert_type.value,
            alert.bssid, alert.ssid, alert.channel, alert.simulated,
        )

        for handler in self._handlers:
            try:
                handler(alert)
            except Exception as exc:
                logger.error("[ESP8266-WIDS] Handler error: %s", exc)

    # ------------------------------------------------------------------
    # MQTT callbacks
    # ------------------------------------------------------------------

    def _on_connect(self, client: Any, userdata: Any, flags: Any, rc: int) -> None:
        if rc == 0:
            logger.info("[ESP8266-WIDS] MQTT connected to %s:%d", self.broker, self.port)
            client.subscribe(self.topic, qos=1)
        else:
            logger.error("[ESP8266-WIDS] MQTT connect failed rc=%d", rc)

    def _on_message(self, client: Any, userdata: Any, message: Any) -> None:
        try:
            alert = decode_payload(
                message.payload,
                source_device=message.topic,
            )
            self._dispatch(alert)
        except Exception as exc:
            logger.error("[ESP8266-WIDS] Message processing error: %s", exc)

    def _on_disconnect(self, client: Any, userdata: Any, rc: int) -> None:
        if rc != 0:
            logger.warning("[ESP8266-WIDS] Unexpected MQTT disconnect rc=%d", rc)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Start the bridge.

        In simulate mode, spawns a thread emitting mock alerts.
        Otherwise, connects to MQTT broker and begins listening.

        Returns:
            True if started successfully.
        """
        if self._running:
            logger.warning("[ESP8266-WIDS] Already running")
            return False

        self._running = True

        if self.simulate:
            logger.info("[ESP8266-WIDS] simulate=True - starting mock alert generator")
            self._mock_thread = threading.Thread(
                target=self._run_mock, daemon=True
            )
            self._mock_thread.start()
            return True

        if not _PAHO_AVAILABLE:
            logger.error(
                "[ESP8266-WIDS] paho-mqtt not installed. "
                "Install with: pip install paho-mqtt"
            )
            self._running = False
            return False

        try:
            client = _mqtt_mod.Client(client_id=self._client_id)
            client.on_connect = self._on_connect
            client.on_message = self._on_message
            client.on_disconnect = self._on_disconnect

            if self._username:
                client.username_pw_set(self._username, self._password)

            client.connect(self.broker, self.port, keepalive=60)
            client.loop_start()
            self._mqtt_client = client
            logger.info(
                "[ESP8266-WIDS] MQTT bridge started: %s:%d topic=%s",
                self.broker, self.port, self.topic,
            )
            return True
        except Exception as exc:
            logger.error("[ESP8266-WIDS] Failed to start MQTT bridge: %s", exc)
            self._running = False
            return False

    def stop(self) -> None:
        """Stop the bridge and clean up connections."""
        self._running = False

        if self._mqtt_client:
            try:
                self._mqtt_client.loop_stop()
                self._mqtt_client.disconnect()
            except Exception:
                pass
            self._mqtt_client = None

        logger.info("[ESP8266-WIDS] Stopped (%d alerts received)", len(self._alerts))

    # ------------------------------------------------------------------
    # Simulate mode
    # ------------------------------------------------------------------

    def _run_mock(self) -> None:
        """Emit mock WIDS alerts at the configured interval."""
        pool = list(_MOCK_ALERT_POOL)
        idx = 0
        while self._running:
            time.sleep(self.mock_interval)
            if not self._running:
                break
            raw = json.dumps(pool[idx % len(pool)])
            alert = decode_payload(raw, source_device="esp8266-mock")
            alert.simulated = True
            self._dispatch(alert)
            idx += 1

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def alerts(self) -> list[WIDSAlert]:
        """Read-only snapshot of all alerts received."""
        with self._lock:
            return list(self._alerts)

    def clear_alerts(self) -> None:
        """Clear the accumulated alert list."""
        with self._lock:
            self._alerts.clear()

    def summary(self) -> dict[str, Any]:
        """Return a brief operational summary."""
        with self._lock:
            total = len(self._alerts)
            by_type: dict[str, int] = {}
            for a in self._alerts:
                key = a.alert_type.value
                by_type[key] = by_type.get(key, 0) + 1

        return {
            "running": self._running,
            "simulate": self.simulate,
            "broker": f"{self.broker}:{self.port}",
            "topic": self.topic,
            "total_alerts": total,
            "by_type": by_type,
            "paho_available": _PAHO_AVAILABLE,
        }

    # ------------------------------------------------------------------
    # Publish mock (for testing the full pipeline)
    # ------------------------------------------------------------------

    def inject_alert(self, payload: dict[str, Any]) -> WIDSAlert:
        """Inject a synthetic alert for testing purposes.

        Args:
            payload: Dict matching the ESP8266 alert schema.

        Returns:
            The resulting WIDSAlert.
        """
        raw = json.dumps(payload)
        alert = decode_payload(raw, source_device="injected")
        alert.simulated = True
        self._dispatch(alert)
        return alert


# ---------------------------------------------------------------------------
# Small helper
# ---------------------------------------------------------------------------

class suppress_exc:
    """Minimal exception suppressor (contextlib.suppress inline clone)."""
    def __enter__(self) -> "suppress_exc":
        return self

    def __exit__(self, exc_type: Any, *_: Any) -> bool:
        return exc_type is not None
