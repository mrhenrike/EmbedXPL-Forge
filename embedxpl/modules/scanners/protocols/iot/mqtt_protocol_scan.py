# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""MQTT Protocol Scanner - Version, Auth, TLS, and Topic Discovery.

Connects to MQTT brokers to enumerate protocol version, authentication
requirements, TLS support, and publicly subscribable topics.

References:
  - MQTT v3.1.1 (OASIS Standard)
  - MQTT v5.0 (OASIS Standard)

Version: 1.0.0
"""

import socket
import ssl
import struct
import time

from embedxpl.core.exploit import *


_MQTT_CONNACK = 0x20
_MQTT_SUBACK = 0x90

_CONNECT_V311 = (
    b"\x10"
    b"\x12"
    b"\x00\x04MQTT"
    b"\x04"
    b"\x02"
    b"\x00\x3c"
    b"\x00\x06exfscan"
)

_CONNECT_V5 = (
    b"\x10"
    b"\x13"
    b"\x00\x04MQTT"
    b"\x05"
    b"\x02"
    b"\x00\x3c"
    b"\x00"
    b"\x00\x06exfscan"
)


class Exploit(Exploit):
    """MQTT Protocol Scanner.

    Probes MQTT brokers for version support, authentication enforcement,
    TLS availability, and public topic subscriptions.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "MQTT Protocol Scanner",
        "description": (
            "Connects to MQTT brokers to detect protocol version (3.1.1/5.0), "
            "check authentication requirements, TLS configuration, and enumerate "
            "publicly accessible topics via wildcard subscription."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html",
            "https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html",
        ),
        "devices": ("MQTT Brokers", "Mosquitto", "EMQ X", "HiveMQ", "VerneMQ"),
        "severity": "info",
        "mitre": ["T0846"],
        "status": "confirmed",
    }

    target = OptIP("", "Target MQTT broker IP")
    port = OptPort(1883, "MQTT TCP port")
    tls_port = OptPort(8883, "MQTT TLS port")
    timeout = OptInteger(5, "Socket timeout in seconds")
    topic_listen = OptInteger(3, "Seconds to listen for public topics")

    def _tcp_connect(self, host: str, port: int, use_tls: bool = False) -> socket.socket:
        """Establish TCP (optionally TLS) connection to broker."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(float(self.timeout))
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.connect((host, int(port)))
        return sock

    def _send_connect(self, sock: socket.socket, packet: bytes) -> tuple:
        """Send CONNECT packet and parse CONNACK.

        Returns:
            Tuple of (accepted: bool, return_code: int).
        """
        sock.sendall(packet)
        resp = sock.recv(256)
        if len(resp) < 4 or (resp[0] & 0xF0) != _MQTT_CONNACK:
            return (False, -1)
        rc = resp[3]
        return (rc == 0x00, rc)

    def _connack_reason(self, code: int, version: str) -> str:
        """Map CONNACK return code to human-readable reason."""
        if version == "3.1.1":
            reasons = {
                0: "Connection Accepted",
                1: "Unacceptable Protocol Version",
                2: "Identifier Rejected",
                3: "Server Unavailable",
                4: "Bad Username or Password",
                5: "Not Authorized",
            }
        else:
            reasons = {
                0: "Success",
                128: "Unspecified Error",
                133: "Not Authorized",
                134: "Bad Username or Password",
                135: "Server Busy",
                140: "Bad Authentication Method",
            }
        return reasons.get(code, "Unknown (0x{:02x})".format(code))

    def _probe_version(self, packet: bytes, version: str) -> dict:
        """Probe broker with specific MQTT version."""
        result = {"version": version, "supported": False, "auth_required": False}
        try:
            sock = self._tcp_connect(self.target, int(self.port))
            accepted, rc = self._send_connect(sock, packet)
            result["supported"] = True
            result["accepted"] = accepted
            result["return_code"] = rc
            result["reason"] = self._connack_reason(rc, version)
            if rc in (4, 5, 133, 134, 135):
                result["auth_required"] = True
            sock.close()
        except (socket.error, OSError, ssl.SSLError):
            pass
        return result

    def _check_tls(self) -> dict:
        """Check if TLS-enabled MQTT port is available."""
        result = {"tls_available": False, "tls_port": int(self.tls_port)}
        try:
            sock = self._tcp_connect(self.target, int(self.tls_port), use_tls=True)
            result["tls_available"] = True
            cert = sock.getpeercert(binary_form=True)
            if cert:
                result["cert_size"] = len(cert)
            sock.close()
        except (socket.error, OSError, ssl.SSLError):
            pass
        return result

    def _subscribe_wildcard(self, sock: socket.socket) -> list:
        """Subscribe to '#' wildcard and collect published topics."""
        sub_packet = (
            b"\x82\x07"
            b"\x00\x01"
            b"\x00\x01#"
            b"\x00"
        )
        sock.sendall(sub_packet)
        resp = sock.recv(256)
        if len(resp) < 4 or (resp[0] & 0xF0) != _MQTT_SUBACK:
            return []

        topics = []
        deadline = time.time() + float(self.topic_listen)
        sock.settimeout(1.0)
        while time.time() < deadline:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                offset = 0
                while offset < len(data):
                    if (data[offset] & 0xF0) != 0x30:
                        break
                    remaining = data[offset + 1]
                    if offset + 2 + remaining > len(data):
                        break
                    topic_len = struct.unpack(">H", data[offset + 2:offset + 4])[0]
                    topic = data[offset + 4:offset + 4 + topic_len].decode(
                        "utf-8", errors="replace"
                    )
                    if topic not in topics:
                        topics.append(topic)
                    offset += 2 + remaining
                    if len(topics) >= 50:
                        break
            except socket.timeout:
                continue
            except (socket.error, OSError):
                break
        return topics

    def _discover_topics(self) -> list:
        """Attempt wildcard subscription for topic discovery."""
        try:
            sock = self._tcp_connect(self.target, int(self.port))
            accepted, _ = self._send_connect(sock, _CONNECT_V311)
            if not accepted:
                sock.close()
                return []
            topics = self._subscribe_wildcard(sock)
            sock.close()
            return topics
        except (socket.error, OSError):
            return []

    @mute
    def check(self) -> bool:
        """Verify MQTT port is reachable."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(self.timeout))
            sock.connect((self.target, int(self.port)))
            sock.close()
            return True
        except (socket.error, OSError):
            return False

    @multi
    def run(self) -> None:
        """Execute MQTT protocol scan."""
        print_status("Scanning MQTT broker at {}:{}".format(self.target, self.port))

        if not self.check():
            print_error("MQTT port {} not reachable".format(self.port))
            return

        print_success("MQTT port {} open".format(self.port))

        v311 = self._probe_version(_CONNECT_V311, "3.1.1")
        if v311.get("supported"):
            print_info("MQTT v3.1.1: {} (RC={})".format(
                v311["reason"], v311["return_code"]
            ))
            if v311.get("auth_required"):
                print_warning("Authentication required (v3.1.1)")

        v5 = self._probe_version(_CONNECT_V5, "5.0")
        if v5.get("supported"):
            print_info("MQTT v5.0: {} (RC={})".format(
                v5["reason"], v5["return_code"]
            ))
            if v5.get("auth_required"):
                print_warning("Authentication required (v5.0)")

        tls = self._check_tls()
        if tls["tls_available"]:
            print_success("TLS available on port {}".format(tls["tls_port"]))
        else:
            print_warning("TLS port {} not reachable".format(tls["tls_port"]))

        if v311.get("accepted") or v5.get("accepted"):
            print_status("Subscribing to wildcard '#' for {} seconds...".format(
                self.topic_listen
            ))
            topics = self._discover_topics()
            if topics:
                print_success("Discovered {} public topic(s):".format(len(topics)))
                for t in topics:
                    print_info("  {}".format(t))
            else:
                print_info("No public topics captured in {} seconds".format(
                    self.topic_listen
                ))
        else:
            print_info("Anonymous access denied, skipping topic discovery")
