# Author: Andre Henrique (LinkedIn/X: @mrhenrike)

import socket
import ssl
import struct
import time

from embedxpl.core.exploit import *


class Exploit(Exploit):
    """MQTT broker discovery and anonymous access scanner.

    Connects to the target on MQTT ports (1883/TCP plaintext, 8883/TCP TLS)
    and tests whether the broker accepts connections without credentials.
    If anonymous access is confirmed, subscribes to the wildcard topic '#'
    to enumerate published topics, payloads, and QoS levels.
    """

    __info__ = {
        "name": "MQTT Broker Anonymous Access Scanner",
        "description": (
            "Discovers MQTT brokers and tests for anonymous access. "
            "Enumerates topics via wildcard subscription when unauthenticated "
            "connections are accepted. Identifies broker software through $SYS topics."
        ),
        "authors": ["Andre Henrique <@mrhenrike>"],
        "references": [
            "https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html",
            "https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html",
        ],
        "devices": ["Generic MQTT Broker"],
        "status": "confirmed",
        "required_hardware": [],
    }

    target = OptIP("", "Target IP address")
    port = OptPort(1883, "MQTT broker port")
    timeout = OptInteger(10, "Connection timeout in seconds")
    listen_duration = OptInteger(5, "Seconds to listen for published messages")
    use_tls = OptBool(False, "Use TLS (port 8883 typical)")

    MQTT_CONNECT = 0x10
    MQTT_CONNACK = 0x20
    MQTT_PUBLISH = 0x30
    MQTT_SUBSCRIBE = 0x80
    MQTT_SUBACK = 0x90
    MQTT_PINGREQ = 0xC0
    MQTT_PINGRESP = 0xD0
    MQTT_DISCONNECT = 0xE0

    CONNACK_ACCEPTED = 0x00

    BROKER_SYS_TOPICS = [
        "$SYS/broker/version",
        "$SYS/broker/uptime",
        "$SYS/broker/clients/connected",
        "$SYS/broker/messages/received",
        "$SYS/broker/load/messages/received/1min",
    ]

    KNOWN_BROKERS = {
        "mosquitto": "Eclipse Mosquitto",
        "emqx": "EMQX",
        "hivemq": "HiveMQ",
        "vernemq": "VerneMQ",
        "rabbitmq": "RabbitMQ (MQTT plugin)",
        "nanomq": "NanoMQ",
    }

    def _build_connect_packet(self):
        """Build an MQTT 3.1.1 CONNECT packet with no credentials."""
        protocol_name = b"\x00\x04MQTT"
        protocol_level = struct.pack("!B", 0x04)  # 3.1.1
        connect_flags = struct.pack("!B", 0x02)   # clean session only
        keep_alive = struct.pack("!H", 60)
        client_id = b"\x00\x00"                    # zero-length client id

        variable_header = protocol_name + protocol_level + connect_flags + keep_alive
        payload = client_id

        remaining = variable_header + payload
        remaining_length = self._encode_remaining_length(len(remaining))

        return struct.pack("!B", self.MQTT_CONNECT) + remaining_length + remaining

    def _build_subscribe_packet(self, topic, packet_id=1):
        """Build an MQTT SUBSCRIBE packet for the given topic filter."""
        topic_encoded = topic.encode("utf-8")
        topic_length = struct.pack("!H", len(topic_encoded))
        qos = struct.pack("!B", 0x00)
        pid = struct.pack("!H", packet_id)

        payload = topic_length + topic_encoded + qos
        remaining = pid + payload
        remaining_length = self._encode_remaining_length(len(remaining))

        header_byte = self.MQTT_SUBSCRIBE | 0x02  # reserved bits per spec
        return struct.pack("!B", header_byte) + remaining_length + remaining

    def _build_pingreq_packet(self):
        """Build an MQTT PINGREQ packet."""
        return struct.pack("!BB", self.MQTT_PINGREQ, 0x00)

    def _build_disconnect_packet(self):
        """Build an MQTT DISCONNECT packet."""
        return struct.pack("!BB", self.MQTT_DISCONNECT, 0x00)

    def _encode_remaining_length(self, length):
        """Encode MQTT remaining length using variable-length encoding."""
        encoded = bytearray()
        while True:
            byte = length % 128
            length = length // 128
            if length > 0:
                byte |= 0x80
            encoded.append(byte)
            if length == 0:
                break
        return bytes(encoded)

    def _decode_remaining_length(self, sock):
        """Read and decode MQTT remaining length from the socket."""
        multiplier = 1
        value = 0
        for _ in range(4):
            raw = sock.recv(1)
            if not raw:
                raise ConnectionError("Socket closed while reading remaining length")
            byte = raw[0]
            value += (byte & 0x7F) * multiplier
            if (byte & 0x80) == 0:
                return value
            multiplier *= 128
        raise ValueError("Malformed remaining length in MQTT packet")

    def _create_socket(self):
        """Create a TCP socket, optionally wrapped with TLS."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        if self.use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            sock = ctx.wrap_socket(sock)

        return sock

    def _read_packet(self, sock):
        """Read a single MQTT packet from the socket.

        Returns:
            tuple: (packet_type, payload_bytes) or (None, None) on failure.
        """
        try:
            header_raw = sock.recv(1)
            if not header_raw:
                return None, None
            packet_type = header_raw[0] & 0xF0
            remaining_len = self._decode_remaining_length(sock)
            payload = b""
            while len(payload) < remaining_len:
                chunk = sock.recv(remaining_len - len(payload))
                if not chunk:
                    break
                payload += chunk
            return packet_type, payload
        except (socket.timeout, ConnectionError, OSError):
            return None, None

    def _parse_publish(self, payload, header_byte=0x30):
        """Extract topic and message from a PUBLISH packet payload."""
        if len(payload) < 2:
            return None, None, 0

        topic_len = struct.unpack("!H", payload[:2])[0]
        if len(payload) < 2 + topic_len:
            return None, None, 0

        topic = payload[2:2 + topic_len].decode("utf-8", errors="replace")
        qos = (header_byte >> 1) & 0x03
        offset = 2 + topic_len

        if qos > 0:
            offset += 2  # skip packet identifier

        message = payload[offset:]
        return topic, message, qos

    def _detect_version(self, connack_payload):
        """Infer MQTT protocol version from CONNACK structure."""
        if len(connack_payload) > 3:
            return "5.0"
        return "3.1.1"

    def _identify_broker(self, sys_data):
        """Match collected $SYS data against known broker signatures."""
        combined = " ".join(sys_data.values()).lower()
        for marker, name in self.KNOWN_BROKERS.items():
            if marker in combined:
                return name
        return "Unknown"

    def _connect_and_test(self):
        """Perform the MQTT connection handshake and return socket + metadata.

        Returns:
            tuple: (socket, version_string, return_code) or (None, None, None).
        """
        host = self.target
        port_num = int(self.port)
        scheme = "TLS" if self.use_tls else "plaintext"

        print_status(f"Connecting to {host}:{port_num} ({scheme})...")

        try:
            sock = self._create_socket()
            sock.connect((host, port_num))
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            print_error(f"Connection failed: {exc}")
            return None, None, None

        connect_pkt = self._build_connect_packet()
        try:
            sock.sendall(connect_pkt)
        except OSError as exc:
            print_error(f"Failed to send CONNECT: {exc}")
            sock.close()
            return None, None, None

        ptype, payload = self._read_packet(sock)
        if ptype != self.MQTT_CONNACK or payload is None:
            print_error("Did not receive a valid CONNACK response")
            sock.close()
            return None, None, None

        if len(payload) < 2:
            print_error("CONNACK payload too short")
            sock.close()
            return None, None, None

        return_code = payload[1]
        version = self._detect_version(payload)

        return sock, version, return_code

    def _collect_messages(self, sock):
        """Subscribe to '#' and collect messages for the configured duration.

        Returns:
            tuple: (list of message dicts, dict of $SYS key-value pairs)
        """
        sub_pkt = self._build_subscribe_packet("#", packet_id=1)
        try:
            sock.sendall(sub_pkt)
        except OSError as exc:
            print_error(f"Failed to send SUBSCRIBE: {exc}")
            return [], {}

        ptype, _ = self._read_packet(sock)
        if ptype != self.MQTT_SUBACK:
            print_warning("Did not receive SUBACK; subscription may have failed")

        messages = []
        sys_data = {}
        seen_topics = set()

        print_status(
            f"Listening for messages on '#' for {self.listen_duration}s..."
        )

        deadline = time.time() + int(self.listen_duration)
        sock.settimeout(1.0)

        while time.time() < deadline:
            ptype, payload = self._read_packet(sock)
            if ptype is None:
                continue

            if ptype == self.MQTT_PUBLISH and payload:
                topic, msg_bytes, qos = self._parse_publish(payload)
                if topic is None:
                    continue

                preview = msg_bytes[:120].decode("utf-8", errors="replace") if msg_bytes else ""

                if topic.startswith("$SYS/"):
                    sys_data[topic] = preview

                if topic not in seen_topics:
                    seen_topics.add(topic)
                    messages.append({
                        "topic": topic,
                        "qos": str(qos),
                        "payload_preview": preview,
                        "payload_size": str(len(msg_bytes)),
                    })

        return messages, sys_data

    def _disconnect(self, sock):
        """Send DISCONNECT and close the socket."""
        try:
            sock.sendall(self._build_disconnect_packet())
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def check(self):
        """Check whether the MQTT broker allows anonymous connections.

        Returns:
            bool: True if the broker accepted connection without credentials.
        """
        sock, version, rc = self._connect_and_test()
        if sock is None:
            return False

        self._disconnect(sock)

        if rc == self.CONNACK_ACCEPTED:
            print_success(
                f"MQTT broker at {self.target}:{self.port} accepts "
                f"anonymous connections (MQTT {version})"
            )
            return True

        print_info(
            f"MQTT broker rejected anonymous connection (return code 0x{rc:02X})"
        )
        return False

    def run(self):
        """Connect, subscribe, collect messages, and display results."""
        sock, version, rc = self._connect_and_test()
        if sock is None:
            return

        if rc != self.CONNACK_ACCEPTED:
            print_warning(
                f"Broker rejected anonymous connection (code 0x{rc:02X}). "
                "Authentication is required."
            )
            self._disconnect(sock)
            return

        print_success(
            f"Anonymous access confirmed on {self.target}:{self.port} "
            f"(MQTT {version})"
        )

        messages, sys_data = self._collect_messages(sock)
        self._disconnect(sock)

        broker_name = self._identify_broker(sys_data) if sys_data else "Unknown"

        print_info(f"Detected broker software: {broker_name}")
        print_info(f"Protocol version: MQTT {version}")
        print_info(f"Connection mode: {'TLS' if self.use_tls else 'Plaintext'}")

        if sys_data:
            print_info("$SYS topic data collected:")
            sys_table = []
            for topic, value in sorted(sys_data.items()):
                sys_table.append([topic, value])
            print_table(["$SYS Topic", "Value"], *sys_table)

        if messages:
            print_success(f"Discovered {len(messages)} unique topic(s):")
            rows = []
            for m in messages:
                rows.append([
                    m["topic"],
                    m["qos"],
                    m["payload_size"],
                    m["payload_preview"][:64],
                ])
            print_table(
                ["Topic", "QoS", "Size (bytes)", "Payload Preview"],
                *rows,
            )
        else:
            print_warning(
                "No messages received during the listening window. "
                "The broker may have no active publishers."
            )

        print_status("Scan complete.")
