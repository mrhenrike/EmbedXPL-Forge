# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Simulated Mirai/Condi CnC infrastructure for EmbedXPL-Forge local lab.

Simulates three services that a real Mirai CnC runs:

1. TCP 3778 — Bot listener (CnC port decoded from Condi table.c, key 0xdeadbeef):
   Sends a binary greeting to connecting clients (simulates bot registration
   handshake from cnc/main.go / cnc/bot.go).

2. TCP 9555 — Scan-callback / loader report port:
   Accepts binary framed scan results (IP/port tuples) and logs them.
   Simulates scanListen.go behavior.

3. TCP 3306 — MySQL simulator:
   Returns a minimal MySQL v5.7 server greeting packet (protocol version 10),
   allowing banner-fingerprinting tools to detect a "Mirai C2 database".

4. HTTP 8888 — Health/admin endpoint:
   Returns JSON status for Docker healthcheck.

All services only echo/log received data -- no real botnet logic.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s"
)
logger = logging.getLogger("lab.mirai-cnc-sim")

# Mirai CnC initial bot greeting (from cnc/bot.go analysis)
# Type byte 0x00 (ping), length 1, data 0x00
_CNC_BOT_GREETING = b"\x00\x00\x00\x00\x01\x00"

# MySQL v5.7 server greeting packet (minimal, protocol version 10)
# Allows banner detectors to identify MySQL on port 3306
_MYSQL_GREETING = (
    b"\x4a\x00\x00\x00"
    b"\x0a"
    b"5.7.42-Mirai-CnC-Sim\x00"
    b"\x01\x00\x00\x00"
    b"AAAAAAAA\x00"
    b"\xff\xf7"
    b"\x21"
    b"\x02\x00"
    b"\xff\x81"
    b"\x15"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"AAAAAAAAAAAAA\x00"
    b"mysql_native_password\x00"
)

# Scan-callback binary frame: 4-byte IP + 2-byte port (big-endian)
_SCAN_FRAME_SIZE = 6


def _handle_cnc_client(conn: socket.socket, addr) -> None:
    """Handle a bot/admin connection on port 3778."""
    try:
        logger.info("[CnC-3778] Connection from %s", addr)
        conn.sendall(_CNC_BOT_GREETING)
        time.sleep(0.3)
        try:
            data = conn.recv(256)
            if data:
                logger.info("[CnC-3778] Received %d bytes from %s: %r",
                            len(data), addr, data[:64])
        except socket.timeout:
            pass
    except OSError as exc:
        logger.debug("[CnC-3778] Client %s error: %s", addr, exc)
    finally:
        conn.close()


def _handle_scan_callback_client(conn: socket.socket, addr) -> None:
    """Handle a scan-result report on port 9555."""
    try:
        logger.info("[ScanCB-9555] Connection from %s", addr)
        buf = b""
        conn.settimeout(3)
        try:
            while True:
                chunk = conn.recv(256)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        # Parse binary IP:port frames
        frames_parsed = 0
        for i in range(0, len(buf) - _SCAN_FRAME_SIZE + 1, _SCAN_FRAME_SIZE):
            ip_bytes = buf[i:i + 4]
            port_bytes = buf[i + 4:i + 6]
            if len(ip_bytes) == 4 and len(port_bytes) == 2:
                ip = ".".join(str(b) for b in ip_bytes)
                port = struct.unpack(">H", port_bytes)[0]
                logger.info("[ScanCB-9555] Scan result: %s:%d", ip, port)
                frames_parsed += 1
        if buf and not frames_parsed:
            logger.info("[ScanCB-9555] Raw data (%d bytes): %r", len(buf), buf[:64])
    except OSError as exc:
        logger.debug("[ScanCB-9555] Client %s error: %s", addr, exc)
    finally:
        conn.close()


def _handle_mysql_client(conn: socket.socket, addr) -> None:
    """Send MySQL greeting to banner-grabbing tools on port 3306."""
    try:
        logger.info("[MySQL-3306] Connection from %s", addr)
        conn.sendall(_MYSQL_GREETING)
        time.sleep(0.5)
    except OSError as exc:
        logger.debug("[MySQL-3306] Client %s error: %s", addr, exc)
    finally:
        conn.close()


def _serve_tcp(port: int, handler, name: str) -> None:
    """Generic TCP server loop."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(32)
    logger.info("[%s] Listening on TCP %d", name, port)
    while True:
        try:
            conn, addr = srv.accept()
            conn.settimeout(5)
            t = threading.Thread(target=handler, args=(conn, addr), daemon=True)
            t.start()
        except OSError:
            break


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(
            b'{"status":"ok","services":["cnc:3778","scan-cb:9555","mysql:3306"]}'
        )

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    logger.info("Starting Mirai CnC Sim -- ports 3778 (CnC), 9555 (scan-cb), 3306 (MySQL), 8888 (health)")

    for port, handler, name in [
        (3778, _handle_cnc_client, "CnC-3778"),
        (9555, _handle_scan_callback_client, "ScanCB-9555"),
        (3306, _handle_mysql_client, "MySQL-3306"),
    ]:
        t = threading.Thread(
            target=_serve_tcp, args=(port, handler, name), daemon=True
        )
        t.start()

    # Health check HTTP server (blocking main thread)
    health_srv = HTTPServer(("0.0.0.0", 8888), _HealthHandler)
    logger.info("[Health-8888] Health endpoint active")
    health_srv.serve_forever()
