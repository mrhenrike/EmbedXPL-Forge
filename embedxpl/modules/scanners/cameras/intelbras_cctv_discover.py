# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Intelbras CCTV — Multi-Model Discovery Scanner.

Discovers Intelbras CCTV devices (IP cameras, DVRs, NVRs) via HTTP banner
fingerprinting. Identifies Dahua OEM heritage through protocol probing.

Version: 1.0.0
"""

import socket
import struct

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_DAHUA_PORT = 37777
_DAHUA_MAGIC = b"\xff\x00\x00\x96"
_DAHUA_PROBE = (
    b"\xff\x00\x00\x96"
    b"\x00\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x58\x00\x00\x00"
    b"\x00\x00\x00\x00"
)


class Exploit(HTTPClient):
    """Intelbras CCTV Multi-Model Discovery Scanner.

    Probes HTTP (80/8080), RTSP (554), and Dahua binary protocol (37777)
    to discover and fingerprint Intelbras CCTV devices across all lines.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Intelbras CCTV Discovery Scanner",
        "description": (
            "Discovers Intelbras CCTV devices (VIP, MHDX, NVD series) via HTTP "
            "banner fingerprinting, RTSP probing, and Dahua binary protocol on "
            "TCP/37777. Identifies model family, firmware indicators, and OEM origin."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://www.intelbras.com/",
            "https://www.intelbras.com/en/coordinated-vulnerability-disclosure-policy-intelbras",
        ),
        "devices": (
            "Intelbras VIP series (IP Cameras)",
            "Intelbras MHDX series (DVRs)",
            "Intelbras NVD series (NVRs)",
        ),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(80, "HTTP web interface port")

    _INTELBRAS_MARKERS = [
        "intelbras", "mhdx", "nvd ", "vip ", "pvip", "iMHDX", "iNVD",
        "dahua", "dh-", "dvr", "nvr", "ipc-",
    ]

    def run(self) -> None:
        print_status("Scanning Intelbras CCTV at {}...".format(self.target))
        detected = False

        resp = self.http_request(method="GET", path="/")
        if resp and resp.status_code in (200, 302, 401):
            server = resp.headers.get("Server", "")
            text = resp.text or ""
            combined = (server + " " + text).lower()

            for marker in self._INTELBRAS_MARKERS:
                if marker in combined:
                    detected = True
                    print_success(
                        "Intelbras/Dahua OEM detected — marker '{}' in response".format(marker)
                    )
                    break

            if server:
                print_status("Server header: {}".format(server))

            if resp.status_code == 401:
                realm = resp.headers.get("WWW-Authenticate", "")
                if realm:
                    print_status("Auth realm: {}".format(realm))
                    if any(m in realm.lower() for m in self._INTELBRAS_MARKERS):
                        detected = True
                        print_success("Intelbras identified via auth realm")

        try:
            sock = socket.create_connection((self.target, _DAHUA_PORT), timeout=5)
            sock.sendall(_DAHUA_PROBE)
            header = sock.recv(20)
            if len(header) >= 4 and header[:4] == _DAHUA_MAGIC:
                detected = True
                print_success(
                    "Dahua protocol confirmed on port {} (Intelbras OEM)".format(
                        _DAHUA_PORT
                    )
                )
                payload_len = struct.unpack("<I", header[16:20])[0] if len(header) >= 20 else 0
                if payload_len:
                    payload = sock.recv(min(payload_len, 4096))
                    text = payload.decode("utf-8", errors="replace")
                    if "DeviceType" in text:
                        import re
                        m = re.search(r'"DeviceType"\s*:\s*"([^"]+)"', text)
                        if m:
                            print_success("Device type: {}".format(m.group(1)))
            sock.close()
        except Exception:
            print_status("Dahua protocol port {} not responding".format(_DAHUA_PORT))

        try:
            rtsp_sock = socket.create_connection((self.target, 554), timeout=3)
            rtsp_req = (
                "OPTIONS rtsp://{}:554/ RTSP/1.0\r\n"
                "CSeq: 1\r\n\r\n"
            ).format(self.target)
            rtsp_sock.sendall(rtsp_req.encode())
            rtsp_resp = rtsp_sock.recv(1024).decode("utf-8", errors="replace")
            if "RTSP" in rtsp_resp:
                detected = True
                print_success("RTSP service on port 554")
            rtsp_sock.close()
        except Exception:
            pass

        if not detected:
            print_error("No Intelbras CCTV device identified at {}".format(self.target))

    @mute
    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/")
        return resp is not None and resp.status_code in (200, 302, 401)
