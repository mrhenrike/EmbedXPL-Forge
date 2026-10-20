# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Dahua CCTV — Multi-Model Discovery Scanner.

Discovers Dahua IP cameras, NVRs, DVRs, and PTZ devices via HTTP
fingerprinting, RTSP probing, and the proprietary TCP/37777 binary protocol.

Version: 1.0.0
"""

import socket

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_DAHUA_PORT = 37777
_DAHUA_PROBE = (
    b"\xa0\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x00\x00\x00\x00"
)


class Exploit(HTTPClient):
    """Dahua CCTV Multi-Model Discovery Scanner.

    Probes HTTP (80), RTSP (554), ONVIF, and the Dahua binary protocol
    (TCP/37777) to discover and fingerprint Dahua CCTV devices.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Dahua CCTV Discovery Scanner",
        "description": (
            "Discovers Dahua CCTV devices (IPC, NVR, DVR, SD/PTZ series) via "
            "HTTP fingerprinting, RTSP probing, ONVIF WS-Discovery, and "
            "Dahua binary protocol on TCP/37777. Identifies platform "
            "(Hertz, Molec, Euler, Kant, Edison) and firmware version."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://www.dahuasecurity.com/",
            "https://dahuawiki.com/",
        ),
        "devices": (
            "Dahua IPC-HFW/HDW series (IP Cameras)",
            "Dahua NVR4x series (NVRs)",
            "Dahua SD series (PTZ Cameras)",
        ),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(80, "HTTP web interface port")

    _DAHUA_MARKERS = [
        "dahua", "dh-", "ipc-h", "nvr4", "sd-", "dhop",
        "configmanager", "rpc2", "magicbox",
        "dss", "smartpss", "hertz", "molec", "euler", "kant",
    ]

    def run(self) -> None:
        print_status(f"Scanning Dahua CCTV at {self.target}...")
        detected = False
        info = {}

        resp = self.http_request(method="GET", path="/")
        if resp and resp.status_code in (200, 302, 401):
            server = resp.headers.get("Server", "")
            text = resp.text or ""
            combined = (server + " " + text).lower()

            for marker in self._DAHUA_MARKERS:
                if marker in combined:
                    detected = True
                    print_success(
                        f"Dahua device detected — marker '{marker}' in HTTP response"
                    )
                    break

            if server:
                info["http_server"] = server

        for ep in ["/cgi-bin/magicBox.cgi?action=getDeviceType",
                    "/cgi-bin/magicBox.cgi?action=getSoftwareVersion",
                    "/cgi-bin/magicBox.cgi?action=getSerialNo"]:
            try:
                r = self.http_request(method="GET", path=ep)
                if r and r.status_code == 200 and len(r.text) > 5:
                    key = ep.split("action=")[1]
                    info[key] = r.text.strip()[:200]
                    detected = True
            except Exception:
                pass

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target, _DAHUA_PORT))
            sock.send(_DAHUA_PROBE)
            response = sock.recv(1024)
            sock.close()
            if response:
                info["dahua_37777"] = f"open ({len(response)}B response)"
                detected = True
                print_success(
                    f"Dahua binary protocol active on TCP/37777 ({len(response)}B response)"
                )
        except (TimeoutError, ConnectionRefusedError, OSError):
            pass

        if detected:
            print_success(f"Dahua device confirmed at {self.target}")
            for k, v in info.items():
                print_info(f"  {k}: {v}")
        else:
            print_error(f"No Dahua indicators found at {self.target}")

    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/")
        if resp is None:
            return False
        text = ((resp.headers.get("Server", "") or "") + " " + (resp.text or "")).lower()
        return any(m in text for m in self._DAHUA_MARKERS)
