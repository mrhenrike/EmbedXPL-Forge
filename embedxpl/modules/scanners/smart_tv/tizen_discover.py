# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Samsung Tizen Smart TV Discovery Scanner.

Probes ports 8001 and 8002 for the Samsung Tizen REST API device-info endpoint
(/api/v2/) and extracts device model, firmware version, year class, and IP
information from the JSON response. Also performs a lightweight AllShare/DLNA
UDP probe on port 55000, and SSDP multicast discovery.

Research: TIZEN-2026-001 — Missing authentication on Smart Hub API (CVSSv3.1 9.8)
CVE: N/A (pending Samsung PSIRT — report date 2026-04-21)
CVSS: 9.8
Version: 2.0.0
"""
import json
import socket
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_API_PATHS = ("/api/v2/", "/api/v2")
_API_PORTS = (8001, 8002)
_ALLSHARE_PORT = 55000
_ALLSHARE_PROBE = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: ssdp:discover\r\nST: ssdp:all\r\nMX: 1\r\n\r\n"

_DEVICE_FIELDS = (
    "name", "modelName", "id", "wifiMac", "ip",
    "firmwareVersion", "year", "resolution",
)


def _udp_allshare_probe(host: str, timeout: float = 2.0) -> bool:
    """Send an SSDP/AllShare UDP probe to port 55000.

    Args:
        host: Target IP address.
        timeout: Socket receive timeout in seconds.

    Returns:
        True if any response is received.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_ALLSHARE_PROBE, (host, _ALLSHARE_PORT))
        data, _ = sock.recvfrom(1024)
        sock.close()
        return bool(data)
    except Exception:
        return False


def _extract_device_info(body: str) -> Optional[dict]:
    """Parse the Tizen REST API JSON response for device info fields.

    Args:
        body: HTTP response body text.

    Returns:
        Dict of device fields if the response is a valid Tizen API payload,
        None otherwise.
    """
    try:
        data = json.loads(body)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if not any(k in data for k in ("id", "modelName", "name", "ip")):
        return None
    return {k: data.get(k, "N/A") for k in _DEVICE_FIELDS}


class Exploit(HTTPClient):
    """Samsung Tizen Smart TV Discovery Scanner.

    Queries the Samsung Tizen REST API on ports 8001 and 8002 to enumerate
    device information including model name, firmware version, year class, IP,
    and Wi-Fi MAC address. Also probes port 55000 UDP for AllShare/DLNA
    service availability.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Samsung Tizen Smart TV Discovery",
        "description": (
            "Queries the Samsung Tizen REST API at /api/v2/ on ports 8001/8002 "
            "to extract device model, firmware version, year class, and network "
            "identifiers. Unauthenticated access confirmed as TIZEN-2026-001 "
            "(CVSSv3.1 9.8 CRITICAL). Also probes AllShare/DLNA on UDP 55000."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
        ),
        "references": (
            "https://developer.samsung.com/smarttv/develop/",
            "TIZEN-2026-001: https://github.com/Uniao-Geek/Embedded-Firmware-Research",
        ),
        "devices": ("Samsung Smart TV (Tizen 4.x–6.x)",),
        "vuln_ids": ("TIZEN-2026-001",),
        "cvss":    "9.8",
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(8001, "Tizen REST API port (8001 or 8002)")
    timeout = OptInteger(6, "HTTP request timeout (seconds)")

    def run(self) -> None:
        """Execute the Tizen device-info discovery scan."""
        print_status(
            "Discovering Samsung Tizen TV at {}".format(self.target)
        )
        found = False

        for api_port in _API_PORTS:
            for path in _API_PATHS:
                info = self._query_api(api_port, path)
                if info:
                    found = True
                    print_success(
                        "Tizen REST API found at {}:{}{}".format(
                            self.target, api_port, path
                        )
                    )
                    for field, value in info.items():
                        if value != "N/A":
                            print_status("  {:20s}: {}".format(field, value))
                    break

        if _udp_allshare_probe(self.target, float(self.timeout)):
            found = True
            print_success(
                "AllShare/DLNA service responding on {}:{}".format(
                    self.target, _ALLSHARE_PORT
                )
            )

        if not found:
            print_error(
                "No Samsung Tizen services detected on {}".format(self.target)
            )

    def _query_api(self, api_port: int, path: str) -> Optional[dict]:
        """Query the Tizen REST API on a specific port.

        Args:
            api_port: TCP port to connect to.
            path: URL path to request.

        Returns:
            Dict of device info fields if successful, None otherwise.
        """
        original_port = self.port
        self.port = api_port
        try:
            resp = self.http_request(
                "GET",
                path,
                headers={"User-Agent": "EmbedXPL-Forge/1.0"},
                timeout=int(self.timeout),
            )
        except Exception:
            self.port = original_port
            return None
        finally:
            self.port = original_port

        if resp is None:
            return None
        status = getattr(resp, "status_code", 0)
        body = getattr(resp, "text", "") or ""
        if status != 200:
            return None
        return _extract_device_info(body)

    @mute
    def check(self) -> bool:
        """Check if a Tizen REST API endpoint is reachable.

        Returns:
            True if the API responds on any candidate port.
        """
        for api_port in _API_PORTS:
            for path in _API_PATHS:
                if self._query_api(api_port, path) is not None:
                    return True
        return False
