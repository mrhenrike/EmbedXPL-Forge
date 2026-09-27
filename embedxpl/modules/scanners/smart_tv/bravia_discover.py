# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Sony Bravia Smart TV Discovery Scanner.

Probes port 80/443 for the Sony Bravia REST API system-info endpoint
(/sony/system) using the default pre-shared key (X-Auth-PSK: 0000).
Also probes the Photo Sharing Plus service endpoint. Extracts model,
firmware version, and IP information from JSON responses.

CVE: N/A
CVSS: N/A
Version: 1.0.0
"""
import json
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_SYSTEM_PATHS = ("/sony/system", "/sony/guide", "/sony/avContent")
_PHOTO_SHARING_PATHS = ("/photo-share/", "/photo-share/status", "/photo-share/api/version")
_PROBE_PORTS = (80, 443)
_DEFAULT_PSK = "0000"

_SYSTEM_INFO_BODY = json.dumps({
    "method": "getSystemInformation",
    "params": [],
    "id": 1,
    "version": "1.0",
}).encode("utf-8")

_SONY_INDICATORS = (
    "sony",
    "bravia",
    "X-Sony",
    "Android TV",
    "generation",
    "model",
    "firmwareVersion",
    '"product"',
)

_DEVICE_FIELDS = (
    "model", "modelNumber", "modelName",
    "generation", "area", "language",
    "macAddr", "wirelessMacAddr",
)


def _is_bravia_response(body: str, headers: str) -> bool:
    """Determine whether a response originates from a Sony Bravia device.

    Args:
        body: HTTP response body text.
        headers: HTTP response headers as a string.

    Returns:
        True if Sony/Bravia indicators are present.
    """
    combined = (body + headers).lower()
    return any(ind.lower() in combined for ind in _SONY_INDICATORS)


def _extract_system_info(body: str) -> Optional[dict]:
    """Parse a Sony REST API JSON response for device information fields.

    Args:
        body: HTTP response body text.

    Returns:
        Dict of device fields if the response is a valid Bravia API payload,
        None otherwise.
    """
    try:
        data = json.loads(body)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    result_list = data.get("result", [])
    if not isinstance(result_list, list) or not result_list:
        return None
    device_data = result_list[0] if isinstance(result_list[0], dict) else {}
    if not device_data:
        return None
    return {k: device_data.get(k, "N/A") for k in _DEVICE_FIELDS}


class Exploit(HTTPClient):
    """Sony Bravia Smart TV Discovery Scanner.

    Queries the Sony Bravia REST API on port 80/443 via the /sony/system
    endpoint with the default PSK (0000) to retrieve device model, firmware
    version, and MAC address. Also probes the Photo Sharing Plus service.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Sony Bravia Smart TV Discovery",
        "description": (
            "Queries Sony Bravia REST API at /sony/system on ports 80/443 using "
            "the default pre-shared key (X-Auth-PSK: 0000) to enumerate device "
            "model, firmware version, and network identifiers. Also probes the "
            "Photo Sharing Plus service."
        ),
        "authors": (
            "André Henrique (@mrhenrike) - EmbedXPL-Forge port",
        ),
        "references": (
            "https://pro-bravia.sony.net/develop/integrate/rest-api/",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16593",
        ),
        "devices": ("Sony Bravia",),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(80, "Target HTTP port (80 or 443)")
    psk = OptString(_DEFAULT_PSK, "Pre-shared key (default: 0000)")
    timeout = OptInteger(8, "HTTP request timeout (seconds)")

    def run(self) -> None:
        """Execute the Sony Bravia discovery scan."""
        print_status(
            "Discovering Sony Bravia TV at {}".format(self.target)
        )
        found = False

        for probe_port in _PROBE_PORTS:
            for path in _SYSTEM_PATHS:
                info = self._query_system_api(probe_port, path)
                if info:
                    found = True
                    print_success(
                        "Sony Bravia REST API at {}:{}{}".format(
                            self.target, probe_port, path
                        )
                    )
                    for field, value in info.items():
                        if value != "N/A":
                            print_status("  {:22s}: {}".format(field, value))
                    break

        for probe_port in _PROBE_PORTS:
            for path in _PHOTO_SHARING_PATHS:
                resp_info = self._probe_path(probe_port, path)
                if resp_info:
                    found = True
                    print_success(
                        "Photo Sharing Plus service at {}:{}{}".format(
                            self.target, probe_port, path
                        )
                    )
                    break

        if not found:
            print_error(
                "No Sony Bravia services detected on {}".format(self.target)
            )

    def _query_system_api(self, probe_port: int, path: str) -> Optional[dict]:
        """POST a system-info request to the Bravia REST API.

        Args:
            probe_port: TCP port to connect to.
            path: URL path to the API endpoint.

        Returns:
            Dict of device info fields if successful, None otherwise.
        """
        original_port = self.port
        self.port = probe_port
        try:
            resp = self.http_request(
                "POST",
                path,
                data=_SYSTEM_INFO_BODY,
                headers={
                    "Content-Type": "application/json",
                    "X-Auth-PSK": str(self.psk),
                    "User-Agent": "EmbedXPL-Forge/1.0",
                },
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
        return _extract_system_info(body)

    def _probe_path(self, probe_port: int, path: str) -> Optional[str]:
        """Perform a GET probe to a given port/path combination.

        Args:
            probe_port: TCP port to connect to.
            path: URL path to request.

        Returns:
            Response body excerpt if the path responds, None otherwise.
        """
        original_port = self.port
        self.port = probe_port
        try:
            resp = self.http_request(
                "GET",
                path,
                headers={
                    "X-Auth-PSK": str(self.psk),
                    "User-Agent": "EmbedXPL-Forge/1.0",
                },
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
        if status in (200, 301, 302) and (body or status in (301, 302)):
            return body[:100] or "(empty 3xx)"
        return None

    @mute
    def check(self) -> bool:
        """Check if a Sony Bravia REST API or Photo Sharing endpoint is reachable.

        Returns:
            True if at least one Bravia service responds.
        """
        for probe_port in _PROBE_PORTS:
            for path in _SYSTEM_PATHS:
                if self._query_system_api(probe_port, path) is not None:
                    return True
            for path in _PHOTO_SHARING_PATHS:
                if self._probe_path(probe_port, path) is not None:
                    return True
        return False
