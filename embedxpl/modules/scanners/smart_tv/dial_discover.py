# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""DIAL Device Discovery via UPnP/SSDP M-SEARCH.

Sends an SSDP M-SEARCH multicast for the DIAL service type
``urn:dial-multiscreen-org:service:dial:1`` and probes responding
devices for the DIAL app-list endpoint to fingerprint device type.

CVE: N/A
CVSS: N/A
Version: 1.0.0
"""

import socket
from typing import List, Tuple

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_SSDP_ADDR = "239.255.255.250"
_SSDP_PORT = 1900
_DIAL_ST   = "urn:dial-multiscreen-org:service:dial:1"

_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: {}:{}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 3\r\n"
    "ST: {}\r\n"
    "\r\n"
).format(_SSDP_ADDR, _SSDP_PORT, _DIAL_ST)

_DIAL_APP_PATHS = ("/apps/", "/dial/apps/", "/upnp/dial/apps/")

# Known DIAL device fingerprints (string → device type)
_FINGERPRINTS = {
    "roku":         "Roku",
    "samsung":      "Samsung Smart TV",
    "amzn":         "Amazon Fire TV",
    "amazon":       "Amazon Fire TV",
    "playstation":  "PlayStation",
    "xbox":         "Xbox",
    "netflix":      "Netflix-capable device",
    "youtube":      "YouTube-capable device",
    "lg":           "LG Smart TV",
    "philips":      "Philips Smart TV",
    "hisense":      "Hisense Smart TV",
}


class Exploit(BaseExploit):
    """DIAL Device Discovery via SSDP M-SEARCH.

    Broadcasts an SSDP M-SEARCH for ``urn:dial-multiscreen-org:service:dial:1``
    on UDP port 1900, collects responding device IPs and LOCATION URLs, then
    probes each discovered device for the DIAL app list to fingerprint the
    device manufacturer and type.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "DIAL Device Discovery via SSDP",
        "description": (
            "Sends SSDP M-SEARCH for the DIAL multiscreen service type and "
            "probes responding devices for the DIAL app-list endpoint to "
            "fingerprint device manufacturer and model."
        ),
        "authors": (
            "DIAL Specification Group",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "references": (
            "http://www.dial-multiscreen.org/dial-protocol-specification",
            "https://github.com/nickstenning/dial",
        ),
        "devices": (
            "Samsung", "LG", "Roku", "Fire TV",
            "Xbox", "PlayStation", "Philips",
        ),
    }

    target  = OptIP(_SSDP_ADDR, "SSDP multicast address (or specific target IP)")
    port    = OptPort(_SSDP_PORT, "SSDP UDP port (default 1900)")
    timeout = OptInteger(5, "SSDP discovery wait timeout (seconds)")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ssdp_discover(self) -> List[Tuple[str, str]]:
        """Send M-SEARCH and collect (ip, location_url) pairs from responses.

        Returns:
            List of tuples containing (source_ip, LOCATION header value).
        """
        found: List[Tuple[str, str]] = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(float(self.timeout))
            sock.sendto(_MSEARCH.encode(), (str(self.target), int(self.port)))
            seen = set()
            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip   = addr[0]
                    text = data.decode(errors="replace")
                    loc  = ""
                    for line in text.splitlines():
                        if line.lower().startswith("location:"):
                            loc = line.split(":", 1)[1].strip()
                            break
                    key = (ip, loc)
                    if key not in seen:
                        seen.add(key)
                        found.append(key)
                        print_success("DIAL device at {} — LOCATION: {}".format(ip, loc or "N/A"))
                except socket.timeout:
                    break
        except OSError as exc:
            print_error("SSDP socket error: {}".format(exc))
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return found

    def _probe_dial_apps(self, ip: str, port: int) -> None:
        """Fetch the DIAL app-list endpoint on the discovered device.

        Args:
            ip:   IPv4 address of the discovered device.
            port: HTTP port to probe (parsed from LOCATION URL or default 8008).
        """
        import urllib.request
        for path in _DIAL_APP_PATHS:
            url = "http://{}:{}{}".format(ip, port, path)
            try:
                with urllib.request.urlopen(url, timeout=5) as resp:
                    body = resp.read(2000).decode(errors="replace")
                    device_type = "Unknown"
                    for marker, label in _FINGERPRINTS.items():
                        if marker.lower() in body.lower():
                            device_type = label
                            break
                    print_success(
                        "DIAL app list at {} — Device: {} — Preview: {}".format(
                            url, device_type, body[:200]
                        )
                    )
                    return
            except Exception:
                continue

    def _parse_location_port(self, loc: str) -> int:
        """Extract the port number from a LOCATION URL.

        Args:
            loc: Full LOCATION URL string.

        Returns:
            Port integer, defaulting to 8008 if not present.
        """
        try:
            from urllib.parse import urlparse
            parsed = urlparse(loc)
            return parsed.port or 8008
        except Exception:
            return 8008

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Discover DIAL devices via SSDP and probe their app lists.

        Broadcasts M-SEARCH, collects responding devices, then probes
        each for the DIAL app-list endpoint to fingerprint the device.
        """
        print_status(
            "Sending SSDP M-SEARCH for DIAL to {} (timeout {}s)...".format(
                self.target, self.timeout
            )
        )
        devices = self._ssdp_discover()

        if not devices:
            print_error("No DIAL devices found via SSDP.")
            return

        print_success("Found {} DIAL device(s). Probing app lists...".format(len(devices)))
        for ip, loc in devices:
            dial_port = self._parse_location_port(loc) if loc else 8008
            self._probe_dial_apps(ip, dial_port)

    @mute
    def check(self) -> bool:
        """Check whether any DIAL device responds to the M-SEARCH.

        Returns:
            True if at least one SSDP response is received.
        """
        return len(self._ssdp_discover()) > 0
