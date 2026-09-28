# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""UPnP/SSDP Device Discovery Scanner.

Discovers UPnP devices via SSDP M-SEARCH multicast, fetches device
description XML, and checks for Internet Gateway Device (IGD) profiles.

References:
  - UPnP Device Architecture 2.0
  - RFC 2616 (HTTP/1.1)

Version: 1.0.0
"""

import re
import socket
import time
from urllib.parse import urlparse
from xml.etree import ElementTree

from embedxpl.core.exploit import *


_SSDP_ADDR = "239.255.255.250"
_SSDP_PORT = 1900

_MSEARCH_ALL = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)

_NS_DEVICE = "urn:schemas-upnp-org:device-1-0"
_IGD_TYPES = (
    "urn:schemas-upnp-org:device:InternetGatewayDevice:",
    "urn:schemas-upnp-org:device:WANConnectionDevice:",
    "urn:schemas-upnp-org:service:WANIPConnection:",
    "urn:schemas-upnp-org:service:WANPPPConnection:",
)


class Exploit(Exploit):
    """UPnP/SSDP Device Discovery Scanner.

    Sends SSDP M-SEARCH requests on UDP/1900, collects device responses,
    fetches description XML, and checks for IGD exposure.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "UPnP/SSDP Device Discovery Scanner",
        "description": (
            "Discovers UPnP devices via SSDP M-SEARCH multicast on UDP/1900. "
            "Fetches device description XML to extract model, manufacturer, and "
            "service list. Detects Internet Gateway Device (IGD) profiles."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0.pdf",
        ),
        "devices": ("UPnP Devices", "Routers", "Smart TVs", "Media Servers", "IoT Gateways"),
        "severity": "info",
        "mitre": ["T0846"],
        "status": "confirmed",
    }

    target = OptIP("", "Target IP (or broadcast range source interface)")
    port = OptPort(1900, "SSDP multicast port")
    timeout = OptInteger(5, "Discovery listen timeout in seconds")
    fetch_desc = OptBool(True, "Fetch device description XML")

    def _send_msearch(self) -> list:
        """Send M-SEARCH and collect unique SSDP responses."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(float(self.timeout))

        if self.target:
            sock.sendto(_MSEARCH_ALL.encode(), (_SSDP_ADDR, _SSDP_PORT))
        else:
            sock.sendto(_MSEARCH_ALL.encode(), (_SSDP_ADDR, _SSDP_PORT))

        responses = []
        seen_locations = set()
        deadline = time.time() + float(self.timeout)
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                text = data.decode("utf-8", errors="replace")
                location = self._extract_header(text, "LOCATION")
                if location and location not in seen_locations:
                    seen_locations.add(location)
                    responses.append({
                        "addr": addr[0],
                        "location": location,
                        "server": self._extract_header(text, "SERVER"),
                        "st": self._extract_header(text, "ST"),
                        "usn": self._extract_header(text, "USN"),
                    })
            except socket.timeout:
                break
            except (socket.error, OSError):
                break
        sock.close()
        return responses

    def _extract_header(self, response: str, header: str) -> str:
        """Extract HTTP-style header value from SSDP response."""
        pattern = re.compile(
            r"^{}\s*:\s*(.+?)\s*$".format(re.escape(header)),
            re.IGNORECASE | re.MULTILINE,
        )
        match = pattern.search(response)
        return match.group(1) if match else ""

    def _fetch_description(self, location: str) -> dict:
        """Fetch and parse UPnP device description XML."""
        result = {"friendly_name": "", "manufacturer": "", "model": "",
                  "device_type": "", "services": [], "igd": False}
        try:
            parsed = urlparse(location)
            host = parsed.hostname
            port = parsed.port or 80
            path = parsed.path or "/"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(self.timeout))
            sock.connect((host, port))
            request = "GET {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n".format(
                path, host, port
            )
            sock.sendall(request.encode())
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:
                    break
            sock.close()

            body = data.split(b"\r\n\r\n", 1)
            if len(body) < 2:
                return result
            xml_data = body[1]
            root = ElementTree.fromstring(xml_data)

            ns = {"d": _NS_DEVICE}
            device = root.find(".//d:device", ns)
            if device is not None:
                fn = device.find("d:friendlyName", ns)
                result["friendly_name"] = fn.text if fn is not None and fn.text else ""
                mf = device.find("d:manufacturer", ns)
                result["manufacturer"] = mf.text if mf is not None and mf.text else ""
                md = device.find("d:modelName", ns)
                result["model"] = md.text if md is not None and md.text else ""
                dt = device.find("d:deviceType", ns)
                result["device_type"] = dt.text if dt is not None and dt.text else ""

                for svc in device.iter():
                    tag = svc.tag.split("}")[-1] if "}" in svc.tag else svc.tag
                    if tag == "serviceType" and svc.text:
                        result["services"].append(svc.text)

            full_text = xml_data.decode("utf-8", errors="replace")
            for igd_type in _IGD_TYPES:
                if igd_type in full_text:
                    result["igd"] = True
                    break

        except (socket.error, OSError, ElementTree.ParseError, ValueError):
            pass
        return result

    @mute
    def check(self) -> bool:
        """Check if SSDP multicast gets at least one response."""
        responses = self._send_msearch()
        return len(responses) > 0

    @multi
    def run(self) -> None:
        """Execute UPnP/SSDP discovery scan."""
        print_status("Sending SSDP M-SEARCH on {}:{}".format(_SSDP_ADDR, self.port))

        responses = self._send_msearch()
        if not responses:
            print_error("No UPnP devices responded")
            return

        print_success("Discovered {} UPnP device(s)".format(len(responses)))
        igd_found = False

        for resp in responses:
            print_info("Device: {} (Server: {})".format(resp["addr"], resp["server"]))
            print_info("  Location: {}".format(resp["location"]))
            print_info("  ST: {}".format(resp["st"]))

            if self.fetch_desc and resp["location"]:
                desc = self._fetch_description(resp["location"])
                if desc["friendly_name"]:
                    print_info("  Name: {}".format(desc["friendly_name"]))
                if desc["manufacturer"]:
                    print_info("  Manufacturer: {}".format(desc["manufacturer"]))
                if desc["model"]:
                    print_info("  Model: {}".format(desc["model"]))
                if desc["services"]:
                    print_info("  Services ({})".format(len(desc["services"])))
                    for svc in desc["services"][:10]:
                        print_info("    {}".format(svc))
                if desc["igd"]:
                    igd_found = True
                    print_warning("  IGD profile detected, external port mapping possible")

        if igd_found:
            print_warning("IGD-capable device(s) found; check for open port mappings")
        else:
            print_info("No IGD profiles detected")
