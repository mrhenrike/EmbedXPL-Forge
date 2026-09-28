# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Roku ECP Discovery Scanner — SSDP + port 8060 HTTP probe.

Discovers Roku devices on the local network via SSDP multicast
and direct HTTP probe to identify models and firmware versions.

Version: 1.0.0
"""

import socket
import struct
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit
from embedxpl.core.http.http_client import HTTPClient

_SSDP_ADDR = "239.255.255.250"
_SSDP_PORT = 1900
_SSDP_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 3\r\n"
    "ST: roku:ecp\r\n"
    "\r\n"
)


class Exploit(HTTPClient):
    """Roku ECP Device Discovery — SSDP + HTTP probe.

    Discovers Roku devices via SSDP multicast (ST: roku:ecp) and
    probes port 8060 /query/device-info for model and firmware details.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Roku ECP Discovery Scanner",
        "description": (
            "Discovers Roku devices on LAN via SSDP multicast (roku:ecp) and "
            "probes port 8060 HTTP ECP endpoint for device fingerprint."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://developer.roku.com/docs/developer-program/dev-tools/external-control-api.md",
        ),
        "devices": ("Roku", "TCL Roku TV", "Hisense Roku TV"),
    }

    target = OptIP("239.255.255.250", "Target IP (use broadcast or specific Roku IP)")
    port = OptPort(8060, "Roku ECP HTTP port")
    timeout = OptInteger(3, "SSDP wait timeout (seconds)")

    def run(self) -> None:
        print_status("Sending SSDP M-SEARCH for roku:ecp to {}...".format(_SSDP_ADDR))
        discovered = []

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(self.timeout)
            sock.sendto(_SSDP_SEARCH.encode(), (_SSDP_ADDR, _SSDP_PORT))
            while True:
                try:
                    data, addr = sock.recvfrom(1024)
                    ip = addr[0]
                    if ip not in discovered:
                        discovered.append(ip)
                        print_success("Roku found via SSDP: {}".format(ip))
                except socket.timeout:
                    break
        except Exception as e:
            print_error("SSDP probe error: {}".format(e))
        finally:
            try:
                sock.close()
            except Exception:
                pass

        # Also probe the specific target if given
        probe_ips = discovered if discovered else [self.target]
        if self.target not in ["239.255.255.250", ""] and self.target not in probe_ips:
            probe_ips.append(self.target)

        for ip in probe_ips:
            self._probe_ecp(ip)

    def _probe_ecp(self, ip: str) -> None:
        """Probe ECP /query/device-info on the given IP.

        Args:
            ip: IPv4 address of the Roku device.
        """
        try:
            resp = self.http_request(
                method="GET",
                path="/query/device-info",
                timeout=3,
            )
            if resp and resp.status_code == 200:
                text = resp.text[:500] if resp.text else ""
                serial = self._extract_xml_tag(text, "serial-number")
                model = self._extract_xml_tag(text, "model-name")
                sw_ver = self._extract_xml_tag(text, "software-version")
                print_success(
                    "ECP OK [{}:{}] model={} serial={} sw={}".format(
                        ip, self.port, model, serial, sw_ver
                    )
                )
            else:
                print_error("ECP probe failed on {}: HTTP {}".format(
                    ip, resp.status_code if resp else "no response"
                ))
        except Exception as e:
            print_error("ECP probe error on {}: {}".format(ip, e))

    @staticmethod
    def _extract_xml_tag(text: str, tag: str) -> str:
        """Extract text content of an XML tag.

        Args:
            text: XML string to search.
            tag: Tag name to find.

        Returns:
            Tag content or empty string.
        """
        start = text.find("<{}>".format(tag))
        end = text.find("</{}>".format(tag))
        if start != -1 and end != -1:
            return text[start + len(tag) + 2:end].strip()
        return ""

    @mute
    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/query/device-info", timeout=3)
        return resp is not None and resp.status_code == 200
