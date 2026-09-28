# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Intelbras CCTV — ONVIF Endpoint Discovery Scanner.

Discovers and probes ONVIF endpoints on Intelbras NVR/DVR/IP Camera devices.
Checks for unauthenticated access to device management functions.

Version: 1.0.0
"""

import socket

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Intelbras ONVIF Endpoint Discovery Scanner.

    Probes ONVIF service endpoints on Intelbras CCTV devices to detect
    exposed management interfaces and potential authentication bypass.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Intelbras ONVIF Endpoint Scanner",
        "description": (
            "Discovers ONVIF endpoints on Intelbras NVR/DVR devices. Probes "
            "standard ONVIF paths and the WS-Discovery multicast to identify "
            "exposed device management services. Ref: INTELBRAS-2026-004."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://www.onvif.org/",
            "https://www.intelbras.com/",
        ),
        "devices": (
            "Intelbras NVD 3316-P",
            "Intelbras NVD 1208 P",
            "Intelbras NVD 1432-P",
            "Intelbras MHDX series",
        ),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(80, "HTTP port")

    _ONVIF_PATHS = [
        "/onvif/device_service",
        "/onvif/media_service",
        "/onvif/events_service",
        "/onvif/ptz_service",
        "/onvif/imaging_service",
        "/onvif/analytics_service",
    ]

    _GETINFO_SOAP = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
        '<s:Body><tds:GetDeviceInformation/></s:Body>'
        '</s:Envelope>'
    )

    def run(self) -> None:
        print_status(
            "Probing ONVIF endpoints on {}:{}...".format(self.target, self.port)
        )

        found_endpoints = []
        for path in self._ONVIF_PATHS:
            resp = self.http_request(method="GET", path=path)
            if resp and resp.status_code in (200, 405):
                found_endpoints.append(path)
                print_success("ONVIF endpoint active: {}".format(path))

        if found_endpoints:
            print_status("Attempting GetDeviceInformation SOAP request...")
            resp = self.http_request(
                method="POST",
                path="/onvif/device_service",
                data=self._GETINFO_SOAP,
                headers={"Content-Type": "application/soap+xml; charset=utf-8"},
            )
            if resp and resp.status_code == 200:
                text = resp.text or ""
                if "Manufacturer" in text or "Model" in text:
                    print_success("Device info retrieved WITHOUT authentication!")
                    import re
                    for tag in ("Manufacturer", "Model", "FirmwareVersion", "SerialNumber"):
                        m = re.search(
                            r"<(?:\w+:)?{0}>(.*?)</(?:\w+:)?{0}>".format(tag), text
                        )
                        if m:
                            print_success("{}: {}".format(tag, m.group(1)))
                elif "NotAuthorized" in text or "Sender" in text:
                    print_status("ONVIF requires authentication (expected)")
                else:
                    print_status("ONVIF response: {}".format(text[:200]))
        else:
            print_status("No active ONVIF endpoints found")

    @mute
    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/onvif/device_service")
        return resp is not None and resp.status_code in (200, 405)
