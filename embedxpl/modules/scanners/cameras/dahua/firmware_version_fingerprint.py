# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Dahua CCTV — Firmware Version Fingerprint Scanner.

Fingerprints Dahua device firmware version, platform, and SoC via
unauthenticated web endpoints and protocol probing.

Version: 1.0.0
"""

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Dahua CCTV Firmware Version Fingerprint Scanner.

    Probes unauthenticated web endpoints to extract firmware version,
    device type, serial number, and platform information.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Dahua CCTV Firmware Fingerprint",
        "description": (
            "Extracts firmware version, device type, serial number, and "
            "hardware version from Dahua devices via unauthenticated CGI "
            "endpoints (magicBox, configManager). Maps firmware version to "
            "known platform generations (Hertz, Molec, Euler, Kant, Edison)."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://dahuawiki.com/Firmware",
            "https://www.dahuasecurity.com/download-center/firmware",
        ),
        "devices": (
            "Dahua IPC-HFW/HDW series",
            "Dahua NVR4x series",
            "Dahua SD series (PTZ)",
        ),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(80, "HTTP port")

    _INFO_ENDPOINTS = [
        ("/cgi-bin/magicBox.cgi?action=getDeviceType", "device_type"),
        ("/cgi-bin/magicBox.cgi?action=getSoftwareVersion", "firmware_version"),
        ("/cgi-bin/magicBox.cgi?action=getSerialNo", "serial"),
        ("/cgi-bin/magicBox.cgi?action=getHardwareVersion", "hardware_version"),
        ("/cgi-bin/magicBox.cgi?action=getMachineName", "machine_name"),
        ("/cgi-bin/magicBox.cgi?action=getVendor", "vendor"),
    ]

    _PLATFORM_MAP = {
        "V2.6": "Edison",
        "V2.8": "Molec/Hertz/Euler/Kant",
        "V2.82": "Molec (S2/S4/S5/S6)",
        "V2.84": "Euler/Molec (S5/S6)",
        "V2.88": "Kant (Entry/S6)",
        "V4.0": "NVR (HiSilicon)",
    }

    def run(self) -> None:
        if not self.check():
            print_error("Target not responding on {}:{}".format(self.target, self.port))
            return

        print_status("Fingerprinting Dahua device at {}...".format(self.target))
        info = {}

        for path, label in self._INFO_ENDPOINTS:
            try:
                r = self.http_request(method="GET", path=path)
                if r and r.status_code == 200 and len(r.text.strip()) > 3:
                    value = r.text.strip()
                    if "=" in value:
                        value = value.split("=", 1)[1].strip()
                    info[label] = value
                    print_success("{}: {}".format(label, value))
            except Exception:
                pass

        if not info:
            print_error("No information extracted — endpoints may require authentication")
            return

        fw_ver = info.get("firmware_version", "")
        for prefix, platform in self._PLATFORM_MAP.items():
            if prefix in fw_ver:
                info["estimated_platform"] = platform
                print_info("Estimated platform: {}".format(platform))
                break

        print_success(
            "Fingerprint complete — {} data points extracted".format(len(info))
        )

    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/")
        return resp is not None and resp.status_code in (200, 302, 401)
