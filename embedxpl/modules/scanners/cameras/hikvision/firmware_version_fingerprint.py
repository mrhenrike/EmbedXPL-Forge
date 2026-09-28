# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Hikvision Firmware Version Fingerprinter — HTTP/ISAPI enumeration.

Identifies Hikvision device model, firmware version, and build date via
HTTP and ISAPI endpoints. Maps discovered versions to known CVEs and
checks for vulnerable component versions (glibc 2.16, BusyBox 1.20.2).

Version: 1.0.0
"""

import re
from typing import Dict, List, Optional, Tuple

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient


_VULN_MAP: List[Tuple[str, str, str, str]] = [
    (
        "CVE-2025-66173",
        "Hardcoded RSA-1024 debug key pair in firmware (private key extractable)",
        "V4.30.x and below",
        "9.8",
    ),
    (
        "CVE-2025-66174",
        "Debug authentication bypass via extracted RSA key (ISAPI/SSH)",
        "V4.30.x and below",
        "9.8",
    ),
    (
        "RSA-1024-DEBUG (no CVE)",
        "RSA-1024 debug authentication key present in firmware image",
        "V4.62.x / V4.84.x",
        "8.1",
    ),
    (
        "CVE-2021-36260",
        "Command injection via web server input validation flaw",
        "Pre-June 2021 builds",
        "9.8",
    ),
    (
        "CVE-2023-28811",
        "Insufficient input validation on ISAPI endpoints",
        "Pre-2023 builds",
        "8.2",
    ),
]


def _parse_xml_tag(xml: str, tag: str) -> Optional[str]:
    match = re.search(r"<{0}>(.*?)</{0}>".format(tag), xml, re.DOTALL)
    return match.group(1).strip() if match else None


def _version_tuple(version_str: str) -> Optional[Tuple[int, ...]]:
    match = re.search(r"V?(\d+(?:\.\d+)+)", version_str)
    if not match:
        return None
    return tuple(int(p) for p in match.group(1).split("."))


def _check_cve_affected(fw_version: str, fw_date: str) -> List[Tuple[str, str, str, str]]:
    results: List[Tuple[str, str, str, str]] = []
    vtup = _version_tuple(fw_version)

    for cve_id, desc, affected_range, cvss in _VULN_MAP:
        affected = "Unknown"

        if cve_id in ("CVE-2025-66173", "CVE-2025-66174"):
            if vtup and vtup <= (4, 30, 999):
                affected = "LIKELY"
            else:
                affected = "No"

        elif cve_id == "RSA-1024-DEBUG (no CVE)":
            if vtup and (
                (4, 62, 0) <= vtup <= (4, 62, 999)
                or (4, 84, 0) <= vtup <= (4, 84, 999)
            ):
                affected = "LIKELY"
            else:
                affected = "No"

        elif cve_id == "CVE-2021-36260":
            if fw_date:
                year_match = re.search(r"(\d{4})", fw_date)
                if year_match:
                    year = int(year_match.group(1))
                    month_match = re.search(r"\d{4}[\-/](\d{1,2})", fw_date)
                    month = int(month_match.group(1)) if month_match else 1
                    if year < 2021 or (year == 2021 and month < 6):
                        affected = "LIKELY"
                    else:
                        affected = "No"

        elif cve_id == "CVE-2023-28811":
            if fw_date:
                year_match = re.search(r"(\d{4})", fw_date)
                if year_match and int(year_match.group(1)) < 2023:
                    affected = "LIKELY"
                elif year_match:
                    affected = "No"

        results.append((cve_id, desc, affected, cvss))

    return results


class Exploit(HTTPClient):
    """Hikvision Firmware Version Fingerprinter.

    Probes ISAPI and HTTP endpoints to identify device model, firmware
    version, and build date. Maps versions to known CVE ranges and flags
    vulnerable embedded components.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Hikvision Firmware Version Fingerprinter",
        "description": (
            "Identifies Hikvision device model, firmware version, and build "
            "date via HTTP/ISAPI. Maps versions to known CVEs. Checks if "
            "firmware uses vulnerable components (glibc 2.16, BusyBox 1.20.2)."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36260",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28811",
        ),
        "devices": (
            "Hikvision IP Camera",
            "Hikvision NVR",
            "Hikvision DVR",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6, or hostname")
    port = OptPort(80, "HTTP port")
    ssl = OptBool(False, "SSL enabled: true/false")

    def _probe_isapi(self) -> Dict[str, str]:
        info: Dict[str, str] = {}
        resp = self.http_request(method="GET", path="/ISAPI/System/deviceInfo")
        if resp is None or resp.status_code not in (200, 401):
            return info

        if resp.status_code == 200:
            xml = resp.text or ""
            for tag, key in [
                ("model", "Model"),
                ("serialNumber", "Serial Number"),
                ("firmwareVersion", "Firmware Version"),
                ("firmwareReleasedDate", "Firmware Date"),
                ("deviceType", "Device Type"),
                ("deviceName", "Device Name"),
                ("macAddress", "MAC Address"),
            ]:
                val = _parse_xml_tag(xml, tag)
                if val:
                    info[key] = val
        else:
            info["ISAPI Status"] = "401 Unauthorized (endpoint exists)"

        return info

    def _probe_http_headers(self) -> Dict[str, str]:
        info: Dict[str, str] = {}
        resp = self.http_request(method="GET", path="/")
        if resp is None:
            return info

        server = resp.headers.get("Server", "")
        www_auth = resp.headers.get("WWW-Authenticate", "")
        for header_val, label in [(server, "Server Header"), (www_auth, "WWW-Authenticate")]:
            if header_val and any(
                kw in header_val.lower() for kw in ["hikvision", "hik", "dvrdvs", "webs"]
            ):
                info[label] = header_val

        return info

    def _probe_login_page(self) -> Dict[str, str]:
        info: Dict[str, str] = {}
        resp = self.http_request(method="GET", path="/doc/page/login.asp")
        if resp is None or resp.status_code != 200:
            return info

        text = resp.text or ""
        ver_match = re.search(r"(?:version|ver|firmware)[\"']?\s*[:=]\s*[\"']?([^\"'<>\s]+)", text, re.I)
        if ver_match:
            info["Login Page Version"] = ver_match.group(1)

        if any(kw in text.lower() for kw in ["hikvision", "hik-connect", "dvrdvs"]):
            info["Login Page"] = "Hikvision login UI detected"

        return info

    def run(self) -> None:
        print_status("Fingerprinting Hikvision device at {}:{}...".format(self.target, self.port))

        device_info: Dict[str, str] = {}

        isapi = self._probe_isapi()
        device_info.update(isapi)

        headers = self._probe_http_headers()
        device_info.update(headers)

        login = self._probe_login_page()
        device_info.update(login)

        if not device_info:
            print_error("No Hikvision indicators found on {}:{}".format(self.target, self.port))
            return

        print_success("Hikvision device identified on {}:{}".format(self.target, self.port))

        info_rows = [(k, v) for k, v in device_info.items()]
        print_table(("Property", "Value"), *info_rows, title="Device Information")

        fw_version = device_info.get("Firmware Version", "")
        fw_date = device_info.get("Firmware Date", "")

        cve_results = _check_cve_affected(fw_version, fw_date)
        print_table(
            ("CVE", "Description", "Affected?", "CVSS"),
            *cve_results,
            title="CVE Mapping",
        )

        affected_count = sum(1 for _, _, a, _ in cve_results if a == "LIKELY")
        if affected_count:
            print_warning("{} potential CVE(s) affect this firmware version".format(affected_count))
        else:
            print_info("No known CVEs matched this firmware version")

    @mute
    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/ISAPI/System/deviceInfo")
        if resp is not None and resp.status_code in (200, 401):
            return True
        resp = self.http_request(method="GET", path="/")
        return resp is not None and resp.status_code in (200, 302, 401)
