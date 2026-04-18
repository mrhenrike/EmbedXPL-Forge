# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Aruba PAPI Protocol Scanner — UDP/8211 Service Detection and Fingerprint.

Scanner for Aruba Networks PAPI (Process Application Programming Interface)
protocol on UDP/8211. Used to discover Aruba Access Points, Mobility
Controllers, Mobility Gateways, and Instant APs on a network.

PAPI exposure is required for exploitation of:
  - CVE-2024-42509 / CVE-2024-47460 (CVSS 9.8/9.0)
  - CVE-2023-35980 / CVE-2023-35981 (CVSS 9.8)
  - CVE-2022-37885/37897 cluster (CVSS 9.8)
  - CVE-2021-25144/25145/25146 (CVSS 9.8)

Version: 1.0.0
"""

import socket

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit
from embedxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Aruba PAPI Service Scanner — UDP/8211.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Aruba PAPI Protocol Scanner (UDP/8211)",
        "description": (
            "Detects Aruba Networks PAPI service on UDP/8211 and fingerprints the device "
            "type and ArubaOS version. PAPI exposure is required for multiple critical CVEs "
            "(CVE-2024-42509, CVE-2023-35980, CVE-2022-37897, CVE-2021-25144 etc.)."
        ),
        "authors": ["André Henrique (@mrhenrike)"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-42509",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-35980",
        ],
        "devices": [
            "Aruba Access Points (all models/firmware)",
            "Aruba Mobility Controllers",
            "Aruba Mobility Gateways",
            "Aruba Instant APs",
            "Aruba SD-WAN Gateways",
        ],
        "severity": "info",
        "cvss": "N/A",
        "cve": "N/A",
        "apt_groups": [],
        "mitre": ["T1046"],
    }

    target = OptIP("", "Target Aruba device IP")
    papi_port = OptPort(8211, "PAPI UDP port")
    web_port = OptPort(443, "Web management HTTPS port")
    ssl = OptBool(True, "Use SSL for web fingerprint")
    timeout = OptInteger(5, "UDP timeout in seconds")

    _PAPI_MAGIC = b"\x49\x72"
    _PAPI_VERSION = b"\x00\x03"

    # Known PAPI process port mapping
    _PAPI_PORTS = {
        8195: "management daemon",
        8200: "license manager",
        8201: "configuration manager",
        8203: "process manager",
        8211: "PAPI main (this scanner)",
    }

    @mute
    def check(self) -> bool:
        """Always returns True — scanner is discovery-mode."""
        return True

    def run(self) -> None:
        """Scan for PAPI service and fingerprint device."""
        print_status(f"[PAPI-SCAN] Scanning Aruba device at {self.target}")

        # Step 1: PAPI UDP/8211 probe
        papi_active = False
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                probe = self._PAPI_MAGIC + self._PAPI_VERSION + b"\x00" * 12
                s.sendto(probe, (self.target, self.papi_port))
                try:
                    data, addr = s.recvfrom(512)
                    if data:
                        papi_active = True
                        print_success(f"[PAPI-SCAN] PAPI service ACTIVE on {addr}")
                        print_info(f"[PAPI-SCAN] Response magic: {data[:4].hex()}")
                        if data[:2] == self._PAPI_MAGIC:
                            ver = data[2:4].hex()
                            print_info(f"[PAPI-SCAN] PAPI version bytes: {ver}")
                        if len(data) > 16:
                            payload = data[16:].replace(b"\x00", b" ").decode("ascii", errors="replace")
                            print_info(f"[PAPI-SCAN] Payload hint: {payload[:80]}")
                except socket.timeout:
                    print_info(f"[PAPI-SCAN] No UDP response from {self.target}:{self.papi_port}")
        except Exception as exc:
            print_error(f"[PAPI-SCAN] UDP probe error: {exc}")

        # Step 2: Web fingerprint
        print_status(f"[PAPI-SCAN] Checking web management interface...")
        try:
            for path in ["/screens/wms/wms.login", "/swarm.cgi", "/", "/visualrf_ajax"]:
                res = self.http_request("GET", f"https://{self.target}:{self.web_port}{path}",
                                        timeout=6)
                if res and res.status_code in (200, 302):
                    body = res.text
                    body_l = body.lower()
                    server = res.headers.get("Server", "")

                    device_type = ""
                    version = ""

                    if "aruba instant" in body_l or "instant" in path:
                        device_type = "Aruba Instant AP"
                    elif "aruba" in body_l or "arubaos" in body_l:
                        device_type = "Aruba Controller/Gateway"
                    elif "mobility" in body_l:
                        device_type = "Aruba Mobility Controller"

                    # Extract version hints
                    import re
                    ver_match = re.search(r"ArubaOS[_ ]([0-9.]+)", body, re.IGNORECASE)
                    if ver_match:
                        version = ver_match.group(1)
                    iap_match = re.search(r"Instant[_ ]([0-9.]+)", body, re.IGNORECASE)
                    if iap_match:
                        version = "Instant " + iap_match.group(1)

                    if device_type or version:
                        print_success(f"[PAPI-SCAN] Device: {device_type or 'Aruba'} | Version: {version or 'unknown'}")
                        break
                    print_info(f"[PAPI-SCAN] {path} → HTTP {res.status_code} | Server: {server}")
                    break
        except Exception as exc:
            print_error(f"[PAPI-SCAN] Web probe error: {exc}")

        # Step 3: Vulnerability assessment
        print_status(f"[PAPI-SCAN] Vulnerability assessment:")
        if papi_active:
            print_success(f"[PAPI-SCAN] PAPI EXPOSED — Potentially vulnerable to:")
            print_success(f"[PAPI-SCAN]   CVE-2024-42509 (CVSS 9.8) — AOS-10 pre-auth RCE")
            print_success(f"[PAPI-SCAN]   CVE-2024-47460 (CVSS 9.0) — AOS-10 cmd injection")
            print_success(f"[PAPI-SCAN]   CVE-2023-35980 (CVSS 9.8) — Heap overflow")
            print_success(f"[PAPI-SCAN]   CVE-2022-37885-37897 cluster (CVSS 9.8)")
            print_success(f"[PAPI-SCAN]   CVE-2021-25144/25145/25146 (CVSS 9.8)")
        else:
            print_info(f"[PAPI-SCAN] PAPI not detected. Either patched, filtered, or not Aruba.")

        print_info(f"[PAPI-SCAN] Recommended: block UDP/8211 from untrusted networks")
        print_info(f"[PAPI-SCAN] Use aos10_instant_papi_rce_cve_2024_42509 for exploitation attempt")
