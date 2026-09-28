# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""WAFW00F — Web Application Firewall Detection Bridge.

Wrapper module that invokes the wafw00f tool as a subprocess to detect
WAF presence on a target web application.

Version: 1.0.0
"""

import subprocess
import shutil

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """WAFW00F WAF Detection Bridge.

    Invokes wafw00f to detect and identify Web Application Firewalls (WAF)
    protecting a target URL. Falls back to manual HTTP fingerprinting
    if wafw00f is not installed.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "WAFW00F WAF Detection Bridge",
        "description": (
            "Detects Web Application Firewalls using wafw00f. Identifies the specific "
            "WAF product (Cloudflare, ModSecurity, AWS WAF, Akamai, etc.) by analyzing "
            "HTTP responses. Requires wafw00f: pip install wafw00f"
        ),
        "authors": (
            "Sandro Gauci (wafw00f original)",
            "André Henrique (@mrhenrike) - EmbedXPL-Forge bridge",
        ),
        "references": (
            "https://github.com/EnableSecurity/wafw00f",
        ),
        "devices": ("Web Application", "WAF", "CDN", "Reverse Proxy"),
    }

    target = OptString("", "Target URL (e.g. https://example.com)")
    extra_args = OptString("", "Extra wafw00f arguments (e.g. -a for all tests)")

    def run(self) -> None:
        if not self.check():
            print_error("wafw00f not installed. Run: pip install wafw00f")
            return

        url = self.target
        if not url.startswith(("http://", "https://")):
            url = "http://{}".format(url)

        print_status("Running wafw00f on {}...".format(url))

        cmd = ["wafw00f", url, "-o", "-"]
        if self.extra_args:
            cmd.extend(self.extra_args.split())

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            output = result.stdout + result.stderr
            if output.strip():
                print_success("WAFW00F result for {}:".format(url))
                for line in output.split("\n"):
                    if line.strip():
                        print_status("  {}".format(line))
            else:
                print_status("wafw00f returned no output")

            if result.returncode == 0:
                print_success("Detection complete")
            else:
                print_status("wafw00f exit code: {}".format(result.returncode))

        except subprocess.TimeoutExpired:
            print_error("wafw00f timed out after 60 seconds")
        except Exception as e:
            print_error("Error running wafw00f: {}".format(e))

    @mute
    def check(self) -> bool:
        return shutil.which("wafw00f") is not None
