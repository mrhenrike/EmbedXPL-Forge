import socket
import time

from embedxpl.core.exploit import *


class Exploit(Exploit):
    __info__ = {
        "name": "SNMP Trap Listener",
        "description": "Operational validation module for SNMP trap reception over UDP.",
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",  # EmbedXPL-Forge module
        ),
        "devices": (
            "Routers",
            "Switches",
            "TAPs",
            "FW",
            "NGFW",
        ),
    }

    listen_host = OptString("0.0.0.0", "Listener bind host")
    listen_port = OptPort(162, "Listener UDP port for SNMP traps")
    timeout = OptInteger(30, "Listener timeout in seconds")
    max_packets = OptInteger(50, "Maximum packets to capture")
    contains = OptString("", "Optional ASCII token expected in trap payload")
    hex_dump = OptBool(False, "Print packet payload in hex: true/false")

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)
        sock.bind((self.listen_host, self.listen_port))

        print_status(
            "SNMP trap listener started on {}:{} timeout={}s max_packets={}".format(
                self.listen_host, self.listen_port, self.timeout, self.max_packets
            )
        )

        start = time.time()
        packets = []
        while len(packets) < self.max_packets and (time.time() - start) < self.timeout:
            try:
                payload, remote = sock.recvfrom(65535)
            except socket.timeout:
                continue

            match = True
            if self.contains:
                token = self.contains.encode("utf-8", errors="ignore")
                match = token in payload

            packets.append((remote[0], remote[1], len(payload), match))
            print_info(
                "[trap] {}:{} bytes={} match={}".format(remote[0], remote[1], len(payload), match)
            )
            if self.hex_dump:
                print_info(payload.hex())

        sock.close()

        if packets:
            headers = ("Source", "Port", "Bytes", "MatchFilter")
            print_table(headers, *packets)
            print_success("SNMP trap listener captured {} packets".format(len(packets)))
        else:
            print_error("No SNMP trap packet captured during validation window")
