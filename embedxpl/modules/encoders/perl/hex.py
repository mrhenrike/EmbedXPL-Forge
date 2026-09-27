from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Perl Hex Encoder",
        "description": "Module encodes PERL payload to Hex format.",
        "authors": (
            "Marcin Bury",
            "André Henrique (@mrhenrike)",
        ),
    }

    architecture = Architectures.PERL

    def encode(self, payload):
        encoded_payload = bytes(payload, "utf-8").hex()
        return "eval(pack('H*','{}'));".format(encoded_payload)
