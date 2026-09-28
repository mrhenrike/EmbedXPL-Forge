from binascii import hexlify
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "PHP Hex Encoder",
        "description": "Module encodes PHP payload to Hex format.",
        "authors": (
            "Marcin Bury",
            "André Henrique (@mrhenrike)",
        ),
    }

    architecture = Architectures.PHP

    def encode(self, payload):
        encoded_payload = str(hexlify(bytes(payload, "utf-8")), "utf-8")
        return "eval(hex2bin('{}'));".format(encoded_payload)
