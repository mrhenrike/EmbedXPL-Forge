from base64 import b32encode

from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Python Base32 Encoder",
        "description": "Module encodes Python payload to Base32 format.",
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",  # EmbedXPL-Forge encoder
        ),
    }

    architecture = Architectures.PYTHON

    def encode(self, payload):
        encoded_payload = str(b32encode(bytes(payload, "utf-8")), "utf-8")
        return "import base64;exec(base64.b32decode('{}'))".format(encoded_payload)
