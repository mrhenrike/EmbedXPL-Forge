import codecs

from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Python ROT13 Encoder",
        "description": "Module encodes Python payload to ROT13 format.",
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",  # EmbedXPL-Forge encoder
        ),
    }

    architecture = Architectures.PYTHON

    def encode(self, payload):
        encoded_payload = codecs.encode(payload, "rot_13")
        return "import codecs;exec(codecs.decode('{}','rot_13'))".format(encoded_payload)
