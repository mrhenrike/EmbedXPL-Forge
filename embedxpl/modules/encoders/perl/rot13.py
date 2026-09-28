from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Perl ROT13 Encoder",
        "description": "Module encodes PERL payload to ROT13 format.",
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",  # EmbedXPL-Forge encoder
        ),
    }

    architecture = Architectures.PERL

    def encode(self, payload):
        encoded_payload = payload.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
        ))
        return "eval(\"{}\" =~ tr/A-Za-z/N-ZA-Mn-za-m/r);".format(encoded_payload)
