from urllib.parse import quote

from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Perl URL Encoder",
        "description": "Module encodes PERL payload to URL-encoded format.",
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",  # EmbedXPL-Forge encoder
        ),
    }

    architecture = Architectures.PERL

    def encode(self, payload):
        encoded_payload = quote(payload, safe="")
        return "use URI::Escape;eval(uri_unescape('{}'));".format(encoded_payload)
