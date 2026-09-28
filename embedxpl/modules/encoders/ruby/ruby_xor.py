"""Ruby XOR encoder."""

import os
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Ruby XOR Encoder",
        "description": "XOR-encodes payload and wraps in inline Ruby decoder.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 5,
    }

    architecture = Architectures.PERL

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        key = os.urandom(1)[0]
        xored = bytes(b ^ key for b in payload)
        hex_str = ",".join(str(b) for b in xored)
        ruby = f"k={key};sc=[{hex_str}].map{{|b|b^k}}.pack('C*');eval(sc)"
        return ruby.encode()
