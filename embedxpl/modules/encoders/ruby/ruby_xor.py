"""Ruby XOR encoder."""

import os
from embedxpl.core.exploit.encoder import BaseEncoder


class Encoder(BaseEncoder):
    name        = "ruby/ruby_xor"
    description = "Ruby XOR encoder — inline decode and eval"
    arch        = ["generic"]
    platform    = ["linux", "windows"]
    evasion_score = 5

    options = {}

    def encode(self, payload: bytes) -> bytes:
        key = os.urandom(1)[0]
        xored = bytes(b ^ key for b in payload)
        hex_str = ",".join(str(b) for b in xored)
        ruby = (
            f"k={key};"
            f"sc=[{hex_str}].map{{|b|b^k}}.pack('C*');"
            "eval(sc)"
        )
        return ruby.encode()
