"""Ruby base64 encoder."""

import base64
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Ruby Base64 Encoder",
        "description": "Wraps payload in eval(Base64.decode64(...)).",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 4,
    }

    architecture = Architectures.PERL

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        b64 = base64.b64encode(payload).decode()
        return f'require "base64";eval(Base64.decode64("{b64}"))'.encode()
