"""LZMA2 + base64 encoder."""

import base64
import lzma
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "LZMA2+Base64 Encoder",
        "description": "LZMA2 compress then base64 — best compression ratio.",
        "authors": ("André Henrike (@mrhenrike)", "União Geek"),
        "evasion_score": 4,
    }

    architecture = None

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        return base64.b64encode(lzma.compress(payload, preset=9))

    def decode(self, encoded: bytes) -> bytes:
        return lzma.decompress(base64.b64decode(encoded))
