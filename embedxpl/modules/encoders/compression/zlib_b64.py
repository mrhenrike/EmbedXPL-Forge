"""zlib + base64 encoder."""

import base64
import zlib
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "zlib+Base64 Encoder",
        "description": "zlib compress then base64 — smaller payload, hides raw bytes.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 4,
    }

    architecture = None
    level: int = 9

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        return base64.b64encode(zlib.compress(payload, self.level))

    def decode(self, encoded: bytes) -> bytes:
        return zlib.decompress(base64.b64decode(encoded))
