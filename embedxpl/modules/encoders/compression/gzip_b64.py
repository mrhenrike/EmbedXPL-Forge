"""gzip + base64 encoder."""

import base64
import gzip
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "gzip+Base64 Encoder",
        "description": "gzip compress then base64.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 4,
    }

    architecture = None

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        return base64.b64encode(gzip.compress(payload, compresslevel=9))

    def decode(self, encoded: bytes) -> bytes:
        return gzip.decompress(base64.b64decode(encoded))
