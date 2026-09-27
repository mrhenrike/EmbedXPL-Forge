"""zlib + base64 encoder.

Comprime com zlib e codifica em base64.
Reduz tamanho do payload e esconde bytes brutos.
"""

import base64
import zlib
from embedxpl.core.exploit.encoder import BaseEncoder


class Encoder(BaseEncoder):
    name        = "compression/zlib_b64"
    description = "zlib compress + base64 encode — smaller payloads, hides raw bytes"
    arch        = ["generic"]
    platform    = ["linux", "windows", "macos", "python", "perl", "php"]
    evasion_score = 4

    options = {
        "LEVEL": {
            "description": "zlib compression level (1-9, 9=best compression)",
            "required": False,
            "default": "9",
            "value": "9",
        },
    }

    def encode(self, payload: bytes) -> bytes:
        level = int(self.options["LEVEL"]["value"])
        compressed = zlib.compress(payload, level)
        return base64.b64encode(compressed)

    def decode(self, encoded: bytes) -> bytes:
        compressed = base64.b64decode(encoded)
        return zlib.decompress(compressed)
