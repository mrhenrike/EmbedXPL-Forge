"""LZMA2 + base64 encoder — melhor compressão."""

import base64
import lzma
from embedxpl.core.exploit.encoder import BaseEncoder


class Encoder(BaseEncoder):
    name        = "compression/lzma_b64"
    description = "LZMA2 compress + base64 — best compression ratio"
    arch        = ["generic"]
    platform    = ["linux", "windows", "macos", "python"]
    evasion_score = 4

    options = {}

    def encode(self, payload: bytes) -> bytes:
        return base64.b64encode(lzma.compress(payload, preset=9))

    def decode(self, encoded: bytes) -> bytes:
        return lzma.decompress(base64.b64decode(encoded))
