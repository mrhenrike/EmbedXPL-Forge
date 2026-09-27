"""gzip + base64 encoder."""

import base64
import gzip
from embedxpl.core.exploit.encoder import BaseEncoder


class Encoder(BaseEncoder):
    name        = "compression/gzip_b64"
    description = "gzip compress + base64 encode"
    arch        = ["generic"]
    platform    = ["linux", "windows", "macos", "python", "powershell"]
    evasion_score = 4

    options = {}

    def encode(self, payload: bytes) -> bytes:
        return base64.b64encode(gzip.compress(payload, compresslevel=9))

    def decode(self, encoded: bytes) -> bytes:
        return gzip.decompress(base64.b64decode(encoded))
