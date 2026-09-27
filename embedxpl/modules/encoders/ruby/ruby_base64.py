"""Ruby base64 encoder."""

import base64
from embedxpl.core.exploit.encoder import BaseEncoder


class Encoder(BaseEncoder):
    name        = "ruby/ruby_base64"
    description = "Ruby base64 encoder — wraps payload in eval(Base64.decode64(...))"
    arch        = ["generic"]
    platform    = ["linux", "windows", "macos"]
    evasion_score = 4

    options = {}

    def encode(self, payload: bytes) -> bytes:
        b64 = base64.b64encode(payload).decode()
        return f'eval(Base64.decode64("{b64}"))'.encode()
