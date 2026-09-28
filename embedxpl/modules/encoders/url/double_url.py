"""Double URL encoder — %25XX."""

from urllib.parse import unquote
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Double URL Encoder",
        "description": "Double URL encoding %25XX — bypasses single-decode WAFs.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 5,
    }

    architecture = None
    layers: int = 2

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        result = "".join(f"%{b:02x}" for b in payload)
        for _ in range(self.layers - 1):
            result = result.replace("%", "%25")
        return result.encode()

    def decode(self, encoded: bytes) -> bytes:
        s = encoded.decode()
        for _ in range(self.layers):
            s = unquote(s)
        return s.encode("latin-1", errors="replace")
