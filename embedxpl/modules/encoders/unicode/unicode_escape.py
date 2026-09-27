"""Unicode \\uXXXX escape encoder."""

from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Unicode Escape Encoder",
        "description": "Encodes bytes as \\u00XX unicode escapes — for JS/JSON/YAML contexts.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 4,
    }

    architecture = None
    prefix: str = "\\u"

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        return "".join(f"{self.prefix}00{b:02x}" for b in payload).encode()

    def decode(self, encoded: bytes) -> bytes:
        import re
        result = bytearray()
        for m in re.finditer(r'\\u00([0-9a-fA-F]{2})', encoded.decode(errors="replace")):
            result.append(int(m.group(1), 16))
        return bytes(result)
