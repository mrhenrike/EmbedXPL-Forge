"""HTML Entity encoder — &#xXX; format."""

import re
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "HTML Entity Encoder",
        "description": "Encodes bytes as &#xXX; HTML entities — bypasses WAF for web contexts.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 5,
    }

    architecture = None
    use_hex: bool = True   # True = &#xXX; / False = &#DD;

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        if self.use_hex:
            return "".join(f"&#x{b:02x};" for b in payload).encode()
        return "".join(f"&#{b};" for b in payload).encode()

    def decode(self, encoded: bytes) -> bytes:
        result = bytearray()
        for m in re.finditer(r'&#x([0-9a-fA-F]+);|&#(\d+);', encoded.decode(errors="replace")):
            if m.group(1):
                result.append(int(m.group(1), 16))
            else:
                result.append(int(m.group(2)))
        return bytes(result)
