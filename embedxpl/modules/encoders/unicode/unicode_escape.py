"""Unicode \\uXXXX encoder.

Converte payload em sequência de escapes unicode \u00XX.
Útil para payloads JSON, JavaScript e contextos onde unicode é aceito.
"""

from embedxpl.core.exploit.encoder import BaseEncoder


class Encoder(BaseEncoder):
    name        = "unicode/unicode_escape"
    description = "Unicode \\uXXXX escape encoder — for JS/JSON/YAML contexts"
    arch        = ["generic"]
    platform    = ["webshell", "linux", "windows"]
    evasion_score = 4

    options = {
        "PREFIX": {
            "description": "Unicode prefix style (\\u, %u, \\x)",
            "required": False,
            "default": "\\u",
            "value": "\\u",
        },
    }

    def encode(self, payload: bytes) -> bytes:
        prefix = self.options["PREFIX"]["value"]
        return "".join(f"{prefix}00{b:02x}" for b in payload).encode()

    def decode(self, encoded: bytes) -> bytes:
        s = encoded.decode()
        prefix = self.options["PREFIX"]["value"]
        parts = s.split(prefix)
        result = bytearray()
        for part in parts:
            if part:
                try:
                    result.append(int(part[:4], 16))
                except ValueError:
                    pass
        return bytes(result)
