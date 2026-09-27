"""Double URL encoder.

Aplica URL encoding duas vezes: byte → %XX → %25XX.
Bypassa WAFs que decodificam apenas uma camada de URL encoding.
"""

from embedxpl.core.exploit.encoder import BaseEncoder


class Encoder(BaseEncoder):
    name        = "url/double_url"
    description = "Double URL encoder %25XX — bypasses single-decode WAFs"
    arch        = ["generic"]
    platform    = ["webshell", "linux", "windows"]
    evasion_score = 5

    options = {
        "LAYERS": {
            "description": "Number of URL encoding layers (1-3)",
            "required": False,
            "default": "2",
            "value": "2",
        },
    }

    def encode(self, payload: bytes) -> bytes:
        layers = int(self.options["LAYERS"]["value"])
        result = "".join(f"%{b:02x}" for b in payload)
        for _ in range(layers - 1):
            result = result.replace("%", "%25")
        return result.encode()

    def decode(self, encoded: bytes) -> bytes:
        from urllib.parse import unquote
        layers = int(self.options["LAYERS"]["value"])
        s = encoded.decode()
        for _ in range(layers):
            s = unquote(s)
        return s.encode("latin-1", errors="replace")
