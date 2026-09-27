"""HTML Entity encoder.

Converte payload em entidades HTML (&#xXX;).
Bypassa WAFs que inspecionam bytes brutos mas não decodificam entidades HTML.
Útil para XSS payloads, webshells injetados via web forms.
"""

from embedxpl.core.exploit.encoder import BaseEncoder


class Encoder(BaseEncoder):
    name        = "html/html_entity"
    description = "HTML entity encoder &#xXX; — WAF bypass for web contexts"
    arch        = ["generic"]
    platform    = ["webshell", "linux", "windows"]
    evasion_score = 5

    options = {
        "FORMAT": {
            "description": "Entity format: hex (&#xXX;) or decimal (&#DD;) or named (&amp;)",
            "required": False,
            "default": "hex",
            "value": "hex",
        },
    }

    def encode(self, payload: bytes) -> bytes:
        fmt = self.options["FORMAT"]["value"]
        parts = []
        for b in payload:
            if fmt == "hex":
                parts.append(f"&#x{b:02x};")
            else:
                parts.append(f"&#{b};")
        return "".join(parts).encode()

    def decode(self, encoded: bytes) -> bytes:
        import re
        result = bytearray()
        for m in re.finditer(r"&#x([0-9a-fA-F]+);|&#(\d+);", encoded.decode(errors="replace")):
            if m.group(1):
                result.append(int(m.group(1), 16))
            else:
                result.append(int(m.group(2)))
        return bytes(result)
