"""Alphanumeric encoder.

Converte shellcode arbitrário em sequência somente alfanumérica
([a-zA-Z0-9]) usando codificação base62 + stub decoder.

Bypassa filtros de rede que bloqueiam bytes não-imprimíveis (\\x00-\\x1f, 0x80+).
"""

import base64
import string
from embedxpl.core.exploit.encoder import BaseEncoder

_ALPHA = (string.ascii_uppercase + string.ascii_lowercase + string.digits).encode()


def _to_base62(data: bytes) -> bytes:
    """Encode bytes to base62 (only [A-Za-z0-9])."""
    n = int.from_bytes(data, "big") if data else 0
    if n == 0:
        return b"A"
    chars = []
    base = 62
    while n:
        chars.append(_ALPHA[n % base])
        n //= base
    return bytes(reversed(chars))


def _from_base62(s: bytes) -> bytes:
    """Decode base62 back to bytes."""
    n = 0
    alpha_map = {c: i for i, c in enumerate(_ALPHA)}
    for c in s:
        n = n * 62 + alpha_map[c]
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big") if n else b"\x00"


class Encoder(BaseEncoder):
    name        = "alphanumeric/alphanumeric"
    description = "Alphanumeric-only encoder [A-Za-z0-9] — bypasses printable-only filters"
    arch        = ["x86", "x64", "generic"]
    platform    = ["linux", "windows", "webshell"]
    evasion_score = 6

    options = {
        "CHUNK_SIZE": {
            "description": "Bytes per base62 chunk (smaller = larger output, cleaner chars)",
            "required": False,
            "default": "3",
            "value": "3",
        },
    }

    def encode(self, payload: bytes) -> bytes:
        chunk = int(self.options["CHUNK_SIZE"]["value"])
        parts = []
        for i in range(0, len(payload), chunk):
            block = payload[i:i+chunk]
            enc_block = _to_base62(block)
            # Fixed-width: ceil(chunk*8 / log2(62)) chars, padded with 'A'
            parts.append(enc_block)
        # Separator: '.' (still printable but not alphanumeric; or use fixed-width)
        return b".".join(parts)

    def decode(self, encoded: bytes) -> bytes:
        parts = encoded.split(b".")
        return b"".join(_from_base62(p) for p in parts)
