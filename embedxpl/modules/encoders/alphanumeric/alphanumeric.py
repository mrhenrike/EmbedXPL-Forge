"""Alphanumeric encoder — output somente [A-Za-z0-9]."""

import string
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures

_ALPHA = (string.ascii_uppercase + string.ascii_lowercase + string.digits).encode()


def _b62_encode(data: bytes) -> bytes:
    n = int.from_bytes(data, "big") if data else 0
    if n == 0:
        return b"A"
    chars = []
    while n:
        chars.append(_ALPHA[n % 62])
        n //= 62
    return bytes(reversed(chars))


def _b62_decode(s: bytes) -> bytes:
    alpha_map = {c: i for i, c in enumerate(_ALPHA)}
    n = 0
    for c in s:
        n = n * 62 + alpha_map[c]
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big") if n else b"\x00"


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Alphanumeric Encoder",
        "description": "Encodes payload to [A-Za-z0-9] only — bypasses printable-only filters.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 6,
    }

    architecture = None
    chunk_size: int = 3

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        parts = []
        for i in range(0, len(payload), self.chunk_size):
            parts.append(_b62_encode(payload[i:i + self.chunk_size]))
        return b".".join(parts)

    def decode(self, encoded: bytes) -> bytes:
        return b"".join(_b62_decode(p) for p in encoded.split(b"."))
