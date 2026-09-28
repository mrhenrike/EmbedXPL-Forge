"""RC4 stream cipher encoder.

Formato output: [1 byte key_len][key bytes][encrypted_payload]
Chave configurável: encoder.key = b'mysecret' (ou deixar None para aleatória de 16 bytes)
"""

import os
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


def _rc4_crypt(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


class Encoder(BaseEncoder):
    __info__ = {
        "name": "RC4 Encoder",
        "description": "RC4 stream cipher. Set encoder.key = b'secret' or leave None for random 16-byte key.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 6,
    }

    architecture = None

    # Configurável: encoder.key = b'mysecret'
    key: bytes | None = None
    key_size: int = 16

    def _get_key(self) -> bytes:
        if self.key:
            return self.key if isinstance(self.key, bytes) else self.key.encode()
        return os.urandom(self.key_size)

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        k = self._get_key()
        encrypted = _rc4_crypt(k, payload)
        return bytes([len(k)]) + k + encrypted

    def decode(self, data: bytes) -> bytes:
        klen = data[0]
        k = data[1:1 + klen]
        encrypted = data[1 + klen:]
        return _rc4_crypt(k, encrypted)
