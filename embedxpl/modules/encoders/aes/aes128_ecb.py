"""AES-128 ECB payload encryption.

Formato output: [16 bytes key][4 bytes original_len big-endian][encrypted_padded_payload]
Chave: encoder.key = bytes(16) ou None para aleatória.
"""

import os
import struct
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


def _pad_pkcs7(data: bytes, block: int = 16) -> bytes:
    pad = block - (len(data) % block)
    return data + bytes([pad] * pad)


def _unpad_pkcs7(data: bytes) -> bytes:
    pad = data[-1]
    return data[:-pad]


class Encoder(BaseEncoder):
    __info__ = {
        "name": "AES-128 ECB Encoder",
        "description": "AES-128 ECB encryption. Set encoder.key = bytes(16) or leave None for random key.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 7,
    }

    architecture = None

    key: bytes | None = None

    def _get_key(self) -> bytes:
        if self.key:
            k = self.key if isinstance(self.key, bytes) else bytes.fromhex(self.key)
            assert len(k) == 16, "AES-128 key must be 16 bytes"
            return k
        return os.urandom(16)

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        k = self._get_key()
        try:
            from Crypto.Cipher import AES
            cipher = AES.new(k, AES.MODE_ECB)
            encrypted = cipher.encrypt(_pad_pkcs7(payload))
        except ImportError:
            # Fallback XOR with key rotation
            padded = _pad_pkcs7(payload)
            encrypted = bytes(padded[i] ^ k[i % 16] for i in range(len(padded)))
        return k + struct.pack(">I", len(payload)) + encrypted

    def decode(self, data: bytes) -> bytes:
        k = data[:16]
        orig_len = struct.unpack(">I", data[16:20])[0]
        ciphertext = data[20:]
        try:
            from Crypto.Cipher import AES
            decrypted = AES.new(k, AES.MODE_ECB).decrypt(ciphertext)
            return _unpad_pkcs7(decrypted)[:orig_len]
        except ImportError:
            dec = bytes(ciphertext[i] ^ k[i % 16] for i in range(len(ciphertext)))
            return dec[:orig_len]
