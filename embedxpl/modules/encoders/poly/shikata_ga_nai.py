"""Shikata-Ga-Nai style polymorphic encoder.

Additive feedback XOR — cada geração usa chave aleatória de 4 bytes.
Formato: [4-byte seed][4-byte orig_len][encoded_payload]
"""

import os
import struct
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Shikata-Ga-Nai (SGN) Encoder",
        "description": "Polymorphic additive-feedback XOR encoder. Seed is random per generation.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 8,
    }

    architecture = None

    # Configuráveis
    iterations: int = 1
    badchars: set = frozenset([0x00])

    def _sgn_encode(self, payload: bytes, seed: int) -> bytes:
        key = seed & 0xFFFFFFFF
        encoded = bytearray()
        for i in range(0, len(payload), 4):
            chunk = payload[i:i + 4].ljust(4, b'\x00')
            val = struct.unpack("<I", chunk)[0]
            enc_val = val ^ key
            key = (key + enc_val) & 0xFFFFFFFF
            encoded += struct.pack("<I", enc_val)
        return bytes(encoded[:len(payload)])

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        result = payload
        last_seed = 0x41424344
        for _ in range(self.iterations):
            for _ in range(1000):
                seed = struct.unpack("<I", os.urandom(4))[0]
                key_bytes = struct.pack("<I", seed)
                if not any(b in self.badchars for b in key_bytes):
                    break
            encoded = self._sgn_encode(result, seed)
            if not any(b in self.badchars for b in encoded):
                result = encoded
                last_seed = seed

        return struct.pack("<II", last_seed, len(payload)) + result

    def decode(self, data: bytes) -> bytes:
        seed = struct.unpack("<I", data[:4])[0]
        orig_len = struct.unpack("<I", data[4:8])[0]
        enc_data = data[8:]
        key = seed
        decoded = bytearray()
        for i in range(0, len(enc_data), 4):
            chunk = enc_data[i:i + 4].ljust(4, b'\x00')
            enc_val = struct.unpack("<I", chunk)[0]
            dec_val = enc_val ^ key
            key = (key + enc_val) & 0xFFFFFFFF
            decoded += struct.pack("<I", dec_val)
        return bytes(decoded[:orig_len])
