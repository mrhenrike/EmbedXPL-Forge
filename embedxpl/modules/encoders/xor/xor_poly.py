"""XOR Polymorphic encoder — chave aleatória por geração.

O primeiro byte do output É a chave — o stub a extrai e decifra.
Bypassa AVs baseados em hash/assinatura estática.
"""

import os
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "XOR Polymorphic Encoder",
        "description": "Polymorphic XOR — random key per generation prepended as first byte.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 5,
    }

    architecture = None

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        key = os.urandom(1)[0]
        encoded = bytes(b ^ key for b in payload)
        return bytes([key]) + encoded

    def decode(self, data: bytes) -> bytes:
        key = data[0]
        return bytes(b ^ key for b in data[1:])

    def decode_stub_c(self) -> str:
        return (
            "// XOR poly decode stub — key is first byte\n"
            "void decode(unsigned char *buf, int len) {\n"
            "    unsigned char key = buf[0];\n"
            "    for (int i = 1; i < len; i++) buf[i] ^= key;\n"
            "}\n"
        )
