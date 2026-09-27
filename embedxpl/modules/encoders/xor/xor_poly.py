"""XOR Polymorphic encoder — chave diferente a cada geração.

Cada chamada a encode() usa uma chave aleatória de 1 byte.
O stub de decodificação é embutido na saída (primeiro byte = chave).
Bypassa AVs baseados em hash/assinatura estática.
"""

import os
from embedxpl.core.exploit.encoder import BaseEncoder


class Encoder(BaseEncoder):
    name        = "xor/xor_poly"
    description = "Polymorphic XOR — random key per generation, key prepended"
    arch        = ["armle", "armbe", "arm64", "mipsbe", "mipsle", "x64", "x86", "generic"]
    platform    = ["linux", "windows", "macos", "firmware"]
    evasion_score = 5

    options = {}

    def encode(self, payload: bytes) -> bytes:
        key = os.urandom(1)[0]
        encoded = bytes(b ^ key for b in payload)
        # Primeiro byte é a chave — o stub extrai e usa
        return bytes([key]) + encoded

    def decode_stub(self, arch: str = "x64") -> bytes:
        stub_c = """
// XOR poly decode stub — key é o primeiro byte do buffer
void decode(unsigned char *buf, int len) {
    unsigned char key = buf[0];
    for (int i = 1; i < len; i++) buf[i] ^= key;
    // memmove(buf, buf+1, len-1);  // shift opcional
}
"""
        return stub_c.encode()
