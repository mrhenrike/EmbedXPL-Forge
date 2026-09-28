"""XOR encoder — chave estática configurável.

Bypassa filtros simples de AV baseados em assinatura.
Uso: encoder.key = 0x41; encoded = encoder.encode(payload_bytes)
"""

from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "XOR Key Encoder",
        "description": "XOR encoder with configurable single-byte key. Set encoder.key = 0xNN before encode().",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 3,
    }

    architecture = None

    # Configurável pelo caller: encoder.key = 0x42
    key: int = 0x41

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        k = self.key & 0xFF
        return bytes(b ^ k for b in payload)

    def decode(self, encoded: bytes) -> bytes:
        return self.encode(encoded)   # XOR é simétrico

    def decode_stub_c(self) -> str:
        return (
            f"// XOR decode stub — key=0x{self.key:02x}\n"
            f"void decode(unsigned char *buf, int len) {{\n"
            f"    for (int i = 0; i < len; i++) buf[i] ^= 0x{self.key:02x};\n"
            f"}}\n"
        )
