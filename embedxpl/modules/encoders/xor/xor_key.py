"""XOR encoder — chave estática configurável.

Bypassa filtros simples de AV baseados em assinatura.
Chave default: 0x41 ('A') — configurável via set KEY <hex>.
"""

from embedxpl.core.exploit.encoder import BaseEncoder


class Encoder(BaseEncoder):
    name        = "xor/xor_key"
    description = "XOR encoder with configurable single-byte key"
    arch        = ["armle", "armbe", "arm64", "mipsbe", "mipsle", "mips64",
                   "x64", "x86", "riscv32", "ppc", "generic"]
    platform    = ["linux", "windows", "macos", "firmware"]
    evasion_score = 3   # 1-10 — baixo para XOR simples

    options = {
        "KEY": {
            "description": "XOR key byte (hex, e.g. 0x41 or 65)",
            "required": True,
            "default": "0x41",
            "value": "0x41",
        },
    }

    def encode(self, payload: bytes) -> bytes:
        key_val = self.options["KEY"]["value"]
        if isinstance(key_val, str):
            key = int(key_val, 16) if key_val.startswith("0x") else int(key_val)
        else:
            key = int(key_val)
        key &= 0xFF
        return bytes(b ^ key for b in payload)

    def decode_stub(self, arch: str = "x64") -> bytes:
        """Retorna stub de decodificação em C (bytes) — inserido antes do shellcode."""
        key = int(self.options["KEY"]["value"], 16) if \
            self.options["KEY"]["value"].startswith("0x") else \
            int(self.options["KEY"]["value"])
        # Stub genérico (pseudo — para uso com CExecutor)
        stub_c = f"""
// XOR decode stub — key=0x{key:02x}
void decode(unsigned char *buf, int len) {{
    for (int i = 0; i < len; i++) buf[i] ^= 0x{key:02x};
}}
"""
        return stub_c.encode()
