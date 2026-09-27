"""RC4 stream cipher encoder.

Cifra o payload com RC4 (ARCFOUR). Chave configurável (default: aleatória de 16 bytes).
Bypassa AVs sem descriptografia de RC4 no engine de scan.
"""

import os
from embedxpl.core.exploit.encoder import BaseEncoder


def _rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    out = []
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


class Encoder(BaseEncoder):
    name        = "rc4/rc4"
    description = "RC4 stream cipher encoder — key prepended to output"
    arch        = ["armle", "armbe", "arm64", "mipsbe", "mipsle", "x64", "x86",
                   "riscv32", "ppc", "generic"]
    platform    = ["linux", "windows", "macos", "firmware"]
    evasion_score = 6

    options = {
        "KEY": {
            "description": "RC4 key (hex string, leave empty for random 16-byte key)",
            "required": False,
            "default": "",
            "value": "",
        },
        "KEY_SIZE": {
            "description": "Size of random key in bytes (used if KEY is empty)",
            "required": False,
            "default": "16",
            "value": "16",
        },
    }

    def _get_key(self) -> bytes:
        key_hex = str(self.options["KEY"]["value"]).strip()
        if key_hex:
            return bytes.fromhex(key_hex)
        size = int(self.options["KEY_SIZE"]["value"])
        return os.urandom(size)

    def encode(self, payload: bytes) -> bytes:
        key = self._get_key()
        encrypted = _rc4(key, payload)
        # Formato: [1 byte key_len][key][encrypted_payload]
        return bytes([len(key)]) + key + encrypted

    def decode_stub(self, arch: str = "x64") -> bytes:
        stub_c = """
// RC4 decode stub
#include <string.h>
void rc4_decode(unsigned char *buf, int total_len) {
    int klen = buf[0];
    unsigned char *key = buf + 1;
    unsigned char *data = buf + 1 + klen;
    int dlen = total_len - 1 - klen;
    unsigned char S[256]; int i, j = 0, t;
    for (i = 0; i < 256; i++) S[i] = i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) % 256;
        t = S[i]; S[i] = S[j]; S[j] = t;
    }
    i = j = 0;
    for (int k = 0; k < dlen; k++) {
        i = (i+1)%256; j = (j+S[i])%256;
        t = S[i]; S[i] = S[j]; S[j] = t;
        data[k] ^= S[(S[i]+S[j])%256];
    }
}
"""
        return stub_c.encode()
