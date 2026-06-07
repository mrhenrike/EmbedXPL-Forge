"""
embedxpl/modules/firmware/huawei/huawei_password_derive.py

Huawei Router Password Encryption/Decryption.

Native Python reimplementation of the Huawei router password crypto from
HuaweiPasswordTool (submodules/IoT/third-party-router-poc/HuaweiPasswordTool/).

Supports:
  $1 format: AES-256 ECB with random per-block salt injection
  $2 format: AES-256 CBC with whitebox key derivation (partial - key pattern analysis)

The encrypted passwords are found in Huawei router configuration files
(backup.cfg, config.xml) in the format: $1<encoded_data>$ or $2<encoded_data>$

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import os
import struct
from typing import Optional

try:
    from Crypto.Cipher import AES  # pycryptodome / pycryptodomex
    _AES_AVAILABLE = True
except ImportError:
    _AES_AVAILABLE = False

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Known Huawei crypto constants (extracted from HuaweiPasswordTool rev_hw.cpp)
# ---------------------------------------------------------------------------

# Format $1: AES-256 ECB base key (32 bytes)
_KEY_AES256 = bytes.fromhex(
    "b8363c9b77daed4b9abb9f2f6df5f1d5"
    "cb64975d5d3bcee8827f2f42235f9229"
)

# Salt injection positions in the 32-byte key
_SALT_POSITIONS = [0x0B, 0x11, 0x17, 0x1D]  # = 11, 17, 23, 29

# Format $2: known string key (part of CBC key derivation)
_STR_KEY_2 = b"Df7!ui%s9(lmV1L8"


# ---------------------------------------------------------------------------
# Base-93 encoding (Huawei "AesEnhSys" encoding)
# ---------------------------------------------------------------------------

def _long_to_base93(n: int) -> bytes:
    """Encode 32-bit integer to 5 bytes in base-93 (little-endian)."""
    result = []
    for _ in range(5):
        result.append(n % 93)
        n //= 93
    return bytes(result)


def _base93_to_long(b: bytes) -> int:
    """Decode 5 bytes from base-93 to 32-bit integer (little-endian)."""
    n = 0
    mul = 1
    for i in range(5):
        n += mul * b[i]
        mul *= 93
    return n & 0xFFFFFFFF


def _bin_to_plain(data: bytes) -> bytes:
    """Convert 16 AES bytes -> 20 base-93 encoded bytes (4 x 4->5)."""
    result = b""
    for i in range(4):
        val = struct.unpack_from("<I", data, i * 4)[0]
        result += _long_to_base93(val)
    return result


def _plain_to_bin(data: bytes) -> bytes:
    """Convert 20 base-93 bytes -> 16 AES bytes (4 x 5->4)."""
    result = b""
    for i in range(4):
        val = _base93_to_long(data[i * 5: i * 5 + 5])
        result += struct.pack("<I", val)
    return result


def _asc_visible(data: bytes) -> bytes:
    """Make binary data ASCII-printable by adding 0x21 (special case: 0x1E -> '~')."""
    return bytes(0x7E if b == 0x1E else (b + 0x21) & 0xFF for b in data)


def _asc_unvisible(data: bytes) -> bytes:
    """Reverse of asc_visible."""
    return bytes(0x1E if b == 0x7E else (b - 0x21) & 0xFF for b in data)


# ---------------------------------------------------------------------------
# Format $1: AES-256 ECB
# ---------------------------------------------------------------------------

def encrypt_format1(plaintext: str) -> str:
    """Encrypt plaintext in Huawei $1 format (AES-256 ECB).

    Args:
        plaintext: Password to encrypt.

    Returns:
        Encrypted password in $1<data>$ format.

    Raises:
        ImportError: If pycryptodome is not installed.
    """
    if not _AES_AVAILABLE:
        raise ImportError("pycryptodome required: pip install pycryptodome")

    pwd_bytes = plaintext.encode("utf-8")
    result = b""

    for i in range(0, max(len(pwd_bytes), 1), 16):
        block = pwd_bytes[i: i + 16].ljust(16, b"\x00")

        # Random salt: 4 bytes each mod 93
        salt = bytes(os.urandom(1)[0] % 93 for _ in range(4))

        # Inject salt into base key
        key = bytearray(_KEY_AES256)
        for j, pos in enumerate(_SALT_POSITIONS):
            key[pos] = salt[j]

        # AES-256 ECB encrypt
        cipher = AES.new(bytes(key), AES.MODE_ECB)
        aes_block = cipher.encrypt(bytes(block))

        # BinToPlain (16 bytes -> 20 bytes) + append salt (4 bytes) = 24 bytes
        plain_encoded = _bin_to_plain(aes_block)
        raw_block = plain_encoded + salt

        # Make printable
        result += _asc_visible(raw_block)

    return f"$1{result.decode('latin-1')}$"


def decrypt_format1(encrypted: str) -> str:
    """Decrypt Huawei $1 format password.

    Args:
        encrypted: Encrypted string in $1<data>$ format.

    Returns:
        Decrypted plaintext password.

    Raises:
        ValueError: If format is invalid.
        ImportError: If pycryptodome is not installed.
    """
    if not _AES_AVAILABLE:
        raise ImportError("pycryptodome required: pip install pycryptodome")

    if not (encrypted.startswith("$1") and encrypted.endswith("$")):
        raise ValueError(f"Invalid $1 format: {encrypted[:20]}")

    enc_data = encrypted[2:-1].encode("latin-1")
    result = b""

    for i in range(0, len(enc_data), 24):
        block = enc_data[i: i + 24]
        if len(block) < 24:
            break

        # Reverse ASCII-visible transform
        raw_block = _asc_unvisible(block)

        # Extract salt (bytes 20-23)
        salt = raw_block[20:24]

        # Rebuild key with salt
        key = bytearray(_KEY_AES256)
        for j, pos in enumerate(_SALT_POSITIONS):
            key[pos] = salt[j]

        # PlainToBin: bytes 0-19 -> 16 AES bytes
        aes_data = _plain_to_bin(raw_block[:20])

        # AES-256 ECB decrypt
        cipher = AES.new(bytes(key), AES.MODE_ECB)
        plain_block = cipher.decrypt(aes_data)
        result += plain_block

    return result.rstrip(b"\x00").decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Auto-detect and dispatch
# ---------------------------------------------------------------------------

def decrypt_password(encrypted: str) -> Optional[str]:
    """Auto-detect format and decrypt Huawei router password.

    Args:
        encrypted: Password in $1..$ or $2..$ format.

    Returns:
        Decrypted plaintext, or None if decryption fails.
    """
    try:
        if encrypted.startswith("$1"):
            return decrypt_format1(encrypted)
        elif encrypted.startswith("$2"):
            # Format $2 requires WBox key derivation - not yet implemented
            # without the wapcbctable lookup (729KB C++ header)
            return None
    except Exception:
        return None
    return None


def is_huawei_encrypted(value: str) -> bool:
    """Return True if string looks like Huawei encrypted password."""
    return (
        len(value) >= 23
        and value.startswith(("$1", "$2"))
        and value.endswith("$")
    )
