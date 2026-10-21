"""
embedxpl/modules/creds/routers/crypto/zte_config_decrypt.py

ZTE Router Configuration Backup Decryptor.

Decrypts ZTE router configuration backup files that use AES-256-ECB with
a fixed key, or the older XOR-based obfuscation scheme.

Affected models include: F660, F670, F680, F612W, H108N, H168N, ZXHN H298A,
ZXDSL 831, and many other ZTE GPON ONT and DSL routers.

The F660/F670 series uses AES-256-ECB with a 32-byte fixed key.
Older models use a simple XOR with a repeating key derived from
the router model string.

Based on research from zte-config-utility and rext tools.

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""
from __future__ import annotations

import re
import struct
from typing import Optional

__version__ = "1.0.0"

try:
    from Crypto.Cipher import AES
    _AES_AVAILABLE = True
except ImportError:
    _AES_AVAILABLE = False

# Fixed AES-256 key for ZTE F660/F670 series
_ZTE_AES_KEY = bytes.fromhex(
    "4D4F4F4E0000000000000000000000"
    "0000000000000000000000000000000000"
    "00"
)[:32]

# Alternative keys found in different firmware versions
_ZTE_AES_KEYS = [
    b"MIIBIjANBgkqhkiG9w0B"[:32].ljust(32, b"\x00"),
    b"MOON" + b"\x00" * 28,
    b"ZTE%FN$GponNJ025" + b"\x00" * 16,
]

# XOR key for older ZTE models
_ZTE_XOR_KEY = b"ZTE"


def _xor_decrypt(data: bytes, key: bytes) -> bytes:
    """Simple XOR decryption with repeating key."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def decrypt_aes_config(data: bytes, key: Optional[bytes] = None) -> Optional[bytes]:
    """Decrypt ZTE config backup using AES-256-ECB.

    Args:
        data: raw bytes from the config backup file.
        key: 32-byte AES key (tries known keys if None).

    Returns:
        Decrypted config XML/text, or None on failure.
    """
    if not _AES_AVAILABLE:
        return None

    if len(data) < 32:
        return None

    # Some ZTE configs have a 4-byte or 8-byte header
    offsets = [0, 4, 8, 16]

    keys_to_try = [key] if key else _ZTE_AES_KEYS

    for k in keys_to_try:
        if k is None or len(k) < 32:
            continue
        for offset in offsets:
            encrypted = data[offset:]
            if len(encrypted) < 16:
                continue
            if len(encrypted) % 16 != 0:
                encrypted = encrypted[: len(encrypted) - (len(encrypted) % 16)]

            try:
                cipher = AES.new(k[:32], AES.MODE_ECB)
                decrypted = cipher.decrypt(encrypted)
            except (ValueError, KeyError):
                continue

            try:
                text = decrypted.decode("utf-8", errors="replace")
            except UnicodeDecodeError:
                continue

            if any(marker in text for marker in ("<?xml", "<config", "SSID", "password", "admin", "<db_")):
                return decrypted

    return None


def decrypt_xor_config(data: bytes, key: bytes = _ZTE_XOR_KEY) -> Optional[bytes]:
    """Decrypt ZTE config using XOR obfuscation (older models).

    Args:
        data: raw bytes from the config backup file.
        key: XOR key bytes.

    Returns:
        Decrypted config text, or None on failure.
    """
    decrypted = _xor_decrypt(data, key)
    try:
        text = decrypted.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return None

    if any(marker in text for marker in ("<?xml", "<config", "SSID", "password", "admin")):
        return decrypted

    return None


def auto_decrypt(data: bytes) -> Optional[tuple[bytes, str]]:
    """Try all known ZTE decryption methods.

    Returns:
        Tuple of (decrypted_data, method_description) or None.
    """
    result = decrypt_aes_config(data)
    if result is not None:
        return result, "AES-256-ECB (ZTE GPON)"

    result = decrypt_xor_config(data)
    if result is not None:
        return result, "XOR obfuscation (ZTE legacy)"

    # Try common model-specific XOR keys
    for model_key in [b"H108N", b"H168N", b"H298A", b"ZXDSL"]:
        result = decrypt_xor_config(data, model_key)
        if result is not None:
            return result, f"XOR key={model_key!r}"

    return None


def extract_credentials(config_text: str) -> list[dict[str, str]]:
    """Extract credentials from decrypted ZTE config.

    Returns:
        List of dicts with keys: type, context, value.
    """
    creds: list[dict[str, str]] = []
    patterns = [
        (r"<AdminPassword>([^<]+)</AdminPassword>", "admin_password"),
        (r"<UserPassword>([^<]+)</UserPassword>", "user_password"),
        (r"<PPPoEPassword>([^<]+)</PPPoEPassword>", "pppoe_password"),
        (r"<PPPoEUserName>([^<]+)</PPPoEUserName>", "pppoe_username"),
        (r"<PreSharedKey>([^<]+)</PreSharedKey>", "wifi_psk"),
        (r"<KeyPassphrase>([^<]+)</KeyPassphrase>", "wifi_passphrase"),
        (r"<WEPKey>([^<]+)</WEPKey>", "wifi_wep"),
        (r"<TelnetPassword>([^<]+)</TelnetPassword>", "telnet_password"),
        (r"<FTPPassword>([^<]+)</FTPPassword>", "ftp_password"),
        (r"<TR069Password>([^<]+)</TR069Password>", "tr069_password"),
        (r"<SSID>([^<]+)</SSID>", "wifi_ssid"),
        (r'password="([^"]+)"', "password_attr"),
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

    outpath = filepath + ".decrypted"
    with open(outpath, "wb") as f:
        f.write(decrypted)
    print(f"\n[+] Decrypted config saved to: {outpath}")
