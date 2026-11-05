"""
xor_crypto.py - XOR encryption and key brute-force tool.

Python 3 port of the original decriptorxor.py (Python 2).
Features:
  - XOR encryption with arbitrary key
  - XOR decryption with known key
  - Single-byte XOR key brute-force (256 attempts)
  - Readable text scoring to identify correct result

Usage:
  wlf.py xor --brute HEXSTRING
  wlf.py xor --encrypt "text" --key "key"
  wlf.py xor --decrypt HEXSTRING --key "key"

Author: Andre Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Readable text charset for scoring
_READABLE_CHARSET = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    ".,\"-+_?/'\n !@#$%&*()[]{}:;<>"
)


def score_text(text: str) -> int:
    """
    Calculate readability score for a text.

    Higher score means more readable text (more chars from the charset).

    Args:
        text: String to evaluate.

    Returns:
        Number of readable characters in the text.
    """
    return sum(1 for ch in text if ch in _READABLE_CHARSET)


def xor_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt bytes with XOR key (repeating key).

    Args:
        ciphertext: Encrypted bytes.
        key: XOR key (any length).

    Returns:
        Decrypted bytes.
    """
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(ciphertext))


def xor_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt bytes with XOR key (repeating key).

    Args:
        plaintext: Plaintext bytes.
        key: XOR key (any length).

    Returns:
        Encrypted bytes.
    """
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(plaintext))


def xor_encrypt_str(plaintext: str, key: str, encoding: str = "utf-8") -> bytes:
    """
    Encrypt a string with XOR key.

    Args:
        plaintext: Plaintext string.
        key: Key as string.
        encoding: Encoding for conversion.

    Returns:
        Encrypted bytes.
    """
    return xor_encrypt(plaintext.encode(encoding), key.encode(encoding))


def xor_decrypt_str(ciphertext: bytes, key: str, encoding: str = "utf-8") -> str:
    """
    Decrypt bytes with XOR key and return string.

    Args:
        ciphertext: Encrypted bytes.
        key: Key as string.
        encoding: Encoding for decoding the result.

    Returns:
        Decrypted text (errors replaced).
    """
    decrypted = xor_decrypt(ciphertext, key.encode(encoding))
    return decrypted.decode(encoding, errors="replace")


def brute_force_single_byte(hex_string: str) -> list[dict]:
    """
    Single-byte XOR key brute-force over hex data.

    Tests all 256 possible single-byte key values and
    ranks results by readability score.

    Args:
        hex_string: Hex string of encrypted data (e.g. "1a2b3c4d").

    Returns:
        List of dicts with 'key', 'key_char', 'score', 'result',
        sorted by descending score. Includes only top 10.
    """
    try:
        data = bytes.fromhex(hex_string.strip())
    except ValueError as exc:
        logger.error("Invalid hex: %s", exc)
        return []

    candidates: list[dict] = []

    for key_byte in range(256):
        key = bytes([key_byte])
        decrypted = xor_decrypt(data, key)
        try:
            text = decrypted.decode("utf-8", errors="replace")
        except Exception:
            text = decrypted.decode("latin-1", errors="replace")

        s = score_text(text)
        candidates.append({
            "key": key_byte,
            "key_char": chr(key_byte) if 32 <= key_byte < 127 else f"0x{key_byte:02X}",
            "score": s,
            "result": text,
        })

    candidates.sort(key=lambda x: x["score"], reverse=True)
    return candidates[:10]


def brute_force_display(hex_string: str) -> None:
    """
    Executa brute-force e exibe os melhores resultados no terminal.

    Args:
        hex_string: String hexadecimal dos dados cifrados.
    """
    results = brute_force_single_byte(hex_string)
    if not results:
        print("Nenhum resultado. Verifique o hex fornecido.")
        return

    print(f"\n=== XOR Brute-Force - Top {len(results)} resultados ===\n")
    for i, r in enumerate(results, 1):
        print(f"#{i:2d}  Key=0x{r['key']:02X} ({r['key_char']!r:5s})  Score={r['score']:4d}  Result: {r['result'][:80]!r}")
