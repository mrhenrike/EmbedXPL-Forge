"""
embedxpl/modules/creds/routers/crypto/cisco_type7_decode.py

Cisco Type 7 Password Decoder.

Decodes Cisco IOS Type 7 encoded passwords found in running-config and
startup-config files. Type 7 uses a Vigenere-like XOR cipher with a fixed
key, providing only obfuscation (not real encryption).

The encoding format is: <2-digit-seed><hex-encoded-xored-bytes>
where the seed (00-15) selects the starting offset in the XOR key.

Commonly seen in: "password 7 ...", "enable password 7 ...",
"username ... password 7 ...", SNMP community strings.

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""
from __future__ import annotations

import re
from typing import Optional

__version__ = "1.0.0"

_XLAT = [
    0x64, 0x73, 0x66, 0x64, 0x3B, 0x6B, 0x66, 0x6F,
    0x41, 0x2C, 0x2E, 0x69, 0x79, 0x65, 0x77, 0x72,
    0x6B, 0x6C, 0x64, 0x4A, 0x4B, 0x44, 0x48, 0x53,
    0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36,
    0x39, 0x38, 0x33, 0x34, 0x6E, 0x63, 0x78, 0x76,
    0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6B,
    0x3B, 0x66, 0x67, 0x38, 0x37,
]

_TYPE7_RE = re.compile(r"^([0-9]{2})([0-9A-Fa-f]+)$")


def decode_type7(encoded: str) -> Optional[str]:
    """Decode a single Cisco Type 7 password string.

    Args:
        encoded: the Type 7 hash, e.g. "104D000A0618" or "0822455D0A16".

    Returns:
        Decoded plaintext, or None if the input is malformed.
    """
    encoded = encoded.strip()
    m = _TYPE7_RE.match(encoded)
    if not m:
        return None

    seed = int(m.group(1))
    hex_data = m.group(2)
    if len(hex_data) % 2 != 0:
        return None
    if seed > 15:
        return None

    result = []
    for i in range(0, len(hex_data), 2):
        byte_val = int(hex_data[i : i + 2], 16)
        key_idx = (seed + i // 2) % len(_XLAT)
        result.append(chr(byte_val ^ _XLAT[key_idx]))

    return "".join(result)


def decode_config_passwords(config_text: str) -> list[dict[str, str]]:
    """Extract and decode all Type 7 passwords from a Cisco config dump.

    Searches for patterns like:
        password 7 <hash>
        enable password 7 <hash>
        username <name> password 7 <hash>
        snmp-server community 7 <hash>

    Returns:
        List of dicts with keys: line, context, encoded, decoded.
    """
    results = []
    pattern = re.compile(
        r"(?:password|secret)\s+7\s+([0-9A-Fa-f]+)"
        r"|community\s+7\s+([0-9A-Fa-f]+)",
        re.IGNORECASE,
    )
    for line_num, line in enumerate(config_text.splitlines(), 1):
        for match in pattern.finditer(line):
            encoded_val = match.group(1) or match.group(2)
            decoded = decode_type7(encoded_val)
            if decoded is not None:
                results.append({
                    "line": str(line_num),
                    "context": line.strip(),
                    "encoded": encoded_val,
                    "decoded": decoded,
                })
    return results


def encode_type7(plaintext: str, seed: int = 0) -> str:
    """Encode a plaintext password into Cisco Type 7 format.

    Useful for testing and round-trip verification.

    Args:
        plaintext: the password to encode.
        seed: starting key offset (0-15).

    Returns:
        Type 7 encoded string.
    """
    if not 0 <= seed <= 15:
        seed = 0
    result = [f"{seed:02d}"]
    for i, ch in enumerate(plaintext):
        key_idx = (seed + i) % len(_XLAT)
        result.append(f"{ord(ch) ^ _XLAT[key_idx]:02X}")
    return "".join(result)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <type7_hash> [<type7_hash> ...]")
        print(f"       {sys.argv[0]} --encode <password> [--seed N]")
        sys.exit(1)

    if sys.argv[1] == "--encode":
        pwd = sys.argv[2] if len(sys.argv) > 2 else ""
        s = int(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[3] == "--seed" else 0
        print(encode_type7(pwd, s))
    else:
        for arg in sys.argv[1:]:
            result = decode_type7(arg)
            if result is not None:
                print(f"{arg} -> {result}")
            else:
                print(f"{arg} -> [invalid format]")
