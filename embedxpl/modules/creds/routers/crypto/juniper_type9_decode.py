"""
embedxpl/modules/creds/routers/crypto/juniper_type9_decode.py

Juniper $9$ Password Decoder.

Decodes Juniper Networks $9$ encoded passwords found in Junos OS
configuration files. The $9$ format uses a multi-character substitution
cipher with a per-password random salt prefix.

Format: $9$<salt><encoded_chars>
The salt length determines the encoding rounds. Each character maps
through Juniper's custom alphabet, then XOR'd with the previous output
and a position-dependent key derived from the alphabet.

Commonly seen in: set system login user ... authentication encrypted-password,
set snmp community ..., set routing-options ... authentication-key.

Note: $9$ passwords with 1-char salt use "single nibble" decoding.
Most modern Junos uses 3-char salt.

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""
from __future__ import annotations

import re
from typing import Optional

__version__ = "1.0.0"

_FAMILY = [
    "QzF3n6/9CAtpu0O",
    "B1IREhcSyrleKvMW8LXx",
    "7N-dVbwsY2g4oaJZGUDj",
    "iHkq.mPf5T",
]

_EXTRA: dict[int, list[int]] = {}

_NUM_ALPHA = "".join(_FAMILY)
_ALPHA_NUM: dict[str, int] = {}
for _i, _c in enumerate(_NUM_ALPHA):
    _ALPHA_NUM[_c] = _i

_ENCODING = [
    [1, 4, 32],
    [1, 16, 32],
    [1, 8, 32],
    [1, 64],
    [1, 32],
    [1, 4, 16, 128],
    [1, 32, 64],
]


def _nibble(cref: list[str], length: int) -> int:
    nib = 0
    for _ in range(length):
        if not cref:
            return 0
        c = cref.pop(0)
        nib = (nib << 6) | _ALPHA_NUM.get(c, 0)
    return nib


def _gap(cref: list[str], enc_list: list[int]) -> int:
    num = 0
    for enc in enc_list:
        if not cref:
            break
        c = cref.pop(0)
        val = _ALPHA_NUM.get(c, 0)
        gap_val = val % enc
        num += gap_val
    return num % 256


def decode_type9(encoded: str) -> Optional[str]:
    """Decode a Juniper $9$ password.

    Args:
        encoded: full $9$ string, e.g. "$9$YGFn/9CRhclW87Ndbs4aZ".

    Returns:
        Decoded plaintext, or None if the format is invalid.
    """
    encoded = encoded.strip()
    if not encoded.startswith("$9$"):
        return None

    payload = encoded[3:]
    if not payload:
        return None

    chars = list(payload)

    # first char is random salt (discarded)
    if not chars:
        return None
    _salt = chars.pop(0)

    # second and third chars are also salt (discarded)
    if len(chars) >= 2:
        chars.pop(0)
        chars.pop(0)

    result = []
    enc_idx = 0
    while chars:
        enc = _ENCODING[enc_idx % len(_ENCODING)]
        try:
            val = _gap(chars, enc)
        except (IndexError, KeyError):
            break
        result.append(chr(val))
        enc_idx += 1

    return "".join(result) if result else None


def decode_config_passwords(config_text: str) -> list[dict[str, str]]:
    """Extract and decode all $9$ passwords from a Junos config.

    Returns:
        List of dicts with keys: line, context, encoded, decoded.
    """
    results = []
    pattern = re.compile(r'(\$9\$[A-Za-z0-9./\-]+)')
    for line_num, line in enumerate(config_text.splitlines(), 1):
        for match in pattern.finditer(line):
            encoded_val = match.group(1)
            decoded = decode_type9(encoded_val)
            if decoded is not None:
                results.append({
                    "line": str(line_num),
                    "context": line.strip(),
                    "encoded": encoded_val,
                    "decoded": decoded,
                })
    return results


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <$9$hash> [<$9$hash> ...]")
        sys.exit(1)

    for arg in sys.argv[1:]:
        result = decode_type9(arg)
        if result is not None:
            print(f"{arg} -> {result}")
        else:
            print(f"{arg} -> [invalid format]")
