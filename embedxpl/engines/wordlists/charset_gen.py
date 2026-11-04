"""
charset_gen.py - Wordlist generation by charset and pattern (Crunch-style).

Supports:
  - Crunch-style placeholders: @ lowercase, , uppercase, % digits, ^ specials
  - Hashcat-style masks: ?u ?l ?d ?s ?a ?b at any position
  - Constrained composition generation: N digits + M lowercase at length L
  - Built-in charsets: alpha, ualpha, lalpha, numeric, mixalpha, mixalpha-numeric
  - External charset files (.cfg) with named charsets
  - Phone mode: Brazilian phone number generation with area codes (DDDs)
  - Size estimation before generating
  - Interactive wizard to create charset files (--create-charset)

Examples:
  wlf.py charset 6 8 abc123
  wlf.py charset 8 8 -p "@,%,^" --pattern "Pass@@@%%%"
  wlf.py charset 8 8 --mask "?u?l?l?l?d?d?s"
  wlf.py charset 8 8 --digits 2 --lower 4 --upper 1 --special 1
  wlf.py charset 10 10 -t phone --prefix "+5511"
  wlf.py charset 6 8 -f my_charsets.cfg mixalpha-numeric
  wlf.py charset --create-charset my_charsets.cfg

Author: André Henrique (@mrhenrike)
Version: 1.1.0
"""
from __future__ import annotations

import logging
from configparser import ConfigParser
from itertools import permutations, product
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

# ── Charsets built-in ────────────────────────────────────────────────────────

BUILTIN_CHARSETS: dict[str, str] = {
    "lalpha":          "abcdefghijklmnopqrstuvwxyz",
    "ualpha":          "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alpha":           "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "numeric":         "0123456789",
    "mixalpha":        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "mixalpha-numeric": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "special":         "!@#$%^&*()-_+=~`[]{}|\\:;\"'<>,.?/",
    "mixalpha-numeric-special":
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=",
    "pt-br-accented":  "abcdefghijklmnopqrstuvwxyzàáâãéêíóôõúüç",
    "hex-lower":       "0123456789abcdef",
    "hex-upper":       "0123456789ABCDEF",
}

# Mapeamento de placeholders estilo Crunch
PLACEHOLDER_MAP: dict[str, str] = {
    "@": BUILTIN_CHARSETS["lalpha"],
    ",": BUILTIN_CHARSETS["ualpha"],
    "%": BUILTIN_CHARSETS["numeric"],
    "^": BUILTIN_CHARSETS["special"],
}

# Mapeamento de placeholders estilo Hashcat (?u ?l ?d ?s ?a)
HASHCAT_MASK_MAP: dict[str, str] = {
    "?u": BUILTIN_CHARSETS["ualpha"],
    "?l": BUILTIN_CHARSETS["lalpha"],
    "?d": BUILTIN_CHARSETS["numeric"],
    "?s": BUILTIN_CHARSETS["special"],
    "?a": BUILTIN_CHARSETS["mixalpha-numeric-special"],
    "?h": "0123456789abcdef",
    "?H": "0123456789ABCDEF",
}

# DDDs brasileiros para modo phone
DDDS_BR = [
    "11", "12", "13", "14", "15", "16", "17", "18", "19",
    "21", "22", "24", "27", "28",
    "31", "32", "33", "34", "35", "37", "38",
    "41", "42", "43", "44", "45", "46", "47", "48", "49",
    "51", "53", "54", "55",
    "61", "62", "63", "64", "65", "66", "67", "68", "69",
    "71", "73", "74", "75", "77", "79",
    "81", "82", "83", "84", "85", "86", "87", "88", "89",
    "91", "92", "93", "94", "95", "96", "97", "98", "99",
]


def load_charset_file(filepath: str, charset_name: str) -> str:
    """
    Load a named charset from a .cfg file.

    File format:
      [mixalpha-numeric]
      abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789

    Args:
        filepath: Path to the .cfg file.
        charset_name: Name of the charset to load.

    Returns:
        String containing the charset characters.

    Raises:
        FileNotFoundError: If the file does not exist.
        KeyError: If charset_name is not found in the file.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Charset file not found: {filepath}")

    cfg = ConfigParser()
    cfg.read(str(path), encoding="utf-8")

    if charset_name not in cfg:
        available = list(cfg.sections())
        raise KeyError(
            f"Charset '{charset_name}' not found in {filepath}. "
            f"Available: {available}"
        )

    # The charset value is the first key in the section (may span multiple lines)
    section = cfg[charset_name]
    chars = ""
    for key in section:
        chars += key + section[key]

    return chars.replace("\n", "").replace("\r", "")


def get_charset(
    charset: str,
    charset_file: Optional[str] = None,
) -> str:
    """
    Resolve a charset by name (built-in or from an external file).

    Args:
        charset: Charset name or direct character string.
        charset_file: Optional path to a .cfg file.

    Returns:
        String of unique charset characters.
    """
    if charset_file:
        return load_charset_file(charset_file, charset)
    if charset in BUILTIN_CHARSETS:
        return BUILTIN_CHARSETS[charset]
    # Treat as a direct character string
    return "".join(dict.fromkeys(charset))


def estimate_size(charset_len: int, min_len: int, max_len: int) -> tuple[int, str]:
    """
    Estimate the number of words and disk size before generating.

    Args:
        charset_len: Charset size.
        min_len: Minimum length.
        max_len: Maximum length.

    Returns:
        Tuple (total_words, formatted_size).
    """
    total = sum(charset_len ** length for length in range(min_len, max_len + 1))
    # Bytes estimate: average word length + newline
    avg_len = (min_len + max_len) / 2
    bytes_est = total * (avg_len + 1)

    if bytes_est < 1024:
        size_str = f"{bytes_est:.0f} B"
    elif bytes_est < 1024**2:
        size_str = f"{bytes_est/1024:.1f} KB"
    elif bytes_est < 1024**3:
        size_str = f"{bytes_est/1024**2:.1f} MB"
    elif bytes_est < 1024**4:
        size_str = f"{bytes_est/1024**3:.1f} GB"
    else:
        size_str = f"{bytes_est/1024**4:.1f} TB"

    return total, size_str


def generate_by_charset(
    charset: str,
    min_len: int,
    max_len: int,
) -> Generator[str, None, None]:
    """
    Generate all character combinations from charset for lengths min..max.

    Args:
        charset: Character string to use.
        min_len: Minimum length.
        max_len: Maximum length.

    Yields:
        Generated strings in lexicographic order.
    """
    chars = list(dict.fromkeys(charset))
    for length in range(min_len, max_len + 1):
        for combo in product(chars, repeat=length):
            yield "".join(combo)


def generate_by_pattern(
    pattern: str,
    charset_file: Optional[str] = None,
    extra_charset: Optional[str] = None,
) -> Generator[str, None, None]:
    """
    Generate strings from a pattern with placeholders.

    Supported placeholders (Crunch-style):
      @  -> lowercase letters
      ,  -> uppercase letters
      %  -> digits
      ^  -> special characters
      ?  -> custom (requires extra_charset)

    Literal characters are kept as-is.

    Args:
        pattern: Pattern string with placeholders.
        charset_file: Charset file for additional lookup.
        extra_charset: Extra charset for the '?' placeholder.

    Yields:
        Strings generated by the pattern.
    """
    slots: list[list[str]] = []
    for ch in pattern:
        if ch in PLACEHOLDER_MAP:
            slots.append(list(PLACEHOLDER_MAP[ch]))
        elif ch == "?" and extra_charset:
            slots.append(list(dict.fromkeys(extra_charset)))
        else:
            slots.append([ch])

    for combo in product(*slots):
        yield "".join(combo)


def generate_phone_numbers(
    prefix: str = "+55",
    ddds: Optional[list[str]] = None,
) -> Generator[str, None, None]:
    """
    Generate Brazilian phone numbers with area codes (DDDs).

    Args:
        prefix: International prefix (e.g. '+55', '0055').
        ddds: List of DDDs; if None, uses all Brazilian DDDs.

    Yields:
        Formatted phone numbers.
    """
    ddd_list = ddds or DDDS_BR
    for ddd in ddd_list:
        # Mobile: 9XXXX-XXXX (9 digits)
        for i in product("0123456789", repeat=8):
            yield f"{prefix}{ddd}9{''.join(i)}"
        # Landline: XXXX-XXXX (8 digits)
        for i in product("0123456789", repeat=8):
            yield f"{prefix}{ddd}{''.join(i)}"


def generate_by_mask(
    mask: str,
    custom_charset: Optional[str] = None,
) -> Generator[str, None, None]:
    """
    Generate a wordlist from a Hashcat-style mask.

    Supported tokens:
      ?u  → uppercase letters (A-Z)
      ?l  → lowercase letters (a-z)
      ?d  → digits (0-9)
      ?s  → special chars (!@#$%...)
      ?a  → all printable (alpha+digits+special)
      ?h  → hex lowercase (0-9a-f)
      ?H  → hex uppercase (0-9A-F)
      ?1  → custom charset (requires custom_charset)
      Any other char → literal

    Args:
        mask: Mask string (e.g. "?u?l?l?l?d?d?s").
        custom_charset: Charset for ?1 (user-defined).

    Yields:
        Generated strings.

    Examples:
        generate_by_mask("?u?l?l?d?d")   # Aabb12-style
        generate_by_mask("Pass?d?d?d?d") # Pass0000..Pass9999
    """
    slots: list[list[str]] = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            token = mask[i : i + 2]
            if token in HASHCAT_MASK_MAP:
                slots.append(list(HASHCAT_MASK_MAP[token]))
                i += 2
                continue
            elif token == "?1" and custom_charset:
                slots.append(list(dict.fromkeys(custom_charset)))
                i += 2
                continue
        slots.append([mask[i]])
        i += 1

    for combo in product(*slots):
        yield "".join(combo)


def estimate_mask_size(mask: str, custom_charset: Optional[str] = None) -> tuple[int, str]:
    """
    Estimate the number of entries for a Hashcat mask.

    Args:
        mask: Hashcat-style mask string.
        custom_charset: Charset for ?1.

    Returns:
        Tuple (total_entries, formatted_size).
    """
    slot_sizes: list[int] = []
    i = 0
    fixed_len = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            token = mask[i : i + 2]
            if token in HASHCAT_MASK_MAP:
                slot_sizes.append(len(HASHCAT_MASK_MAP[token]))
                i += 2
                continue
            elif token == "?1" and custom_charset:
                slot_sizes.append(len(dict.fromkeys(custom_charset)))
                i += 2
                continue
        slot_sizes.append(1)  # literal
        fixed_len += 1
        i += 1

    total = 1
    for s in slot_sizes:
        total *= s

    mask_len = len(slot_sizes)
    bytes_est = total * (mask_len + 1)
    if bytes_est < 1024:
        size_str = f"{bytes_est:.0f} B"
    elif bytes_est < 1024**2:
        size_str = f"{bytes_est/1024:.1f} KB"
    elif bytes_est < 1024**3:
        size_str = f"{bytes_est/1024**2:.1f} MB"
    elif bytes_est < 1024**4:
        size_str = f"{bytes_est/1024**3:.1f} GB"
    else:
        size_str = f"{bytes_est/1024**4:.1f} TB"

    return total, size_str


def generate_constrained(
    length: int,
    n_digits: int = 0,
    n_lower: int = 0,
    n_upper: int = 0,
    n_special: int = 0,
) -> Generator[str, None, None]:
    """
    Generate combinations with an exact character-type composition.

    Guarantees exactly N digits, M lowercase, K uppercase, and P specials
    within total length L. Useful for satisfying password policies.

    Args:
        length: Total password length.
        n_digits: Exact number of digits.
        n_lower: Exact number of lowercase letters.
        n_upper: Exact number of uppercase letters.
        n_special: Exact number of special characters.

    Yields:
        Strings with the specified composition.

    Raises:
        ValueError: If the sum of constraints exceeds the total length.

    Examples:
        generate_constrained(8, n_digits=2, n_lower=4, n_upper=1, n_special=1)
    """
    required = n_digits + n_lower + n_upper + n_special
    free = length - required
    if free < 0:
        raise ValueError(
            f"Constraints sum to {required} but length is {length}. "
            "Reduce counts or increase the length."
        )

    digits_chars = list(BUILTIN_CHARSETS["numeric"])
    lower_chars = list(BUILTIN_CHARSETS["lalpha"])
    upper_chars = list(BUILTIN_CHARSETS["ualpha"])
    special_chars = list(BUILTIN_CHARSETS["special"])
    all_chars = list(BUILTIN_CHARSETS["mixalpha-numeric-special"])

    # Each position slot → possible charsets; build pool based on constraints
    slot_pools: list[list[str]] = []
    slot_pools.extend([digits_chars] * n_digits)
    slot_pools.extend([lower_chars] * n_lower)
    slot_pools.extend([upper_chars] * n_upper)
    slot_pools.extend([special_chars] * n_special)
    slot_pools.extend([all_chars] * free)

    # Generate all slot-position permutations
    seen: set[str] = set()
    n_slots = len(slot_pools)

    for pos_order in set(permutations(range(n_slots))):
        ordered_pools = [slot_pools[i] for i in pos_order]
        for combo in product(*ordered_pools):
            word = "".join(combo)
            if word not in seen:
                seen.add(word)
                yield word


def estimate_constrained_size(
    length: int,
    n_digits: int = 0,
    n_lower: int = 0,
    n_upper: int = 0,
    n_special: int = 0,
) -> tuple[int, str]:
    """
    Estimate the number of entries for constrained composition generation.

    Args:
        length: Total length.
        n_digits: Required digit count.
        n_lower: Required lowercase count.
        n_upper: Required uppercase count.
        n_special: Required special-character count.

    Returns:
        Tuple (estimated_total, formatted_size).
    """
    from math import factorial

    d = len(BUILTIN_CHARSETS["numeric"])
    l_ = len(BUILTIN_CHARSETS["lalpha"])
    u = len(BUILTIN_CHARSETS["ualpha"])
    s = len(BUILTIN_CHARSETS["special"])
    a = len(BUILTIN_CHARSETS["mixalpha-numeric-special"])
    free = length - n_digits - n_lower - n_upper - n_special

    if free < 0:
        return 0, "0 B"

    # Value combinations × position permutations
    value_combos = (d ** n_digits) * (l_ ** n_lower) * (u ** n_upper) * (s ** n_special) * (a ** free)

    # Multinomial coefficient for position arrangements
    total_slots = n_digits + n_lower + n_upper + n_special + free
    denom = factorial(n_digits) * factorial(n_lower) * factorial(n_upper) * factorial(n_special) * factorial(free)
    arrangements = factorial(total_slots) // denom

    total = value_combos * arrangements
    bytes_est = total * (length + 1)
    if bytes_est < 1024:
        size_str = f"{bytes_est:.0f} B"
    elif bytes_est < 1024**2:
        size_str = f"{bytes_est/1024:.1f} KB"
    elif bytes_est < 1024**3:
        size_str = f"{bytes_est/1024**2:.1f} MB"
    elif bytes_est < 1024**4:
        size_str = f"{bytes_est/1024**3:.1f} GB"
    else:
        size_str = f"{bytes_est/1024**4:.1f} TB"

    return total, size_str


def create_charset_wizard(output_file: str) -> None:
    """
    Interactive wizard to create a .cfg charset file.

    Guides the user through defining named charsets and saves
    the result in .cfg format compatible with wlf.py.

    Args:
        output_file: Output file path.
    """
    print("\n=== Charset File Creation Wizard ===\n")
    print(f"Destination: {output_file}")
    print("Define named charsets. Type 'done' to finish.\n")

    charsets: dict[str, str] = {}

    while True:
        name = input("Charset name (e.g. 'mixalpha', 'custom-corp', or 'done' to finish): ").strip()
        if name.lower() in ("done", "fim"):
            break
        if not name:
            print("Name cannot be empty.")
            continue
        chars = input(f"Characters for '{name}': ").strip()
        if not chars:
            print("Charset cannot be empty.")
            continue
        charsets[name] = "".join(dict.fromkeys(chars))
        print(f"  OK '{name}' with {len(charsets[name])} unique characters.\n")

    if not charsets:
        print("No charsets defined. Aborting.")
        return

    lines = []
    for name, chars in charsets.items():
        lines.append(f"[{name}]")
        lines.append(chars)
        lines.append("")

    Path(output_file).write_text("\n".join(lines), encoding="utf-8")
    print(f"\nCharset file saved to: {output_file}")
    print(f"Charsets created: {list(charsets.keys())}")
    print(f"\nUsage: wlf.py charset 6 8 -f {output_file} <charset_name>")
