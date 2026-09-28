"""
entropy_strength.py - zxcvbn-style password strength and entropy estimation.

Estimates the guessability of a password through pattern matching (common
password dictionary, l33t normalization, sequences, repeats, keyboard walks and
dates), computes an entropy figure and a 0-4 score, and derives time-to-crack
estimates for several attack scenarios and specific hash algorithms. Can also
check exposure against Have I Been Pwned using the k-anonymity range API.

References: Wheeler (zxcvbn), zxcvbn-ts threat model, HIBP Pwned Passwords API.

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import hashlib
import logging
import math
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Small built-in set of the most common passwords (rank approximated by order).
_COMMON = [
    "password", "123456", "123456789", "12345678", "12345", "qwerty",
    "abc123", "football", "monkey", "letmein", "dragon", "111111",
    "baseball", "iloveyou", "master", "sunshine", "ashley", "bailey",
    "passw0rd", "shadow", "superman", "qazwsx", "michael", "welcome",
    "admin", "login", "princess", "solo", "starwars", "trustno1",
    "whatever", "hello", "freedom", "batman", "access", "flower",
    "hottie", "loveme", "zaq1zaq1", "password1", "000000", "654321",
]
_COMMON_RANK = {p: i + 1 for i, p in enumerate(_COMMON)}

_LEET_NORMALIZE = str.maketrans({
    "4": "a", "@": "a", "3": "e", "1": "i", "!": "i", "0": "o",
    "5": "s", "$": "s", "7": "t", "+": "t", "9": "g", "8": "b",
})

_KEYBOARD_ROWS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "!@#$%^&*()",
]

# Guessing rates in guesses per second for common attack scenarios.
_SCENARIOS = {
    "online_throttled_100_per_hour": 100 / 3600,
    "online_no_throttle_10_per_second": 10.0,
    "offline_slow_bcrypt_1e4_per_second": 1e4,
    "offline_fast_md5_1e11_per_second": 1e11,
}

# Guessing rates by hash algorithm on a modern single-GPU rig (order of magnitude).
_HASH_RATES = {
    "ntlm": 1e12,
    "md5": 1e11,
    "sha1": 3e10,
    "sha256": 1e10,
    "sha512": 3e9,
    "pbkdf2": 2e6,
    "bcrypt": 3e4,
    "scrypt": 2e4,
    "argon2": 3e3,
}


def _char_cardinality(pw: str) -> int:
    """Estimate the effective alphabet size used by a password."""
    size = 0
    if re.search(r"[a-z]", pw):
        size += 26
    if re.search(r"[A-Z]", pw):
        size += 26
    if re.search(r"[0-9]", pw):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", pw):
        size += 33
    return max(size, 1)


def _has_sequence(pw: str, min_run: int = 3) -> bool:
    """Detect ascending or descending character runs (abcd, 4321)."""
    low = pw.lower()
    run = 1
    for i in range(1, len(low)):
        d = ord(low[i]) - ord(low[i - 1])
        if d in (1, -1):
            run += 1
            if run >= min_run:
                return True
        else:
            run = 1
    return False


def _has_repeat(pw: str) -> bool:
    """Detect repeated single characters (aaa) or repeated blocks (abcabc)."""
    if re.search(r"(.)\1{2,}", pw):
        return True
    n = len(pw)
    for size in range(1, n // 2 + 1):
        block = pw[:size]
        if block * (n // size) == pw[: size * (n // size)] and n // size >= 2:
            return True
    return False


def _has_keyboard(pw: str, min_run: int = 4) -> bool:
    """Detect straight keyboard-row walks (qwerty, asdf)."""
    low = pw.lower()
    for row in _KEYBOARD_ROWS:
        for i in range(len(row) - min_run + 1):
            frag = row[i : i + min_run]
            if frag in low or frag[::-1] in low:
                return True
    return False


def _has_date(pw: str) -> bool:
    """Detect date-like digit groups (years and dd/mm/yyyy fragments)."""
    if re.search(r"(19|20)\d{2}", pw):
        return True
    if re.search(r"\b\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}\b", pw):
        return True
    return False


def estimate(pw: str, extra_dict: Optional[set[str]] = None) -> dict:
    """Estimate strength, entropy and crack times for one password.

    Args:
        pw: Password to score.
        extra_dict: Optional extra dictionary of known words (lowercase).

    Returns:
        Dict with guesses, entropy bits, score, matched patterns and crack times.
    """
    if not pw:
        return {"password": pw, "guesses": 1, "entropy_bits": 0.0, "score": 0,
                "patterns": ["empty"], "crack_times": {}, "hash_times": {}}

    patterns: list[str] = []
    normalized = pw.lower().translate(_LEET_NORMALIZE)

    # Base bruteforce entropy.
    cardinality = _char_cardinality(pw)
    entropy = len(pw) * math.log2(cardinality)

    # Dictionary matches strongly reduce guesses.
    dict_hit = None
    if pw.lower() in _COMMON_RANK:
        dict_hit = _COMMON_RANK[pw.lower()]
        patterns.append("common-password")
    elif normalized in _COMMON_RANK:
        dict_hit = _COMMON_RANK[normalized] * 2
        patterns.append("common-password+leet")
    elif extra_dict and normalized in extra_dict:
        dict_hit = 5000
        patterns.append("dictionary")

    if _has_sequence(pw):
        patterns.append("sequence")
        entropy = min(entropy, math.log2(max(2, cardinality)) + len(pw))
    if _has_repeat(pw):
        patterns.append("repeat")
        entropy = min(entropy, len(pw) + 4)
    if _has_keyboard(pw):
        patterns.append("keyboard")
        entropy = min(entropy, len(pw) + 6)
    if _has_date(pw):
        patterns.append("date")

    if dict_hit is not None:
        guesses = float(max(1, dict_hit)) * 10
        # A few extra bits for capitalization and appended digits/symbols.
        if pw != pw.lower():
            guesses *= 4
        tail = re.search(r"[^a-zA-Z]+$", pw)
        if tail:
            guesses *= max(1, 10 ** min(4, len(tail.group())))
        entropy = math.log2(max(2.0, guesses))
    else:
        guesses = 2 ** entropy

    guesses = max(1.0, guesses)
    entropy = max(0.0, entropy)

    # zxcvbn-style score buckets.
    if guesses < 1e3:
        score = 0
    elif guesses < 1e6:
        score = 1
    elif guesses < 1e8:
        score = 2
    elif guesses < 1e10:
        score = 3
    else:
        score = 4

    crack_times = {
        name: guesses / rate for name, rate in _SCENARIOS.items()
    }
    hash_times = {
        name: guesses / rate for name, rate in _HASH_RATES.items()
    }

    return {
        "password": pw,
        "guesses": guesses,
        "entropy_bits": round(entropy, 2),
        "score": score,
        "patterns": patterns or ["bruteforce"],
        "crack_times": crack_times,
        "hash_times": hash_times,
    }


def _fmt_seconds(seconds: float) -> str:
    """Format a duration in seconds into a compact human string."""
    if seconds < 1:
        return "instant"
    steps = [("century", 3155760000), ("year", 31557600), ("month", 2629800),
             ("day", 86400), ("hour", 3600), ("minute", 60), ("second", 1)]
    for name, size in steps:
        if seconds >= size:
            qty = seconds / size
            return f"{qty:.1f} {name}{'s' if qty >= 2 else ''}"
    return "instant"


def hibp_check(pw: str, timeout: float = 8.0) -> Optional[int]:
    """Check a password against Have I Been Pwned using k-anonymity.

    Only the first five characters of the SHA-1 hash are sent to the range API,
    so the password itself never leaves the machine.

    Args:
        pw: Password to check.
        timeout: HTTP timeout in seconds.

    Returns:
        The breach count, 0 if not found, or None if the check could not run.
    """
    try:
        import requests
    except ImportError:
        logger.warning("HIBP check requires 'requests'")
        return None
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=timeout,
            headers={"Add-Padding": "true"},
        )
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        logger.warning("HIBP request failed: %s", exc)
        return None
    for line in resp.text.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0].strip() == suffix:
            try:
                return int(parts[1].strip())
            except ValueError:
                return None
    return 0


def format_report(result: dict, hibp: Optional[int] = None) -> list[str]:
    """Build a detailed text report for a single password estimate."""
    labels = ["very weak", "weak", "fair", "strong", "very strong"]
    lines = [
        f"Password        : {result['password']}",
        f"Score           : {result['score']}/4 ({labels[result['score']]})",
        f"Entropy         : {result['entropy_bits']} bits",
        f"Guesses         : {result['guesses']:.3g}",
        f"Patterns        : {', '.join(result['patterns'])}",
        "Crack time by scenario:",
    ]
    for name, secs in result["crack_times"].items():
        lines.append(f"  {name:42s}: {_fmt_seconds(secs)}")
    lines.append("Crack time by hash (single GPU):")
    for name, secs in result["hash_times"].items():
        lines.append(f"  {name:10s}: {_fmt_seconds(secs)}")
    if hibp is not None:
        if hibp > 0:
            lines.append(f"HIBP            : found in {hibp:,} breaches")
        else:
            lines.append("HIBP            : not found in known breaches")
    return lines


def handle_strength(args, ctx: dict):
    """CLI handler for the ``strength`` command.

    Returns:
        A tuple (kind, iterable_of_lines) or None on error.
    """
    extra: Optional[set[str]] = None
    dict_file = getattr(args, "dictionary", None)
    if dict_file:
        dp = Path(dict_file)
        if dp.exists():
            extra = set()
            with dp.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    w = line.strip().lower()
                    if w:
                        extra.add(w)

    use_hibp = bool(getattr(args, "hibp", False))
    wordlist = getattr(args, "wordlist", None)
    password = getattr(args, "password", None)

    if wordlist:
        wp = Path(wordlist)
        if not wp.exists():
            logger.error("wordlist not found: %s", wordlist)
            return None
        lines: list[str] = ["entropy_bits\tscore\tpatterns\tpassword"]
        max_lines = int(getattr(args, "max_lines", 0) or 0)
        n = 0
        with wp.open("r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                pw = raw.rstrip("\n\r")
                if not pw:
                    continue
                r = estimate(pw, extra)
                lines.append(
                    f"{r['entropy_bits']}\t{r['score']}\t"
                    f"{','.join(r['patterns'])}\t{pw}"
                )
                n += 1
                if max_lines and n >= max_lines:
                    break
        return ("lines", iter(lines))

    if not password:
        logger.error("provide a password or --wordlist FILE")
        return None

    result = estimate(password, extra)
    hibp = hibp_check(password) if use_hibp else None
    return ("report", iter(format_report(result, hibp)))
