"""
mangler.py - Hashcat/John-style mangling rules for wordlists.

Applies transformation rules to each word generating multiple variants.
Inspired by hashcat rule engine, pipal mangling, BEWGor permutations,
and PyMangler (mask-based generation + time-budget Overseer).

Author: André Henrique (@mrhenrike)
Version: 2.0.0
"""
from __future__ import annotations

import itertools
import logging
import math
import zlib
from dataclasses import dataclass, field
from typing import Generator, Optional

logger = logging.getLogger(__name__)

BUILTIN_RULES: dict[str, str] = {
    "capitalize":     "Capitalize first letter (e.g. password -> Password)",
    "upper":          "Uppercase entire word (e.g. password -> PASSWORD)",
    "lower":          "Lowercase entire word (e.g. Password -> password)",
    "reverse":        "Reverse the word (e.g. password -> drowssap)",
    "toggle":         "Toggle case of all characters (e.g. Password -> pASSWORD)",
    "append_num":     "Append 0-99, common years 2020-2026 (e.g. pass -> pass1, pass2024)",
    "prepend_num":    "Prepend 0-9 (e.g. pass -> 1pass)",
    "append_special": "Append common specials: ! @ # $ % & * (e.g. pass -> pass!)",
    "leet_basic":     "Basic leet substitutions (a->@, e->3, o->0, s->$, i->1)",
    "duplicate":      "Duplicate the word (e.g. pass -> passpass)",
    "strip_vowels":   "Remove all vowels (e.g. password -> psswrd)",
}

_LEET_MAP: dict[str, str] = {
    "a": "@", "A": "@",
    "e": "3", "E": "3",
    "i": "1", "I": "1",
    "o": "0", "O": "0",
    "s": "$", "S": "$",
}

_COMMON_SPECIALS = ["!", "@", "#", "$", "%", "&", "*", "?", ".", "+"]
_COMMON_YEARS = [str(y) for y in range(2020, 2027)]
_VOWELS = set("aeiouAEIOU")


def _apply_capitalize(word: str) -> list[str]:
    """Capitalize first letter."""
    cap = word.capitalize()
    return [cap] if cap != word else []


def _apply_upper(word: str) -> list[str]:
    """Uppercase the entire word."""
    up = word.upper()
    return [up] if up != word else []


def _apply_lower(word: str) -> list[str]:
    """Lowercase the entire word."""
    lo = word.lower()
    return [lo] if lo != word else []


def _apply_reverse(word: str) -> list[str]:
    """Reverse the word."""
    rev = word[::-1]
    return [rev] if rev != word else []


def _apply_toggle(word: str) -> list[str]:
    """Toggle case of each character."""
    toggled = word.swapcase()
    return [toggled] if toggled != word else []


def _apply_append_num(word: str) -> list[str]:
    """Append numbers 0-99 and common years."""
    results = []
    for n in range(100):
        results.append(f"{word}{n}")
    for year in _COMMON_YEARS:
        results.append(f"{word}{year}")
    return results


def _apply_prepend_num(word: str) -> list[str]:
    """Prepend digits 0-9."""
    return [f"{n}{word}" for n in range(10)]


def _apply_append_special(word: str) -> list[str]:
    """Append common special characters."""
    return [f"{word}{s}" for s in _COMMON_SPECIALS]


def _apply_leet_basic(word: str) -> list[str]:
    """Apply basic leet substitutions."""
    result = []
    for ch in word:
        result.append(_LEET_MAP.get(ch, ch))
    leeted = "".join(result)
    return [leeted] if leeted != word else []


def _apply_duplicate(word: str) -> list[str]:
    """Duplicate the word."""
    return [word + word]


def _apply_strip_vowels(word: str) -> list[str]:
    """Remove all vowels."""
    stripped = "".join(ch for ch in word if ch not in _VOWELS)
    return [stripped] if stripped and stripped != word else []


_RULE_FUNCS: dict[str, callable] = {
    "capitalize":     _apply_capitalize,
    "upper":          _apply_upper,
    "lower":          _apply_lower,
    "reverse":        _apply_reverse,
    "toggle":         _apply_toggle,
    "append_num":     _apply_append_num,
    "prepend_num":    _apply_prepend_num,
    "append_special": _apply_append_special,
    "leet_basic":     _apply_leet_basic,
    "duplicate":      _apply_duplicate,
    "strip_vowels":   _apply_strip_vowels,
}


def apply_rules(
    words: list[str],
    rules: list[str],
) -> Generator[str, None, None]:
    """
    Apply mangling rules to a list of words, yielding unique results.

    Args:
        words: Base words to mangle.
        rules: List of rule names to apply (keys from BUILTIN_RULES).

    Yields:
        Mangled word variants (original word + all rule outputs, deduplicated).
    """
    seen: set[str] = set()

    active_funcs = []
    for rule_name in rules:
        fn = _RULE_FUNCS.get(rule_name)
        if fn:
            active_funcs.append(fn)
        else:
            logger.warning("Unknown rule: %s - skipping.", rule_name)

    for word in words:
        if not word:
            continue

        if word not in seen:
            seen.add(word)
            yield word

        for fn in active_funcs:
            variants = fn(word)
            for v in variants:
                if v and v not in seen:
                    seen.add(v)
                    yield v


# ── PyMangler: mask-based generation + capswap + Overseer ─────────────────────

# PyMangler mask alphabet:
#   w = word token from input
#   d = digit token (from top numbers list)
#   s = special char token (from top specials list)
MASK_TOKENS = ("w", "d", "s")

# Top digits used in real passwords (PyMangler liststat analysis)
_TOP_DIGITS: list[str] = [
    "1", "12", "123", "1234", "12345", "123456", "0", "11", "00", "69",
    "99", "21", "01", "2024", "2025", "2026", "2023", "2022", "2021",
    "2020", "2019", "2018", "007", "666", "777", "888", "999", "100",
]

# Top special sequences in real passwords
_TOP_SPECIALS: list[str] = [
    "!", "@", "#", "$", "!", "!!", "@#", "!@#", "123!",
    ".", "_", "-", "*", "&", "%", "?", "!1", "@1",
]

# Common masks ordered by LinkedIn/leak frequency (PyMangler distribution)
COMMON_MASKS: list[str] = [
    "w", "wd", "wdd", "wddd", "dw", "ddw",
    "ws", "wds", "wsd", "wdds", "dwds",
    "ww", "wwd", "wwdd", "wdw",
    "d", "dd", "ddd",
    "s", "ss",
]


def capswap(word: str) -> Generator[str, None, None]:
    """Yield all positional case combinations of a word (PyMangler capswap).

    For each character position, independently choose lower or upper case.
    Uses itertools.product to generate all 2^n combinations, capped at 128
    variants for words longer than 7 chars.

    Args:
        word: Input word.

    Yields:
        Case-swapped variants (unique, excluding original).
    """
    if not word:
        return
    lower = word.lower()
    upper = word.upper()
    if lower == upper:
        return

    pairs = []
    for ch in word:
        lo, hi = ch.lower(), ch.upper()
        if lo == hi:
            pairs.append((ch,))
        else:
            pairs.append((lo, hi))

    seen_h: set[int] = set()
    cap_limit = 128 if len(word) > 7 else 2 ** len(pairs)

    for i, combo in enumerate(itertools.product(*pairs)):
        if i >= cap_limit:
            break
        variant = "".join(combo)
        h = zlib.crc32(variant.encode("utf-8", errors="replace")) & 0xFFFFFFFF
        if h not in seen_h and variant != word:
            seen_h.add(h)
            yield variant


def mask_expand(
    mask: str,
    words: list[str],
    digits: Optional[list[str]] = None,
    specials: Optional[list[str]] = None,
    max_output: int = 0,
) -> Generator[str, None, None]:
    """Expand a PyMangler-style mask into password candidates.

    Mask tokens:
      w = next word from ``words``
      d = digit sequence from ``digits``
      s = special char from ``specials``

    Args:
        mask: Mask string, e.g. 'wd', 'wds', 'wdw'.
        words: Word tokens to use for 'w' positions.
        digits: Digit strings to use for 'd' positions (default: _TOP_DIGITS).
        specials: Special strings for 's' positions (default: _TOP_SPECIALS).
        max_output: Hard limit on total yielded candidates (0 = unlimited).

    Yields:
        Password candidates.
    """
    d_list = digits if digits is not None else _TOP_DIGITS
    s_list = specials if specials is not None else _TOP_SPECIALS

    pools: list[list[str]] = []
    for ch in mask:
        if ch == "w":
            pools.append(words)
        elif ch == "d":
            pools.append(d_list)
        elif ch == "s":
            pools.append(s_list)
        else:
            pools.append([ch])

    if not pools:
        return

    seen_h: set[int] = set()
    count = 0
    for combo in itertools.product(*pools):
        candidate = "".join(combo)
        h = zlib.crc32(candidate.encode("utf-8", errors="replace")) & 0xFFFFFFFF
        if h not in seen_h:
            seen_h.add(h)
            yield candidate
            count += 1
            if max_output and count >= max_output:
                return


@dataclass
class OverseerConfig:
    """Configuration for the Overseer time-budget controller (PyMangler parity).

    Controls how many candidates to generate per mask, distributing the total
    budget proportionally to mask occurrence frequency.

    GPU is entirely optional: set ``pps`` from your ``hashcat --benchmark``
    result. If running in a VM without CUDA passthrough, use CPU constants.
    """

    pps: int = 5_000_000
    """Passwords per second for your hardware. 0 = unlimited (no budget)."""

    target_time_hrs: float = 1.0
    """Total time budget in hours."""

    masks: list[str] = field(default_factory=lambda: list(COMMON_MASKS))
    """Ordered list of masks to expand."""

    use_capswap: bool = False
    """Apply positional capswap to 'w' tokens."""

    use_gpu: bool = False
    """If True and pps=0, use GPU default PPS (~8G/s Nvidia MD5)."""

    gpu_type: str = "gpu_nvidia"
    """GPU type key when use_gpu=True and pps=0."""

    @property
    def effective_pps(self) -> int:
        if self.pps > 0:
            return self.pps
        if self.use_gpu:
            return 8_000_000_000 if self.gpu_type == "gpu_nvidia" else 6_000_000_000
        return 5_000_000

    @property
    def total_budget(self) -> int:
        """Total candidate budget across all masks."""
        if self.effective_pps == 0 or self.target_time_hrs == 0:
            return 0
        return int(self.effective_pps * self.target_time_hrs * 3600)

    def per_mask_limit(self, n_masks: int) -> int:
        """Candidates to generate per mask (even distribution)."""
        if self.total_budget == 0 or n_masks == 0:
            return 0
        return max(1, self.total_budget // n_masks)


def overseer_expand(
    words: list[str],
    config: Optional[OverseerConfig] = None,
    digits: Optional[list[str]] = None,
    specials: Optional[list[str]] = None,
) -> Generator[str, None, None]:
    """Expand masks with time-budget control (PyMangler Overseer parity).

    Iterates through each mask in ``config.masks`` and generates candidates,
    stopping each mask when its per-mask limit is reached.

    GPU usage is optional - configure via ``OverseerConfig.use_gpu``.

    Args:
        words: Base word tokens.
        config: Overseer configuration; uses defaults if None.
        digits: Custom digit list (default: _TOP_DIGITS).
        specials: Custom special list (default: _TOP_SPECIALS).

    Yields:
        Password candidates across all masks within the time budget.
    """
    cfg = config or OverseerConfig()
    n_masks = len(cfg.masks)
    per_limit = cfg.per_mask_limit(n_masks)

    w_tokens = words
    if cfg.use_capswap:
        expanded: list[str] = list(words)
        for word in words:
            for variant in capswap(word):
                expanded.append(variant)
        w_tokens = expanded

    seen_h: set[int] = set()

    for mask in cfg.masks:
        for candidate in mask_expand(mask, w_tokens, digits, specials, max_output=per_limit):
            h = zlib.crc32(candidate.encode("utf-8", errors="replace")) & 0xFFFFFFFF
            if h not in seen_h:
                seen_h.add(h)
                yield candidate


def generate_hashcat_rules(
    masks: list[str],
    words: list[str],
    digits: Optional[list[str]] = None,
    specials: Optional[list[str]] = None,
) -> list[str]:
    """Generate hashcat-compatible rule strings for mask-based patterns.

    Produces prepend/append rules for each mask that can be written to a
    hashcat .rule file and applied to a base word dictionary.

    Args:
        masks: List of masks to generate rules for.
        words: Word tokens (only needed for context; rules use $X / ^X syntax).
        digits: Digit tokens.
        specials: Special tokens.

    Returns:
        List of hashcat rule strings.
    """
    d_list = digits or _TOP_DIGITS[:10]
    s_list = specials or _TOP_SPECIALS[:5]
    rules: list[str] = []

    for mask in masks:
        for ch in mask:
            if ch == "d":
                for d in d_list:
                    rule_parts = []
                    for digit_ch in d:
                        rule_parts.append(f"${digit_ch}")
                    rules.append(" ".join(rule_parts))
                    rule_parts_pre = []
                    for digit_ch in reversed(d):
                        rule_parts_pre.append(f"^{digit_ch}")
                    rules.append(" ".join(rule_parts_pre))
            elif ch == "s":
                for s in s_list:
                    for s_ch in s:
                        rules.append(f"${s_ch}")
                        rules.append(f"^{s_ch}")

    return list(dict.fromkeys(rules))
