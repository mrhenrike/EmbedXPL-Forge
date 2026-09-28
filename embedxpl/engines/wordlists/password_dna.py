"""
password_dna.py - Password DNA: pattern analysis and variant generation.

Analyzes 1-10 known passwords from a target to extract behavioral "DNA":
structural patterns, word banks, separator habits, number placement,
capitalization style, leet substitution preferences, and suffix/prefix habits.
Then generates a wordlist of new candidates that match the same DNA profile.

The more passwords provided (ideal: 3+), the more accurate the DNA extraction.

Usage:
  wlf.py password-dna "Empresa@2024" "empresa#2025" "Empresa!123"
  wlf.py password-dna --file known_passwords.txt --depth deep -o candidates.lst

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
import re
import string
from collections import Counter
from itertools import product as iterproduct
from typing import Generator, Optional

logger = logging.getLogger(__name__)

# ── Character classification ─────────────────────────────────────────────────

_LEET_REVERSE: dict[str, list[str]] = {
    "@": ["a"], "4": ["a", "A"], "3": ["e", "E"], "!": ["i", "I", "l"],
    "0": ["o", "O"], "$": ["s", "S"], "7": ["t", "T"], "1": ["i", "l", "I"],
    "5": ["s"], "6": ["b"], "8": ["B"], "9": ["g"], "2": ["z"],
}

_LEET_FORWARD: dict[str, list[str]] = {
    "a": ["@", "4"], "A": ["4", "@"], "e": ["3"], "E": ["3"],
    "i": ["1", "!"], "I": ["1", "!"], "o": ["0"], "O": ["0"],
    "s": ["$", "5"], "S": ["$", "5"], "t": ["7"], "T": ["7"],
    "l": ["1"], "L": ["1"], "b": ["6"], "B": ["8"],
    "g": ["9"], "G": ["9"], "z": ["2"], "Z": ["2"],
}

COMMON_SEPARATORS = ["", ".", "-", "_", "@", "#", "!", "$", "&", "*"]

COMMON_SUFFIXES_NUM = [
    "0", "1", "2", "3", "01", "02", "10", "11", "12", "13",
    "21", "22", "23", "69", "99", "00", "007", "100",
    "123", "1234", "12345", "321", "666", "777", "888",
]

COMMON_YEARS = [str(y) for y in range(2015, 2028)] + [str(y)[-2:] for y in range(2015, 2028)]


# ── DNA Extraction ────────────────────────────────────────────────────────────

class PasswordGene:
    """Structural decomposition of a single password."""

    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.length = len(raw)
        self.segments = self._segment(raw)
        self.structure = "".join(s["type"] for s in self.segments)
        self.words = [s["value"] for s in self.segments if s["type"] == "W"]
        self.numbers = [s["value"] for s in self.segments if s["type"] == "D"]
        self.specials = [s["value"] for s in self.segments if s["type"] == "S"]
        self.cap_style = self._detect_cap_style()
        self.has_leet = self._detect_leet()
        self.year_used = self._detect_year()
        self.length_range = (max(self.length - 2, 4), self.length + 4)

    def _segment(self, pwd: str) -> list[dict]:
        """Decompose password into typed segments: W(ord), D(igit), S(pecial).

        Leet chars are only part of a word if surrounded by alpha chars on both sides.
        Otherwise, they're treated as separators (S).
        """
        segments: list[dict] = []
        i = 0
        while i < len(pwd):
            c = pwd[i]
            if c.isalpha():
                j = i
                while j < len(pwd) and (pwd[j].isalpha() or self._is_embedded_leet(pwd, j)):
                    j += 1
                segments.append({"type": "W", "value": pwd[i:j]})
                i = j
            elif c.isdigit():
                j = i
                while j < len(pwd) and pwd[j].isdigit():
                    j += 1
                segments.append({"type": "D", "value": pwd[i:j]})
                i = j
            else:
                j = i
                while j < len(pwd) and not pwd[j].isalpha() and not pwd[j].isdigit():
                    j += 1
                segments.append({"type": "S", "value": pwd[i:j]})
                i = j
        return segments

    @staticmethod
    def _is_embedded_leet(pwd: str, pos: int) -> bool:
        """Check if a char at pos is a leet substitution embedded within alpha chars."""
        if pos >= len(pwd):
            return False
        c = pwd[pos]
        if c not in _LEET_REVERSE or c.isalpha():
            return False
        has_alpha_before = pos > 0 and pwd[pos - 1].isalpha()
        has_alpha_after = pos + 1 < len(pwd) and pwd[pos + 1].isalpha()
        return has_alpha_before and has_alpha_after

    def _detect_cap_style(self) -> str:
        """Detect capitalization pattern: lower, upper, title, mixed."""
        alpha = "".join(c for c in self.raw if c.isalpha())
        if not alpha:
            return "none"
        if alpha.islower():
            return "lower"
        if alpha.isupper():
            return "upper"
        if alpha[0].isupper() and alpha[1:].islower():
            return "title"
        return "mixed"

    def _detect_leet(self) -> bool:
        return any(c in _LEET_REVERSE for c in self.raw)

    def _detect_year(self) -> Optional[str]:
        for seg in self.segments:
            if seg["type"] == "D" and len(seg["value"]) == 4 and seg["value"].startswith("20"):
                return seg["value"]
        return None

    def get_base_words(self) -> list[str]:
        """Extract probable base words, de-leeting if needed."""
        result: list[str] = []
        for word in self.words:
            deleeted = _deleet(word)
            result.append(deleeted.lower())
            if deleeted != word:
                result.append(word.lower())
        return list(dict.fromkeys(result))


class PasswordDNA:
    """Aggregate behavioral pattern from 1-10 passwords."""

    def __init__(self, passwords: list[str]) -> None:
        if not passwords:
            raise ValueError("At least 1 password required")
        if len(passwords) > 10:
            passwords = passwords[:10]

        self.genes = [PasswordGene(p) for p in passwords]
        self.n = len(self.genes)

        self.structures = Counter(g.structure for g in self.genes)
        self.cap_styles = Counter(g.cap_style for g in self.genes)
        self.separators = self._extract_separators()
        self.word_bank = self._build_word_bank()
        self.number_bank = self._build_number_bank()
        self.length_min = min(g.length_range[0] for g in self.genes)
        self.length_max = max(g.length_range[1] for g in self.genes)
        self.uses_leet = sum(1 for g in self.genes if g.has_leet) / self.n
        self.uses_year = sum(1 for g in self.genes if g.year_used) / self.n

    def _extract_separators(self) -> list[str]:
        """Find recurring separator characters."""
        sep_counter: Counter = Counter()
        for g in self.genes:
            for s in g.specials:
                for ch in s:
                    sep_counter[ch] += 1
        if not sep_counter:
            return [""]
        return [ch for ch, _ in sep_counter.most_common(5)]

    def _build_word_bank(self) -> list[str]:
        """Aggregate all base words from all passwords."""
        bank: list[str] = []
        for g in self.genes:
            for w in g.get_base_words():
                if w and w not in bank:
                    bank.append(w)
        return bank

    def _build_number_bank(self) -> list[str]:
        """Aggregate all number segments."""
        bank: list[str] = []
        for g in self.genes:
            for n in g.numbers:
                if n not in bank:
                    bank.append(n)
            if g.year_used and g.year_used not in bank:
                bank.append(g.year_used)
        for y in COMMON_YEARS:
            if y not in bank:
                bank.append(y)
        for n in COMMON_SUFFIXES_NUM:
            if n not in bank:
                bank.append(n)
        return bank

    def describe(self) -> str:
        """Human-readable DNA profile summary."""
        lines = [
            f"=== Password DNA Profile ({self.n} sample(s)) ===",
            f"Structures found: {dict(self.structures.most_common())}",
            f"Cap styles:       {dict(self.cap_styles.most_common())}",
            f"Separators:       {self.separators}",
            f"Word bank:        {self.word_bank[:20]}",
            f"Number bank:      {self.number_bank[:15]}",
            f"Length range:     {self.length_min}-{self.length_max}",
            f"Leet tendency:    {self.uses_leet:.0%}",
            f"Year tendency:    {self.uses_year:.0%}",
        ]
        return "\n".join(lines)


# ── Variant Generation ────────────────────────────────────────────────────────

def generate_from_dna(
    dna: PasswordDNA,
    depth: str = "normal",
) -> Generator[str, None, None]:
    """Generate password candidates based on DNA profile.

    Depth levels:
        quick:  ~500-2K candidates (word × sep × number, basic caps)
        normal: ~5K-20K candidates (+ leet, + structure variations)
        deep:   ~50K-200K candidates (+ positional leet, + extra permutations)

    Yields:
        Password candidate strings.
    """
    seen: set[str] = set()
    words = dna.word_bank
    numbers = dna.number_bank
    seps = dna.separators or [""]
    min_len = dna.length_min
    max_len = dna.length_max

    def emit(s: str) -> Optional[str]:
        if s and s not in seen and min_len <= len(s) <= max_len:
            seen.add(s)
            return s
        return None

    cap_funcs = _get_cap_transforms(dna.cap_styles)

    # Phase 1: Structure-based generation from observed patterns
    for struct, _ in dna.structures.most_common():
        yield from _generate_from_structure(
            struct, words, numbers, seps, cap_funcs, dna, seen, min_len, max_len
        )

    # Phase 2: Word + separator + number (classic pattern)
    for word in words:
        for cap_fn in cap_funcs:
            w = cap_fn(word)
            for sep in seps:
                r = emit(w + sep)
                if r:
                    yield r
                for num in numbers[:30]:
                    r = emit(w + sep + num)
                    if r:
                        yield r
                    r = emit(num + sep + w)
                    if r:
                        yield r

    # Phase 3: Word + word combinations
    if len(words) >= 2:
        for w1 in words[:8]:
            for w2 in words[:8]:
                if w1 == w2:
                    continue
                for cap_fn in cap_funcs:
                    for sep in seps:
                        r = emit(cap_fn(w1) + sep + cap_fn(w2))
                        if r:
                            yield r
                        for num in numbers[:10]:
                            r = emit(cap_fn(w1) + sep + cap_fn(w2) + num)
                            if r:
                                yield r

    # Phase 4: Leet variants
    if depth in ("normal", "deep") and dna.uses_leet > 0:
        for word in words[:10]:
            for cap_fn in cap_funcs:
                base = cap_fn(word)
                for leet in _leet_variants(base, depth == "deep"):
                    for sep in seps:
                        r = emit(leet + sep)
                        if r:
                            yield r
                        for num in numbers[:15]:
                            r = emit(leet + sep + num)
                            if r:
                                yield r

    # Phase 5: Reversed words (behavioral pattern)
    if depth in ("normal", "deep"):
        for word in words[:6]:
            rev = word[::-1]
            for cap_fn in cap_funcs:
                w = cap_fn(rev)
                for sep in seps:
                    for num in numbers[:10]:
                        r = emit(w + sep + num)
                        if r:
                            yield r

    # Phase 6: Deep - positional leet (all combinations per char)
    if depth == "deep":
        for word in words[:5]:
            for cap_fn in cap_funcs:
                base = cap_fn(word)
                yield from _positional_leet(base, seps, numbers[:10], seen, min_len, max_len)

    # Phase 7: Original passwords + mutations of originals
    for gene in dna.genes:
        r = emit(gene.raw)
        if r:
            yield r
        r = emit(gene.raw[::-1])
        if r:
            yield r
        for num in numbers[:10]:
            r = emit(gene.raw + num)
            if r:
                yield r
        for sep in seps:
            for num in numbers[:10]:
                r = emit(gene.raw + sep + num)
                if r:
                    yield r


def _generate_from_structure(
    struct: str, words: list, numbers: list, seps: list,
    cap_funcs: list, dna, seen: set, min_len: int, max_len: int,
) -> Generator[str, None, None]:
    """Reconstruct passwords matching a given structural pattern."""
    for word in words[:12]:
        for cap_fn in cap_funcs:
            for sep in (seps if "S" in struct else [""]):
                for num in (numbers[:20] if "D" in struct else [""]):
                    candidate = ""
                    for token_type in struct:
                        if token_type == "W":
                            candidate += cap_fn(word)
                        elif token_type == "D":
                            candidate += num
                        elif token_type == "S":
                            candidate += sep
                    if candidate and candidate not in seen and min_len <= len(candidate) <= max_len:
                        seen.add(candidate)
                        yield candidate


def _get_cap_transforms(cap_counter: Counter) -> list:
    """Return capitalization functions based on DNA profile."""
    funcs = [str.lower]
    styles = [s for s, _ in cap_counter.most_common()]
    if "title" in styles or "mixed" in styles:
        funcs.append(str.capitalize)
    if "upper" in styles:
        funcs.append(str.upper)
    funcs.append(str.lower)
    return list(dict.fromkeys(funcs))


def _deleet(text: str) -> str:
    """Reverse leet substitutions to recover base word."""
    result = []
    for ch in text:
        if ch in _LEET_REVERSE:
            result.append(_LEET_REVERSE[ch][0])
        else:
            result.append(ch)
    return "".join(result)


def _leet_variants(word: str, exhaustive: bool = False) -> list[str]:
    """Generate leet speak variants of a word."""
    variants: list[str] = []
    base_leet = ""
    for ch in word:
        subs = _LEET_FORWARD.get(ch)
        if subs:
            base_leet += subs[0]
        else:
            base_leet += ch
    if base_leet != word:
        variants.append(base_leet)

    if exhaustive:
        full_leet = ""
        for ch in word:
            subs = _LEET_FORWARD.get(ch)
            if subs and len(subs) > 1:
                full_leet += subs[1]
            elif subs:
                full_leet += subs[0]
            else:
                full_leet += ch
        if full_leet not in variants and full_leet != word:
            variants.append(full_leet)

    return variants


def _positional_leet(
    word: str, seps: list, numbers: list, seen: set,
    min_len: int, max_len: int,
) -> Generator[str, None, None]:
    """Generate all positional leet combinations for a word (elpscrk-style)."""
    positions = []
    for ch in word:
        subs = _LEET_FORWARD.get(ch)
        if subs:
            positions.append([ch] + subs)
        else:
            positions.append([ch])

    if len(positions) > 12:
        return

    count = 0
    for combo in iterproduct(*positions):
        if count > 500:
            break
        candidate = "".join(combo)
        if candidate in seen:
            continue
        for sep in seps[:2]:
            for num in numbers[:5]:
                full = candidate + sep + num
                if full not in seen and min_len <= len(full) <= max_len:
                    seen.add(full)
                    yield full
                    count += 1


# ── CLI Handler ───────────────────────────────────────────────────────────────

def handle_password_dna(args, ctx: dict) -> tuple:
    """CLI handler: analyze passwords and return (dna, generator).

    Returns:
        Tuple of (PasswordDNA, Generator) for the caller to write.
    """
    passwords: list[str] = []

    if getattr(args, "passwords", None):
        passwords.extend(args.passwords)

    if getattr(args, "file", None):
        try:
            with open(args.file, encoding="utf-8") as f:
                for line in f:
                    pw = line.strip()
                    if pw and not pw.startswith("#") and len(passwords) < 10:
                        passwords.append(pw)
        except FileNotFoundError:
            logger.error("File not found: %s", args.file)
            return None, None

    if not passwords:
        logger.error("No passwords provided.")
        return None, None

    if len(passwords) > 10:
        passwords = passwords[:10]

    depth = getattr(args, "depth", "normal") or "normal"
    dna = PasswordDNA(passwords)

    return dna, generate_from_dna(dna, depth=depth)
