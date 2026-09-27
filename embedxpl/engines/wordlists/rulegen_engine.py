"""
rulegen_engine.py - Automatic hashcat rule generation from password analysis.

Analyzes real passwords to reverse-engineer the transformation rules that
could derive them from base words. Generates .rule files compatible with
hashcat and John the Ripper.

Inspired by PACK rulegen.py and Cynosureprime's rulecat/rulechef.

Supported hashcat rule operations:
  l/u/c/C/t     - case transforms
  r/d/f         - reverse, duplicate, reflect
  $X/^X         - append/prepend
  sXY           - substitute
  @X            - purge char
  iNX/oNX       - insert/overwrite at position
  DN/xNM        - delete / extract
  <N/>N         - reject length filters

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
import re
from collections import Counter
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

LEET_MAP = {
    "a": ["4", "@"], "e": ["3"], "i": ["1", "!"],
    "o": ["0"], "s": ["5", "$"], "t": ["7", "+"],
    "l": ["1"], "g": ["9"], "b": ["8"],
}

REVERSE_LEET = {}
for _ch, _subs in LEET_MAP.items():
    for _s in _subs:
        REVERSE_LEET[_s] = _ch

COMMON_SUFFIXES = [
    "1", "12", "123", "1234", "12345", "!", "!!", "!!!", "@", "#",
    "01", "07", "69", "99", "00", "007",
    "2020", "2021", "2022", "2023", "2024", "2025", "2026",
]

COMMON_PREFIXES = ["1", "12", "123", "!", "@", "#", "the", "my"]


def _deleet(word: str) -> str:
    """Reverse leet substitutions to recover a base word."""
    result = []
    for ch in word:
        result.append(REVERSE_LEET.get(ch, ch))
    return "".join(result)


def _find_base_word(password: str, dictionary: set[str]) -> Optional[tuple[str, list[str]]]:
    """Attempt to find a base word and the rules to derive the password.

    Tries progressively more complex transformations:
    1. Exact match (no rules)
    2. Case transforms (l, u, c, C, t)
    3. Suffix append ($X)
    4. Prefix prepend (^X)
    5. Leet substitutions (sXY)
    6. Combinations of the above

    Args:
        password: The target password.
        dictionary: Set of known base words.

    Returns:
        Tuple of (base_word, list_of_rules) or None if no derivation found.
    """
    if password in dictionary:
        return (password, [":"])

    lower = password.lower()
    if lower in dictionary:
        if password == lower:
            return (lower, ["l"])
        if password == lower.upper():
            return (lower, ["u"])
        if password == lower.capitalize():
            return (lower, ["c"])
        return (lower, ["t" * len(password)])

    for suffix in COMMON_SUFFIXES:
        if password.endswith(suffix):
            base = password[:-len(suffix)]
            base_lower = base.lower()
            if base_lower in dictionary:
                rules = []
                if base != base_lower:
                    if base == base_lower.capitalize():
                        rules.append("c")
                    elif base == base_lower.upper():
                        rules.append("u")
                for ch in suffix:
                    rules.append(f"${ch}")
                return (base_lower, rules)

    for prefix in COMMON_PREFIXES:
        if password.startswith(prefix):
            base = password[len(prefix):]
            base_lower = base.lower()
            if base_lower in dictionary:
                rules = []
                for ch in reversed(prefix):
                    rules.append(f"^{ch}")
                if base != base_lower:
                    if base == base_lower.capitalize():
                        rules.append("c")
                return (base_lower, rules)

    deleeted = _deleet(password.lower())
    if deleeted in dictionary and deleeted != password.lower():
        rules = []
        for i, (orig, clean) in enumerate(zip(password.lower(), deleeted)):
            if orig != clean:
                rules.append(f"s{clean}{orig}")
        if password[0].isupper():
            rules.insert(0, "c")
        return (deleeted, rules)

    for suffix in COMMON_SUFFIXES:
        if password.endswith(suffix):
            core = password[:-len(suffix)]
            deleeted_core = _deleet(core.lower())
            if deleeted_core in dictionary:
                rules = []
                for orig_ch, clean_ch in zip(core.lower(), deleeted_core):
                    if orig_ch != clean_ch:
                        rules.append(f"s{clean_ch}{orig_ch}")
                if core[0:1].isupper():
                    rules.insert(0, "c")
                for ch in suffix:
                    rules.append(f"${ch}")
                return (deleeted_core, rules)

    return None


def analyze_passwords(
    passwords: list[str],
    dictionary: Optional[set[str]] = None,
    max_rules_per_password: int = 3,
) -> tuple[Counter, dict[str, list[str]]]:
    """Analyze passwords and extract transformation rules.

    Args:
        passwords: List of passwords to analyze.
        dictionary: Set of base words for matching.
        max_rules_per_password: Max rule chains per password.

    Returns:
        Tuple of (rule_counter, {password: [rule_chains]}).
    """
    if dictionary is None:
        dictionary = _build_auto_dictionary(passwords)

    rule_counter: Counter = Counter()
    derivations: dict[str, list[str]] = {}

    for pw in passwords:
        result = _find_base_word(pw, dictionary)
        if result:
            base, rules = result
            rule_chain = " ".join(rules)
            rule_counter[rule_chain] += 1
            derivations[pw] = rules

    return rule_counter, derivations


def _build_auto_dictionary(passwords: list[str], min_len: int = 3) -> set[str]:
    """Build a dictionary from the passwords themselves (for self-analysis).

    Extracts alpha substrings as candidate base words.
    """
    words: set[str] = set()
    alpha_re = re.compile(r"[a-zA-Z]+")
    for pw in passwords:
        for match in alpha_re.finditer(pw):
            word = match.group().lower()
            if len(word) >= min_len:
                words.add(word)
    return words


def generate_rules(
    passwords: list[str],
    dictionary: Optional[set[str]] = None,
    min_frequency: int = 1,
    top_rules: int = 0,
    include_colon: bool = True,
) -> Generator[str, None, None]:
    """Generate hashcat-compatible rule lines from password analysis.

    Args:
        passwords: List of passwords to analyze.
        dictionary: Optional base word dictionary.
        min_frequency: Minimum rule frequency to include.
        top_rules: Limit to top N rules (0 = all).
        include_colon: Include identity rule ':' in output.

    Yields:
        Hashcat rule strings (one per line).
    """
    rule_counter, _ = analyze_passwords(passwords, dictionary)

    sorted_rules = rule_counter.most_common(top_rules if top_rules else None)

    for rule_chain, freq in sorted_rules:
        if freq < min_frequency:
            continue
        if not include_colon and rule_chain.strip() == ":":
            continue
        yield rule_chain


def generate_rule_file(
    input_file: str,
    output_file: str,
    dict_file: Optional[str] = None,
    max_lines: int = 0,
    top_rules: int = 100,
) -> dict:
    """Analyze a password file and generate a .rule file.

    Args:
        input_file: Path to password file.
        output_file: Path for output .rule file.
        dict_file: Optional dictionary file (one word per line).
        max_lines: Max passwords to analyze (0 = unlimited).
        top_rules: Number of top rules to include.

    Returns:
        Statistics dict.
    """
    passwords: list[str] = []
    path = Path(input_file)
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            pw = line.rstrip("\n\r")
            if not pw:
                continue
            if ":" in pw:
                pw = pw.split(":", 1)[-1]
            passwords.append(pw)
            if max_lines and len(passwords) >= max_lines:
                break

    dictionary = None
    if dict_file:
        dp = Path(dict_file)
        if dp.exists():
            dictionary = set()
            with dp.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    w = line.strip().lower()
                    if w:
                        dictionary.add(w)

    rule_counter, derivations = analyze_passwords(passwords, dictionary)

    out = Path(output_file)
    out.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with out.open("w", encoding="utf-8") as fh:
        fh.write(f"# Auto-generated rules from {path.name}\n")
        fh.write(f"# Analyzed {len(passwords)} passwords, found {len(rule_counter)} unique rule chains\n")
        fh.write("# Format: hashcat-compatible rule syntax\n\n")
        for rule_chain, freq in rule_counter.most_common(top_rules):
            fh.write(f"{rule_chain}\n")
            written += 1

    return {
        "passwords_analyzed": len(passwords),
        "derivations_found": len(derivations),
        "unique_rules": len(rule_counter),
        "rules_written": written,
        "output": str(out),
    }


def handle_rulegen(args, ctx: dict) -> Optional[Generator[str, None, None]]:
    """CLI handler for hashcat rule generation.

    Args:
        args: Parsed CLI arguments.
        ctx: Global execution context.

    Returns:
        Generator yielding rules or status, or None.
    """
    input_files = getattr(args, "wordlist", None) or []
    if not input_files:
        logger.error("No input file provided (--wordlist)")
        return None

    dict_file = getattr(args, "dictionary", None)
    top_rules = getattr(args, "top_rules", 100) or 100
    output = getattr(args, "output", None)

    if output and output.endswith(".rule"):
        stats = generate_rule_file(
            input_files[0], output,
            dict_file=dict_file,
            max_lines=getattr(args, "max_lines", 0),
            top_rules=top_rules,
        )
        summary = (
            f"Rule Generation Complete:\n"
            f"  Passwords analyzed : {stats['passwords_analyzed']:,}\n"
            f"  Derivations found  : {stats['derivations_found']:,}\n"
            f"  Unique rules       : {stats['unique_rules']:,}\n"
            f"  Rules written      : {stats['rules_written']:,}\n"
            f"  Output             : {stats['output']}"
        )
        return iter([summary])

    all_passwords: list[str] = []
    for src in input_files:
        p = Path(src)
        if not p.exists():
            logger.warning("File not found: %s", src)
            continue
        with p.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                pw = line.rstrip("\n\r")
                if pw:
                    if ":" in pw:
                        pw = pw.split(":", 1)[-1]
                    all_passwords.append(pw)
                    max_lines = getattr(args, "max_lines", 0)
                    if max_lines and len(all_passwords) >= max_lines:
                        break

    dictionary = None
    if dict_file:
        dp = Path(dict_file)
        if dp.exists():
            dictionary = set()
            with dp.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    w = line.strip().lower()
                    if w:
                        dictionary.add(w)

    return generate_rules(
        all_passwords, dictionary,
        top_rules=top_rules,
    )
