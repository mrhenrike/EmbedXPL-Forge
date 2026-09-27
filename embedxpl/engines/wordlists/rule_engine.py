"""
rule_engine.py - Hashcat and John the Ripper rule executor, converter and optimizer.

Runs password mangling rules against a wordlist, the equivalent of
`hashcat --stdout -r rules.rule wordlist`, converts between the hashcat and
John the Ripper rule dialects (their shared function set), and optimizes rule
files by removing duplicates and no-op rules.

The interpreter implements the widely used hashcat rule function set. Position
arguments follow the hashcat convention where a single character encodes an
index: 0-9 map to 0-9 and A-Z map to 10-35. Rejection functions cause the
candidate to be dropped, matching the behavior of `--stdout` with rules.

References: hashcat rule_based_attack, hashcat-utils rules_optimize,
John the Ripper rules documentation.

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Generator, Iterable, Optional

logger = logging.getLogger(__name__)


class RuleError(ValueError):
    """Raised when a rule cannot be parsed or is unsupported."""


def _pos(ch: str) -> int:
    """Decode a hashcat position character to an integer index.

    Args:
        ch: Single position character (0-9, A-Z).

    Returns:
        Integer index (0-35).

    Raises:
        RuleError: If the character is not a valid position token.
    """
    if "0" <= ch <= "9":
        return ord(ch) - 48
    if "A" <= ch <= "Z":
        return ord(ch) - 55
    if "a" <= ch <= "z":
        return ord(ch) - 87
    raise RuleError(f"invalid position token: {ch!r}")


# Number of argument characters consumed by each rule function.
_ARG_COUNT = {
    ":": 0, "l": 0, "u": 0, "c": 0, "C": 0, "t": 0, "r": 0, "d": 0,
    "f": 0, "{": 0, "}": 0, "[": 0, "]": 0, "k": 0, "K": 0, "q": 0,
    "E": 0,
    "T": 1, "p": 1, "D": 1, "z": 1, "Z": 1, "'": 1, "$": 1, "^": 1,
    "@": 1, "!": 1, "/": 1, "(": 1, ")": 1, "<": 1, ">": 1, "_": 1,
    "y": 1, "Y": 1, "L": 1, "R": 1, "+": 1, "-": 1, ".": 1, ",": 1,
    "e": 1,
    "s": 2, "x": 2, "O": 2, "o": 2, "i": 2, "=": 2, "%": 2, "*": 2,
}


def parse_rule(rule: str) -> list[tuple[str, str]]:
    """Parse a rule line into a list of (function, args) tuples.

    Whitespace between functions is ignored, but a space can still be a valid
    argument character (for example ``$`` followed by a space appends a space).

    Args:
        rule: A single rule line.

    Returns:
        List of (function_char, argument_string) tuples.

    Raises:
        RuleError: On unknown functions or truncated arguments.
    """
    ops: list[tuple[str, str]] = []
    i = 0
    n = len(rule)
    while i < n:
        ch = rule[i]
        if ch in (" ", "\t"):
            i += 1
            continue
        if ch not in _ARG_COUNT:
            raise RuleError(f"unsupported rule function: {ch!r}")
        need = _ARG_COUNT[ch]
        args = rule[i + 1 : i + 1 + need]
        if len(args) < need:
            raise RuleError(f"truncated arguments for {ch!r} in {rule!r}")
        ops.append((ch, args))
        i += 1 + need
    return ops


def _apply_op(word: str, func: str, args: str) -> Optional[str]:
    """Apply a single rule function to a word.

    Args:
        word: Current candidate string.
        func: Rule function character.
        args: Argument characters for the function.

    Returns:
        The transformed word, or None if a rejection rule drops the candidate.
    """
    w = word
    if func == ":":
        return w
    if func == "l":
        return w.lower()
    if func == "u":
        return w.upper()
    if func == "c":
        return w[:1].upper() + w[1:].lower() if w else w
    if func == "C":
        return w[:1].lower() + w[1:].upper() if w else w
    if func == "t":
        return w.swapcase()
    if func == "T":
        p = _pos(args)
        if p >= len(w):
            return w
        return w[:p] + w[p].swapcase() + w[p + 1 :]
    if func == "r":
        return w[::-1]
    if func == "d":
        return w + w
    if func == "p":
        cnt = _pos(args)
        return w * (cnt + 1)
    if func == "f":
        return w + w[::-1]
    if func == "{":
        return w[1:] + w[:1] if w else w
    if func == "}":
        return w[-1:] + w[:-1] if w else w
    if func == "[":
        return w[1:]
    if func == "]":
        return w[:-1]
    if func == "D":
        p = _pos(args)
        if p >= len(w):
            return w
        return w[:p] + w[p + 1 :]
    if func == "x":
        p = _pos(args[0])
        c = _pos(args[1])
        return w[p : p + c]
    if func == "O":
        p = _pos(args[0])
        c = _pos(args[1])
        return w[:p] + w[p + c :]
    if func == "i":
        p = _pos(args[0])
        if p > len(w):
            return w
        return w[:p] + args[1] + w[p:]
    if func == "o":
        p = _pos(args[0])
        if p >= len(w):
            return w
        return w[:p] + args[1] + w[p + 1 :]
    if func == "s":
        return w.replace(args[0], args[1])
    if func == "@":
        return w.replace(args, "")
    if func == "z":
        cnt = _pos(args)
        return (w[:1] * cnt) + w if w else w
    if func == "Z":
        cnt = _pos(args)
        return w + (w[-1:] * cnt) if w else w
    if func == "q":
        return "".join(ch * 2 for ch in w)
    if func == "'":
        cnt = _pos(args)
        return w[:cnt]
    if func == "y":
        cnt = _pos(args)
        return w[:cnt] + w
    if func == "Y":
        cnt = _pos(args)
        return w + w[len(w) - cnt :] if cnt <= len(w) else w + w
    if func == "$":
        return w + args
    if func == "^":
        return args + w
    if func == "k":
        return w[1] + w[0] + w[2:] if len(w) >= 2 else w
    if func == "K":
        return w[:-2] + w[-1] + w[-2] if len(w) >= 2 else w
    if func == "*":
        a = _pos(args[0])
        b = _pos(args[1])
        if a < len(w) and b < len(w):
            lst = list(w)
            lst[a], lst[b] = lst[b], lst[a]
            return "".join(lst)
        return w
    if func == "L":
        p = _pos(args)
        if p < len(w):
            return w[:p] + chr((ord(w[p]) << 1) & 0xFF) + w[p + 1 :]
        return w
    if func == "R":
        p = _pos(args)
        if p < len(w):
            return w[:p] + chr(ord(w[p]) >> 1) + w[p + 1 :]
        return w
    if func == "+":
        p = _pos(args)
        if p < len(w):
            return w[:p] + chr((ord(w[p]) + 1) & 0xFF) + w[p + 1 :]
        return w
    if func == "-":
        p = _pos(args)
        if p < len(w):
            return w[:p] + chr((ord(w[p]) - 1) & 0xFF) + w[p + 1 :]
        return w
    if func == ".":
        p = _pos(args)
        if p + 1 < len(w):
            return w[:p] + w[p + 1] + w[p + 1 :]
        return w
    if func == ",":
        p = _pos(args)
        if 0 < p < len(w):
            return w[:p] + w[p - 1] + w[p + 1 :]
        return w
    if func == "e":
        sep = args
        out = []
        cap_next = True
        for ch in w:
            if cap_next and ch.isalpha():
                out.append(ch.upper())
                cap_next = False
            else:
                out.append(ch.lower())
            if ch == sep:
                cap_next = True
        return "".join(out)
    # ── Rejection functions (drop candidate on failure) ──────────────────
    if func == "<":
        return w if len(w) < _pos(args) else None
    if func == ">":
        return w if len(w) > _pos(args) else None
    if func == "_":
        return w if len(w) == _pos(args) else None
    if func == "!":
        return w if args not in w else None
    if func == "/":
        return w if args in w else None
    if func == "(":
        return w if w[:1] == args else None
    if func == ")":
        return w if w[-1:] == args else None
    if func == "=":
        p = _pos(args[0])
        return w if p < len(w) and w[p] == args[1] else None
    if func == "%":
        cnt = _pos(args[0])
        return w if w.count(args[1]) >= cnt else None
    raise RuleError(f"unsupported rule function: {func!r}")


def apply_rule(word: str, rule: str) -> Optional[str]:
    """Apply a full rule line (one or more functions) to a word.

    Args:
        word: Input word.
        rule: Rule line composed of one or more functions.

    Returns:
        Transformed candidate, or None if any rejection rule drops it.
    """
    ops = parse_rule(rule)
    w: Optional[str] = word
    for func, args in ops:
        w = _apply_op(w, func, args)
        if w is None:
            return None
    return w


def _read_rules(rule_file: Optional[str], inline: Optional[str]) -> list[str]:
    """Load rule lines from a file and/or an inline specification.

    Args:
        rule_file: Path to a rule file (one rule per line, ``#`` comments).
        inline: Inline rules separated by ``;``.

    Returns:
        List of rule strings.
    """
    rules: list[str] = []
    if rule_file:
        path = Path(rule_file)
        if not path.exists():
            raise FileNotFoundError(f"rule file not found: {rule_file}")
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n\r")
                if not line or line.lstrip().startswith("#"):
                    continue
                rules.append(line)
    if inline:
        for r in inline.split(";"):
            if r:
                rules.append(r)
    return rules


def apply_rules_stream(
    words: Iterable[str],
    rules: list[str],
    dedupe: bool = False,
) -> Generator[str, None, None]:
    """Apply a set of rules to a stream of words.

    Args:
        words: Iterable of input words.
        rules: List of rule strings.
        dedupe: If True, suppress duplicate outputs (uses memory).

    Yields:
        Transformed candidates in word-major, rule-minor order.
    """
    compiled: list[list[tuple[str, str]]] = []
    for r in rules:
        try:
            compiled.append(parse_rule(r))
        except RuleError as exc:
            logger.warning("skipping rule %r: %s", r, exc)
    seen: Optional[set[str]] = set() if dedupe else None
    for word in words:
        word = word.rstrip("\n\r")
        if not word:
            continue
        for ops in compiled:
            w: Optional[str] = word
            for func, args in ops:
                w = _apply_op(w, func, args)
                if w is None:
                    break
            if w is None:
                continue
            if seen is not None:
                if w in seen:
                    continue
                seen.add(w)
            yield w


# ── Conversion between hashcat and John the Ripper dialects ──────────────────
# The two dialects share almost the entire function set implemented here.
# These functions exist only in one dialect and are not portable.
_HASHCAT_ONLY = {"L", "R", "+", "-", ".", ",", "e", "q", "k", "K", "*", "%"}
_JOHN_ONLY = {"A", "M", "Q", "X", "v"}


def convert_rule(rule: str, to: str) -> str:
    """Convert a rule line between hashcat and John the Ripper dialects.

    Only the shared function set is converted. Functions specific to the source
    dialect are preserved verbatim with a trailing comment marker so the user
    can review them.

    Args:
        rule: Source rule line.
        to: Target dialect, ``hashcat`` or ``john``.

    Returns:
        Converted rule line.
    """
    ops = parse_rule(rule)
    out_parts: list[str] = []
    notes: list[str] = []
    for func, args in ops:
        if to == "john" and func in _HASHCAT_ONLY:
            notes.append(func)
        elif to == "hashcat" and func in _JOHN_ONLY:
            notes.append(func)
        out_parts.append(func + args)
    line = " ".join(out_parts)
    if notes:
        line += f"    # review non-portable: {' '.join(sorted(set(notes)))}"
    return line


def optimize_rules(rules: list[str]) -> list[str]:
    """Deduplicate and clean a list of rule lines.

    Removes exact duplicates (order preserving), drops blank and comment lines,
    and collapses redundant whitespace between functions.

    Args:
        rules: Input rule lines.

    Returns:
        Optimized rule lines.
    """
    seen: set[str] = set()
    out: list[str] = []
    for r in rules:
        if not r or r.lstrip().startswith("#"):
            continue
        try:
            ops = parse_rule(r)
        except RuleError:
            continue
        canonical = " ".join(f + a for f, a in ops)
        if not canonical:
            canonical = ":"
        if canonical in seen:
            continue
        seen.add(canonical)
        out.append(canonical)
    return out


def _iter_wordfile(path: str) -> Generator[str, None, None]:
    """Yield stripped lines from a wordlist file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"wordlist not found: {path}")
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            yield line.rstrip("\n\r")


def handle_rules(args, ctx: dict) -> Optional[Generator[str, None, None]]:
    """CLI handler for the ``rules`` command.

    Args:
        args: Parsed CLI arguments.
        ctx: Global execution context.

    Returns:
        Generator of output lines, or None on error.
    """
    action = getattr(args, "rules_action", "apply")
    rule_file = getattr(args, "rules", None)
    inline = getattr(args, "rule", None)

    try:
        rules = _read_rules(rule_file, inline)
    except FileNotFoundError as exc:
        logger.error(str(exc))
        return None

    if not rules and action != "apply":
        logger.error("no rules provided (use --rules FILE or --rule STR)")
        return None

    if action == "convert":
        to = getattr(args, "to", "john") or "john"
        return iter(convert_rule(r, to) for r in rules)

    if action == "optimize":
        return iter(optimize_rules(rules))

    # apply
    wordlist = getattr(args, "wordlist", None)
    if not wordlist:
        logger.error("apply requires --wordlist FILE")
        return None
    if not rules:
        rules = [":"]
    try:
        words = _iter_wordfile(wordlist)
    except FileNotFoundError as exc:
        logger.error(str(exc))
        return None
    dedupe = bool(getattr(args, "dedupe", False))
    return apply_rules_stream(words, rules, dedupe=dedupe)
