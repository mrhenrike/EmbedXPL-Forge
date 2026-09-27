"""
isp_keygen.py - ISP default WiFi password keyspace generator.

Generates vendor-specific WiFi password wordlists based on known ISP default
password patterns (e.g., Xfinity/Comcast: word5 + 4digit + word6).

Patterns are loaded from data/behavior_patterns.json (vendor_isp_patterns).
Word banks are loaded from data/isp_words_5.txt and data/isp_words_6.txt.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import itertools
import json
import logging
import sys
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

_MODULE_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _MODULE_DIR.parent

_ISP_PATTERNS: Optional[dict] = None
_WORD_BANKS: dict[int, list[str]] = {}


def _resolve_data(filename: str) -> Path:
    """Resolve data file path, checking embedxpl.engines.wordlists/data/ first then repo root data/."""
    pkg_path = _MODULE_DIR / "data" / filename
    if pkg_path.exists():
        return pkg_path
    return _REPO_ROOT / "data" / filename


def _load_isp_patterns() -> dict:
    """Load ISP patterns from behavior_patterns.json."""
    global _ISP_PATTERNS
    if _ISP_PATTERNS is not None:
        return _ISP_PATTERNS

    bp_path = _resolve_data("behavior_patterns.json")
    if not bp_path.exists():
        logger.error("behavior_patterns.json not found at %s", bp_path)
        _ISP_PATTERNS = {}
        return _ISP_PATTERNS

    with open(bp_path, "r", encoding="utf-8") as f:
        bp = json.load(f)

    cpb = bp.get("common_password_behaviors", {})
    _ISP_PATTERNS = cpb.get("vendor_isp_patterns", {})
    logger.info("Loaded %d ISP patterns", len(_ISP_PATTERNS))
    return _ISP_PATTERNS


def _load_word_bank(length: int) -> list[str]:
    """Load word bank for a given word length."""
    if length in _WORD_BANKS:
        return _WORD_BANKS[length]

    fname = f"isp_words_{length}.txt"
    fpath = _resolve_data(fname)

    if not fpath.exists():
        logger.warning("Word bank %s not found - using empty list", fpath)
        _WORD_BANKS[length] = []
        return _WORD_BANKS[length]

    words = []
    with open(fpath, "r", encoding="utf-8") as f:
        for line in f:
            w = line.strip()
            if w:
                words.append(w)
    _WORD_BANKS[length] = words
    logger.info("Loaded %d words of length %d from %s", len(words), length, fpath)
    return words


def list_isps() -> list[str]:
    """Return available ISP pattern names."""
    return sorted(_load_isp_patterns().keys())


def get_isp_info(isp: str) -> Optional[dict]:
    """Return pattern info for a specific ISP."""
    patterns = _load_isp_patterns()
    return patterns.get(isp)


def estimate_keyspace(
    isp: str,
    direction: str = "forward",
    word5_file: Optional[str] = None,
    word6_file: Optional[str] = None,
) -> tuple[int, str]:
    """Estimate total keyspace size and human-readable size string.

    Returns:
        Tuple of (total_entries, human_readable_size).
    """
    info = get_isp_info(isp)
    if not info:
        return 0, "0 B"

    w5 = _load_custom_words(word5_file, 5) if word5_file else _load_word_bank(5)
    w6 = _load_custom_words(word6_file, 6) if word6_file else _load_word_bank(6)

    numeric_range = 10000
    avg_len = info.get("total_length", 15)

    if direction == "both":
        total = (len(w5) * numeric_range * len(w6)) * 2
    else:
        total = len(w5) * numeric_range * len(w6)

    size_bytes = total * (avg_len + 1)
    if size_bytes >= 1 << 30:
        size_str = f"{size_bytes / (1 << 30):.1f} GB"
    elif size_bytes >= 1 << 20:
        size_str = f"{size_bytes / (1 << 20):.1f} MB"
    elif size_bytes >= 1 << 10:
        size_str = f"{size_bytes / (1 << 10):.1f} KB"
    else:
        size_str = f"{size_bytes} B"

    return total, size_str


def _load_custom_words(filepath: str, expected_len: int) -> list[str]:
    """Load words from a custom file, filtering by expected length."""
    words = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            w = line.strip().lower()
            if w and len(w) == expected_len:
                words.append(w)
    return words


def generate_isp_keyspace(
    isp: str,
    direction: str = "forward",
    word5_file: Optional[str] = None,
    word6_file: Optional[str] = None,
    limit: int = 0,
) -> Generator[str, None, None]:
    """Generate ISP default WiFi password candidates.

    Args:
        isp: ISP pattern name (e.g., 'xfinity_comcast').
        direction: 'forward' (word5+num+word6), 'reverse' (word6+num+word5), or 'both'.
        word5_file: Custom 5-letter word file (overrides default bank).
        word6_file: Custom 6-letter word file (overrides default bank).
        limit: Max entries to generate (0 = unlimited).

    Yields:
        Password candidate strings.
    """
    info = get_isp_info(isp)
    if not info:
        logger.error("Unknown ISP pattern: %s", isp)
        return

    w5 = _load_custom_words(word5_file, 5) if word5_file else _load_word_bank(5)
    w6 = _load_custom_words(word6_file, 6) if word6_file else _load_word_bank(6)

    case = info.get("case", "lowercase")
    nums = (f"{n:04d}" for n in range(10000))
    num_list = [f"{n:04d}" for n in range(10000)]

    count = 0

    def _apply_case(word: str) -> str:
        if case == "lowercase":
            return word.lower()
        elif case == "uppercase":
            return word.upper()
        return word

    def _forward() -> Generator[str, None, None]:
        for w5_word in w5:
            w5w = _apply_case(w5_word)
            for num in num_list:
                for w6_word in w6:
                    yield w5w + num + _apply_case(w6_word)

    def _reverse() -> Generator[str, None, None]:
        for w6_word in w6:
            w6w = _apply_case(w6_word)
            for num in num_list:
                for w5_word in w5:
                    yield w6w + num + _apply_case(w5_word)

    if direction == "forward":
        gen = _forward()
    elif direction == "reverse":
        gen = _reverse()
    else:
        gen = itertools.chain(_forward(), _reverse())

    for candidate in gen:
        yield candidate
        count += 1
        if limit and count >= limit:
            return


def handle_isp_keygen(args: object, _ctx: dict) -> None:
    """CLI handler for the isp-keygen subcommand."""
    if getattr(args, "list_isps", False):
        isps = list_isps()
        print(f"[+] {len(isps)} ISP patterns available:")
        for name in isps:
            info = get_isp_info(name)
            fmt = info.get("format", "N/A") if info else "N/A"
            note = info.get("note", "") if info else ""
            print(f"  {name:25s} format={fmt:30s} {note}")
        return

    isp = getattr(args, "isp", "xfinity_comcast")
    direction = getattr(args, "direction", "forward")
    limit = getattr(args, "limit", 0) or 0
    out = getattr(args, "output", None)
    estimate_only = getattr(args, "estimate", False)
    word5_file = getattr(args, "word5_file", None)
    word6_file = getattr(args, "word6_file", None)

    info = get_isp_info(isp)
    if not info:
        print(f"[-] Unknown ISP pattern: {isp}", file=sys.stderr)
        print(f"    Available: {', '.join(list_isps())}", file=sys.stderr)
        return

    total, size_str = estimate_keyspace(isp, direction, word5_file, word6_file)
    print(f"[*] ISP: {isp}")
    print(f"[*] Direction: {direction}")
    print(f"[*] Format: {info.get('format', 'N/A')}")
    print(f"[*] Estimated keyspace: {total:,} entries (~{size_str})")

    if limit:
        print(f"[*] Limit: {limit:,} entries")

    if estimate_only:
        return

    if total > 10_000_000 and not out and not limit:
        print("[!] WARNING: Generating >10M entries to stdout. Use -o or --limit.")
        print("[!] Aborting. Use -o <file> or --limit <N> to proceed.")
        return

    fh = open(out, "w", encoding="utf-8", newline="\n") if out else sys.stdout
    count = 0
    try:
        for candidate in generate_isp_keyspace(isp, direction, word5_file, word6_file, limit):
            fh.write(candidate + "\n")
            count += 1
            if count % 1_000_000 == 0:
                logger.info("Generated %d entries...", count)
    finally:
        if fh is not sys.stdout:
            fh.close()

    if out:
        print(f"[+] {count:,} entries written to {out}")
