"""
merger.py - Wordlist merging, filtering, and deduplication.

Features:
  - Merge multiple files with deduplication
  - Filtering by length, charset, regex pattern
  - Sorting (alphabetical, by length, random)
  - Removal of purely numeric entries
  - Streaming output for large volumes

Usage:
  wlf.py merge list1.lst list2.lst -o merged.lst
  wlf.py merge *.lst --min-len 8 --no-numeric --sort alpha
  wlf.py merge list.lst --filter "^[a-z]+$" --dedupe

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
import random
import re
from collections import Counter
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)


def _is_purely_numeric(s: str) -> bool:
    """
    Check whether a string consists entirely of digits.

    Args:
        s: String to check.

    Returns:
        True if the string is purely numeric.
    """
    return bool(re.fullmatch(r"\d+", s))


def stream_merged(
    filepaths: list[str],
    min_len: int = 6,
    max_len: int = 128,
    no_numeric: bool = False,
    filter_pattern: Optional[str] = None,
    dedupe: bool = True,
    sort_mode: Optional[str] = None,
) -> Generator[str, None, None]:
    """
    Merge multiple wordlists with filtering and deduplication.

    Args:
        filepaths: List of wordlist paths to merge.
        min_len: Minimum entry length.
        max_len: Maximum entry length.
        no_numeric: If True, remove purely numeric entries.
        filter_pattern: Regex to filter entries (only matches pass).
        dedupe: If True, remove duplicates.
        sort_mode: 'alpha', 'length', 'random', or None (input order).

    Yields:
        Filtered and deduplicated entries.
    """
    compiled_filter = re.compile(filter_pattern) if filter_pattern else None
    seen: set[str] = set()
    entries: list[str] = []

    for filepath in filepaths:
        path = Path(filepath)
        if not path.exists():
            logger.warning("File not found: %s", filepath)
            continue

        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                entry = line.rstrip("\n\r")
                if not entry:
                    continue
                if len(entry) < min_len or len(entry) > max_len:
                    continue
                if no_numeric and _is_purely_numeric(entry):
                    continue
                if compiled_filter and not compiled_filter.search(entry):
                    continue
                if dedupe:
                    if entry in seen:
                        continue
                    seen.add(entry)
                entries.append(entry)

    # Sorting
    if sort_mode == "alpha":
        entries.sort(key=str.lower)
    elif sort_mode == "length":
        entries.sort(key=len)
    elif sort_mode == "random":
        random.shuffle(entries)
    elif sort_mode == "frequency":
        freq = Counter(entries)
        entries.sort(key=lambda x: freq[x], reverse=True)

    yield from entries


def merge_to_file(
    filepaths: list[str],
    output_path: str,
    min_len: int = 6,
    max_len: int = 128,
    no_numeric: bool = False,
    filter_pattern: Optional[str] = None,
    dedupe: bool = True,
    sort_mode: Optional[str] = None,
) -> int:
    """
    Merge wordlists and save to a file.

    Args:
        filepaths: List of input files.
        output_path: Output file path.
        min_len: Minimum entry length.
        max_len: Maximum entry length.
        no_numeric: If True, remove numeric entries.
        filter_pattern: Filtering regex.
        dedupe: If True, remove duplicates.
        sort_mode: Sort mode.

    Returns:
        Total entries written.
    """
    out = Path(output_path)
    count = 0
    with out.open("w", encoding="utf-8") as f:
        for entry in stream_merged(
            filepaths, min_len, max_len, no_numeric,
            filter_pattern, dedupe, sort_mode,
        ):
            f.write(entry + "\n")
            count += 1

    logger.info("Merge complete: %d entries in %s", count, output_path)
    return count
