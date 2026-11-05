"""
sanitizer.py - Wordlist sanitization, sorting and transformation.

Features:
  - Remove blank lines
  - Remove comments (lines starting with #)
  - Deduplication (keep only unique lines)
  - Sorting: alphabetical, by length, reverse, random, frequency
  - Length filters: --min-len, --max-len
  - File reversal (cat -> tac, last line first)
  - Custom regex filters
  - Strip control characters (tabs, null bytes, escape sequences)
  - Replace in-place or to output file

Usage:
  wlf.py sanitize list.lst
  wlf.py sanitize list.lst --min-len 8 --max-len 20 --sort alpha -o out.lst
  wlf.py sanitize list.lst --strip-control --sort frequency -o out.lst
  wlf.py sanitize list.lst --filter "^[a-zA-Z]" --no-comments --dedupe
  wlf.py reverse list.lst -o reversed.lst

Author: Andre Henrique (@mrhenrike)
Version: 1.1.0
"""
from __future__ import annotations

import logging
import random
import re
from collections import Counter
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _is_comment_line(line: str) -> bool:
    """True only for metadata comments, not passwords starting with '#'."""
    s = line.lstrip()
    if not s.startswith("#"):
        return False
    if len(s) == 1:
        return True
    return s[1].isspace()


def _read_lines(filepath: str) -> list[str]:
    """
    Read lines from a file preserving original content.

    Args:
        filepath: File path.

    Returns:
        List of lines without line terminators.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")
    with path.open(encoding="utf-8", errors="replace") as f:
        return [line.rstrip("\n\r") for line in f]


def sanitize(
    filepath: str,
    output: Optional[str] = None,
    no_blank: bool = True,
    no_comments: bool = True,
    dedupe: bool = True,
    sort_mode: Optional[str] = None,
    min_len: Optional[int] = None,
    max_len: Optional[int] = None,
    filter_pattern: Optional[str] = None,
    exclude_pattern: Optional[str] = None,
    inplace: bool = False,
    strip_control: bool = False,
) -> dict:
    """
    Sanitize a wordlist applying all configured filters.

    Application order:
      0. Strip control characters (if strip_control=True)
      1. Remove comments (# at start)
      2. Remove blank lines
      3. Length filter (min_len / max_len)
      4. Regex inclusion filter (filter_pattern)
      5. Regex exclusion filter (exclude_pattern)
      6. Deduplication
      7. Sorting (alpha, length, random, frequency)

    Args:
        filepath: Input file path.
        output: Output file. If None and inplace=False, writes to stdout.
        no_blank: Remove blank lines.
        no_comments: Remove lines starting with '#'.
        dedupe: Remove duplicate entries keeping the first occurrence.
        sort_mode: 'alpha', 'alpha-rev', 'length', 'length-rev', 'random' or None.
        min_len: Minimum length (includes lines >= min_len).
        max_len: Maximum length (includes lines <= max_len).
        filter_pattern: Regex - keep only matching lines.
        exclude_pattern: Regex - remove matching lines.
        inplace: If True, overwrite the input file.

    Returns:
        Dict with stats: total_input, total_output, removed_blank,
        removed_comments, removed_length, removed_filter, removed_dupes.
    """
    lines = _read_lines(filepath)
    stats = {
        "total_input": len(lines),
        "removed_comments": 0,
        "removed_blank": 0,
        "removed_length": 0,
        "removed_filter": 0,
        "removed_exclude": 0,
        "removed_dupes": 0,
        "stripped_control": 0,
        "total_output": 0,
    }

    if strip_control:
        cleaned: list[str] = []
        for line in lines:
            new_line = _CONTROL_RE.sub("", line)
            if new_line != line:
                stats["stripped_control"] += 1
            cleaned.append(new_line)
        lines = cleaned

    result: list[str] = []

    for line in lines:
        # Remove comments
        if no_comments and _is_comment_line(line):
            stats["removed_comments"] += 1
            continue

        # Remove blank lines
        if no_blank and not line.strip():
            stats["removed_blank"] += 1
            continue

        # Length filter
        if min_len is not None and len(line) < min_len:
            stats["removed_length"] += 1
            continue
        if max_len is not None and len(line) > max_len:
            stats["removed_length"] += 1
            continue

        # Regex inclusion filter
        if filter_pattern and not re.search(filter_pattern, line):
            stats["removed_filter"] += 1
            continue

        # Regex exclusion filter
        if exclude_pattern and re.search(exclude_pattern, line):
            stats["removed_exclude"] += 1
            continue

        result.append(line)

    # Deduplication preserving first-occurrence order
    if dedupe:
        seen: set[str] = set()
        deduped: list[str] = []
        for line in result:
            if line not in seen:
                seen.add(line)
                deduped.append(line)
            else:
                stats["removed_dupes"] += 1
        result = deduped

    # Sorting
    if sort_mode == "alpha":
        result.sort(key=str.lower)
    elif sort_mode == "alpha-rev":
        result.sort(key=str.lower, reverse=True)
    elif sort_mode == "length":
        result.sort(key=len)
    elif sort_mode == "length-rev":
        result.sort(key=len, reverse=True)
    elif sort_mode == "random":
        random.shuffle(result)
    elif sort_mode == "frequency":
        freq = Counter(result)
        result.sort(key=lambda x: freq[x], reverse=True)

    stats["total_output"] = len(result)

    # Output destination
    dest = output or (filepath if inplace else None)
    if dest:
        Path(dest).write_text("\n".join(result) + "\n", encoding="utf-8")
    else:
        for line in result:
            print(line)

    return stats


def reverse_file(
    filepath: str,
    output: Optional[str] = None,
    inplace: bool = False,
) -> int:
    """
    Reverse the line order of a file (cat -> tac).

    Args:
        filepath: Input file path.
        output: Output file. If None and inplace=False, writes to stdout.
        inplace: If True, overwrite the input file.

    Returns:
        Total lines processed.
    """
    lines = _read_lines(filepath)
    reversed_lines = list(reversed(lines))

    dest = output or (filepath if inplace else None)
    if dest:
        Path(dest).write_text("\n".join(reversed_lines) + "\n", encoding="utf-8")
    else:
        for line in reversed_lines:
            print(line)

    return len(reversed_lines)


def format_sanitize_stats(stats: dict, filepath: str) -> str:
    """
    Format sanitization statistics for display.

    Args:
        stats: Dict returned by sanitize().
        filepath: Processed file path.

    Returns:
        Formatted string with statistics.
    """
    lines = [
        f"Sanitize: {filepath}",
        f"  Input:              {stats['total_input']:>10,}",
        f"  Comments removed:   {stats['removed_comments']:>10,}",
        f"  Blank lines:        {stats['removed_blank']:>10,}",
        f"  Out of length:      {stats['removed_length']:>10,}",
        f"  Regex filter (incl):{stats['removed_filter']:>10,}",
        f"  Regex exclusion:    {stats['removed_exclude']:>10,}",
        f"  Duplicates:         {stats['removed_dupes']:>10,}",
        f"  Control chars strip:{stats.get('stripped_control', 0):>10,}",
        f"  {'─'*30}",
        f"  Final output:       {stats['total_output']:>10,}",
    ]
    return "\n".join(lines)
