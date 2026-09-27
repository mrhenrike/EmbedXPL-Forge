"""
list_ops.py - High-performance wordlist operations.

Streaming utilities for very large wordlists: order-preserving deduplication
with an optional Bloom filter, set subtraction against one or more files,
splitting by count, size or entry length, and keyspace and time-to-exhaust
estimation for masks, charsets and rule sets.

Inspired by rling, duplicut and the hashcat-utils family (splitlen, rli).

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import hashlib
import logging
import math
from pathlib import Path
from typing import Generator, Iterable, Optional

logger = logging.getLogger(__name__)


class BloomFilter:
    """Space-efficient probabilistic set for order-preserving deduplication.

    Uses double hashing derived from a single SHA-256 digest. False positives
    are possible (a real entry may rarely be treated as a duplicate), false
    negatives never happen. Suitable when exact-set memory is too large.
    """

    def __init__(self, capacity: int, error_rate: float = 0.001) -> None:
        """Initialize the filter.

        Args:
            capacity: Expected number of distinct items.
            error_rate: Target false positive probability.
        """
        capacity = max(1, capacity)
        error_rate = min(max(error_rate, 1e-9), 0.5)
        m = int(math.ceil(-capacity * math.log(error_rate) / (math.log(2) ** 2)))
        self.m = max(8, m)
        self.k = max(1, int(round(self.m / capacity * math.log(2))))
        self.bits = bytearray((self.m + 7) // 8)

    def _indices(self, item: str) -> Generator[int, None, None]:
        digest = hashlib.sha256(item.encode("utf-8", "replace")).digest()
        h1 = int.from_bytes(digest[:8], "little")
        h2 = int.from_bytes(digest[8:16], "little") | 1
        for i in range(self.k):
            yield (h1 + i * h2) % self.m

    def add(self, item: str) -> bool:
        """Add an item and report whether it was probably new.

        Args:
            item: Item to add.

        Returns:
            True if the item was probably not present before, False if it was
            probably already present.
        """
        new = False
        for idx in self._indices(item):
            byte, bit = idx >> 3, idx & 7
            if not (self.bits[byte] >> bit) & 1:
                new = True
                self.bits[byte] |= 1 << bit
        return new


def dedup_stream(
    words: Iterable[str],
    use_bloom: bool = False,
    capacity: int = 1_000_000,
) -> Generator[str, None, None]:
    """Yield unique entries in first-seen order.

    Args:
        words: Iterable of input entries.
        use_bloom: Use a Bloom filter instead of an exact set (lower memory).
        capacity: Expected distinct count when using a Bloom filter.

    Yields:
        Unique entries preserving input order.
    """
    if use_bloom:
        bloom = BloomFilter(capacity)
        for word in words:
            word = word.rstrip("\n\r")
            if not word:
                continue
            if bloom.add(word):
                yield word
    else:
        seen: set[str] = set()
        for word in words:
            word = word.rstrip("\n\r")
            if not word:
                continue
            if word not in seen:
                seen.add(word)
                yield word


def _load_set(paths: list[str]) -> set[str]:
    """Load the union of entries from several files into a set."""
    out: set[str] = set()
    for p in paths:
        path = Path(p)
        if not path.exists():
            logger.warning("file not found: %s", p)
            continue
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                entry = line.rstrip("\n\r")
                if entry:
                    out.add(entry)
    return out


def subtract_stream(
    words: Iterable[str],
    remove_paths: list[str],
) -> Generator[str, None, None]:
    """Yield entries from ``words`` that are absent from the removal files.

    Args:
        words: Iterable of input entries.
        remove_paths: Files whose entries must be removed from the output.

    Yields:
        Entries not present in any removal file (deduplicated).
    """
    remove = _load_set(remove_paths)
    seen: set[str] = set()
    for word in words:
        word = word.rstrip("\n\r")
        if not word or word in remove or word in seen:
            continue
        seen.add(word)
        yield word


def _parse_size(spec: str) -> int:
    """Parse a human size string (for example ``50MB``) into bytes."""
    spec = spec.strip().upper()
    units = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}
    for suffix in ("GB", "MB", "KB", "B"):
        if spec.endswith(suffix):
            return int(float(spec[: -len(suffix)]) * units[suffix])
    return int(spec)


def split_file(
    input_path: str,
    out_prefix: str,
    by_lines: int = 0,
    by_size: str = "",
    by_length: bool = False,
) -> dict:
    """Split a wordlist into multiple files.

    Exactly one split mode is used, evaluated in this order: by_length,
    by_lines, by_size.

    Args:
        input_path: Source wordlist.
        out_prefix: Output path prefix. Parts are named ``<prefix>.<key>``.
        by_lines: Max lines per part (line count mode).
        by_size: Max size per part as a human string (size mode).
        by_length: If True, group entries into one file per entry length.

    Returns:
        Statistics dict with the created files and totals.
    """
    src = Path(input_path)
    if not src.exists():
        raise FileNotFoundError(f"wordlist not found: {input_path}")

    prefix = Path(out_prefix)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    files_created: list[str] = []
    total = 0

    if by_length:
        handles: dict[int, object] = {}
        try:
            with src.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    entry = line.rstrip("\n\r")
                    if not entry:
                        continue
                    total += 1
                    ln = len(entry)
                    if ln not in handles:
                        fp = f"{out_prefix}.len{ln:02d}.txt"
                        handles[ln] = open(fp, "w", encoding="utf-8")
                        files_created.append(fp)
                    handles[ln].write(entry + "\n")  # type: ignore[attr-defined]
        finally:
            for h in handles.values():
                h.close()  # type: ignore[attr-defined]
        return {"mode": "length", "parts": len(files_created),
                "files": files_created, "total": total}

    max_bytes = _parse_size(by_size) if by_size else 0
    part = 0
    cur = None
    cur_lines = 0
    cur_bytes = 0

    def _open_part() -> object:
        nonlocal part
        fp = f"{out_prefix}.part{part:04d}.txt"
        files_created.append(fp)
        return open(fp, "w", encoding="utf-8")

    try:
        with src.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                entry = line.rstrip("\n\r")
                if not entry:
                    continue
                if cur is None:
                    cur = _open_part()
                    cur_lines = 0
                    cur_bytes = 0
                data = entry + "\n"
                cur.write(data)  # type: ignore[attr-defined]
                total += 1
                cur_lines += 1
                cur_bytes += len(data.encode("utf-8"))
                roll = False
                if by_lines and cur_lines >= by_lines:
                    roll = True
                if max_bytes and cur_bytes >= max_bytes:
                    roll = True
                if roll:
                    cur.close()  # type: ignore[attr-defined]
                    cur = None
                    part += 1
    finally:
        if cur is not None:
            cur.close()  # type: ignore[attr-defined]

    return {"mode": "lines" if by_lines else "size", "parts": len(files_created),
            "files": files_created, "total": total}


# ── Keyspace estimation ──────────────────────────────────────────────────────
_MASK_CHARSETS = {
    "l": 26, "u": 26, "d": 10, "s": 33, "a": 95, "b": 256, "h": 16, "H": 16,
}


def mask_keyspace(mask: str, custom: Optional[dict[str, int]] = None) -> int:
    """Compute the number of candidates for a hashcat mask.

    Args:
        mask: Hashcat mask string (for example ``?u?l?l?l?d?d``).
        custom: Optional sizes for custom charsets ``1``-``4``.

    Returns:
        Total candidate count.
    """
    sizes = dict(_MASK_CHARSETS)
    if custom:
        sizes.update(custom)
    total = 1
    i = 0
    while i < len(mask):
        ch = mask[i]
        if ch == "?" and i + 1 < len(mask):
            token = mask[i + 1]
            total *= sizes.get(token, 1)
            i += 2
        else:
            total *= 1  # static character contributes one option
            i += 1
    return total


def charset_keyspace(charset_size: int, min_len: int, max_len: int) -> int:
    """Sum candidate counts for a charset over a length range.

    Args:
        charset_size: Number of distinct characters.
        min_len: Minimum length.
        max_len: Maximum length.

    Returns:
        Total candidate count across all lengths.
    """
    total = 0
    for length in range(max(1, min_len), max(min_len, max_len) + 1):
        total += charset_size ** length
    return total


def _fmt_count(n: int) -> str:
    return f"{n:,}"


def _fmt_eta(seconds: float) -> str:
    """Format a duration in seconds as a compact human string."""
    if seconds < 1:
        return "< 1 second"
    units = [("year", 31557600), ("day", 86400), ("hour", 3600),
             ("minute", 60), ("second", 1)]
    parts: list[str] = []
    for name, size in units:
        if seconds >= size:
            qty = int(seconds // size)
            seconds -= qty * size
            parts.append(f"{qty} {name}{'s' if qty != 1 else ''}")
        if len(parts) >= 2:
            break
    return ", ".join(parts) if parts else "< 1 second"


def keyspace_report(total: int, pps: float) -> list[str]:
    """Build a keyspace and time-to-exhaust report.

    Args:
        total: Total candidate count.
        pps: Guessing rate in passwords per second.

    Returns:
        List of report lines.
    """
    lines = [
        "Keyspace estimate:",
        f"  Candidates      : {_fmt_count(total)}",
        f"  Rate (p/s)      : {_fmt_count(int(pps))}",
        f"  Time to exhaust : {_fmt_eta(total / pps) if pps > 0 else 'n/a'}",
    ]
    return lines


def _iter_wordfile(path: str) -> Generator[str, None, None]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"wordlist not found: {path}")
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            yield line.rstrip("\n\r")


def _count_lines(path: str) -> int:
    n = 0
    p = Path(path)
    if not p.exists():
        return 0
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.rstrip("\n\r"):
                n += 1
    return n


def handle_dedup(args, ctx: dict) -> Optional[Generator[str, None, None]]:
    """CLI handler for the ``dedup`` command."""
    wordlist = getattr(args, "wordlist", None)
    if not wordlist:
        logger.error("dedup requires a wordlist")
        return None
    try:
        words = _iter_wordfile(wordlist)
    except FileNotFoundError as exc:
        logger.error(str(exc))
        return None
    use_bloom = bool(getattr(args, "bloom", False))
    capacity = int(getattr(args, "capacity", 0) or 1_000_000)
    return dedup_stream(words, use_bloom=use_bloom, capacity=capacity)


def handle_subtract(args, ctx: dict) -> Optional[Generator[str, None, None]]:
    """CLI handler for the ``subtract`` command."""
    wordlist = getattr(args, "wordlist", None)
    remove = getattr(args, "remove", None) or []
    if not wordlist or not remove:
        logger.error("subtract requires a wordlist and --remove FILE ...")
        return None
    try:
        words = _iter_wordfile(wordlist)
    except FileNotFoundError as exc:
        logger.error(str(exc))
        return None
    return subtract_stream(words, remove)
