"""
hash_tools.py - Hash identification, generation and hcmask export.

Provides three cracking-interop utilities:

- identify likely hash algorithms for a given digest (name-that-hash style),
- generate digests for a wordlist to build test corpora (md5, sha1, sha256,
  sha512, ntlm, bcrypt, argon2, pbkdf2, scrypt),
- export a hashcat ``.hcmask`` file from the mask distribution of a wordlist.

bcrypt, argon2 and scrypt use vetted libraries when available and are skipped
with a clear message otherwise. Plaintext values are never logged.

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import hashlib
import logging
import re
from collections import Counter
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)


# ── Hash identification ──────────────────────────────────────────────────────
_HEX = re.compile(r"^[0-9a-fA-F]+$")

# (name, hashcat_mode) candidates keyed by exact hex length.
_BY_HEX_LEN = {
    32: [("MD5", 0), ("NTLM", 1000), ("MD4", 900), ("LM", 3000),
         ("MD5(half)", None)],
    40: [("SHA1", 100), ("MySQL4.1+ (without *)", 300), ("RIPEMD-160", 6000)],
    56: [("SHA-224", None), ("SHA3-224", None)],
    64: [("SHA-256", 1400), ("SHA3-256", 5000), ("BLAKE2s", None)],
    96: [("SHA-384", 10800)],
    128: [("SHA-512", 1700), ("SHA3-512", None), ("Whirlpool", 6100),
          ("BLAKE2b", 600)],
    16: [("MySQL323", 200), ("CRC64", None)],
    8: [("CRC32", 11500), ("Adler32", None)],
}

_PREFIX_RULES = [
    (re.compile(r"^\$2[abxy]\$\d\d\$"), ("bcrypt", 3200)),
    (re.compile(r"^\$argon2id\$"), ("Argon2id", None)),
    (re.compile(r"^\$argon2i\$"), ("Argon2i", None)),
    (re.compile(r"^\$argon2d\$"), ("Argon2d", None)),
    (re.compile(r"^\$6\$"), ("sha512crypt", 1800)),
    (re.compile(r"^\$5\$"), ("sha256crypt", 7400)),
    (re.compile(r"^\$1\$"), ("md5crypt", 500)),
    (re.compile(r"^\$y\$"), ("yescrypt", None)),
    (re.compile(r"^\$scrypt\$|^SCRYPT:"), ("scrypt", 8900)),
    (re.compile(r"^\{SSHA\}"), ("SSHA (LDAP)", 111)),
    (re.compile(r"^\{SHA\}"), ("SHA (LDAP)", 101)),
    (re.compile(r"^\*[0-9A-F]{40}$"), ("MySQL4.1+ (with *)", 300)),
    (re.compile(r"^[0-9a-f]{32}:[0-9a-zA-Z]+$"), ("md5($pass.$salt) or md5:salt", 10)),
    (re.compile(r"^sha1\$"), ("Django SHA1", 124)),
    (re.compile(r"^pbkdf2_sha256\$"), ("Django PBKDF2-SHA256", 10000)),
]


def identify(digest: str) -> list[tuple[str, Optional[int]]]:
    """Identify likely hash algorithms for a digest string.

    Args:
        digest: Hash string to classify.

    Returns:
        List of (name, hashcat_mode) candidates, most likely first.
    """
    digest = digest.strip()
    out: list[tuple[str, Optional[int]]] = []
    for rx, cand in _PREFIX_RULES:
        if rx.search(digest):
            out.append(cand)
    if not out and _HEX.match(digest):
        out.extend(_BY_HEX_LEN.get(len(digest), []))
    if not out:
        out.append(("unknown", None))
    return out


# ── NTLM / MD4 fallback ──────────────────────────────────────────────────────
def _md4(data: bytes) -> bytes:
    """Compute MD4, using hashlib when available or a pure-Python fallback."""
    try:
        h = hashlib.new("md4")
        h.update(data)
        return h.digest()
    except (ValueError, TypeError):
        return _md4_pure(data)


def _md4_pure(msg: bytes) -> bytes:
    """Pure-Python MD4 implementation (RFC 1320) for NTLM when OpenSSL lacks it."""
    def lrot(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    ml = len(msg) * 8
    msg += b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += ml.to_bytes(8, "little")

    for off in range(0, len(msg), 64):
        x = [int.from_bytes(msg[off + i * 4 : off + i * 4 + 4], "little")
             for i in range(16)]
        aa, bb, cc, dd = a, b, c, d
        for i in (0, 4, 8, 12):
            a = lrot((a + (b & c | ~b & d) + x[i]) & 0xFFFFFFFF, 3)
            d = lrot((d + (a & b | ~a & c) + x[i + 1]) & 0xFFFFFFFF, 7)
            c = lrot((c + (d & a | ~d & b) + x[i + 2]) & 0xFFFFFFFF, 11)
            b = lrot((b + (c & d | ~c & a) + x[i + 3]) & 0xFFFFFFFF, 19)
        for i in (0, 1, 2, 3):
            a = lrot((a + (b & c | b & d | c & d) + x[i] + 0x5A827999) & 0xFFFFFFFF, 3)
            d = lrot((d + (a & b | a & c | b & c) + x[i + 4] + 0x5A827999) & 0xFFFFFFFF, 5)
            c = lrot((c + (d & a | d & b | a & b) + x[i + 8] + 0x5A827999) & 0xFFFFFFFF, 9)
            b = lrot((b + (c & d | c & a | d & a) + x[i + 12] + 0x5A827999) & 0xFFFFFFFF, 13)
        for i in (0, 2, 1, 3):
            a = lrot((a + (b ^ c ^ d) + x[i] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
            d = lrot((d + (a ^ b ^ c) + x[i + 8] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
            c = lrot((c + (d ^ a ^ b) + x[i + 4] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
            b = lrot((b + (c ^ d ^ a) + x[i + 12] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)
        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return b"".join(v.to_bytes(4, "little") for v in (a, b, c, d))


def _ntlm(pw: str) -> str:
    return _md4(pw.encode("utf-16le")).hex()


def _hash_one(pw: str, algo: str) -> Optional[str]:
    """Compute a single digest for a password, or None if unsupported."""
    a = algo.lower()
    if a in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512"):
        return hashlib.new(a, pw.encode("utf-8")).hexdigest()
    if a == "ntlm":
        return _ntlm(pw)
    if a == "md4":
        return _md4(pw.encode("utf-8")).hex()
    if a == "bcrypt":
        try:
            import bcrypt
        except ImportError:
            return None
        return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("ascii")
    if a in ("argon2", "argon2id"):
        try:
            from argon2 import PasswordHasher
        except ImportError:
            return None
        return PasswordHasher().hash(pw)
    if a == "pbkdf2":
        salt = b"wlf-static-salt"  # test corpora only; not for production storage
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 100_000)
        return "pbkdf2_sha256$100000$" + salt.hex() + "$" + dk.hex()
    if a == "scrypt":
        salt = b"wlf-static-salt"
        try:
            dk = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=16384, r=8, p=1)
        except (ValueError, MemoryError):
            return None
        return "scrypt$16384$8$1$" + salt.hex() + "$" + dk.hex()
    return None


def hash_stream(
    words, algo: str, fmt: str = "hash", separator: str = ":"
) -> Generator[str, None, None]:
    """Generate digests for a stream of words.

    Args:
        words: Iterable of passwords.
        algo: Hash algorithm name.
        fmt: Output format, one of ``hash``, ``hash:plain`` or ``plain:hash``.
        separator: Field separator for the combined formats.

    Yields:
        Formatted digest lines.
    """
    warned = False
    for raw in words:
        pw = raw.rstrip("\n\r")
        if not pw:
            continue
        digest = _hash_one(pw, algo)
        if digest is None:
            if not warned:
                logger.error("algorithm %r unavailable (missing optional library)",
                             algo)
                warned = True
            return
        if fmt == "hash":
            yield digest
        elif fmt == "plain:hash":
            yield f"{pw}{separator}{digest}"
        else:
            yield f"{digest}{separator}{pw}"


# ── hcmask export ────────────────────────────────────────────────────────────
def _word_to_mask(word: str) -> str:
    """Convert a word into a hashcat mask string."""
    out = []
    for ch in word:
        if ch.islower():
            out.append("?l")
        elif ch.isupper():
            out.append("?u")
        elif ch.isdigit():
            out.append("?d")
        else:
            out.append("?s")
    return "".join(out)


def export_hcmask(input_path: str, output_path: str, top_n: int = 0,
                  min_count: int = 1) -> dict:
    """Export a hashcat .hcmask file from a wordlist mask distribution.

    Args:
        input_path: Source wordlist.
        output_path: Destination .hcmask file.
        top_n: Keep only the top N masks (0 = all).
        min_count: Minimum occurrence count to keep a mask.

    Returns:
        Statistics dict.
    """
    src = Path(input_path)
    if not src.exists():
        raise FileNotFoundError(f"wordlist not found: {input_path}")
    counter: Counter = Counter()
    total = 0
    with src.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            w = line.rstrip("\n\r")
            if not w:
                continue
            total += 1
            counter[_word_to_mask(w)] += 1

    ranked = [(m, c) for m, c in counter.most_common(top_n or None) if c >= min_count]
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for mask, _c in ranked:
            fh.write(mask + "\n")
    return {"total": total, "unique_masks": len(counter),
            "written": len(ranked), "output": str(out)}


def _iter_wordfile(path: str) -> Generator[str, None, None]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"wordlist not found: {path}")
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            yield line.rstrip("\n\r")


def handle_hash_id(args, ctx: dict):
    """CLI handler for the ``hash-id`` command."""
    value = getattr(args, "hash", None)
    wordlist = getattr(args, "wordlist", None)
    lines: list[str] = []
    if value:
        cands = identify(value)
        lines.append(f"Input: {value}")
        for name, mode in cands:
            mode_s = f"  (hashcat -m {mode})" if mode is not None else ""
            lines.append(f"  {name}{mode_s}")
    elif wordlist:
        wp = Path(wordlist)
        if not wp.exists():
            logger.error("file not found: %s", wordlist)
            return None
        with wp.open("r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                h = raw.rstrip("\n\r")
                if not h:
                    continue
                cands = identify(h)
                best = cands[0]
                mode_s = f" -m {best[1]}" if best[1] is not None else ""
                lines.append(f"{h}\t{best[0]}{mode_s}")
    else:
        logger.error("provide a hash value or --wordlist FILE")
        return None
    return iter(lines)


def handle_hash_gen(args, ctx: dict) -> Optional[Generator[str, None, None]]:
    """CLI handler for the ``hash-gen`` command."""
    wordlist = getattr(args, "wordlist", None)
    if not wordlist:
        logger.error("hash-gen requires a wordlist")
        return None
    try:
        words = _iter_wordfile(wordlist)
    except FileNotFoundError as exc:
        logger.error(str(exc))
        return None
    algo = getattr(args, "algo", "md5") or "md5"
    fmt = getattr(args, "format", "hash") or "hash"
    sep = getattr(args, "separator", ":") or ":"
    return hash_stream(words, algo, fmt, sep)
