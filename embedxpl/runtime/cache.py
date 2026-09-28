"""EmbedXPL Runtime — Binary Cache.

Caches compiled binaries keyed by a SHA-256 hash of the source file(s).
Avoids recompilation on every run for C/C++/Go/Rust modules.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path
from typing import Optional

_WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
_CACHE_DIR = _WORKSPACE_ROOT / ".tmp" / "runtime_cache"


def _ensure_cache_dir() -> Path:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return _CACHE_DIR


def _hash_source(src: Path) -> str:
    """Return SHA-256 hex digest of file content."""
    h = hashlib.sha256()
    h.update(src.read_bytes())
    return h.hexdigest()[:16]


def _hash_dir(src_dir: Path) -> str:
    """Return SHA-256 of all source files in a directory (sorted)."""
    h = hashlib.sha256()
    for f in sorted(src_dir.rglob("*")):
        if f.is_file():
            h.update(f.name.encode())
            h.update(f.read_bytes())
    return h.hexdigest()[:16]


def get_cached_binary(src: Path, arch: str = "x64", ext: str = "") -> Optional[Path]:
    """Return path to cached binary if it exists and is up to date."""
    try:
        if src.is_dir():
            src_hash = _hash_dir(src)
        else:
            src_hash = _hash_source(src)
        cache_dir = _ensure_cache_dir()
        binary = cache_dir / f"{src.stem}_{arch}_{src_hash}{ext}"
        if binary.exists():
            return binary
    except Exception:
        pass
    return None


def store_binary(src: Path, binary_path: Path, arch: str = "x64", ext: str = "") -> Path:
    """Copy compiled binary into cache and return cached path."""
    try:
        if src.is_dir():
            src_hash = _hash_dir(src)
        else:
            src_hash = _hash_source(src)
        cache_dir = _ensure_cache_dir()
        cached = cache_dir / f"{src.stem}_{arch}_{src_hash}{ext}"
        shutil.copy2(binary_path, cached)
        cached.chmod(0o755)
        return cached
    except Exception:
        return binary_path


def clear_cache(older_than_days: int = 30) -> int:
    """Remove cache entries older than N days. Returns count removed."""
    import time
    removed = 0
    cache_dir = _ensure_cache_dir()
    cutoff = time.time() - (older_than_days * 86400)
    for f in cache_dir.iterdir():
        if f.is_file() and f.stat().st_mtime < cutoff:
            try:
                f.unlink()
                removed += 1
            except Exception:
                pass
    return removed


def cache_info() -> dict:
    """Return cache directory stats."""
    cache_dir = _ensure_cache_dir()
    files = list(cache_dir.iterdir())
    total_bytes = sum(f.stat().st_size for f in files if f.is_file())
    return {
        "path": str(cache_dir),
        "entries": len(files),
        "total_mb": round(total_bytes / 1024 / 1024, 2),
    }
