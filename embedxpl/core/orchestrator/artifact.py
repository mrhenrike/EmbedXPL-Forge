# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Compiled Artifact - Build result container with hash-based caching.

Provides the CompiledArtifact dataclass and ArtifactCache manager
for storing and retrieving compiled exploit binaries under .tmp/builds/
with hash-based invalidation.

Version: 1.0.0
"""

import hashlib
import json
import os
import shutil
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


_BUILDS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", ".tmp", "builds"
)


@dataclass
class CompiledArtifact:
    """Represents the result of a cross-compilation build.

    Attributes:
        source_hash: SHA-256 hash of the source file at build time.
        binary_path: Absolute path to the compiled binary.
        target_arch: Target architecture (x86, x86_64, ARM, MIPS, RISC-V).
        compiler_used: Compiler binary that produced this artifact.
        build_time: Unix timestamp of the build completion.
        cached: Whether this artifact was served from cache.
        source_path: Original source file path.
        build_flags: Compiler flags used for the build.
        binary_size: Size of the compiled binary in bytes.
        exit_code: Compiler process exit code.
    """

    source_hash: str
    binary_path: str
    target_arch: str
    compiler_used: str
    build_time: float
    cached: bool = False
    source_path: str = ""
    build_flags: str = ""
    binary_size: int = 0
    exit_code: int = 0

    def is_valid(self) -> bool:
        """Check if the artifact binary exists and is non-empty."""
        return (
            os.path.isfile(self.binary_path)
            and os.path.getsize(self.binary_path) > 0
        )

    def to_dict(self) -> dict:
        """Serialize artifact metadata to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "CompiledArtifact":
        """Deserialize artifact from dictionary.

        Args:
            data: Dictionary with artifact fields.

        Returns:
            CompiledArtifact instance.
        """
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)


class ArtifactCache:
    """Hash-based build cache for compiled artifacts.

    Stores compiled binaries and metadata in .tmp/builds/ using the
    SHA-256 of source content + target arch + compiler as the cache key.

    Args:
        builds_dir: Base directory for cached builds. Defaults to
            project .tmp/builds/ relative to this module.
    """

    def __init__(self, builds_dir: str = ""):
        self._builds_dir = builds_dir or os.path.abspath(_BUILDS_DIR)
        os.makedirs(self._builds_dir, exist_ok=True)

    @property
    def builds_dir(self) -> str:
        """Return the absolute path to the builds cache directory."""
        return self._builds_dir

    def _compute_source_hash(self, source_path: str) -> str:
        """Compute SHA-256 hash of a source file.

        Args:
            source_path: Path to the source file.

        Returns:
            Hex-encoded SHA-256 digest.

        Raises:
            FileNotFoundError: If source_path does not exist.
        """
        h = hashlib.sha256()
        with open(source_path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def _cache_key(self, source_hash: str, target_arch: str,
                   compiler: str) -> str:
        """Generate a deterministic cache key.

        Args:
            source_hash: SHA-256 of the source file.
            target_arch: Target architecture string.
            compiler: Compiler binary name.

        Returns:
            SHA-256 hex string used as directory name.
        """
        key_input = "{}:{}:{}".format(source_hash, target_arch, compiler)
        return hashlib.sha256(key_input.encode("utf-8")).hexdigest()[:16]

    def _meta_path(self, cache_dir: str) -> str:
        """Return the metadata JSON path for a cache entry."""
        return os.path.join(cache_dir, "artifact.json")

    def lookup(self, source_path: str, target_arch: str,
               compiler: str) -> Optional[CompiledArtifact]:
        """Look up a cached artifact by source, arch, and compiler.

        Args:
            source_path: Path to the source file.
            target_arch: Target architecture string.
            compiler: Compiler binary name.

        Returns:
            CompiledArtifact if cache hit and binary is valid, else None.
        """
        try:
            source_hash = self._compute_source_hash(source_path)
        except (FileNotFoundError, OSError):
            return None

        key = self._cache_key(source_hash, target_arch, compiler)
        cache_dir = os.path.join(self._builds_dir, key)
        meta_file = self._meta_path(cache_dir)

        if not os.path.isfile(meta_file):
            return None

        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

        if meta.get("source_hash") != source_hash:
            return None

        artifact = CompiledArtifact.from_dict(meta)
        artifact.cached = True

        if not artifact.is_valid():
            self._remove_entry(cache_dir)
            return None

        return artifact

    def store(self, artifact: CompiledArtifact) -> CompiledArtifact:
        """Store a compiled artifact in the cache.

        Copies the binary into the cache directory and writes metadata.

        Args:
            artifact: CompiledArtifact to cache.

        Returns:
            Updated CompiledArtifact with cached binary_path.
        """
        key = self._cache_key(
            artifact.source_hash, artifact.target_arch, artifact.compiler_used
        )
        cache_dir = os.path.join(self._builds_dir, key)
        os.makedirs(cache_dir, exist_ok=True)

        binary_name = os.path.basename(artifact.binary_path)
        cached_binary = os.path.join(cache_dir, binary_name)

        if os.path.abspath(artifact.binary_path) != os.path.abspath(cached_binary):
            shutil.copy2(artifact.binary_path, cached_binary)

        artifact.binary_path = cached_binary
        artifact.binary_size = os.path.getsize(cached_binary)

        meta_file = self._meta_path(cache_dir)
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(artifact.to_dict(), f, indent=2)

        return artifact

    def invalidate(self, source_path: str, target_arch: str,
                   compiler: str) -> bool:
        """Remove a specific cache entry.

        Args:
            source_path: Path to the source file.
            target_arch: Target architecture string.
            compiler: Compiler binary name.

        Returns:
            True if an entry was removed, False otherwise.
        """
        try:
            source_hash = self._compute_source_hash(source_path)
        except (FileNotFoundError, OSError):
            return False

        key = self._cache_key(source_hash, target_arch, compiler)
        cache_dir = os.path.join(self._builds_dir, key)
        return self._remove_entry(cache_dir)

    def _remove_entry(self, cache_dir: str) -> bool:
        """Remove a cache directory and its contents."""
        if os.path.isdir(cache_dir):
            shutil.rmtree(cache_dir, ignore_errors=True)
            return True
        return False

    def clear(self) -> int:
        """Remove all cached builds.

        Returns:
            Number of cache entries removed.
        """
        count = 0
        if not os.path.isdir(self._builds_dir):
            return count
        for entry in os.listdir(self._builds_dir):
            entry_path = os.path.join(self._builds_dir, entry)
            if os.path.isdir(entry_path):
                shutil.rmtree(entry_path, ignore_errors=True)
                count += 1
        return count

    def list_entries(self) -> list:
        """List all cached artifacts.

        Returns:
            List of CompiledArtifact instances from cache.
        """
        artifacts = []
        if not os.path.isdir(self._builds_dir):
            return artifacts
        for entry in os.listdir(self._builds_dir):
            meta_file = os.path.join(self._builds_dir, entry, "artifact.json")
            if not os.path.isfile(meta_file):
                continue
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                artifact = CompiledArtifact.from_dict(meta)
                artifact.cached = True
                artifacts.append(artifact)
            except (json.JSONDecodeError, OSError):
                continue
        return artifacts
