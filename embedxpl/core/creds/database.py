"""Default credentials database loader and query interface.

Provides :class:`DefaultCredsDatabase` — a lightweight, lazy-loading wrapper
around the compiled JSON databases in ``embedxpl/data/``.

Usage::

    from embedxpl.core.creds.database import DefaultCredsDatabase

    db = DefaultCredsDatabase()
    entries = db.get_by_vendor("dahua")
    http_entries = db.get_by_vendor("hikvision", protocol="http")
    cameras = db.get_by_type("camera")
    results = db.search("admin:12345")
    protocols = db.get_protocols("cisco")
    wordlist = db.to_wordlist("axis")   # ["root:pass", "root:root", ...]

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 1.0.0
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

__all__ = ["DefaultCredsDatabase"]

_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
_GENERAL_DB = _DATA_DIR / "default_creds.json"
_ICS_DB = _DATA_DIR / "ics_default_creds.json"


class DefaultCredsDatabase:
    """Lazy-loading interface to the compiled default credentials JSON databases.

    Args:
        ics_mode: If ``True`` queries the ICS/SCADA database instead of the
            general device database. Defaults to ``False``.
    """

    def __init__(self, ics_mode: bool = False) -> None:
        self._ics_mode = ics_mode
        self._db: dict[str, list[dict[str, Any]]] | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load(self) -> dict[str, list[dict[str, Any]]]:
        """Load and cache the database JSON on first access."""
        if self._db is None:
            path = _ICS_DB if self._ics_mode else _GENERAL_DB
            if not path.exists():
                raise FileNotFoundError(
                    f"Default credentials database not found: {path}\n"
                    "Run scripts/compile_default_creds.py to generate it."
                )
            with open(path, encoding="utf-8") as fh:
                self._db = json.load(fh)
        return self._db

    @staticmethod
    def _normalise_vendor(name: str) -> str:
        """Normalise vendor name to database key format."""
        key = name.strip().lower()
        key = re.sub(r"[^a-z0-9]+", "_", key).strip("_")
        return key

    # ------------------------------------------------------------------
    # Public query API
    # ------------------------------------------------------------------

    def get_by_vendor(
        self,
        vendor: str,
        *,
        protocol: str | None = None,
        device_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return all credential entries for *vendor*.

        Args:
            vendor: Vendor name (case-insensitive; spaces/hyphens normalised).
            protocol: Optional filter — ``"http"``, ``"ssh"``, ``"telnet"``,
                ``"ftp"``, ``"snmp"``, ``"rtsp"``, or ``"multi"`` (unspecified).
            device_type: Optional filter — ``"camera"``, ``"router"``,
                ``"switch"``, ``"printer"``, ``"nas"``, ``"voip"``,
                ``"firewall"``, ``"ics"``, ``"wireless"``, etc.

        Returns:
            List of entry dicts with keys ``user``, ``pass``, ``protocol``,
            ``device_type``, ``notes`` (and optionally ``device``, ``port``,
            ``source`` for ICS entries).
        """
        db = self._load()
        key = self._normalise_vendor(vendor)
        entries = db.get(key, [])

        if protocol:
            proto_lower = protocol.lower()
            entries = [
                e for e in entries
                if proto_lower in e.get("protocol", "").lower()
                or e.get("protocol", "").lower() == "multi"
            ]

        if device_type:
            dtype_lower = device_type.lower()
            entries = [
                e for e in entries
                if e.get("device_type", "").lower() == dtype_lower
            ]

        return entries

    def get_by_type(self, device_type: str) -> dict[str, list[dict[str, Any]]]:
        """Return all vendors and entries matching *device_type*.

        Args:
            device_type: Device category string (e.g. ``"camera"``, ``"nas"``).

        Returns:
            Dict mapping vendor key → list of matching entries.
        """
        db = self._load()
        dtype_lower = device_type.lower()
        result: dict[str, list[dict[str, Any]]] = {}
        for vendor, entries in db.items():
            matching = [e for e in entries if e.get("device_type", "").lower() == dtype_lower]
            if matching:
                result[vendor] = matching
        return result

    def search(self, query: str) -> dict[str, list[dict[str, Any]]]:
        """Full-text search across vendor names, usernames, passwords, and notes.

        Args:
            query: Case-insensitive search string. Supports ``user:pass`` format
                for exact credential lookups.

        Returns:
            Dict mapping vendor key → list of matching entries.
        """
        db = self._load()
        q = query.strip().lower()
        result: dict[str, list[dict[str, Any]]] = {}

        # Check if it looks like a user:pass pair
        exact_user = exact_pass = None
        if ":" in q:
            parts = q.split(":", 1)
            exact_user, exact_pass = parts[0], parts[1]

        for vendor, entries in db.items():
            matching: list[dict[str, Any]] = []
            for e in entries:
                if exact_user is not None and exact_pass is not None:
                    if (
                        e.get("user", "").lower() == exact_user
                        and e.get("pass", "").lower() == exact_pass
                    ):
                        matching.append(e)
                else:
                    haystack = " ".join([
                        vendor,
                        e.get("user", ""),
                        e.get("pass", ""),
                        e.get("notes", ""),
                        e.get("device_type", ""),
                    ]).lower()
                    if q in haystack:
                        matching.append(e)
            if matching:
                result[vendor] = matching

        return result

    def get_protocols(self, vendor: str) -> list[str]:
        """Return the distinct protocol strings available for *vendor*.

        Args:
            vendor: Vendor name.

        Returns:
            Sorted list of protocol strings (e.g. ``["ftp", "http", "ssh"]``).
        """
        entries = self.get_by_vendor(vendor)
        return sorted({e.get("protocol", "multi") for e in entries})

    def list_vendors(self, device_type: str | None = None) -> list[str]:
        """Return sorted list of all vendor keys in the database.

        Args:
            device_type: Optional filter to restrict to vendors that have at
                least one entry of this device type.

        Returns:
            Sorted list of vendor key strings.
        """
        db = self._load()
        if device_type is None:
            return sorted(db.keys())

        dtype_lower = device_type.lower()
        return sorted(
            v for v, entries in db.items()
            if any(e.get("device_type", "").lower() == dtype_lower for e in entries)
        )

    def to_wordlist(
        self,
        vendor: str,
        *,
        protocol: str | None = None,
        include_empty_pass: bool = True,
    ) -> list[str]:
        """Return ``["user:pass", ...]`` formatted wordlist for *vendor*.

        Args:
            vendor: Vendor name.
            protocol: Optional protocol filter.
            include_empty_pass: If ``True`` (default) includes entries where
                the password is an empty string.

        Returns:
            Deduplicated list of ``"user:pass"`` strings.
        """
        entries = self.get_by_vendor(vendor, protocol=protocol)
        seen: set[str] = set()
        result: list[str] = []
        for e in entries:
            u = e.get("user", "")
            p = e.get("pass", "")
            if not include_empty_pass and not p:
                continue
            line = f"{u}:{p}"
            if line not in seen:
                seen.add(line)
                result.append(line)
        return result

    def __repr__(self) -> str:
        """Show database type and load state."""
        mode = "ICS" if self._ics_mode else "general"
        loaded = f"{len(self._db)} vendors" if self._db is not None else "not loaded"
        return f"DefaultCredsDatabase(mode={mode!r}, state={loaded!r})"


# Convenience singletons (lazily initialised on first use)
@lru_cache(maxsize=1)
def get_db() -> DefaultCredsDatabase:
    """Return the cached general-purpose DefaultCredsDatabase instance."""
    return DefaultCredsDatabase(ics_mode=False)


@lru_cache(maxsize=1)
def get_ics_db() -> DefaultCredsDatabase:
    """Return the cached ICS/SCADA DefaultCredsDatabase instance."""
    return DefaultCredsDatabase(ics_mode=True)
