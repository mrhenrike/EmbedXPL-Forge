#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Sync router/switch/tap scoped credential wordlists from local sources.

This script updates EmbedXPL-Forge scoped wordlists by merging:
- existing bundled wordlists;
- SecLists router vendor defaults under Passwords/Default-Credentials/Routers.

It enforces project scope by excluding entries related to cameras, DVRs, and printers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Set, Tuple
import re


SCOPE_BLOCK_TOKENS: Tuple[str, ...] = ("camera", "dvr", "printer")


def _read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        return [line.strip() for line in handle if line.strip() and not line.strip().startswith("#")]


def _is_scoped_entry(value: str) -> bool:
    lowered = value.lower()
    return not any(token in lowered for token in SCOPE_BLOCK_TOKENS)


def _dedup(values: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    output: List[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            output.append(value)
    return output


def _write_lines(path: Path, values: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", errors="ignore") as handle:
        for value in values:
            handle.write(value + "\n")


def _build_router_pairs(sec_routers_dir: Path) -> List[str]:
    vendor_users = {}
    vendor_passwords = {}

    for file_path in sec_routers_dir.glob("*_default-users.txt"):
        vendor = file_path.name.replace("_default-users.txt", "")
        vendor_users[vendor] = [u for u in _read_lines(file_path) if _is_scoped_entry(u)]

    for file_path in sec_routers_dir.glob("*_default-passwords.txt"):
        vendor = file_path.name.replace("_default-passwords.txt", "")
        vendor_passwords[vendor] = [p for p in _read_lines(file_path) if _is_scoped_entry(p)]

    pairs: List[str] = []
    for vendor in sorted(set(vendor_users) | set(vendor_passwords)):
        users = vendor_users.get(vendor, [])
        passwords = vendor_passwords.get(vendor, [])
        for username in users:
            for password in passwords:
                pairs.append(f"{username}:{password}")

    return pairs


def _extract_from_pairs(pairs: Iterable[str]) -> Tuple[List[str], List[str]]:
    usernames: List[str] = []
    passwords: List[str] = []
    for pair in pairs:
        if ":" not in pair:
            continue
        username, password = pair.split(":", 1)
        usernames.append(username)
        passwords.append(password)
    return usernames, passwords


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    wordlists_dir = repo_root / "embedxpl" / "resources" / "wordlists"
    seclists_routers = (
        repo_root.parents[2]
        / "Wordlists"
        / "SecLists"
        / "Passwords"
        / "Default-Credentials"
        / "Routers"
    )

    base_defaults = [entry for entry in _read_lines(wordlists_dir / "defaults.txt") if _is_scoped_entry(entry)]
    base_usernames = [entry for entry in _read_lines(wordlists_dir / "usernames.txt") if _is_scoped_entry(entry)]
    base_passwords = [entry for entry in _read_lines(wordlists_dir / "passwords.txt") if _is_scoped_entry(entry)]
    base_snmp = [entry for entry in _read_lines(wordlists_dir / "snmp.txt") if _is_scoped_entry(entry)]

    seclists_pairs = _build_router_pairs(seclists_routers)
    seclists_users, seclists_passwords = _extract_from_pairs(seclists_pairs)

    scope_defaults = _dedup([entry for entry in (base_defaults + seclists_pairs) if _is_scoped_entry(entry)])
    scope_usernames = _dedup([entry for entry in (base_usernames + seclists_users) if _is_scoped_entry(entry)])
    scope_passwords = _dedup([entry for entry in (base_passwords + seclists_passwords) if _is_scoped_entry(entry)])
    scope_snmp = _dedup(base_snmp)

    _write_lines(wordlists_dir / "router_scope_defaults.txt", scope_defaults)
    _write_lines(wordlists_dir / "router_scope_usernames.txt", scope_usernames)
    _write_lines(wordlists_dir / "router_scope_passwords.txt", scope_passwords)
    _write_lines(wordlists_dir / "router_scope_snmp.txt", scope_snmp)

    print(
        "Synced scoped wordlists: defaults={}, usernames={}, passwords={}, snmp={}".format(
            len(scope_defaults), len(scope_usernames), len(scope_passwords), len(scope_snmp)
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
