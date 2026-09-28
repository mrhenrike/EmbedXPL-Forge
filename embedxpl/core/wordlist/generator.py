"""Wordlist generator engine with profile-aware mutation rules.

Generates password and username wordlists based on target profile
(corporate vs personal), applying common mutation patterns inspired
by crunch/CUPP but focused on router/network device contexts.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import itertools
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger("embedxpl.wordlist")

LEET_MAP: Dict[str, List[str]] = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["$", "5"],
    "t": ["7"],
    "l": ["1"],
    "g": ["9"],
    "b": ["8"],
}

COMMON_SUFFIXES = [
    "", "1", "12", "123", "1234", "12345", "123456",
    "!", "!!", "@", "#", "$", "%",
    "01", "02", "00", "99", "2024", "2025", "2026",
    "@1", "@123", "#1", "!1",
]

COMMON_PREFIXES = [
    "", "!", "@", "#", "1", "12",
]

SEPARATOR_CHARS = ["", ".", "-", "_", "@", "#"]

CORPORATE_BASE_WORDS = [
    "admin", "Admin", "ADMIN", "root", "Root", "ROOT",
    "manager", "Manager", "MANAGER",
    "supervisor", "Supervisor",
    "guest", "Guest", "user", "User",
    "network", "Network", "router", "Router",
    "switch", "Switch", "firewall", "Firewall",
    "cisco", "Cisco", "mikrotik", "Mikrotik", "MikroTik",
    "ubiquiti", "Ubiquiti", "huawei", "Huawei",
    "tplink", "TP-Link", "dlink", "D-Link",
    "fortinet", "Fortinet", "juniper", "Juniper",
    "paloalto", "PaloAlto",
    "default", "Default", "password", "Password",
    "changeme", "Changeme", "letmein",
    "setup", "Setup", "config", "Config",
    "monitor", "Monitor", "backup", "Backup",
    "support", "Support", "service", "Service",
    "teste", "Teste", "test", "Test",
]

PERSONAL_BASE_WORDS = [
    "admin", "Admin", "root", "Root",
    "password", "Password", "senha", "Senha",
    "guest", "Guest", "user", "User",
    "wifi", "WiFi", "WIFI", "internet", "Internet",
    "casa", "Casa", "home", "Home",
    "amor", "Amor", "love", "Love",
    "familia", "Familia",
    "default", "Default",
]

ROUTER_COMMON_USERNAMES = [
    "admin", "root", "user", "guest", "support",
    "supervisor", "manager", "cisco", "ubnt",
    "pi", "debug", "tech", "service", "operator",
]


@dataclass
class TargetProfile:
    """Target information for wordlist generation."""

    profile_type: str = "corporate"

    # Corporate fields
    company_name: str = ""
    company_acronym: str = ""
    company_domain: str = ""
    department: str = ""
    admin_name: str = ""

    # Personal fields
    first_name: str = ""
    last_name: str = ""
    nickname: str = ""
    birth_date: str = ""
    pet_name: str = ""
    partner_name: str = ""

    # Shared fields
    ssid_name: str = ""
    device_vendor: str = ""
    device_model: str = ""
    city: str = ""
    zip_code: str = ""
    phone_suffix: str = ""
    custom_words: List[str] = field(default_factory=list)

    # Generation control
    min_length: int = 4
    max_length: int = 16
    enable_leet: bool = True
    enable_case_mutations: bool = True
    enable_year_suffix: bool = True
    enable_number_suffix: bool = True
    max_candidates: int = 50000
    generate_usernames: bool = True


@dataclass
class GenerationResult:
    """Result of a wordlist generation operation."""

    passwords: List[str]
    usernames: List[str]
    passwords_file: Optional[str] = None
    usernames_file: Optional[str] = None
    estimated_size_bytes: int = 0
    profile_type: str = ""
    base_words_used: int = 0
    mutations_applied: int = 0


def _clean_word(word: str) -> str:
    """Normalize a seed word, removing surrounding whitespace."""
    return word.strip()


def _case_mutations(word: str) -> List[str]:
    """Generate common case variations of a word."""
    results = [word]
    if word != word.lower():
        results.append(word.lower())
    if word != word.upper():
        results.append(word.upper())
    if word != word.capitalize():
        results.append(word.capitalize())
    # Title case for multi-word
    if " " in word or "-" in word or "_" in word:
        results.append(word.title())
    return list(dict.fromkeys(results))


def _leet_speak(word: str, depth: int = 1) -> List[str]:
    """Apply leet-speak substitutions (limited depth to avoid explosion)."""
    results = [word]
    lower = word.lower()
    for char, replacements in LEET_MAP.items():
        if char in lower:
            for rep in replacements[:depth]:
                variant = word.replace(char, rep).replace(char.upper(), rep)
                if variant != word:
                    results.append(variant)
    return list(dict.fromkeys(results))


def _number_mutations(word: str) -> List[str]:
    """Append common number/special suffixes and prefixes."""
    results = []
    for suffix in COMMON_SUFFIXES:
        results.append(word + suffix)
    for prefix in COMMON_PREFIXES:
        if prefix:
            results.append(prefix + word)
    return results


def _date_mutations(word: str, date_str: str) -> List[str]:
    """Combine word with date fragments (DDMMYYYY, MMYYYY, YYYY, YY, DD)."""
    results = []
    date_clean = re.sub(r"[^0-9]", "", date_str)
    if len(date_clean) >= 8:
        dd = date_clean[:2]
        mm = date_clean[2:4]
        yyyy = date_clean[4:8]
        yy = yyyy[2:]
        fragments = [dd, mm, yyyy, yy, dd + mm, mm + yyyy, dd + mm + yy]
        for frag in fragments:
            results.append(word + frag)
            results.append(frag + word)
    elif len(date_clean) >= 4:
        results.append(word + date_clean)
        results.append(date_clean + word)
    return results


def _combine_words(words: List[str], separators: Optional[List[str]] = None) -> List[str]:
    """Create combinations of 2 seed words with optional separators."""
    if separators is None:
        separators = ["", ".", "-", "_"]
    results = []
    for w1, w2 in itertools.combinations(words[:12], 2):
        for sep in separators:
            results.append(w1 + sep + w2)
            results.append(w2 + sep + w1)
    return results


def _collect_seed_words(profile: TargetProfile) -> List[str]:
    """Build the base seed word list from profile information."""
    seeds: List[str] = []

    if profile.profile_type == "corporate":
        seeds.extend(CORPORATE_BASE_WORDS)
        for val in [
            profile.company_name,
            profile.company_acronym,
            profile.company_domain,
            profile.department,
            profile.admin_name,
        ]:
            if val:
                seeds.append(_clean_word(val))
    else:
        seeds.extend(PERSONAL_BASE_WORDS)
        for val in [
            profile.first_name,
            profile.last_name,
            profile.nickname,
            profile.pet_name,
            profile.partner_name,
        ]:
            if val:
                seeds.append(_clean_word(val))

    for val in [
        profile.ssid_name,
        profile.device_vendor,
        profile.device_model,
        profile.city,
        profile.zip_code,
        profile.phone_suffix,
    ]:
        if val:
            seeds.append(_clean_word(val))

    seeds.extend([_clean_word(w) for w in profile.custom_words if w.strip()])

    return list(dict.fromkeys(seeds))


def _generate_usernames(profile: TargetProfile) -> List[str]:
    """Generate candidate usernames based on profile."""
    usernames: List[str] = list(ROUTER_COMMON_USERNAMES)

    if profile.profile_type == "corporate":
        if profile.admin_name:
            name = profile.admin_name.strip()
            parts = name.split()
            usernames.append(name.lower().replace(" ", "."))
            usernames.append(name.lower().replace(" ", ""))
            if len(parts) >= 2:
                usernames.append(parts[0][0].lower() + parts[-1].lower())
                usernames.append(parts[0].lower() + "." + parts[-1].lower())
                usernames.append(parts[0].lower())
                usernames.append(parts[-1].lower())
        if profile.company_acronym:
            usernames.append(profile.company_acronym.lower())
            usernames.append(profile.company_acronym.lower() + "admin")
        if profile.department:
            usernames.append(profile.department.lower())
            usernames.append(profile.department.lower() + ".admin")
    else:
        if profile.first_name:
            usernames.append(profile.first_name.lower())
        if profile.last_name:
            usernames.append(profile.last_name.lower())
        if profile.first_name and profile.last_name:
            usernames.append(profile.first_name[0].lower() + profile.last_name.lower())
            usernames.append(profile.first_name.lower() + "." + profile.last_name.lower())
        if profile.nickname:
            usernames.append(profile.nickname.lower())

    if profile.device_vendor:
        vendor_lower = profile.device_vendor.lower().replace("-", "").replace(" ", "")
        usernames.append(vendor_lower)

    return list(dict.fromkeys(usernames))


def generate_wordlist(profile: TargetProfile) -> GenerationResult:
    """Generate password and username wordlists from a target profile.

    Args:
        profile: Target profile with seed information.

    Returns:
        GenerationResult with generated passwords and usernames.
    """
    seeds = _collect_seed_words(profile)
    base_count = len(seeds)

    candidates: Set[str] = set()
    mutations_count = 0

    for seed in seeds:
        # Case mutations
        case_variants = _case_mutations(seed) if profile.enable_case_mutations else [seed]
        for variant in case_variants:
            # Number suffix mutations
            if profile.enable_number_suffix:
                for pwd in _number_mutations(variant):
                    candidates.add(pwd)
                    mutations_count += 1
            else:
                candidates.add(variant)
                mutations_count += 1

            # Leet speak
            if profile.enable_leet:
                for leet in _leet_speak(variant):
                    candidates.add(leet)
                    if profile.enable_number_suffix:
                        for pwd in _number_mutations(leet):
                            candidates.add(pwd)
                            mutations_count += 1

        # Date mutations
        if profile.birth_date:
            for variant in _case_mutations(seed) if profile.enable_case_mutations else [seed]:
                for pwd in _date_mutations(variant, profile.birth_date):
                    candidates.add(pwd)
                    mutations_count += 1

    # Combinations of user-provided seeds only (not base words)
    user_seeds = [s for s in seeds if s not in CORPORATE_BASE_WORDS and s not in PERSONAL_BASE_WORDS]
    if len(user_seeds) >= 2:
        for combo in _combine_words(user_seeds[:8], SEPARATOR_CHARS[:4]):
            candidates.add(combo)
            if profile.enable_number_suffix:
                for suf in COMMON_SUFFIXES[:8]:
                    candidates.add(combo + suf)

    # Filter by length
    filtered = sorted(
        pwd for pwd in candidates
        if profile.min_length <= len(pwd) <= profile.max_length
    )

    # Enforce max_candidates
    if len(filtered) > profile.max_candidates:
        filtered = filtered[: profile.max_candidates]

    # Usernames
    usernames = _generate_usernames(profile) if profile.generate_usernames else []

    estimated_bytes = sum(len(p) + 1 for p in filtered)

    return GenerationResult(
        passwords=filtered,
        usernames=usernames,
        estimated_size_bytes=estimated_bytes,
        profile_type=profile.profile_type,
        base_words_used=base_count,
        mutations_applied=mutations_count,
    )


def save_wordlist(
    words: List[str],
    output_path: str,
    label: str = "wordlist",
) -> Path:
    """Save a word list to a text file (one entry per line).

    Args:
        words: List of words to write.
        output_path: Destination file path.
        label: Label for logging purposes.

    Returns:
        Resolved path to the written file.
    """
    path = Path(output_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(words) + "\n", encoding="utf-8")
    logger.info("Saved %s with %d entries to %s", label, len(words), path)
    return path


def estimate_size_human(size_bytes: int) -> str:
    """Return a human-readable size string."""
    if size_bytes < 1024:
        return "{} B".format(size_bytes)
    if size_bytes < 1024 * 1024:
        return "{:.1f} KB".format(size_bytes / 1024)
    return "{:.1f} MB".format(size_bytes / (1024 * 1024))
