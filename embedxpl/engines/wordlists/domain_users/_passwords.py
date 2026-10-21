# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Corporate domain username and password generation."""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

from typing import Generator, Optional

from embedxpl.engines.wordlists.domain_users._utils import _norm
from embedxpl.engines.wordlists.domain_users._generators import (
    generate_usernames_from_list,
)

    """
    Generate leet-speak variants of a word by substituting 1-2 characters.

    Args:
        word: Input word to leet-ify.
        max_variants: Maximum number of variants to return.

    Returns:
        List of leet variants (without duplicates, excluding the original).
    """
    # Find all positions with leet substitutions
    positions = [(i, c) for i, c in enumerate(word) if c in _LEET_MAP]
    variants: set[str] = set()

    # Single substitutions
    for idx, char in positions:
        for sub in _LEET_MAP[char]:
            variant = word[:idx] + sub + word[idx + 1:]
            if variant != word:
                variants.add(variant)
        if len(variants) >= max_variants:
            break

    # Two-position substitutions (most impactful ones)
    if len(positions) >= 2 and len(variants) < max_variants:
        for i in range(min(3, len(positions))):
            for j in range(i + 1, min(4, len(positions))):
                idx1, c1 = positions[i]
                idx2, c2 = positions[j]
                for s1 in _LEET_MAP[c1][:1]:
                    for s2 in _LEET_MAP[c2][:1]:
                        w = list(word)
                        w[idx1] = s1
                        w[idx2] = s2
                        variant = "".join(w)
                        if variant != word:
                            variants.add(variant)
                if len(variants) >= max_variants:
                    break

    return list(variants)[:max_variants]


def generate_passwords_for_person(
    full_name: str,
    company_name: str,
    domain: str,
    year_range: Optional[range] = None,
) -> Generator[str, None, None]:
    """
    Generate password candidates for a person in a company context.

    Args:
        full_name: Employee full name.
        company_name: Company short name or trade name.
        domain: Company domain (e.g., 'acme.example').
        year_range: Years to use in patterns (default: 2020-2026).

    Yields:
        Password strings.
    """
    parsed = parse_full_name(full_name)
    fn = _clean(parsed["first"])
    ln = _clean(parsed["last"])
    fi = fn[0] if fn else ""
    company = _clean(company_name.split()[0] if company_name else domain.split(".")[0])
    domain_short = _clean(domain.split(".")[0])
    years = year_range or range(2020, 2027)

    seen: set[str] = set()

    def _emit(s: str) -> Optional[str]:
        if s and s not in seen and len(s) >= 6:
            seen.add(s)
            return s
        return None

    # Build company tokens with leet variants for key tokens
    company_tokens = [company, company.capitalize(), company.upper(), domain_short]
    # Include both capitalized and lowercase leet variants (covers saf3labs and S4felabs)
    leet_company = _leet_variants(company.capitalize(), max_variants=3)
    leet_company_lower = _leet_variants(company, max_variants=6)
    company_tokens.extend(leet_company)
    company_tokens.extend(leet_company_lower)

    # Leet variants of first name for later use
    leet_fn_variants = _leet_variants(fn.capitalize(), max_variants=3)

    for year in years:
        y = str(year)
        y2 = y[-2:]
        for pat in CORPORATE_PASSWORD_PATTERNS:
            for comp_token in company_tokens:
                try:
                    pw = pat.format(
                        fn=fn, ln=ln, fi=fi, company=comp_token,
                        domain=domain_short, year=y, y2=y2,
                    )
                except KeyError:
                    continue
                r = _emit(pw)
                if r:
                    yield r
                # Capitalize first name variant
                r = _emit(pw.replace(fn, fn.capitalize(), 1))
                if r:
                    yield r

    # ── Leet variants of fn-based passwords ──────────────────────────────────
    # Observed pattern: S3gu4@nca, UserAlias@2023, CorpX2020!
    for leet_fn in leet_fn_variants:
        for year in years:
            y = str(year)
            y2 = y[-2:]
            for tmpl in ["{fn}{year}!", "{fn}@{year}", "{fn}{year}@", "{fn}#{year}"]:
                try:
                    pw = tmpl.format(fn=leet_fn, year=y, y2=y2)
                except KeyError:
                    continue
                r = _emit(pw)
                if r:
                    yield r

    # ── Vault-observed structural patterns with special compound tokens ───────
    # Pattern: #{lowercase}@{UPPER}{Year} - observed: #xpto@CORPX2024
    if fn and ln:
        for year in years:
            y = str(year)
            for r in [
                _emit(f"#{fn}@{ln.upper()}{y}"),
                _emit(f"#{fn}@{company.upper()}{y}"),
                _emit(f"#{company}@{fn.upper()}{y}"),
                _emit(f"#{fn.capitalize()}{y}#{ln.capitalize()}"),
            ]:
                if r:
                    yield r

    # Pattern: {Company}@{Year}#{Region} - observed: BrandX@2022#xpto
    for year in years:
        y = str(year)
        for region in ["Brasil", "Brazil", "SP", "RJ", "MG", "RS"]:
            r = _emit(f"{company.capitalize()}@{y}#{region}")
            if r:
                yield r


def generate_combo_list(
    names: list[str],
    company_name: str,
    domain: str,
    separators: Optional[list[str]] = None,
    year_range: Optional[range] = None,
    with_passwords: bool = True,
) -> Generator[str, None, None]:
    """
    Generate a combined user:password combo list for a set of names.

    Output format: username@domain:password

    Args:
        names: List of employee full names.
        company_name: Company name.
        domain: Company domain.
        separators: Separator chars for username generation.
        year_range: Year range for password patterns.
        with_passwords: If True, generate user:password pairs; else usernames only.

    Yields:
        Strings in format 'username@domain:password' or just 'username@domain'.
    """
    for name in names:
        name = name.strip()
        if not name or name.startswith("#"):
            continue

        users = list(generate_usernames_from_name(
            name, domain, separators, with_at_domain=True,
        ))

        if not with_passwords:
            yield from users
            continue

        passwords = list(generate_passwords_for_person(
            name, company_name, domain, year_range,
        ))

        for user in users:
            for pw in passwords:
                yield f"{user}:{pw}"


# ── Interactive wizard ─────────────────────────────────────────────────────────

def interactive_domain_users_wizard() -> dict:
