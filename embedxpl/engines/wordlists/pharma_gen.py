"""
pharma_gen.py - Password and username generator for retail/pharmacy chain patterns.

Generates wordlists based on common credential patterns observed in retail chain
environments (point-of-sale systems, ERP integrations, store-level accounts).

Password patterns:
  • system/partner + store-id          system1206   partner#1206
  • brand-abbrev + separator + id      Brand#1206   ABBREV_1206   abbrev1206
  • partner + CNPJ                     system01234567890123
  • brand-abbrev + separator + CNPJ    ABBREV-01234567890123

Username patterns:
  • abbrev + store-id + @domain        XX1206@corp.example   xx0100@corp.example
  • system prefix + padded id          lj1206   ds0100
  • internal system prefixes + id      IJ1206   IJ120601   IJ120602   TC1206   LJ0100

Usage:
  wlf pharma --brand BrandX --ids 1200-1210 -o out.lst
  wlf pharma --brand RetailCo --abbrevs RC,RETAIL --mode passwords
  wlf pharma --brand BrandX --ids 5,6,7,8 --domains corp.example --mode usernames
  wlf pharma --brand BrandX --ids 1206 --partners system,partner --separators @,#

Author: André Henrique (@mrhenrike)
"""
from __future__ import annotations

import re
import unicodedata
from itertools import product as iproduct
from typing import Generator, Iterable

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_SEPARATORS = ["", "@", "#", "!", "&", "_", "-", ".", "*"]

# Common system/partner prefixes used in retail integrations
DEFAULT_PARTNERS = [
    "med", "MED",
    "clinic", "Clinic",
    "portal", "Portal",
    "system", "SYSTEM",
    "corp", "CORP",
    "erp", "ERP",
    "crm", "CRM",
    "pdv", "PDV",
    "store", "STORE",
    "retail", "RETAIL",
]

# Generic placeholder domains - override with --domains
DEFAULT_DOMAINS: list[str] = []

# Internal system username prefixes common in retail/POS environments
SYSTEM_PREFIXES = ["XX", "xx", "LJ", "lj", "IJ", "ij", "TC", "tc", "AG", "PDV", "FIL", "DS", "ds"]

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _strip_accents(s: str) -> str:
    return unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()


def _derive_abbrevs(brand: str) -> list[str]:
    """
    Derives abbreviations from a brand name automatically.

    Examples:
      "BrandX" → ["BrandXPHARMA", "brandxpharma", "BrandX", "BX", "BrandX", "brandx"]
      "RetailCo"   → ["RETAILCO", "retailco", "RetailCo", "RC", "RET", "ret"]
      "BrandX"     → ["BRANDX", "brandx", "BrandX", "B", "BRA", "bra"]
    """
    b = _strip_accents(brand).strip()
    words = b.split()
    abbrevs: list[str] = []

    # Full name variants
    abbrevs += [b.upper(), b.lower(), b.title()]

    # Initials of each word (e.g. "BrandX Pharma" → "AP")
    initials = "".join(w[0] for w in words).upper()
    if len(initials) >= 2:
        abbrevs += [initials, initials.lower()]

    # First 2-5 characters of the first word
    first = words[0]
    for n in (2, 3, 4, 5):
        if len(first) >= n:
            abbrevs += [first[:n].upper(), first[:n].lower()]

    # First letter of first word + first 3 of last word
    if len(words) >= 2:
        combo = words[0][0].upper() + words[-1][:3].upper()
        abbrevs.append(combo)

    # Deduplicate preserving order
    seen: set[str] = set()
    result: list[str] = []
    for a in abbrevs:
        if a not in seen and a:
            seen.add(a)
            result.append(a)
    return result


def _expand_id_range(raw: str) -> list[int]:
    """
    Expands an ID expression into a list of integers.

    Examples:
      "1200-1210"  → [1200, 1201, ..., 1210]
      "1206,1207"  → [1206, 1207]
      "1206"       → [1206]
    """
    ids: list[int] = []
    for token in raw.split(","):
        token = token.strip()
        m = re.match(r"^(\d+)-(\d+)$", token)
        if m:
            start, end = int(m.group(1)), int(m.group(2))
            ids.extend(range(start, end + 1))
        elif token.isdigit():
            ids.append(int(token))
    return ids


def _id_variants(n: int, padding: bool = True) -> list[str]:
    """Returns formatting variants of a numeric store ID."""
    variants = [str(n)]
    if padding:
        for w in (4, 5, 6):
            p = f"{n:0{w}d}"
            if p not in variants:
                variants.append(p)
    return variants


def _parse_cnpj(raw: str) -> str:
    """Returns a CNPJ as digits only, zero-padded to 14 characters."""
    digits = re.sub(r"\D", "", raw)
    return digits.zfill(14)


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

def gen_passwords(
    brand: str,
    store_ids: Iterable[int],
    cnpjs: Iterable[str] | None = None,
    extra_abbrevs: list[str] | None = None,
    separators: list[str] | None = None,
    partners: list[str] | None = None,
    padding: bool = True,
    min_len: int = 0,
    max_len: int = 0,
) -> Generator[str, None, None]:
    """
    Generates passwords from brand name, store IDs and optional CNPJs.

    Patterns produced:
      {abbrev}{sep}{id}        Brand#1206   ABBREV_1206   abbrev1206
      {partner}{sep}{id}       system@1206  partner1206
      {partner}{cnpj}          system01234567890123
      {abbrev}{sep}{cnpj}      ABBREV-01234567890123
      {abbrev}{sep}{cnpj8}     AB#01234567  (CNPJ root - first 8 digits)
    """
    seps      = separators if separators is not None else DEFAULT_SEPARATORS
    prt_list  = partners if partners is not None else DEFAULT_PARTNERS
    abbrevs   = _derive_abbrevs(brand) + (extra_abbrevs or [])
    ids       = list(store_ids)
    cnpj_list = [_parse_cnpj(c) for c in (cnpjs or [])]

    seen: set[str] = set()

    def emit(s: str) -> Generator[str, None, None]:
        if s in seen:
            return
        seen.add(s)
        if min_len and len(s) < min_len:
            return
        if max_len and len(s) > max_len:
            return
        yield s

    # abbrev + sep + store_id
    for n in ids:
        for id_str in _id_variants(n, padding):
            for abbrev, sep in iproduct(abbrevs, seps):
                yield from emit(f"{abbrev}{sep}{id_str}")

    # partner + sep + store_id
    for n in ids:
        for id_str in _id_variants(n, padding):
            for partner, sep in iproduct(prt_list, seps):
                yield from emit(f"{partner}{sep}{id_str}")

    # partner + CNPJ  /  abbrev + sep + CNPJ
    for cnpj in cnpj_list:
        cnpj_root = cnpj[:8]
        for partner in prt_list:
            yield from emit(f"{partner}{cnpj}")
        for abbrev, sep in iproduct(abbrevs, seps):
            yield from emit(f"{abbrev}{sep}{cnpj}")
            yield from emit(f"{abbrev}{sep}{cnpj_root}")


def gen_usernames(
    brand: str,
    store_ids: Iterable[int],
    domains: list[str] | None = None,
    extra_abbrevs: list[str] | None = None,
    padding: bool = True,
    with_at_domain: bool = True,
    min_len: int = 0,
    max_len: int = 0,
) -> Generator[str, None, None]:
    """
    Generates usernames from brand name and store IDs.

    Patterns produced:
      {abbrev}{id}@{domain}       XX1206@corp.example
      {abbrev}{id_pad4}@{domain}  xx0100@corp.example
      IJ{id}                      IJ1206  (internal system login)
      IJ{id}1 / IJ{id}2           IJ120601  IJ120602  (manager accounts)
      TC{id}  LJ{id}              TC1206   LJ0100
    """
    domains_list = domains if domains is not None else DEFAULT_DOMAINS
    abbrevs      = _derive_abbrevs(brand) + (extra_abbrevs or [])
    ids          = list(store_ids)

    seen: set[str] = set()

    def emit(s: str) -> Generator[str, None, None]:
        if s in seen:
            return
        seen.add(s)
        if min_len and len(s) < min_len:
            return
        if max_len and len(s) > max_len:
            return
        yield s

    for n in ids:
        id_vars = _id_variants(n, padding)

        # abbrev + id  (with and without domain)
        for abbrev, id_str in iproduct(abbrevs, id_vars):
            bare = f"{abbrev}{id_str}"
            yield from emit(bare)
            if with_at_domain and domains_list:
                for domain in domains_list:
                    yield from emit(f"{bare}@{domain}")

        # system prefixes + id
        for pfx, id_str in iproduct(SYSTEM_PREFIXES, id_vars):
            bare = f"{pfx}{id_str}"
            yield from emit(bare)
            if with_at_domain and domains_list:
                for domain in domains_list:
                    yield from emit(f"{bare}@{domain}")

        # manager variants: IJ{id}1, IJ{id}2
        for id_str in id_vars:
            for sfx in ("1", "2", "01", "02"):
                bare = f"IJ{id_str}{sfx}"
                yield from emit(bare)
                if with_at_domain and domains_list:
                    for domain in domains_list:
                        yield from emit(f"{bare}@{domain}")


def gen_both(
    brand: str,
    store_ids: list[int],
    cnpjs: list[str] | None = None,
    extra_abbrevs: list[str] | None = None,
    separators: list[str] | None = None,
    partners: list[str] | None = None,
    domains: list[str] | None = None,
    padding: bool = True,
    min_len: int = 0,
    max_len: int = 0,
) -> Generator[str, None, None]:
    """Generates passwords and usernames combined (deduplicated)."""
    seen: set[str] = set()

    def dedup(gen: Generator[str, None, None]) -> Generator[str, None, None]:
        for item in gen:
            if item not in seen:
                seen.add(item)
                yield item

    yield from dedup(gen_passwords(
        brand, store_ids, cnpjs, extra_abbrevs, separators, partners, padding, min_len, max_len,
    ))
    yield from dedup(gen_usernames(
        brand, store_ids, domains, extra_abbrevs, padding, True, min_len, max_len,
    ))
