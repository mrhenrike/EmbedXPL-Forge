# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Corporate domain username and password generation."""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

from embedxpl.engines.wordlists.domain_users._utils import (
    _norm, _clean, parse_full_name,
)

    full_name: str,
    domain: str,
    separators: Optional[list[str]] = None,
    patterns: Optional[list[str]] = None,
    with_at_domain: bool = True,
    subdomain: Optional[str] = None,
    company_abbr: Optional[str] = None,
) -> Generator[str, None, None]:
    """
    Generate all corporate username variations for a single person's name.

    Args:
        full_name: Full name of the employee.
        domain: Company domain (e.g., 'acme.example').
        separators: Separator characters to use (default: ['.', '_', '-', '']).
        patterns: List of pattern IDs to include (default: all).
        with_at_domain: If True, appends '@domain' to each username.
        subdomain: Subdomain prefix for subdomain-admin patterns.
        company_abbr: Company abbreviation for contractor patterns (fn.company).
                      Can be comma-separated for multiple companies.

    Yields:
        Username strings (with or without @domain).
    """
    parsed = parse_full_name(full_name)
    fn  = _clean(parsed["first"])
    ln  = _clean(parsed["last"])
    lf  = _clean(parsed.get("last_full", parsed["last"]))  # particle-inclusive last
    fi  = fn[0] if fn else ""
    li  = ln[0] if ln else ""
    mn  = _clean(parsed["middle"][0]) if parsed["middle"] else ""
    mi  = mn[0] if mn else ""
    ini = _clean(parsed["initials"])

    # Compound first name: fn2 = fn + mn (e.g. "pessoaxpersonay" from "PessoaX PersonY")
    fn2 = fn + mn if mn else ""

    if not fn and not ln:
        return

    seps = separators if separators is not None else DOMAIN_SEPARATORS
    filter_ids = set(patterns) if patterns else None
    seen: set[str] = set()
    sub = _clean(subdomain) if subdomain else ""

    # Resolve company abbreviation list for contractor patterns
    co_variants: list[str] = []
    if company_abbr:
        for co_raw in re.split(r"[,;|]", company_abbr):
            co_c = _clean(co_raw)
            if co_c and co_c not in co_variants:
                co_variants.append(co_c)

    suffix = "@" + domain if with_at_domain else ""

    def _emit(user: str) -> Optional[str]:
        if not user or user in seen:
            return None
        if not re.search(r"[a-z0-9]", user):
            return None
        if re.search(r"[._\-]{2,}", user):
            return None
        if user[0] in "._-" or user[-1] in "._-":
            return None
        seen.add(user)
        return user + suffix

    for pat in CORPORATE_PATTERNS:
        pid = pat["id"]
        if filter_ids and pid not in filter_ids:
            continue
        if pat.get("needs_middle") and not mn:
            continue
        if pat.get("subdomain") and not sub:
            continue
        if pat.get("needs_company") and not co_variants:
            continue
        if pat.get("needs_fn2") and not fn2:
            continue
        if pat.get("needs_lf") and (not lf or lf == ln):
            continue   # skip when particle-inclusive last = plain last (no particle)
        if not ln and any(tok in pat["fmt"] for tok in ("{ln}", "{li}")):
            continue
        if not fn and any(tok in pat["fmt"] for tok in ("{fn}", "{fi}")):
            continue

        fmt = pat["fmt"]

        # Determine iteration axes
        co_list = co_variants if pat.get("needs_company") else [""]
        num_list = NUMERIC_SUFFIXES if "{num}" in fmt else [""]
        sep_list = seps if "{sep}" in fmt else [""]

        for co in co_list:
            for sep in sep_list:
                for num in num_list:
                    try:
                        user = fmt.format(
                            fn=fn, ln=ln, lf=lf, fi=fi, li=li,
                            mn=mn, mi=mi, ini=ini,
                            sep=sep, num=num, sub=sub,
                            co=co, fn2=fn2,
                        )
                    except KeyError:
                        continue
                    r = _emit(user)
                    if r:
                        yield r


def generate_usernames_from_list(
    names: list[str],
    domain: str,
    separators: Optional[list[str]] = None,
    patterns: Optional[list[str]] = None,
    with_at_domain: bool = True,
    subdomain: Optional[str] = None,
    company_abbr: Optional[str] = None,
) -> Generator[str, None, None]:
    """
    Generate username variations for a list of employee names.

    Args:
        names: List of full name strings.
        domain: Company domain.
        separators: Separator chars (default: ['.', '_', '-', '']).
        patterns: List of pattern IDs to include.
        with_at_domain: Append '@domain' suffix.
        subdomain: Subdomain prefix for admin patterns.
        company_abbr: Company abbreviation(s) for contractor patterns.

    Yields:
        Username strings.
    """
    global_seen: set[str] = set()
    for name in names:
        name = name.strip()
        if not name or name.startswith("#"):
            continue
        for user in generate_usernames_from_name(
            name, domain, separators, patterns,
            with_at_domain, subdomain, company_abbr,
        ):
            if user not in global_seen:
                global_seen.add(user)
                yield user


def generate_subdomain_admin_users(
    subdomains: list[str],
    domain: str,
    with_at_domain: bool = False,
) -> Generator[str, None, None]:
    """
    Generate admin/service account usernames from subdomain prefixes.

    Pattern: corp-ad.acme.example → corp-adadmin, corp-ad_admin, etc.

    Args:
        subdomains: List of subdomain prefixes (e.g., ['corp-ad', 'webmail']).
        domain: Company domain for context.
        with_at_domain: Append '@domain' to results.

    Yields:
        Admin username strings.
    """
    seen: set[str] = set()
    suffix = "@" + domain if with_at_domain else ""

    for sub in subdomains:
        sub = _clean(sub)
        if not sub:
            continue
        candidates = [
            sub + "admin",
            sub + "_admin",
            sub + ".admin",
            "admin_" + sub,
            "admin." + sub,
            "admin" + sub,
            sub + "-admin",
            "admin-" + sub,
            sub,                # bare subdomain as user
        ]
        for c in candidates:
            if c not in seen:
                seen.add(c)
                yield c + suffix


# ── Name collection from file ──────────────────────────────────────────────────

def collect_names_from_file(filepath: str) -> list[str]:
