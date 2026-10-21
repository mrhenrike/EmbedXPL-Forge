"""Interactive wizard and runner for domain user generation."""
from __future__ import annotations

import os
from typing import Generator

from ._normalize import _clean
from ._patterns import DOMAIN_SEPARATORS, ALL_DOMAIN_SEPARATORS
from ._username_gen import generate_usernames_from_list, generate_subdomain_admin_users
from ._name_collect import (
    collect_names_from_file,
    search_names_google_dorks,
    search_names_linkedin_api,
)
from ._password_gen import (
    generate_passwords_for_person,
    generate_combo_list,
)


# ── Interactive wizard ─────────────────────────────────────────────────────────

def interactive_domain_users_wizard() -> dict:
    """
    Interactive wizard to collect parameters for domain username generation.

    Returns:
        Dict with all parameters needed for generation.
    """
    print("\n[ CORPORATE DOMAIN USER GENERATOR ]")
    print("Generates usernames and passwords for corporate domain accounts.\n")

    domain = input("  Company domain (e.g. acme.example): ").strip()
    company_name = input("  Company trade name (short, e.g. BrandX): ").strip()

    print("\n  Name source:")
    print("  [1] Load from file")
    print("  [2] Search online (Google dorks, no API needed)")
    print("  [3] Search via LinkedIn API (requires LINKEDIN_RAPIDAPI_KEY env var)")
    print("  [4] Enter names manually")
    source = input("  Choose [1-4]: ").strip()

    names: list[str] = []
    filepath = None

    if source == "1":
        filepath = input("  File path (txt/csv/xlsx/pdf): ").strip()
        try:
            names = collect_names_from_file(filepath)
            print(f"  Found {len(names)} candidate name(s) in file.")
        except FileNotFoundError as exc:
            print(f"  ERROR: {exc}")
    elif source == "2":
        max_r = input("  Max results [50]: ").strip() or "50"
        print(f"  Searching Google for '{company_name}'... (may take a moment)")
        names = search_names_google_dorks(company_name, domain, int(max_r))
        print(f"  Found {len(names)} name(s) via Google dorks.")
    elif source == "3":
        api_key = os.environ.get("LINKEDIN_RAPIDAPI_KEY", "")
        if not api_key:
            print("  WARNING: LINKEDIN_RAPIDAPI_KEY not set in environment.")
            print("  Set it with: $env:LINKEDIN_RAPIDAPI_KEY='your-key'  (PowerShell)")
            print("  Falling back to Google dorks...")
            names = search_names_google_dorks(company_name, domain, 50)
        else:
            names = search_names_linkedin_api(company_name, 100)
        print(f"  Found {len(names)} name(s).")
    elif source == "4":
        print("  Enter full names (one per line, empty line to stop):")
        while True:
            n = input("    > ").strip()
            if not n:
                break
            names.append(n)
    else:
        print("  Invalid option, using manual entry.")

    if names:
        print(f"\n  Preview (first 5): {names[:5]}")
        ok = input("  Use these names? [Y/n]: ").strip().lower()
        if ok in ("n", "no"):
            names = []

    # Custom separators
    print("\n  Username separator (used between name parts, e.g. pessoax.personay).")
    print("  Default: '.'  |  Options: any chars, 'none' for no separator, 'all' for . _ - (empty)")
    sep_input = input("  Separator(s) [Enter = default '.']: ").strip()
    if not sep_input:
        separators = DOMAIN_SEPARATORS  # ["." only]
    elif sep_input.lower() == "all":
        separators = ALL_DOMAIN_SEPARATORS
    elif sep_input.lower() == "none":
        separators = [""]
    else:
        # Parse comma-separated list; support 'none'/'empty'/'' as empty separator token
        separators = []
        for token in sep_input.split(","):
            t = token.strip()
            if t.lower() in ("none", "empty", "''", '""', ""):
                if "" not in separators:
                    separators.append("")
            else:
                if t not in separators:
                    separators.append(t)
        if not separators:
            separators = DOMAIN_SEPARATORS

    # Subdomain admin
    sub_input = input("\n  Subdomain prefix for admin patterns (e.g. corp-ad, or Enter to skip): ").strip()
    subdomains = [s.strip() for s in sub_input.split(",") if s.strip()] if sub_input else []

    # Output options
    gen_users = input("\n  Generate usernames? [Y/n]: ").strip().lower() not in ("n", "no")
    gen_passwords = input("  Generate passwords? [Y/n]: ").strip().lower() not in ("n", "no")
    gen_combo = input("  Generate user:password combo? [Y/n]: ").strip().lower() not in ("n", "no")

    year_start = int(input("  Year range start [2020]: ").strip() or "2020")
    year_end = int(input("  Year range end [2026]: ").strip() or "2026")

    with_at = input("  Include @domain in usernames? [Y/n]: ").strip().lower() not in ("n", "no")

    return {
        "domain": domain,
        "company_name": company_name,
        "names": names,
        "filepath": filepath,
        "separators": separators,
        "subdomains": subdomains,
        "gen_users": gen_users,
        "gen_passwords": gen_passwords,
        "gen_combo": gen_combo,
        "year_start": year_start,
        "year_end": year_end,
        "with_at_domain": with_at,
    }


def run_domain_users(params: dict) -> Generator[str, None, None]:
    """
    Execute domain user generation based on wizard parameters.

    Args:
        params: Dict returned by interactive_domain_users_wizard() or built manually.

    Yields:
        Username, password, or combo strings.
    """
    domain = params.get("domain", "")
    company_name = params.get("company_name", domain.split(".")[0] if domain else "")
    names = params.get("names", [])
    separators = params.get("separators", DOMAIN_SEPARATORS)
    subdomains = params.get("subdomains", [])
    gen_users = params.get("gen_users", True)
    gen_passwords = params.get("gen_passwords", False)
    gen_combo = params.get("gen_combo", False)
    year_start = int(params.get("year_start", 2020))
    year_end = int(params.get("year_end", 2026))
    with_at = params.get("with_at_domain", True)
    year_range = range(year_start, year_end + 1)

    # ── Usernames from names ───────────────────────────────────
    if gen_users and names:
        yield from generate_usernames_from_list(
            names, domain, separators, with_at_domain=with_at,
        )

    # ── Subdomain-admin users ──────────────────────────────────
    if subdomains:
        yield from generate_subdomain_admin_users(subdomains, domain, with_at_domain=with_at)

    # ── Passwords only ─────────────────────────────────────────
    if gen_passwords and not gen_combo and names:
        seen: set[str] = set()
        for name in names:
            for pw in generate_passwords_for_person(name, company_name, domain, year_range):
                if pw not in seen:
                    seen.add(pw)
                    yield pw

    # ── Combo user:pass ────────────────────────────────────────
    if gen_combo and names:
        yield from generate_combo_list(names, company_name, domain, separators, year_range)

