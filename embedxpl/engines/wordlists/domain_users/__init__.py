"""
domain_users - Corporate domain username and password generation.

Generates realistic corporate username/password combinations from employee
name lists, applying globally used naming conventions plus Brazilian patterns.

Features:
  - Corporate username patterns (firstname.lastname, f.lastname, etc.)
  - Employee name collection from any file (txt/csv/xlsx/pdf/docx)
  - Online name search via Google dorks (no mandatory API)
  - Optional LinkedIn API via LINKEDIN_RAPIDAPI_KEY env var (graceful fallback)
  - Subdomain-admin pattern generation (corp-ad -> corp-adadmin)
  - Password generation from behavioral + corporate context
  - Accent normalization for Brazilian/Portuguese names
  - Custom pattern support

Usage:
  wlf.py corp-users --domain acme.example --file employees.txt
  wlf.py corp-users --domain acme.example --search "EmpresaXpto"
  wlf.py corp-users --domain acme.example --subdomain corp-ad
  wlf.py corp-users --domain acme.example --file names.txt --passwords --out combo.lst
  wlf.py corp-users --domain acme.example --interactive

Author: Andre Henrique (@mrhenrike)
Version: 1.1.0
"""
from __future__ import annotations

# -- Normalize and name parsing ------------------------------------------------
from ._normalize import _norm, _clean, parse_full_name

# -- Constants and patterns ----------------------------------------------------
from ._patterns import (
    CORPORATE_PATTERNS,
    KNOWN_BR_DOMAIN_PATTERNS,
    KNOWN_BR_EMPLOYEE_ID_PREFIXES,
    DOMAIN_SEPARATORS,
    ALL_DOMAIN_SEPARATORS,
    NUMERIC_SUFFIXES,
)

# -- Username generation -------------------------------------------------------
from ._username_gen import (
    generate_usernames_from_name,
    generate_usernames_from_list,
    generate_subdomain_admin_users,
)

# -- Name collection -----------------------------------------------------------
from ._name_collect import (
    collect_names_from_file,
    _filter_names,
    search_names_google_dorks,
    search_names_linkedin_api,
    collect_names_online,
)

# -- Password generation -------------------------------------------------------
from ._password_gen import (
    CORPORATE_PASSWORD_PATTERNS,
    _LEET_MAP,
    _leet_variants,
    generate_passwords_for_person,
    generate_combo_list,
)

# -- Wizard and runner ---------------------------------------------------------
from ._wizard import (
    interactive_domain_users_wizard,
    run_domain_users,
)

__all__ = [
    # Normalize / parse
    "_norm",
    "_clean",
    "parse_full_name",
    # Constants
    "CORPORATE_PATTERNS",
    "KNOWN_BR_DOMAIN_PATTERNS",
    "KNOWN_BR_EMPLOYEE_ID_PREFIXES",
    "DOMAIN_SEPARATORS",
    "ALL_DOMAIN_SEPARATORS",
    "NUMERIC_SUFFIXES",
    # Username generation
    "generate_usernames_from_name",
    "generate_usernames_from_list",
    "generate_subdomain_admin_users",
    # Name collection
    "collect_names_from_file",
    "_filter_names",
    "search_names_google_dorks",
    "search_names_linkedin_api",
    "collect_names_online",
    # Password generation
    "CORPORATE_PASSWORD_PATTERNS",
    "_LEET_MAP",
    "_leet_variants",
    "generate_passwords_for_person",
    "generate_combo_list",
    # Wizard
    "interactive_domain_users_wizard",
    "run_domain_users",
]
