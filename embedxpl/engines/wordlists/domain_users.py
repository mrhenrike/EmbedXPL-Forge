"""
domain_users.py - Corporate domain username and password generation.

Generates realistic corporate username/password combinations from employee
name lists, applying globally used naming conventions plus Brazilian patterns.

Features:
  - Corporate username patterns (firstname.lastname, f.lastname, etc.)
  - Employee name collection from any file (txt/csv/xlsx/pdf/docx)
  - Online name search via Google dorks (no mandatory API)
  - Optional LinkedIn API via LINKEDIN_RAPIDAPI_KEY env var (graceful fallback)
  - Subdomain-admin pattern generation (corp-ad → corp-adadmin)
  - Password generation from behavioral + corporate context
  - Accent normalization for Brazilian/Portuguese names
  - Custom pattern support

Usage:
  wlf.py corp-users --domain acme.example --file employees.txt
  wlf.py corp-users --domain acme.example --search "EmpresaXpto"
  wlf.py corp-users --domain acme.example --subdomain corp-ad
  wlf.py corp-users --domain acme.example --file names.txt --passwords --out combo.lst
  wlf.py corp-users --domain acme.example --interactive

Author: André Henrique (@mrhenrike)
Version: 1.1.0
"""
from __future__ import annotations

import logging
import os
import re
import time
from itertools import product
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

# ── Accent normalization ───────────────────────────────────────────────────────
# Use Unicode NFD decomposition: correct for all Latin-script accents.
# Previous str.maketrans approach had an off-by-one error (6 'a's for 5 vowels).

import unicodedata as _ud


def _norm(text: str) -> str:
    """
    Normalize: strip accents via NFD decomposition, lowercase, strip whitespace.

    Correctly handles all Portuguese/Spanish accented characters including
    ç → c, ã → a, õ → o, é → e, ó → o, ú → u, etc.
    """
    nfd = _ud.normalize("NFD", text)
    stripped = "".join(c for c in nfd if _ud.category(c) != "Mn")
    return stripped.lower().strip()


def _clean(text: str) -> str:
    """Normalize and strip non-alphanumeric characters."""
    return re.sub(r"[^a-z0-9]", "", _norm(text))


# ── Name parsing ───────────────────────────────────────────────────────────────

def parse_full_name(full_name: str) -> dict:
    """
    Parse a full name string into structured components.

    Handles compound last names (da PessoaY, de CorpX, etc.) and
    Brazilian naming conventions.

    Args:
        full_name: Full name string (e.g., "PessoaX da PessoaY").

    Returns:
        Dict with keys:
          - first: First name
          - middle: List of middle names (may be empty)
          - last: Last name (last token, may include particles)
          - all_parts: All name parts as list
          - initials: String of first letters of each part
          - fi: First letter of first name
          - li: First letter of last name
    """
    # Portuguese/Brazilian name particles (prepositions) - not counted as names
    particles = {"da", "de", "do", "das", "dos", "di", "du", "van", "von", "del", "el", "la", "le"}

    raw_parts = [p.strip() for p in full_name.split() if p.strip()]
    if not raw_parts:
        return {
            "first": "", "middle": [], "last": "",
            "all_parts": [], "initials": "", "fi": "", "li": "",
        }

    # Filter out pure particles for building name parts
    name_parts = [p for p in raw_parts if p.lower() not in particles]

    if not name_parts:
        name_parts = raw_parts

    first = name_parts[0]
    last = name_parts[-1] if len(name_parts) > 1 else ""
    middle = name_parts[1:-1] if len(name_parts) > 2 else []

    # Build initials from all parts (including particles skipped)
    initials = "".join(p[0] for p in raw_parts if p)

    # Particle-inclusive last name: e.g. "da PessoaY" → "dapessoay", "de CorpX" → "decorpx"
    # Detected when particle(s) immediately precede the last name_part in raw_parts.
    last_idx_in_raw = None
    for i in range(len(raw_parts) - 1, -1, -1):
        if raw_parts[i].lower() not in particles:
            last_idx_in_raw = i
            break
    last_full = last  # default: same as last
    if last_idx_in_raw is not None and last_idx_in_raw > 0:
        preceding = raw_parts[last_idx_in_raw - 1]
        if preceding.lower() in particles:
            # Collect consecutive particles before last
            parts_before = []
            j = last_idx_in_raw - 1
            while j >= 0 and raw_parts[j].lower() in particles:
                parts_before.insert(0, raw_parts[j])
                j -= 1
            last_full = "".join(parts_before) + last

    return {
        "first": first,
        "middle": middle,
        "last": last,
        "last_full": last_full,        # particle-inclusive (e.g. "dasilva")
        "all_parts": name_parts,
        "raw_parts": raw_parts,
        "initials": initials,
        "fi": first[0] if first else "",
        "li": last[0] if last else "",
        "mi": middle[0][0] if middle else "",
    }


# ── Corporate username patterns ────────────────────────────────────────────────

# Pattern tokens:
#   {fn}  = first name (normalized, no accents)
#   {ln}  = last name
#   {mn}  = first middle name (empty if none)
#   {fi}  = first initial
#   {li}  = last initial
#   {mi}  = middle initial
#   {ini} = all initials
#   {sep} = separator (iterated: ".", "_", "-", "")
#   {num} = numeric suffix (iterated: "01", "1", "02", "2", …)
#   {sub} = subdomain prefix (requires subdomain=True)
#
# Ordering follows common corporate AD username frequency.
# Username format patterns. Operator-supplied names drive generation.
CORPORATE_PATTERNS: list[dict] = [
    # ── Tier 1: Highest frequency (fn.ln in energy/utilities and similar) ──
    {"id": "fn_sep_ln",        "desc": "firstname.lastname",                  "fmt": "{fn}{sep}{ln}"},
    # ── Tier 2: No-separator variants (filn common in energy/utilities) ───
    {"id": "fi_ln",            "desc": "flastname (initial+last, no sep)",    "fmt": "{fi}{ln}"},
    {"id": "fn_li",            "desc": "firstnamel (name+last initial)",      "fmt": "{fn}{li}"},
    # ── Tier 3: With separator - initial+last, name+initial ──────────────────
    {"id": "fi_sep_ln",        "desc": "f.lastname",                          "fmt": "{fi}{sep}{ln}"},
    {"id": "fn_sep_li",        "desc": "firstname.l",                         "fmt": "{fn}{sep}{li}"},
    # ── Tier 4: First/last name alone (service accounts, single-name users) ───
    {"id": "fn_only",          "desc": "firstname only",                      "fmt": "{fn}"},
    {"id": "ln_only",          "desc": "lastname only",                       "fmt": "{ln}"},
    # ── Tier 5: No-separator compound (fnln, lnfn) ────────────────────────────
    {"id": "fn_ln",            "desc": "firstnamelastname (no sep)",          "fmt": "{fn}{ln}"},
    {"id": "ln_fn",            "desc": "lastnamefirstname (no sep)",          "fmt": "{ln}{fn}"},
    # ── Tier 6: Reversed (ln.fn, ln.f) - government/judicial pattern ─────────
    {"id": "ln_sep_fn",        "desc": "lastname.firstname",                  "fmt": "{ln}{sep}{fn}"},
    {"id": "ln_sep_fi",        "desc": "lastname.f (reversed initial)",       "fmt": "{ln}{sep}{fi}"},
    {"id": "ln_fi",            "desc": "lastnamef (no sep)",                  "fmt": "{ln}{fi}"},
    # ── Tier 7: Disambiguation with numeric suffix ────────────────────────────
    # Pattern fn.lnNUM (pessoax.corpx01) - when duplicate fn.ln exists
    {"id": "fn_sep_ln_num",    "desc": "fn.ln + numeric suffix (duplicate)",  "fmt": "{fn}{sep}{ln}{num}"},
    # Pattern fn.ln.NUM (pessoax.corpx.01) - dot-separated disambiguation
    {"id": "fn_sep_ln_sep_num","desc": "fn.ln.N (dot-separated, BR common)",  "fmt": "{fn}{sep}{ln}{sep}{num}"},
    # Pattern filn01 - initial+last with numeric suffix
    {"id": "fi_ln_num",        "desc": "filn + numeric suffix",               "fmt": "{fi}{ln}{num}"},
    # ── Tier 8: With middle name (when available) ──────────────────────────────
    {"id": "fn_sep_mn_sep_ln", "desc": "first.middle.last",                   "fmt": "{fn}{sep}{mn}{sep}{ln}", "needs_middle": True},
    {"id": "fi_mi_ln",         "desc": "fml initials (fimiln)",               "fmt": "{fi}{mi}{ln}",           "needs_middle": True},
    {"id": "fi_sep_mi_sep_li", "desc": "f.m.l (all initials with sep)",       "fmt": "{fi}{sep}{mi}{sep}{li}", "needs_middle": True},
    # ── Tier 9: Initials ──────────────────────────────────────────────────────
    {"id": "fi_li",            "desc": "initials fl (no sep)",                "fmt": "{fi}{li}"},
    {"id": "ini",              "desc": "all initials fml… (no sep)",          "fmt": "{ini}"},
    {"id": "fi_sep_li",        "desc": "f.l (initials with sep)",             "fmt": "{fi}{sep}{li}"},
    # ── Tier 10: BR institutional - name + middle/company part as alias ───────
    # Observed: firstname.middlename used when last name causes collision
    {"id": "fn_sep_mn",        "desc": "firstname.middlename (collision alt)","fmt": "{fn}{sep}{mn}",          "needs_middle": True},
    # ── Tier 10b: Particle-inclusive last name (dapessoay, decorpx, deacme) ───
    # Observed: pessoax.dapessoay, personay.decorpx, robotx.dacorpx
    # Some AD admins include the particle when the last name alone is ambiguous.
    {"id": "fn_sep_lf",        "desc": "firstname.dapessoay (particle+last)",  "fmt": "{fn}{sep}{lf}",          "needs_lf": True},
    {"id": "lf_sep_fn",        "desc": "dapessoay.firstname (reversed)",       "fmt": "{lf}{sep}{fn}",          "needs_lf": True},
    {"id": "fi_sep_lf",        "desc": "f.dapessoay (initial+full-last)",      "fmt": "{fi}{sep}{lf}",          "needs_lf": True},
    # ── Tier 11: Admin/role accounts ─────────────────────────────────────────
    {"id": "fn_sep_ln_adm",    "desc": "firstname.lastname.admin",            "fmt": "{fn}{sep}{ln}{sep}admin"},
    {"id": "adm_fn_sep_ln",    "desc": "admin.firstname.lastname",            "fmt": "admin{sep}{fn}{sep}{ln}"},
    # ── Tier 12: Subdomain-admin (e.g. corp-ad → corp-adadmin) ────────────
    {"id": "sub_admin",        "desc": "subdomainadmin (no sep)",             "fmt": "{sub}admin",              "subdomain": True},
    {"id": "sub_sep_admin",    "desc": "subdomain.admin (with sep)",          "fmt": "{sub}{sep}admin",         "subdomain": True},
    {"id": "admin_sep_sub",    "desc": "admin.subdomain",                     "fmt": "admin{sep}{sub}",         "subdomain": True},
    # ── Tier 13: Contractor pattern - fn.COMPANY_ABBR (validated BR pattern) ─
    # Observed: contractors from external companies use firstname.company_code
    # e.g. pessoax.acme, personay.xpto, robotx.corpx, pessoax.xptoinc
    # Requires company_abbr parameter to be set.
    {"id": "fn_sep_co",        "desc": "firstname.company_abbr (contractor)", "fmt": "{fn}{sep}{co}",           "needs_company": True},
    {"id": "fi_sep_co",        "desc": "f.company_abbr (contractor)",         "fmt": "{fi}{sep}{co}",           "needs_company": True},
    {"id": "fn_co",            "desc": "firstnamecompany (no sep, contractor)","fmt": "{fn}{co}",                "needs_company": True},
    # ── Tier 14: compound firstname (pessoaxpersonay, personay) ──────────────────
    # Observed: pessoaxpersonay.corpx, personay.acme (compound first names)
    {"id": "fn2_sep_ln",       "desc": "fn1fn2.lastname (compound first)",   "fmt": "{fn2}{sep}{ln}",          "needs_fn2": True},
    {"id": "fn2_sep_fi",       "desc": "fn1fn2.l (compound+initial)",        "fmt": "{fn2}{sep}{li}",          "needs_fn2": True},
]

# Generic sector templates. Real target names are never stored.
# At runtime, usernames/passwords are derived from the domain and company
# strings the operator supplies, not from a hardcoded org list.
KNOWN_BR_DOMAIN_PATTERNS: dict[str, dict] = {
    "acme.example": {"primary": "fn.ln", "secondary": "filn", "notes": "energy sector; contractors often use externo.acme.example"},
    "externo.acme.example": {"primary": "fn.ln", "secondary": "filn", "notes": "third-party/contractors"},
    "acme.local": {"primary": "fn.ln", "secondary": None, "notes": "AD local domain"},
    "xpto.example": {"primary": "numeric_padded", "secondary": "fn.ln", "notes": "padded numeric employee ID"},
    "corpx.example": {"primary": "numeric", "secondary": "prefix+num", "notes": "internal prefix+num; contractor prefix+num"},
    "brandx.example": {"primary": "numeric_padded", "secondary": "fn.ln", "notes": "employee ID plus fn.ln email slug"},
    "empresax.example": {"primary": "fn.ln", "secondary": "fn-ln", "notes": "public sector; hyphenated short names"},
    "xptoinc.example": {"primary": "numeric", "secondary": "prefix+num", "notes": "internal prefix+num; contractor prefix+num"},
    "companyxpto.example": {"primary": "fn.ln", "secondary": None, "notes": "agribusiness"},
    "corp.example": {"primary": "fn.ln", "secondary": "fn", "notes": "education / training"},
}

# Generic role prefixes for employee-id style usernames. Not tied to any org.
KNOWN_BR_EMPLOYEE_ID_PREFIXES: dict[str, str] = {
    "int": "internal employee",
    "uni": "internal employee prefix",
    "trc": "contractor / outsourced",
    "crm": "CRM system user",
    "est": "intern",
    "apr": "apprentice",
    "svc": "service account",
    "eng": "engineering",
    "log": "logistics",
    "ops": "operations",
}

# Separators used when generating with SEP token
# Default separator: dot only. User can override with --separators.
DOMAIN_SEPARATORS = ["."]

# All available separators (for --separators all or interactive "all")
ALL_DOMAIN_SEPARATORS = [".", "_", "-", ""]

# Numeric suffixes for generic/service accounts
NUMERIC_SUFFIXES = [
    "01", "02", "1", "2", "00", "10", "99",
    "03", "04", "05", "06", "07", "08", "09",
    "11", "12", "13", "20", "21", "100", "0",
]


# ── Username generation ────────────────────────────────────────────────────────

def generate_usernames_from_name(
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
    """
    Extract person names from any supported file type.

    Supported formats: .txt, .csv, .tsv, .xlsx, .xls, .pdf, .docx, .doc, .md

    The function reads lines/cells and returns values that look like person names
    (at least 2 words, non-numeric, no URLs/emails).

    Args:
        filepath: Path to the input file.

    Returns:
        List of candidate full name strings.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    ext = path.suffix.lower()
    raw_values: list[str] = []

    if ext in (".txt", ".md", ".lst", ".csv", ".tsv"):
        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    # CSV: take first non-numeric column
                    parts = re.split(r"[,;\t]", line)
                    for p in parts:
                        p = p.strip().strip('"').strip("'")
                        if p:
                            raw_values.append(p)

    elif ext in (".xlsx", ".xls"):
        try:
            import openpyxl
            wb = openpyxl.load_workbook(filepath, read_only=True, data_only=True)
            for ws in wb.worksheets:
                for row in ws.iter_rows(values_only=True):
                    for cell in row:
                        if cell:
                            raw_values.append(str(cell).strip())
        except ImportError:
            logger.warning("openpyxl not installed. Install: pip install openpyxl")

    elif ext == ".pdf":
        try:
            import pdfplumber
            with pdfplumber.open(filepath) as pdf:
                for page in pdf.pages:
                    text = page.extract_text() or ""
                    raw_values.extend(text.splitlines())
        except ImportError:
            logger.warning("pdfplumber not installed. Install: pip install pdfplumber")

    elif ext in (".docx",):
        try:
            import docx
            doc = docx.Document(filepath)
            for para in doc.paragraphs:
                if para.text.strip():
                    raw_values.append(para.text.strip())
        except ImportError:
            logger.warning("python-docx not installed. Install: pip install python-docx")

    else:
        # Fallback: read as plain text
        with path.open(encoding="utf-8", errors="replace") as f:
            raw_values = [line.strip() for line in f if line.strip()]

    return _filter_names(raw_values)


def _filter_names(candidates: list[str]) -> list[str]:
    """
    Filter a list of raw strings to retain only plausible person names.

    Rejects: URLs, emails, pure numbers, very short strings, strings with
    typical non-name patterns (CPF, CNPJ, phone numbers).

    Args:
        candidates: Raw strings to filter.

    Returns:
        List of plausible name strings.
    """
    _email_re = re.compile(r"@|https?://|www\.|\.com")
    _numeric_re = re.compile(r"^\d+[\d\.\-\/]*$")
    _cpf_re = re.compile(r"\d{3}\.?\d{3}\.?\d{3}-?\d{2}")
    _phone_re = re.compile(r"\(?\d{2}\)?\s?\d{4,5}-?\d{4}")

    names: list[str] = []
    seen: set[str] = set()

    for raw in candidates:
        s = raw.strip()
        if not s or len(s) < 4:
            continue
        if _email_re.search(s):
            continue
        if _numeric_re.match(s):
            continue
        if _cpf_re.search(s):
            continue
        if _phone_re.search(s):
            continue
        # Must have at least one letter
        if not re.search(r"[a-zA-ZÀ-ÿ]", s):
            continue
        # Normalize spacing
        s = re.sub(r"\s+", " ", s).strip()
        if s.lower() not in seen:
            seen.add(s.lower())
            names.append(s)

    return names


# ── Online name search (no mandatory API) ─────────────────────────────────────

def search_names_google_dorks(
    company_name: str,
    domain: Optional[str] = None,
    max_results: int = 50,
    delay: float = 2.0,
) -> list[str]:
    """
    Search for employee names via Google dorks (no API required).

    Uses search queries like:
      site:linkedin.com/in "at CompanyName"
      "CompanyName" "LinkedIn" people employees

    Note: Google may rate-limit or block. The function applies delays
    and respects response codes. Results are parsed from snippets.

    Args:
        company_name: Company name to search for.
        domain: Optional company domain for extra context.
        max_results: Maximum names to collect.
        delay: Delay between requests in seconds.

    Returns:
        List of candidate name strings found.
    """
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        logger.error("requests and beautifulsoup4 required. Install: pip install requests beautifulsoup4")
        return []

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    }

    queries = [
        f'site:linkedin.com/in "{company_name}"',
        f'site:linkedin.com "at {company_name}"',
    ]
    if domain:
        queries.append(f'site:linkedin.com "{domain}"')

    _name_re = re.compile(r"\b([A-ZÁÀÃÉÊÍÓÔÕÚ][a-záàãéêíóôõúç]+(?:\s+[A-ZÁÀÃÉÊÍÓÔÕÚ][a-záàãéêíóôõúç]+){1,4})\b")

    collected: list[str] = []
    seen: set[str] = set()

    for query in queries:
        if len(collected) >= max_results:
            break
        try:
            url = f"https://www.google.com/search?q={requests.utils.quote(query)}&num=20&hl=pt-BR"
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 429:
                logger.warning("Google rate-limited. Try again later or use --file.")
                break
            if resp.status_code != 200:
                logger.debug("Google returned %d for query: %s", resp.status_code, query)
                continue

            soup = BeautifulSoup(resp.content.decode("utf-8", errors="replace"), "lxml")

            # Parse h3 titles and snippet divs
            for el in soup.find_all(["h3", "div"], class_=lambda c: c and ("BNeawe" in c or "VwiC3b" in c)):
                text = el.get_text(" ", strip=True)
                for match in _name_re.finditer(text):
                    name = match.group(1).strip()
                    if len(name.split()) >= 2 and name.lower() not in seen:
                        seen.add(name.lower())
                        collected.append(name)
                        if len(collected) >= max_results:
                            break

            time.sleep(delay)

        except Exception as exc:
            logger.debug("Error during Google dork search: %s", exc)
            continue

    return collected


def search_names_linkedin_api(
    company_name: str,
    max_results: int = 50,
) -> list[str]:
    """
    Search for employee names via LinkedIn API (RapidAPI).

    Requires LINKEDIN_RAPIDAPI_KEY environment variable.
    If not set, returns an empty list with a warning - no exception raised.

    Args:
        company_name: Company name to search for.
        max_results: Maximum results to fetch.

    Returns:
        List of candidate name strings, or [] if API key is not set.
    """
    api_key = os.environ.get("LINKEDIN_RAPIDAPI_KEY", "").strip()
    if not api_key:
        logger.warning(
            "LINKEDIN_RAPIDAPI_KEY not set. LinkedIn API search skipped. "
            "Set the env var or use --search (Google dorks) or --file instead."
        )
        return []

    try:
        import requests
    except ImportError:
        logger.error("requests required. Install: pip install requests")
        return []

    headers = {
        "X-RapidAPI-Key": api_key,
        "X-RapidAPI-Host": "linkedin-profiles-and-company-data.p.rapidapi.com",
    }

    names: list[str] = []
    try:
        resp = requests.get(
            "https://linkedin-profiles-and-company-data.p.rapidapi.com/search-people",
            headers=headers,
            params={"keywords": company_name, "count": str(min(max_results, 50))},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("people", data.get("results", [])):
                full_name = item.get("name") or item.get("fullName") or ""
                if full_name.strip():
                    names.append(full_name.strip())
        else:
            logger.warning("LinkedIn API returned %d: %s", resp.status_code, resp.text[:200])
    except Exception as exc:
        logger.error("LinkedIn API error: %s", exc)

    return names


def collect_names_online(
    company_name: str,
    domain: Optional[str] = None,
    max_results: int = 50,
    use_linkedin_api: bool = True,
    delay: float = 2.0,
) -> list[str]:
    """
    Collect employee names using all available online methods.

    Priority order:
      1. LinkedIn official OAuth2 API (if LINKEDIN_ACCESS_TOKEN is set)
      2. LinkedIn RapidAPI (if LINKEDIN_RAPIDAPI_KEY is set - legacy fallback)
      3. Google dorks (no API required, always available)

    Args:
        company_name: Company name to search for.
        domain: Optional company domain for extra context.
        max_results: Maximum names to collect.
        use_linkedin_api: Attempt LinkedIn API if key/token is available.
        delay: Delay between requests in seconds.

    Returns:
        Deduplicated list of candidate name strings.
    """
    names: list[str] = []
    seen: set[str] = set()

    if use_linkedin_api:
        # Strategy 1: Official LinkedIn OAuth2 API
        try:
            from embedxpl.engines.wordlists.linkedin_search import search_employees
            oauth_names = search_employees(company_name, domain, max_results)
            for n in oauth_names:
                if n.lower() not in seen:
                    seen.add(n.lower())
                    names.append(n)
        except Exception as exc:
            logger.debug("LinkedIn OAuth2 search failed: %s", exc)

        # Strategy 2: RapidAPI fallback (legacy)
        if len(names) < max_results:
            rapidapi_names = search_names_linkedin_api(company_name, max_results - len(names))
            for n in rapidapi_names:
                if n.lower() not in seen:
                    seen.add(n.lower())
                    names.append(n)

    # Strategy 3: Google dorks (always tried if quota not met)
    if len(names) < max_results:
        remaining = max_results - len(names)
        dork_names = search_names_google_dorks(company_name, domain, remaining, delay)
        for n in dork_names:
            if n.lower() not in seen:
                seen.add(n.lower())
                names.append(n)

    return names


# ── Password generation ────────────────────────────────────────────────────────

# Common corporate password patterns (global + Brazilian)
# Tokens: {fn} first name, {ln} last name, {fi} first initial, {domain} domain name,
#         {year} current year, {company} company short name
CORPORATE_PASSWORD_PATTERNS: list[str] = [
    # ── Global standards ──────────────────────────────────────
    "{fn}@{year}",
    "{fn}{year}!",
    "{fn}{year}@",
    "{fn}{year}#",
    "{fn}.{ln}@{year}",
    "{fn}{ln}{year}",
    "{fn}{ln}!",
    "{fn}{ln}@",
    "{ln}{fn}{year}",
    "{ln}@{year}",
    "{company}{year}",
    "{company}@{year}",
    "{company}#{year}",
    "{company}!",
    "{company}123",
    "{company}1234",
    "{company}@123",
    "{company}_{year}",
    "Welcome{year}!",
    "Welcome@{year}",
    "Welcome1!",
    "{company}2024",
    "{company}2025",
    "{company}2026",
    # ── Brazilian patterns ────────────────────────────────────
    "{fn}@corp",
    "{fn}123456",
    "{fn}12345",
    "{fn}1234",
    "{fn}123",
    "{company}@{year}!",
    "{company}Mudar{year}",
    "{company}mudar{year}",
    "Mudar{year}!",
    "Mudar@{year}",
    "mudar{year}",
    "{fn}Mudar{year}",
    "{fn}mudar{year}",
    "{fn}@mudar",
    "P@ssw0rd{year}",
    "S3nh@{year}",
    "Senha{year}!",
    "senha{year}",
    "{fn}_{ln}@{year}",
    "{fn}.{ln}@{company}",
    "{fn}.{ln}{year}",
    # ── IT-role patterns ──────────────────────────────────────
    "Admin{year}!",
    "admin{year}@",
    "root{year}!",
    "{company}vpn{year}",
    "{company}VPN{year}",
    "{company}local{year}",
    "{company}corp{year}",
    "{company}adm{year}",
    "{company}admin!",
    "{company}admin{year}",
    # ── Vault behavioral patterns (observed in Brazilian corp environments) ──
    # Pattern: {Company}${Year} and variants with ### suffix (MSSP analysis)
    "{company}${year}",
    "{company}${year}!",
    "{company}${year}###",
    # Pattern: @{Company}{Year} / @{Company}{digits}
    "@{company}{year}",
    "@{company}{year}#",
    "@{company}123",
    "@{company}1234",
    # Pattern: #{Company}@{Year} - observed in vault
    "#{company}@{year}",
    "#{company}@{year}#",
    "#{company}{year}#",
    # Pattern: {Company}#{Year}### - vault sample Corp#2026 variants
    "{company}#{year}!",
    "{company}@{year}#{y2}",
    "{company}&{year}",
    "{company}+{year}!",
    # Pattern: {Company}{2-digit year} - cartel2030 → cartel30
    "{company}{y2}",
    "{company}{y2}!",
    "{fn}{y2}",
    "{ln}{y2}",
    # Pattern: {Role}{Company}{Year}! - UGAdmin2025!, AdminCorp2024!
    "Admin{company}{year}!",
    "admin{company}{year}",
    "Admin{company}!",
    "{company}Admin{year}!",
    "{company}Admin!",
    "Root{company}{year}!",
    "root{company}{year}",
    "Dev{company}{year}!",
    "dev{company}{year}",
    # Pattern: {fn}@{Company} / {fn}.{Company} - user@init123
    "{fn}@{company}",
    "{fn}@{company}{y2}",
    "{fn}@{company}{year}",
    "{fn}.{company}",
    "{fn}.{company}{year}",
    # Pattern: {Company}@{Year}#{word} - BrandX@2022#xpto
    "{company}@{year}#brasil",
    "{company}@{year}#brazil",
    # Pattern: {Company}{Word}{Year} - CorpX2020!, XptoInc1
    "{company}mudar@{year}",
    "{company}Acesso{year}",
    "{company}acesso{year}",
    "{company}acesso@{year}",
    # Pattern: {word}+digits suffix (word+01, word+2025, word+88)
    "{fn}{year}01",
    "{fn}{year}00",
    "{fn}{ln}01",
    "{fn}{ln}2025",
    "{ln}{fn}01",
    # Pattern: {Company}{year}! with capital
    # e.g. CorpX2020! → {CompanyCap}{year}!
    "{company}{year}!",
    "{fn}{year}!!",
    # Pattern: passphrase-like {word}-{word}-{word}-{NNN}
    # These require compound generation - added as static suffixed templates:
    "{company}-{fn}-{ln}-{y2}",
    "{fn}-{ln}-{company}-{y2}",
    # Pattern: Date-based 29/01/2018 (rare but observed)
    "{fn}01{year}",
    "{fn}01{y2}",
    # Pattern: leet in password - base templates (leet expansion in generator)
    "S3nh@{year}!",
    "Acss0@{year}",
    "Acc3ss@{year}",
    "4dm1n{year}!",
    "4dm1n{year}@",
    "P4ssw0rd{year}!",
    "P@$$word{year}!",
    "Mudar@{year}!",
    "Tr0c4r{year}!",
    # Pattern: numeric suffixes on company (seen in vault)
    "{company}88",
    "{company}99",
    "{company}01",
    "{company}00",
    "{company}02",
]


# Leet substitution map for password generation
_LEET_MAP: dict[str, list[str]] = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["$", "5"],
    "A": ["@", "4"],
    "E": ["3"],
    "I": ["1", "!"],
    "O": ["0"],
    "S": ["$", "5"],
}


def _leet_variants(word: str, max_variants: int = 6) -> list[str]:
    """
    Generate leet-speak variants of a word by substituting 1-2 characters.

    Args:
        word: Input word to leet-ify.
        max_variants: Maximum number of variants to return.

    Returns:
        List of leet variants (without duplicates, excluding the original).
    """
    from itertools import product as iproduct
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
