# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Corporate domain username and password generation."""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

import os
import re
import time
from pathlib import Path
from typing import Optional

from embedxpl.engines.wordlists.domain_users._utils import _norm, _clean

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
