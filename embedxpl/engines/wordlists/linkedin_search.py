"""
linkedin_search.py - LinkedIn employee name search via official OAuth2 API.

Uses the LinkedIn REST API v2 with an OAuth2 access token.
Credentials are read exclusively from environment variables (never hardcoded).

Env vars required (set in .env or OS environment):
  LINKEDIN_ACCESS_TOKEN  - OAuth2 Bearer token (expires ~60 days)
  LINKEDIN_CLIENT_ID     - App client ID (for token refresh)
  LINKEDIN_CLIENT_SECRET - App client secret (for token refresh)

Fallback chain:
  1. LinkedIn official OAuth2 API (Bearer token)
  2. RapidAPI LinkedIn wrapper (LINKEDIN_RAPIDAPI_KEY)
  3. Google dorks scraping (no key required)

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)

# LinkedIn REST API v2 base URL
_LI_API_BASE = "https://api.linkedin.com/v2"
_LI_TIMEOUT  = 15


def _load_dotenv() -> None:
    """Load .env file from the wfh root directory into os.environ if not already set."""
    from pathlib import Path
    env_path = Path(__file__).parent.parent / ".env"
    if not env_path.exists():
        return
    try:
        with open(env_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
    except Exception as exc:
        logger.debug("Could not load .env: %s", exc)


def _get_access_token() -> str:
    """
    Return the LinkedIn OAuth2 access token from env.

    Returns:
        Access token string, or empty string if not configured.
    """
    _load_dotenv()
    return os.environ.get("LINKEDIN_ACCESS_TOKEN", "").strip()


def _get_session():
    """Return a configured requests.Session with LinkedIn OAuth2 headers."""
    try:
        import requests
    except ImportError:
        raise ImportError("requests required - install with: pip install requests")

    token = _get_access_token()
    if not token:
        raise EnvironmentError(
            "LINKEDIN_ACCESS_TOKEN not set. "
            "Add it to your .env file or set the environment variable."
        )

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "X-Restli-Protocol-Version": "2.0.0",
        "Content-Type": "application/json",
    })
    return session


def validate_token() -> dict:
    """
    Validate the current access token by fetching the authenticated profile.

    Uses /v2/userinfo (OpenID Connect) which is accessible with the base
    'openid' scope - does not require r_liteprofile.

    Scope requirements for full functionality:
      openid            → /v2/userinfo (validated here)
      r_liteprofile     → /v2/me, basic people lookups
      r_emailaddress    → email address in /v2/emailAddress
      r_fullprofile     → full profile data
      [Recruiter API]   → /v2/people/search by company (partner access required)

    Returns:
        Dict with 'ok' (bool), 'name' (str), 'email' (str),
        'scopes' (list), 'error' (str if failed).
    """
    _load_dotenv()
    token = _get_access_token()
    if not token:
        return {"ok": False, "error": "LINKEDIN_ACCESS_TOKEN não configurado."}

    try:
        import requests
    except ImportError:
        return {"ok": False, "error": "requests não instalado. Execute: pip install requests"}

    headers = {"Authorization": f"Bearer {token}"}

    # /v2/userinfo - OpenID Connect, works with 'openid' scope
    try:
        resp = requests.get(
            "https://api.linkedin.com/v2/userinfo",
            headers=headers,
            timeout=_LI_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            name  = data.get("name", "")
            email = data.get("email", "")
            sub   = data.get("sub", "")

            # Check if r_liteprofile is also available (needed for people search)
            has_liteprofile = False
            try:
                r2 = requests.get(
                    f"{_LI_API_BASE}/me",
                    headers={**headers, "X-Restli-Protocol-Version": "2.0.0"},
                    timeout=8,
                )
                has_liteprofile = r2.status_code == 200
            except Exception:
                pass

            return {
                "ok":             True,
                "id":             sub,
                "name":           name,
                "email":          email,
                "scope_openid":   True,
                "scope_liteprofile": has_liteprofile,
                "search_available": has_liteprofile,
                "warning": (
                    None if has_liteprofile else
                    "Token tem apenas scope 'openid'. "
                    "Para busca de employees: reautorize com r_liteprofile. "
                    "Será usado Google dorks como fallback."
                ),
            }
        elif resp.status_code == 401:
            return {"ok": False, "error": "Token expirado ou inválido (401). Renove em: https://www.linkedin.com/developers/apps"}
        else:
            return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def get_company_urn(company_name: str) -> Optional[str]:
    """
    Try to find a LinkedIn organization URN by company name.

    Uses the organization search endpoint (requires r_organization_social scope).
    Falls back to vanity name search if organization search is unavailable.

    Args:
        company_name: Company trade name to search.

    Returns:
        LinkedIn organization URN string (e.g. 'urn:li:organization:12345')
        or None if not found.
    """
    try:
        session = _get_session()
    except (ImportError, EnvironmentError) as exc:
        logger.warning("LinkedIn session error: %s", exc)
        return None

    # Try organization search by keyword
    try:
        resp = session.get(
            f"{_LI_API_BASE}/search",
            params={
                "q":       "company",
                "keywords": company_name,
                "count":   "5",
                "start":   "0",
            },
            timeout=_LI_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            elements = data.get("elements", [])
            if elements:
                entity = elements[0].get("targetUrn") or elements[0].get("urn") or ""
                if "organization" in entity:
                    return entity
    except Exception as exc:
        logger.debug("Organization search failed: %s", exc)

    return None


def search_employees_by_company(
    company_name: str,
    max_results:  int = 50,
) -> list[str]:
    """
    Search for employee full names at a given company via LinkedIn API.

    Attempts multiple LinkedIn API strategies in order:
      1. People search with company keyword (v2/search)
      2. People search with vanity name / facetCurrentCompany

    Args:
        company_name: Company name to search employees for.
        max_results: Max number of names to return.

    Returns:
        List of full name strings found (may be empty if API scope is insufficient).
    """
    try:
        session = _get_session()
    except (ImportError, EnvironmentError) as exc:
        logger.warning("LinkedIn not available: %s", exc)
        return []

    names: list[str] = []

    # Strategy 1: People search by keywords (company name + "employee")
    try:
        resp = session.get(
            f"{_LI_API_BASE}/search",
            params={
                "q":        "people",
                "keywords":  company_name,
                "count":    str(min(max_results, 50)),
                "start":    "0",
                "origin":   "GLOBAL_SEARCH_HEADER",
            },
            timeout=_LI_TIMEOUT,
        )
        logger.debug("LinkedIn search /search?q=people: HTTP %d", resp.status_code)

        if resp.status_code == 200:
            data = resp.json()
            for elem in data.get("elements", []):
                name = _extract_name_from_element(elem)
                if name:
                    names.append(name)

        elif resp.status_code == 403:
            logger.warning(
                "LinkedIn people search returned 403 - API scope 'r_liteprofile' or "
                "Recruiter/Talent Solutions required for employee search."
            )
        elif resp.status_code == 401:
            logger.error("LinkedIn token expired (401). Renew access token.")
            return []
    except Exception as exc:
        logger.debug("LinkedIn search strategy 1 failed: %s", exc)

    # Strategy 2: people/search endpoint (older v2 format)
    if not names:
        try:
            resp2 = session.get(
                f"{_LI_API_BASE}/people/search",
                params={
                    "q":       "company",
                    "company":  company_name,
                    "count":   str(min(max_results, 50)),
                },
                timeout=_LI_TIMEOUT,
            )
            logger.debug("LinkedIn /people/search: HTTP %d", resp2.status_code)
            if resp2.status_code == 200:
                data2 = resp2.json()
                for elem in data2.get("elements", []):
                    name = _extract_name_from_element(elem)
                    if name:
                        names.append(name)
        except Exception as exc:
            logger.debug("LinkedIn search strategy 2 failed: %s", exc)

    logger.info("LinkedIn API returned %d names for '%s'", len(names), company_name)
    return names[:max_results]


def _extract_name_from_element(elem: dict) -> str:
    """Extract a full name from a LinkedIn API response element."""
    # Various response shapes from different LinkedIn API versions
    for key in ("name", "fullName", "localizedName"):
        v = elem.get(key)
        if v and isinstance(v, str):
            return v.strip()

    first = elem.get("localizedFirstName") or elem.get("firstName", {})
    last  = elem.get("localizedLastName")  or elem.get("lastName", {})

    if isinstance(first, dict):
        first = first.get("localized", {})
        first = next(iter(first.values()), "") if isinstance(first, dict) else ""
    if isinstance(last, dict):
        last = last.get("localized", {})
        last = next(iter(last.values()), "") if isinstance(last, dict) else ""

    full = f"{first} {last}".strip()
    return full if len(full) > 2 else ""


def search_employees(
    company_name: str,
    domain:       Optional[str] = None,
    max_results:  int = 50,
) -> list[str]:
    """
    Public interface: search for employee names using the best available LinkedIn method.

    Falls back gracefully if the token is missing or the API scope is insufficient.

    Args:
        company_name: Company name to search.
        domain: Company domain (used as additional search hint).
        max_results: Maximum number of names.

    Returns:
        List of full name strings.
    """
    _load_dotenv()

    token = _get_access_token()
    if not token:
        logger.warning(
            "LINKEDIN_ACCESS_TOKEN not set - LinkedIn search disabled. "
            "Set the token in .env or use --search (Google dorks) instead."
        )
        return []

    names = search_employees_by_company(company_name, max_results)

    # If name returned, try also searching by domain keyword
    if not names and domain:
        domain_company = domain.split(".")[0]
        if domain_company.lower() != company_name.lower():
            names = search_employees_by_company(domain_company, max_results)

    return names


def refresh_access_token() -> Optional[str]:
    """
    Attempt to refresh the LinkedIn access token using client credentials.

    Note: LinkedIn does not support client_credentials grant for user tokens.
    This function only works if a refresh_token is available (Authorization Code flow).

    Returns:
        New access token string, or None if refresh is not possible.
    """
    _load_dotenv()
    client_id     = os.environ.get("LINKEDIN_CLIENT_ID", "").strip()
    client_secret = os.environ.get("LINKEDIN_CLIENT_SECRET", "").strip()

    if not client_id or not client_secret:
        logger.warning("LINKEDIN_CLIENT_ID or LINKEDIN_CLIENT_SECRET not set.")
        return None

    try:
        import requests
        resp = requests.post(
            "https://www.linkedin.com/oauth/v2/accessToken",
            data={
                "grant_type":    "client_credentials",
                "client_id":      client_id,
                "client_secret":  client_secret,
            },
            timeout=10,
        )
        if resp.status_code == 200:
            new_token = resp.json().get("access_token")
            logger.info("LinkedIn token refreshed via client_credentials.")
            return new_token
        else:
            logger.warning(
                "Token refresh failed (HTTP %d). "
                "LinkedIn requires Authorization Code flow for user tokens - "
                "renew manually at: https://www.linkedin.com/developers/apps",
                resp.status_code,
            )
    except Exception as exc:
        logger.error("Token refresh error: %s", exc)

    return None
