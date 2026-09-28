"""
osint_advanced.py - Advanced OSINT wordlist collectors.

Builds hyper-contextual wordlists from passive OSINT sources: the Wayback
Machine (historical URLs for a domain) and GitHub organizations (repository
names, descriptions and topics). Collected text is passed through a lightweight
named-entity extractor, and can be optionally enriched with a local or remote
LLM. Only fixed, well-known hosts are contacted (web.archive.org and
api.github.com), which avoids arbitrary outbound requests.

Inspired by CeWL, cewlai and WordForge.

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
import os
import re
from typing import Generator, Iterable, Optional
from urllib.parse import unquote, urlparse

logger = logging.getLogger(__name__)

_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9]{2,}")
_CAMEL_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
_STOPWORDS = {
    "the", "and", "for", "you", "with", "this", "that", "http", "https", "www",
    "com", "net", "org", "html", "php", "index", "page", "home", "about",
}


def _split_tokens(text: str, min_len: int = 3) -> Generator[str, None, None]:
    """Yield candidate word tokens from arbitrary text (camelCase aware)."""
    for match in _TOKEN_RE.finditer(text):
        raw = match.group()
        for part in _CAMEL_RE.findall(raw):
            if len(part) >= min_len and part.lower() not in _STOPWORDS:
                yield part


def extract_entities(texts: Iterable[str], min_len: int = 3) -> set[str]:
    """Extract candidate entities and words from a collection of texts.

    Args:
        texts: Iterable of text blobs.
        min_len: Minimum token length.

    Returns:
        Set of candidate words.
    """
    out: set[str] = set()
    for text in texts:
        if not text:
            continue
        for tok in _split_tokens(text, min_len):
            out.add(tok)
    return out


def collect_wayback(domain: str, limit: int = 5000, timeout: float = 20.0) -> set[str]:
    """Collect words from historical URLs of a domain via the Wayback CDX API.

    Args:
        domain: Target domain (for example ``example.com``).
        limit: Maximum URLs to fetch.
        timeout: HTTP timeout in seconds.

    Returns:
        Set of candidate words from URL paths and query parameters.
    """
    try:
        import requests
    except ImportError:
        logger.error("wayback collector requires 'requests'")
        return set()
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}"
    )
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        rows = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.error("wayback request failed: %s", exc)
        return set()
    texts: list[str] = []
    for row in rows[1:] if rows and isinstance(rows[0], list) else rows:
        original = row[0] if isinstance(row, list) else str(row)
        parsed = urlparse(original)
        texts.append(unquote(parsed.path.replace("/", " ")))
        texts.append(unquote(parsed.query.replace("&", " ").replace("=", " ")))
    logger.info("wayback: %d URLs collected for %s", max(0, len(rows) - 1), domain)
    return extract_entities(texts)


def collect_github_org(org: str, max_repos: int = 200,
                       timeout: float = 20.0) -> set[str]:
    """Collect words from a GitHub organization's public repositories.

    Uses the ``GITHUB_TOKEN`` environment variable when present to raise the
    rate limit. The token is never logged.

    Args:
        org: GitHub organization login.
        max_repos: Maximum repositories to inspect.
        timeout: HTTP timeout in seconds.

    Returns:
        Set of candidate words from repo names, descriptions and topics.
    """
    try:
        import requests
    except ImportError:
        logger.error("github collector requires 'requests'")
        return set()
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    texts: list[str] = []
    page = 1
    fetched = 0
    while fetched < max_repos:
        try:
            resp = requests.get(
                f"https://api.github.com/orgs/{org}/repos",
                params={"per_page": 100, "page": page, "type": "public"},
                headers=headers,
                timeout=timeout,
            )
            resp.raise_for_status()
            repos = resp.json()
        except Exception as exc:  # noqa: BLE001
            logger.error("github request failed: %s", exc)
            break
        if not repos:
            break
        for repo in repos:
            texts.append(repo.get("name") or "")
            texts.append(repo.get("description") or "")
            for topic in repo.get("topics", []) or []:
                texts.append(topic)
            fetched += 1
            if fetched >= max_repos:
                break
        page += 1
    logger.info("github: %d repos inspected for %s", fetched, org)
    return extract_entities(texts)


def enrich_local(words: set[str], years: Optional[list[int]] = None) -> set[str]:
    """Enrich a word set with common human mutations, without any network call.

    Applies capitalization, a few leet substitutions and year suffixes. This is
    the default enrichment when no LLM provider is configured.

    Args:
        words: Base words.
        years: Year suffixes to append.

    Returns:
        Enriched set including the originals.
    """
    years = years or [2023, 2024, 2025, 2026]
    leet = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$"})
    out: set[str] = set(words)
    for w in list(words):
        lw = w.lower()
        out.add(lw)
        out.add(lw.capitalize())
        out.add(lw.translate(leet))
        for y in years:
            out.add(f"{lw}{y}")
            out.add(f"{lw.capitalize()}{y}")
        out.add(f"{lw}!")
        out.add(f"{lw}123")
    return out


def enrich_llm(words: set[str], provider: str, model: str,
               max_terms: int = 100) -> set[str]:
    """Enrich a word set with related terms from an LLM provider (optional).

    Supported providers: ``ollama`` (local, no key) and ``openai`` (requires the
    ``OPENAI_API_KEY`` environment variable). On any failure, falls back to the
    original set so the pipeline never breaks.

    Args:
        words: Base words (a sample is sent as context).
        provider: ``ollama`` or ``openai``.
        model: Model name for the provider.
        max_terms: Maximum related terms to request.

    Returns:
        Set including the originals plus any related terms obtained.
    """
    try:
        import requests
    except ImportError:
        return words
    sample = ", ".join(sorted(list(words))[:60])
    prompt = (
        "Given these organization-related keywords, list up to "
        f"{max_terms} closely related terms, product names, and industry jargon "
        "as a plain comma-separated list, no explanations:\n" + sample
    )
    out = set(words)
    try:
        if provider == "ollama":
            resp = requests.post(
                "http://localhost:11434/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=60,
            )
            resp.raise_for_status()
            text = resp.json().get("response", "")
        elif provider == "openai":
            key = os.environ.get("OPENAI_API_KEY")
            if not key:
                logger.warning("OPENAI_API_KEY not set; skipping LLM enrichment")
                return out
            resp = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}"},
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.7,
                },
                timeout=60,
            )
            resp.raise_for_status()
            text = resp.json()["choices"][0]["message"]["content"]
        else:
            logger.warning("unknown provider %r; skipping LLM enrichment", provider)
            return out
    except Exception as exc:  # noqa: BLE001
        logger.warning("LLM enrichment failed (%s); using base words", exc)
        return out
    for tok in re.split(r"[,\n]", text):
        tok = tok.strip()
        if 2 < len(tok) < 40:
            out.add(tok)
    return out


def handle_osint(args, ctx: dict) -> Optional[Generator[str, None, None]]:
    """CLI handler for the ``osint`` command.

    Args:
        args: Parsed CLI arguments.
        ctx: Global execution context.

    Returns:
        Generator of candidate words, or None on error.
    """
    words: set[str] = set()
    domain = getattr(args, "wayback", None)
    org = getattr(args, "github_org", None)
    if not domain and not org:
        logger.error("provide --wayback DOMAIN and/or --github-org ORG")
        return None

    if domain:
        words |= collect_wayback(domain, limit=int(getattr(args, "limit_urls", 5000)))
    if org:
        words |= collect_github_org(org, max_repos=int(getattr(args, "max_repos", 200)))

    if not words:
        logger.warning("no words collected")
        return iter([])

    if getattr(args, "enrich", False):
        provider = getattr(args, "provider", None)
        if provider:
            words = enrich_llm(words, provider,
                               getattr(args, "model", "llama3") or "llama3")
        else:
            words = enrich_local(words)

    if getattr(args, "lowercase", False):
        words = {w.lower() for w in words}

    return iter(sorted(words))
