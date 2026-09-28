"""
embedxpl/modules/osint/github_recon.py - GitHub IoT/Embedded Device OSINT.

Searches GitHub for leaked credentials, config files, and API keys
related to IoT devices and embedded systems.

Native implementation based on:
  submodules/Safelabs-Operacao-Desenvolvimento/collectors-platform/apps/collectors/github/

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

__version__ = "1.0.0"

try:
    import requests  # type: ignore
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

# Pre-defined search queries by device vertical
QUERIES: Dict[str, List[str]] = {
    "mikrotik": [
        "mikrotik password extension:rsc",
        "routeros api token site:github.com",
        "winbox password",
    ],
    "fortigate": [
        "fortigate config password",
        "fortinet api key extension:conf",
        "fortigate backup extension:conf",
    ],
    "cisco": [
        "cisco enable secret",
        "cisco running-config extension:txt",
        "ios password",
    ],
    "printer": [
        "printer admin password extension:xml",
        "jetdirect password",
        "cups admin password",
    ],
    "iot_generic": [
        "admin password 192.168 extension:txt",
        "router default password extension:ini",
        "iot firmware key",
    ],
    "modbus": [
        "modbus password",
        "scada credentials extension:ini",
        "plc admin password",
    ],
}

# GitHub API search endpoint
GITHUB_SEARCH_URL = "https://api.github.com/search/code"


@dataclass
class CodeSnippet:
    """A code snippet found in GitHub search."""
    query: str
    repo_full_name: str
    file_path: str
    url: str
    sha: str = ""
    snippet: str = ""
    potential_credential: bool = False


@dataclass
class GitHubReconResult:
    """Results from a GitHub recon search."""
    vertical: str
    total_found: int = 0
    snippets: List[CodeSnippet] = field(default_factory=list)
    error: str = ""


class GitHubRecon:
    """GitHub code search for IoT device credential and config leaks.

    Requires GITHUB_TOKEN environment variable for authenticated search.
    Without token: 10 requests/minute, 10 results per query.
    With token: 30 requests/minute, more results.

    Usage:
        recon = GitHubRecon()
        if recon.available:
            result = recon.search("mikrotik")
            for snippet in result.snippets:
                print(snippet.file_path, snippet.url)
    """

    def __init__(
        self,
        token: str = "",
        rate_limit_sec: float = 2.0,
    ) -> None:
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self.rate_limit_sec = rate_limit_sec
        self._last_request = 0.0

    @property
    def available(self) -> bool:
        return _REQUESTS

    def _rate_limit(self) -> None:
        elapsed = time.time() - self._last_request
        if elapsed < self.rate_limit_sec:
            time.sleep(self.rate_limit_sec - elapsed)
        self._last_request = time.time()

    def search(
        self,
        vertical: str,
        limit: int = 10,
        custom_queries: Optional[List[str]] = None,
    ) -> GitHubReconResult:
        """Search GitHub for code related to the specified device vertical.

        Args:
            vertical: Device category ("mikrotik", "fortigate", "printer", etc.)
            limit: Maximum results per query.
            custom_queries: Override default queries for this vertical.

        Returns:
            GitHubReconResult with found snippets.
        """
        if not _REQUESTS:
            return GitHubReconResult(vertical=vertical, error="requests not installed")

        queries = custom_queries or QUERIES.get(vertical, QUERIES["iot_generic"])
        result = GitHubReconResult(vertical=vertical)
        headers = {"Accept": "application/vnd.github.v3.text-match+json"}
        if self.token:
            headers["Authorization"] = f"token {self.token}"

        for query in queries[:3]:  # limit to 3 queries per vertical
            self._rate_limit()
            try:
                resp = requests.get(
                    GITHUB_SEARCH_URL,
                    params={"q": query, "per_page": min(limit, 30)},
                    headers=headers,
                    timeout=15,
                )

                if resp.status_code == 403:
                    result.error = "Rate limit exceeded or token required"
                    break
                if resp.status_code == 422:
                    continue  # Query syntax issue, skip
                if resp.status_code != 200:
                    continue

                data = resp.json()
                items = data.get("items", [])
                result.total_found += data.get("total_count", 0)

                for item in items:
                    snippet = CodeSnippet(
                        query=query,
                        repo_full_name=item.get("repository", {}).get("full_name", ""),
                        file_path=item.get("path", ""),
                        url=item.get("html_url", ""),
                        sha=item.get("sha", ""),
                    )

                    # Extract text match snippets
                    text_matches = item.get("text_matches", [])
                    if text_matches:
                        snippet.snippet = text_matches[0].get("fragment", "")[:300]
                        # Heuristic: check for potential credential in snippet
                        snippet_lower = snippet.snippet.lower()
                        snippet.potential_credential = any(
                            kw in snippet_lower for kw in
                            ["password", "passwd", "secret", "token", "api_key", "apikey"]
                        )

                    result.snippets.append(snippet)

            except Exception as exc:
                result.error = str(exc)
                break

        return result

    def extract_credentials(self, snippet: CodeSnippet) -> List[str]:
        """Attempt to extract credentials from a code snippet.

        Args:
            snippet: Code snippet to analyze.

        Returns:
            List of potential credential strings found.
        """
        import re
        creds = []
        text = snippet.snippet

        # Common patterns: key=value, key: value, "key": "value"
        patterns = [
            r'(?:password|passwd|secret|token|api.?key)\s*[=:]\s*["\']?([^\s"\'<>{}\[\]]{4,64})',
        ]
        for pattern in patterns:
            for m in re.finditer(pattern, text, re.I):
                creds.append(m.group(1))

        return creds
