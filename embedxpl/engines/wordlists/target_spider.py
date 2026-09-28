"""
embedxpl.engines.wordlists/target_spider.py - Target Web Spider for Wordlist Generation.

Crawls a target URL and extracts words from HTML content, CSS, JS, and
embedded text to build a target-specific wordlist (cewler-style).

Native Python implementation using requests + BeautifulSoup.
No Scrapy dependency required.

Inspired by:
  - submodules/Wordlists/cewler/src/cewler/spider.py (Scrapy version)
  - submodules/Wordlists/CeWL/cewl.rb (Ruby CeWL - HTML/meta/PDF)

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import re
import time
import urllib.parse
from pathlib import Path
from typing import List, Optional, Set

__version__ = "1.0.0"

try:
    import requests  # type: ignore
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

try:
    from bs4 import BeautifulSoup  # type: ignore
    _BS4 = True
except ImportError:
    _BS4 = False

# Default word extraction patterns
_WORD_RE = re.compile(r"[a-zA-Z]{4,32}")  # only alpha words >= 4 chars
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}")


def _extract_words_from_html(html: str, min_len: int = 4) -> Set[str]:
    """Extract words from HTML text content.

    Args:
        html: Raw HTML string.
        min_len: Minimum word length.

    Returns:
        Set of extracted words (lowercase).
    """
    if not _BS4:
        return set(_WORD_RE.findall(html.lower()))

    soup = BeautifulSoup(html, "html.parser")

    # Remove script and style tags
    for tag in soup(["script", "style", "meta", "link"]):
        tag.decompose()

    text = soup.get_text(separator=" ")
    words = set()

    for word in re.findall(r"[a-zA-Z]{" + str(min_len) + r",32}", text):
        words.add(word.lower())

    # Also extract from alt, title, placeholder attributes
    for tag in soup.find_all(True):
        for attr in ["alt", "title", "placeholder", "value", "name", "id", "class"]:
            val = tag.get(attr, "")
            if isinstance(val, list):
                val = " ".join(val)
            if val:
                for w in re.findall(r"[a-zA-Z]{" + str(min_len) + r",32}", val):
                    words.add(w.lower())

    return words


def _get_links(html: str, base_url: str) -> List[str]:
    """Extract internal links from HTML."""
    links = []
    if not _BS4:
        return links

    soup = BeautifulSoup(html, "html.parser")
    base_parsed = urllib.parse.urlparse(base_url)

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith("#") or href.startswith("mailto:"):
            continue
        if href.startswith("/"):
            full = f"{base_parsed.scheme}://{base_parsed.netloc}{href}"
        elif href.startswith("http"):
            full = href
        else:
            full = urllib.parse.urljoin(base_url, href)

        # Only include same-domain links
        parsed = urllib.parse.urlparse(full)
        if parsed.netloc == base_parsed.netloc:
            links.append(full)

    return links


class TargetSpider:
    """Web spider for target-specific wordlist generation.

    Crawls a URL up to a given depth and extracts words
    from page text, attributes, and embedded content.

    Usage:
        spider = TargetSpider(min_len=5)
        words = spider.crawl("http://192.168.1.1/", depth=2)
    """

    def __init__(
        self,
        min_len: int = 4,
        timeout: float = 10.0,
        delay_sec: float = 0.5,
        user_agent: str = "Mozilla/5.0 (compatible; wordlist-gen/1.0)",
        max_pages: int = 30,
    ) -> None:
        self.min_len = min_len
        self.timeout = timeout
        self.delay_sec = delay_sec
        self.user_agent = user_agent
        self.max_pages = max_pages

    def crawl(
        self,
        url: str,
        depth: int = 2,
    ) -> List[str]:
        """Crawl URL and extract words.

        Args:
            url: Starting URL to crawl.
            depth: Maximum crawl depth (1 = only start URL).

        Returns:
            Sorted list of unique words.
        """
        if not _REQUESTS:
            raise ImportError("requests required: pip install requests")

        all_words: Set[str] = set()
        visited: Set[str] = set()
        queue = [(url, 0)]
        pages_crawled = 0

        headers = {"User-Agent": self.user_agent}

        while queue and pages_crawled < self.max_pages:
            current_url, current_depth = queue.pop(0)

            if current_url in visited:
                continue
            visited.add(current_url)

            try:
                resp = requests.get(current_url, headers=headers, timeout=self.timeout)
                if resp.status_code != 200:
                    continue

                content_type = resp.headers.get("content-type", "")
                if "html" not in content_type.lower():
                    continue

                words = _extract_words_from_html(resp.text, self.min_len)
                all_words.update(words)
                pages_crawled += 1

                # Queue child links if depth allows
                if current_depth < depth - 1:
                    for link in _get_links(resp.text, current_url):
                        if link not in visited:
                            queue.append((link, current_depth + 1))

            except Exception:
                pass

            if self.delay_sec > 0 and queue:
                time.sleep(self.delay_sec)

        # Filter by length and sort
        return sorted(
            w for w in all_words
            if self.min_len <= len(w) <= 32
        )

    def crawl_to_file(self, url: str, output_path: str, depth: int = 2) -> int:
        """Crawl URL and save words to file.

        Returns:
            Number of words saved.
        """
        words = self.crawl(url, depth=depth)
        Path(output_path).write_text("\n".join(words), encoding="utf-8")
        return len(words)


def spider_words(
    url: str,
    min_len: int = 4,
    max_words: int = 500,
    depth: int = 2,
    delay_sec: float = 0.5,
) -> List[str]:
    """Crawl *url* and return up to *max_words* unique words (cewl_mut helper).

    Args:
        url: Starting URL.
        min_len: Minimum word length.
        max_words: Cap on returned words (0 = unlimited).
        depth: Crawl depth passed to :class:`TargetSpider`.
        delay_sec: Delay between HTTP requests.

    Returns:
        List of unique words (sorted), at most *max_words* when max_words > 0.
    """
    spider = TargetSpider(
        min_len=min_len,
        delay_sec=delay_sec,
        max_pages=max(10, max_words // 10) if max_words else 30,
    )
    words = spider.crawl(url, depth=depth)
    if max_words and len(words) > max_words:
        return words[:max_words]
    return words
