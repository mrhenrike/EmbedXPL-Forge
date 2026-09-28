"""Async HTTP client using aiohttp with automatic fallback to requests.

Provides ``AsyncHTTPClient`` mixin that exploit modules can inherit
alongside ``HTTPClient`` for non-blocking HTTP I/O when running under
the ``AsyncScanEngine``.

For existing modules that inherit only ``HTTPClient``, the engine wraps
their synchronous ``http_request()`` in ``run_in_executor()`` transparently.

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

import logging
import ssl as _ssl
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

HTTP_TIMEOUT = 30.0


class AsyncHTTPClient:
    """Async HTTP mixin for exploit modules.

    Usage::

        from embedxpl.core.http.http_client import HTTPClient
        from embedxpl.core.http.async_client import AsyncHTTPClient

        class Exploit(HTTPClient, AsyncHTTPClient):
            async def async_check(self):
                resp = await self.async_http_request("GET", "/login.cgi")
                return resp is not None and resp.status == 200

    If ``aiohttp`` is not installed, ``async_http_request`` falls back to
    running the synchronous ``http_request()`` in the current thread
    (caller is expected to be inside ``run_in_executor`` already).
    """

    async def async_http_request(
        self,
        method: str,
        path: str,
        timeout: float = HTTP_TIMEOUT,
        verify_ssl: bool = False,
        allow_redirects: bool = False,
        **kwargs,
    ) -> Optional[Any]:
        """Non-blocking HTTP request via aiohttp.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, ...).
            path: URL path appended to ``http(s)://target:port``.
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify TLS certificates.
            allow_redirects: Follow redirects.
            **kwargs: Extra arguments forwarded to ``aiohttp.ClientSession.request``.

        Returns:
            ``aiohttp.ClientResponse`` on success, ``None`` on error.
        """
        if not HAS_AIOHTTP:
            logger.debug("aiohttp unavailable; falling back to sync http_request")
            return getattr(self, "http_request", lambda *a, **k: None)(method, path, **kwargs)

        scheme = "https" if getattr(self, "ssl", False) else "http"
        url = "{}://{}:{}{}".format(scheme, self.target, self.port, path)

        ssl_ctx: Any = False
        if scheme == "https" and not verify_ssl:
            ssl_ctx = _ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = _ssl.CERT_NONE

        client_timeout = aiohttp.ClientTimeout(total=timeout)

        try:
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                async with session.request(
                    method.upper(),
                    url,
                    ssl=ssl_ctx,
                    allow_redirects=allow_redirects,
                    **kwargs,
                ) as response:
                    await response.read()
                    return response
        except aiohttp.ClientError as err:
            logger.debug("aiohttp request failed for %s: %s", url, err)
            return None
        except Exception as err:
            logger.debug("Unexpected error in async_http_request for %s: %s", url, err)
            return None

    @staticmethod
    def is_async_available() -> bool:
        """Check if aiohttp is installed."""
        return HAS_AIOHTTP
