# Author: André Henrique (LinkedIn/X: @mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""EmbedXPL-Forge — RTSP Protocol Client.

Low-level raw socket RTSP client ported and extended from cameradar.
Implements full RTSP/1.0 per RFC 2326 with:
  - OPTIONS request (device discovery + banner)
  - DESCRIBE request (stream info + SDP retrieval)
  - HTTP Basic and HTTP Digest authentication parsing
  - RTSPS (RTSP over TLS) support
  - Status code–based attack decision logic matching cameradar

References:
  - cameradar: https://github.com/ullaakut/cameradar (MIT, Ullaakut)
  - RFC 2326: https://tools.ietf.org/html/rfc2326

Author: André Henrique (@mrhenrike) | União Geek
Version: 1.0.0
"""

from __future__ import annotations

import base64
import hashlib
import re
import socket
import ssl
import time
from typing import Optional, Tuple

from embedxpl.core.rtsp.models import AuthType, RTSPStream


# RTSP status codes (RFC 2326)
RTSP_OK = 200
RTSP_UNAUTHORIZED = 401
RTSP_FORBIDDEN = 403
RTSP_NOT_FOUND = 404
RTSP_METHOD_NOT_VALID = 455
RTSP_SERVICE_UNAVAILABLE = 503


def _build_options_request(host: str, port: int) -> str:
    return (
        f"OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\n"
        f"CSeq: 1\r\n"
        f"User-Agent: EmbedXPL-Forge\r\n"
        f"\r\n"
    )


def _build_describe_request(
    host: str,
    port: int,
    route: str,
    cseq: int = 2,
    username: str = "",
    password: str = "",
    auth_type: AuthType = AuthType.NONE,
    digest_realm: str = "",
    digest_nonce: str = "",
    scheme: str = "rtsp",
) -> str:
    url = f"{scheme}://{host}:{port}/{route.lstrip('/')}"
    headers = (
        f"DESCRIBE {url} RTSP/1.0\r\n"
        f"CSeq: {cseq}\r\n"
        f"User-Agent: EmbedXPL-Forge\r\n"
        f"Accept: application/sdp\r\n"
    )
    if auth_type == AuthType.BASIC and username:
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers += f"Authorization: Basic {creds}\r\n"
    elif auth_type == AuthType.DIGEST and username and digest_realm and digest_nonce:
        ha1 = hashlib.md5(f"{username}:{digest_realm}:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"DESCRIBE:{url}".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{digest_nonce}:{ha2}".encode()).hexdigest()
        headers += (
            f'Authorization: Digest username="{username}", realm="{digest_realm}", '
            f'nonce="{digest_nonce}", uri="{url}", response="{response}"\r\n'
        )
    headers += "\r\n"
    return headers


def _parse_rtsp_response(raw: bytes) -> Tuple[int, dict, str]:
    """Parse an RTSP/1.0 response.

    Args:
        raw: Raw bytes received from socket.

    Returns:
        Tuple of (status_code, headers_dict, body_str).
    """
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return 0, {}, ""

    parts = text.split("\r\n\r\n", 1)
    header_block = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    lines = header_block.split("\r\n")
    status_code = 0
    if lines:
        m = re.match(r"RTSP/1\.\d+\s+(\d+)", lines[0])
        if m:
            status_code = int(m.group(1))

    headers: dict = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, val = line.partition(":")
            headers[key.strip().lower()] = val.strip()

    return status_code, headers, body


def _parse_digest_challenge(www_auth: str) -> Tuple[str, str]:
    """Extract realm and nonce from a Digest WWW-Authenticate header."""
    realm_m = re.search(r'realm="([^"]*)"', www_auth, re.IGNORECASE)
    nonce_m = re.search(r'nonce="([^"]*)"', www_auth, re.IGNORECASE)
    realm = realm_m.group(1) if realm_m else ""
    nonce = nonce_m.group(1) if nonce_m else ""
    return realm, nonce


def _detect_auth_type_from_header(www_auth: str) -> AuthType:
    """Determine auth type from WWW-Authenticate header value."""
    if not www_auth:
        return AuthType.NONE
    lower = www_auth.lower()
    if "digest" in lower:
        return AuthType.DIGEST
    if "basic" in lower:
        return AuthType.BASIC
    return AuthType.UNKNOWN


class RTSPOverHTTPTunnel:
    """RTSP-over-HTTP tunnel — pure Python implementation.

    Implements RFC 2326 Appendix C (RTSP-over-HTTP tunneling).
    Used when cameras sit behind HTTP proxies or NAT that only pass HTTP.

    Cameradar uses gortsplib's TunnelHTTP mode. This is our pure-Python
    equivalent, built from scratch.

    The tunnel protocol:
      1. Client sends HTTP GET to establish response channel (server → client).
      2. Client sends HTTP POST to establish request channel (client → server).
      3. RTSP messages are base64-encoded and sent via POST body.
      4. RTSP responses arrive via GET response body (chunked/streaming).

    Author: André Henrique (@mrhenrike) | União Geek
    Version: 1.0.0
    """

    def __init__(self, host: str, port: int, timeout: float = 5.0,
                 use_tls: bool = False) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.use_tls = use_tls
        self._session_cookie = base64.b64encode(
            __import__("os").urandom(12)
        ).decode("ascii").rstrip("=")

    def _wrap(self, sock: socket.socket) -> socket.socket:
        if self.use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx.wrap_socket(sock, server_hostname=self.host)
        return sock

    def send_rtsp_via_http(self, rtsp_request: str) -> Optional[bytes]:
        """Send an RTSP request through HTTP POST tunnel.

        Args:
            rtsp_request: Raw RTSP/1.0 request string.

        Returns:
            Raw RTSP response bytes (decoded from base64), or None on error.
        """
        encoded = base64.b64encode(rtsp_request.encode("utf-8")).decode("ascii")
        http_post = (
            f"POST /rtsp-tunnel HTTP/1.0\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Content-Type: application/x-rtsp-tunnelled\r\n"
            f"Pragma: no-cache\r\n"
            f"Cache-Control: no-cache\r\n"
            f"Content-Length: {len(encoded)}\r\n"
            f"x-sessioncookie: {self._session_cookie}\r\n"
            f"\r\n"
            f"{encoded}"
        )
        try:
            sock = self._wrap(
                socket.create_connection((self.host, self.port), timeout=self.timeout)
            )
            sock.sendall(http_post.encode("utf-8"))
            data = b""
            sock.settimeout(self.timeout)
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"\r\n\r\n" in data:
                        break
                except socket.timeout:
                    break
            sock.close()
            # Strip HTTP headers; remaining body is base64 RTSP response
            if b"\r\n\r\n" in data:
                body = data.split(b"\r\n\r\n", 1)[1]
                try:
                    return base64.b64decode(body)
                except Exception:
                    return body  # return raw if not base64
        except Exception:
            return None
        return None

    def establish_get_channel(self) -> Optional[socket.socket]:
        """Establish the HTTP GET channel for server→client RTSP responses."""
        http_get = (
            f"GET /rtsp-tunnel HTTP/1.0\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"x-sessioncookie: {self._session_cookie}\r\n"
            f"Accept: application/x-rtsp-tunnelled\r\n"
            f"Pragma: no-cache\r\n"
            f"Cache-Control: no-cache\r\n"
            f"\r\n"
        )
        try:
            sock = self._wrap(
                socket.create_connection((self.host, self.port), timeout=self.timeout)
            )
            sock.sendall(http_get.encode("utf-8"))
            return sock
        except Exception:
            return None


class RTSPClient:
    """Low-level RTSP socket client.

    Ported from cameradar's internal/attack/rtsp.go with Python extensions.
    Supports plain RTSP, RTSPS (TLS), Basic auth, Digest auth,
    and **RTSP-over-HTTP tunneling** (pure Python — replaces gortsplib TunnelHTTP).

    Transport modes
    ---------------
    ``rtsp``    — Plain RTSP/1.0 over TCP (default, port 554)
    ``rtsps``   — RTSP over TLS (port 443 or 8443)
    ``http``    — RTSP-over-HTTP tunnel (port 80 or 8080)
    ``https``   — RTSP-over-HTTPS tunnel (port 443 or 8443)

    Author: André Henrique (@mrhenrike) | União Geek
    Version: 1.1.0
    """

    def __init__(self, host: str, port: int = 554, timeout: float = 5.0,
                 use_tls: bool = False, tunnel_http: bool = False) -> None:
        """Initialise the RTSP client.

        Args:
            host: Target IP or hostname.
            port: RTSP port number.
            timeout: Socket timeout in seconds.
            use_tls: If True, wrap socket with TLS (for RTSPS).
            tunnel_http: If True, use RTSP-over-HTTP tunnel mode.
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.use_tls = use_tls
        self.tunnel_http = tunnel_http
        self._cseq = 0
        self._http_tunnel: Optional[RTSPOverHTTPTunnel] = None
        if tunnel_http:
            self._http_tunnel = RTSPOverHTTPTunnel(
                host, port, timeout=timeout, use_tls=use_tls
            )

    @classmethod
    def from_scheme(cls, host: str, port: int, scheme: str,
                    timeout: float = 5.0) -> "RTSPClient":
        """Create an RTSPClient configured for a specific transport scheme.

        Args:
            host: Target IP or hostname.
            port: RTSP port.
            scheme: One of 'rtsp', 'rtsps', 'http', 'https'.
            timeout: Socket timeout.

        Returns:
            Configured RTSPClient instance.

        Example::

            client = RTSPClient.from_scheme("192.168.1.100", 8080, "http")
        """
        scheme = (scheme or "rtsp").lower()
        if scheme == "rtsp":
            return cls(host, port, timeout=timeout)
        if scheme == "rtsps":
            return cls(host, port, timeout=timeout, use_tls=True)
        if scheme == "http":
            return cls(host, port, timeout=timeout, tunnel_http=True)
        if scheme == "https":
            return cls(host, port, timeout=timeout, use_tls=True, tunnel_http=True)
        return cls(host, port, timeout=timeout)

    def _connect(self) -> socket.socket:
        """Open a TCP connection to the RTSP server."""
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_tls and not self.tunnel_http:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        return sock

    def _send_recv(self, request: str, sock: Optional[socket.socket] = None) -> bytes:
        """Send an RTSP request and read the full response.

        Automatically routes through HTTP tunnel if ``tunnel_http=True``.
        """
        # HTTP tunnel path
        if self.tunnel_http and self._http_tunnel:
            result = self._http_tunnel.send_rtsp_via_http(request)
            return result if result else b""

        close_after = sock is None
        if sock is None:
            sock = self._connect()
        try:
            sock.sendall(request.encode("utf-8"))
            data = b""
            sock.settimeout(self.timeout)
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    # Stop reading once we have the full RTSP response
                    # (either headers-only for non-200 or headers+body for 200)
                    if b"\r\n\r\n" in data:
                        # For DESCRIBE 200, read Content-Length bytes of body
                        _, headers, _ = _parse_rtsp_response(data)
                        cl = int(headers.get("content-length", 0))
                        header_end = data.find(b"\r\n\r\n") + 4
                        if len(data) - header_end >= cl:
                            break
                except socket.timeout:
                    break
        except Exception:
            pass
        finally:
            if close_after:
                try:
                    sock.close()
                except Exception:
                    pass
        return data

    def options(self) -> Tuple[int, dict, str]:
        """Send RTSP OPTIONS request.

        Returns:
            Tuple of (status_code, headers, body).
        """
        self._cseq += 1
        req = _build_options_request(self.host, self.port)
        raw = self._send_recv(req)
        return _parse_rtsp_response(raw)

    def describe(
        self,
        route: str = "",
        username: str = "",
        password: str = "",
        auth_type: AuthType = AuthType.NONE,
        digest_realm: str = "",
        digest_nonce: str = "",
        scheme: str = "rtsp",
    ) -> Tuple[int, dict, str]:
        """Send RTSP DESCRIBE request.

        Args:
            route: Stream route path (e.g. '/live.sdp').
            username: Username for authentication.
            password: Password for authentication.
            auth_type: Authentication method to use.
            digest_realm: Digest realm (required for Digest auth).
            digest_nonce: Digest nonce (required for Digest auth).
            scheme: URL scheme (rtsp/rtsps).

        Returns:
            Tuple of (status_code, headers, sdp_body).
        """
        self._cseq += 1
        req = _build_describe_request(
            host=self.host,
            port=self.port,
            route=route,
            cseq=self._cseq,
            username=username,
            password=password,
            auth_type=auth_type,
            digest_realm=digest_realm,
            digest_nonce=digest_nonce,
            scheme=scheme,
        )
        raw = self._send_recv(req)
        return _parse_rtsp_response(raw)

    def probe_auth_type(self, route: str = "") -> Tuple[AuthType, str, str]:
        """Probe a stream to detect authentication type.

        Mirrors cameradar's probeDescribeHeaders — sends DESCRIBE without auth
        and parses the WWW-Authenticate header from 401 response.

        Args:
            route: Stream route to probe.

        Returns:
            Tuple of (auth_type, digest_realm, digest_nonce).
        """
        status, headers, _ = self.describe(route=route)
        www_auth = headers.get("www-authenticate", "")

        if status == RTSP_OK:
            return AuthType.NONE, "", ""
        if status == RTSP_UNAUTHORIZED:
            auth_type = _detect_auth_type_from_header(www_auth)
            realm, nonce = _parse_digest_challenge(www_auth)
            return auth_type, realm, nonce
        return AuthType.UNKNOWN, "", ""

    def test_route(self, route: str) -> bool:
        """Test if a route is accessible (200, 401, or 403 = route exists).

        This mirrors cameradar's routeAttack logic:
        - 200 = accessible (no auth needed)
        - 401 = route exists but needs credentials
        - 403 = route exists but forbidden
        - 404 = route not found
        - other = possible

        Args:
            route: Stream route to test.

        Returns:
            True if route appears to exist on the server.
        """
        status, _, _ = self.describe(route=route)
        return status in (RTSP_OK, RTSP_UNAUTHORIZED, RTSP_FORBIDDEN)

    def test_credentials(
        self,
        route: str,
        username: str,
        password: str,
        auth_type: AuthType,
        digest_realm: str = "",
        digest_nonce: str = "",
    ) -> bool:
        """Test a username/password combination for a stream.

        Mirrors cameradar's credAttack logic:
        - 200 = credentials valid
        - 404 = credentials valid (route not found but auth accepted)

        Args:
            route: Stream route.
            username: Username to test.
            password: Password to test.
            auth_type: Authentication method to use.
            digest_realm: Digest realm.
            digest_nonce: Digest nonce.

        Returns:
            True if credentials are valid.
        """
        status, _, _ = self.describe(
            route=route,
            username=username,
            password=password,
            auth_type=auth_type,
            digest_realm=digest_realm,
            digest_nonce=digest_nonce,
        )
        return status in (RTSP_OK, RTSP_NOT_FOUND)

    def banner(self) -> str:
        """Return Server header from OPTIONS response (device fingerprint)."""
        try:
            _, headers, _ = self.options()
            return headers.get("server", "")
        except Exception:
            return ""

    def is_rtsp(self) -> bool:
        """Return True if the target responds to RTSP OPTIONS."""
        try:
            status, _, _ = self.options()
            return status in (RTSP_OK, RTSP_UNAUTHORIZED, RTSP_FORBIDDEN,
                              RTSP_METHOD_NOT_VALID, 501)
        except Exception:
            return False
