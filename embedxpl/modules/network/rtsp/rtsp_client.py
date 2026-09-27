"""Native Python RTSP client implementing RFC 2326.

Supports OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN methods with
Digest and Basic authentication, SDP parsing, and timeout handling.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
import base64
import hashlib
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RtspResponse:
    """Parsed RTSP response."""

    status_code: int
    status_text: str
    headers: dict[str, str]
    body: str
    raw: bytes


@dataclass
class SdpStream:
    """Parsed SDP media stream."""

    media_type: str
    port: int
    protocol: str
    formats: list[str]
    attributes: dict[str, str] = field(default_factory=dict)
    control: str = ""


@dataclass
class SdpInfo:
    """Parsed SDP session description."""

    session_name: str = ""
    streams: list[SdpStream] = field(default_factory=list)
    base_url: str = ""
    control: str = ""


class RTSPClient:
    """Native Python RTSP/1.0 client (RFC 2326).

    Supports OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN.
    Implements Basic and Digest authentication.

    Args:
        host: Target RTSP server hostname or IP.
        port: RTSP server port (default 554).
        timeout: Socket timeout in seconds (default 10).

    Example:
        client = RTSPClient("192.168.1.10", 554, timeout=5)
        resp = client.describe("/live")
        sdp = client.parse_sdp(resp.body)
    """

    _RTSP_VERSION = "RTSP/1.0"
    _BUFFER_SIZE = 65536
    _CSEQ_START = 1

    def __init__(self, host: str, port: int = 554, timeout: float = 10.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._cseq = self._CSEQ_START
        self._session_id: Optional[str] = None
        self._username: Optional[str] = None
        self._password: Optional[str] = None
        self._realm: Optional[str] = None
        self._nonce: Optional[str] = None
        self._auth_type: Optional[str] = None

    def connect(self) -> None:
        """Open TCP connection to the RTSP server.

        Raises:
            ConnectionError: If connection fails.
        """
        try:
            self._sock = socket.create_connection(
                (self.host, self.port), timeout=self.timeout
            )
        except Exception as exc:
            raise ConnectionError(f"Cannot connect to {self.host}:{self.port}: {exc}") from exc

    def disconnect(self) -> None:
        """Close the TCP connection."""
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            finally:
                self._sock = None

    def set_credentials(self, username: str, password: str) -> None:
        """Set credentials for Basic or Digest authentication.

        Args:
            username: RTSP username.
            password: RTSP password.
        """
        self._username = username
        self._password = password

    def options(self, path: str = "*") -> RtspResponse:
        """Send OPTIONS request.

        Args:
            path: Request URI path.

        Returns:
            Parsed RTSP response.
        """
        return self._send_request("OPTIONS", path)

    def describe(self, path: str) -> RtspResponse:
        """Send DESCRIBE request to retrieve SDP.

        Args:
            path: Stream URI path.

        Returns:
            Parsed RTSP response with SDP body.
        """
        return self._send_request("DESCRIBE", path, {"Accept": "application/sdp"})

    def setup(self, path: str, client_port_rtp: int = 5004, client_port_rtcp: int = 5005) -> RtspResponse:
        """Send SETUP request for a stream.

        Args:
            path: Stream control URI.
            client_port_rtp: Local RTP port.
            client_port_rtcp: Local RTCP port.

        Returns:
            Parsed RTSP response.
        """
        transport = f"RTP/AVP;unicast;client_port={client_port_rtp}-{client_port_rtcp}"
        extra = {"Transport": transport}
        if self._session_id:
            extra["Session"] = self._session_id
        resp = self._send_request("SETUP", path, extra)
        if resp.status_code == 200:
            self._session_id = resp.headers.get("Session", "").split(";")[0].strip()
        return resp

    def play(self, path: str) -> RtspResponse:
        """Send PLAY request to start streaming.

        Args:
            path: Stream URI.

        Returns:
            Parsed RTSP response.
        """
        extra: dict[str, str] = {"Range": "npt=0.000-"}
        if self._session_id:
            extra["Session"] = self._session_id
        return self._send_request("PLAY", path, extra)

    def teardown(self, path: str) -> RtspResponse:
        """Send TEARDOWN to end the session.

        Args:
            path: Stream URI.

        Returns:
            Parsed RTSP response.
        """
        extra: dict[str, str] = {}
        if self._session_id:
            extra["Session"] = self._session_id
        resp = self._send_request("TEARDOWN", path, extra)
        self._session_id = None
        return resp

    def parse_sdp(self, sdp_text: str) -> SdpInfo:
        """Parse SDP session description from DESCRIBE response body.

        Args:
            sdp_text: Raw SDP string from DESCRIBE response body.

        Returns:
            SdpInfo dataclass with session and stream details.
        """
        info = SdpInfo()
        current_stream: Optional[SdpStream] = None

        for line in sdp_text.splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            field_type, _, value = line.partition("=")

            if field_type == "s":
                info.session_name = value
            elif field_type == "m":
                if current_stream:
                    info.streams.append(current_stream)
                parts = value.split()
                if len(parts) >= 3:
                    current_stream = SdpStream(
                        media_type=parts[0],
                        port=int(parts[1].split("/")[0]),
                        protocol=parts[2],
                        formats=parts[3:],
                    )
            elif field_type == "a" and current_stream:
                if value.startswith("control:"):
                    current_stream.control = value[8:].strip()
                else:
                    attr_name, _, attr_val = value.partition(":")
                    current_stream.attributes[attr_name.strip()] = attr_val.strip()
            elif field_type == "a" and not current_stream:
                if value.startswith("control:"):
                    info.control = value[8:].strip()

        if current_stream:
            info.streams.append(current_stream)

        return info

    def _send_request(
        self,
        method: str,
        path: str,
        extra_headers: Optional[dict[str, str]] = None,
        retry_auth: bool = True,
    ) -> RtspResponse:
        """Build and send an RTSP request, handling 401 auth challenges.

        Args:
            method: RTSP method string.
            path: Request URI path.
            extra_headers: Additional headers to include.
            retry_auth: Whether to retry with auth on 401 response.

        Returns:
            Parsed RtspResponse.
        """
        if not self._sock:
            self.connect()

        uri = f"rtsp://{self.host}:{self.port}{path}"
        cseq = self._cseq
        self._cseq += 1

        headers: dict[str, str] = {
            "CSeq": str(cseq),
            "User-Agent": "EmbedXPL-Forge/2.0",
        }
        if extra_headers:
            headers.update(extra_headers)

        if self._auth_type and self._username and self._password:
            headers["Authorization"] = self._build_auth_header(method, uri)

        raw_request = self._build_raw_request(method, uri, headers)
        self._sock.sendall(raw_request)

        resp = self._recv_response()

        if resp.status_code == 401 and retry_auth and self._username:
            www_auth = resp.headers.get("WWW-Authenticate", "")
            self._parse_auth_challenge(www_auth)
            if self._auth_type:
                headers["Authorization"] = self._build_auth_header(method, uri)
                headers["CSeq"] = str(self._cseq)
                self._cseq += 1
                raw_request = self._build_raw_request(method, uri, headers)
                self._sock.sendall(raw_request)
                resp = self._recv_response()

        return resp

    def _build_raw_request(self, method: str, uri: str, headers: dict[str, str]) -> bytes:
        """Build a raw RTSP request string.

        Args:
            method: HTTP-like method.
            uri: Full request URI.
            headers: Headers dict.

        Returns:
            Encoded byte string of the RTSP request.
        """
        lines = [f"{method} {uri} {self._RTSP_VERSION}"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append("")
        return "\r\n".join(lines).encode("utf-8")

    def _recv_response(self) -> RtspResponse:
        """Receive and parse an RTSP response from the socket.

        Returns:
            Parsed RtspResponse object.
        """
        data = b""
        self._sock.settimeout(self.timeout)
        deadline = time.monotonic() + self.timeout

        while b"\r\n\r\n" not in data:
            if time.monotonic() > deadline:
                break
            try:
                chunk = self._sock.recv(self._BUFFER_SIZE)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break

        header_part, _, body_part = data.partition(b"\r\n\r\n")
        header_text = header_part.decode("utf-8", errors="replace")
        lines = header_text.splitlines()

        status_code = 0
        status_text = ""
        if lines:
            parts = lines[0].split(None, 2)
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass
                status_text = parts[2] if len(parts) > 2 else ""

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ": " in line:
                k, _, v = line.partition(": ")
                headers[k.strip()] = v.strip()

        content_length = int(headers.get("Content-Length", 0))
        body = body_part[:content_length].decode("utf-8", errors="replace")

        return RtspResponse(
            status_code=status_code,
            status_text=status_text,
            headers=headers,
            body=body,
            raw=data,
        )

    def _parse_auth_challenge(self, www_auth: str) -> None:
        """Parse WWW-Authenticate header and set auth state.

        Args:
            www_auth: Value of WWW-Authenticate response header.
        """
        if www_auth.lower().startswith("digest"):
            self._auth_type = "digest"
            realm_m = re.search(r'realm="([^"]+)"', www_auth)
            nonce_m = re.search(r'nonce="([^"]+)"', www_auth)
            self._realm = realm_m.group(1) if realm_m else ""
            self._nonce = nonce_m.group(1) if nonce_m else ""
        elif www_auth.lower().startswith("basic"):
            self._auth_type = "basic"
            realm_m = re.search(r'realm="([^"]+)"', www_auth)
            self._realm = realm_m.group(1) if realm_m else ""

    def _build_auth_header(self, method: str, uri: str) -> str:
        """Build the Authorization header value.

        Args:
            method: RTSP method string.
            uri: Full request URI.

        Returns:
            Authorization header value string.
        """
        if self._auth_type == "basic":
            cred = base64.b64encode(
                f"{self._username}:{self._password}".encode()
            ).decode()
            return f"Basic {cred}"

        if self._auth_type == "digest":
            ha1 = hashlib.md5(  # noqa: S324
                f"{self._username}:{self._realm}:{self._password}".encode()
            ).hexdigest()
            ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()  # noqa: S324
            nc = "00000001"
            cnonce = hashlib.md5(str(time.monotonic()).encode()).hexdigest()[:8]  # noqa: S324
            response_hash = hashlib.md5(  # noqa: S324
                f"{ha1}:{self._nonce}:{nc}:{cnonce}:auth:{ha2}".encode()
            ).hexdigest()
            return (
                f'Digest username="{self._username}", '
                f'realm="{self._realm}", '
                f'nonce="{self._nonce}", '
                f'uri="{uri}", '
                f'qop=auth, nc={nc}, cnonce="{cnonce}", '
                f'response="{response_hash}"'
            )

        return ""

    def __enter__(self) -> "RTSPClient":
        self.connect()
        return self

    def __exit__(self, *args: object) -> None:
        self.disconnect()
