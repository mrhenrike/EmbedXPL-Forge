# Author: André Henrique (LinkedIn/X: @mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""EmbedXPL-Forge — RTSP Stream Data Models.

Ported and extended from cameradar (https://github.com/ullaakut/cameradar, MIT).

Author: André Henrique (@mrhenrike) | União Geek
Version: 1.0.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional


class AuthType(IntEnum):
    """RTSP authentication method detected on a stream."""
    UNKNOWN = 0
    NONE = 1
    BASIC = 2
    DIGEST = 3


@dataclass
class RTSPStream:
    """Represents a discovered RTSP camera stream.

    Mirrors the cameradar Stream struct with Python extensions.

    Attributes:
        address: Target IP address.
        port: RTSP port number.
        device: Device model/product string from nmap discovery.
        username: Discovered username (empty if not found).
        password: Discovered password (empty if not found).
        routes: List of valid RTSP routes found.
        scheme: Protocol scheme (rtsp, rtsps, http, https).
        auth_type: Authentication method detected.
        route_found: Whether a valid route was found.
        credentials_found: Whether valid credentials were found.
        available: Whether the stream is fully accessible.
        server_banner: Server header from RTSP OPTIONS/DESCRIBE response.
        sdp: Session Description Protocol data from DESCRIBE.
    """

    address: str
    port: int = 554
    device: str = ""
    username: str = ""
    password: str = ""
    routes: List[str] = field(default_factory=list)
    scheme: str = "rtsp"
    auth_type: AuthType = AuthType.UNKNOWN
    route_found: bool = False
    credentials_found: bool = False
    available: bool = False
    server_banner: str = ""
    sdp: str = ""

    def route(self) -> str:
        """Return the primary discovered route, or empty string."""
        return self.routes[0] if self.routes else ""

    def url(self) -> str:
        """Build the full RTSP URL for this stream."""
        scheme = self.scheme or "rtsp"
        route = "/" + self.route().lstrip("/") if self.route() else "/"
        if self.username or self.password:
            import urllib.parse
            user = urllib.parse.quote(self.username, safe="")
            pwd = urllib.parse.quote(self.password, safe="")
            return f"{scheme}://{user}:{pwd}@{self.address}:{self.port}{route}"
        return f"{scheme}://{self.address}:{self.port}{route}"

    def url_no_creds(self) -> str:
        """Build URL without credentials."""
        scheme = self.scheme or "rtsp"
        route = "/" + self.route().lstrip("/") if self.route() else "/"
        return f"{scheme}://{self.address}:{self.port}{route}"

    def to_m3u_entry(self) -> str:
        """Generate M3U playlist entry for this stream."""
        device_label = self.device or f"{self.address}:{self.port}"
        return f"#EXTINF:-1,{device_label}\n{self.url()}"

    def summary(self) -> str:
        """Return a human-readable summary."""
        auth_str = self.auth_type.name
        status = "ACCESSIBLE" if self.available else ("ROUTE_FOUND" if self.route_found else "NOT_ACCESSIBLE")
        return (
            f"[{status}] {self.address}:{self.port} "
            f"device={self.device!r} auth={auth_str} "
            f"creds={self.username!r}:{self.password!r} "
            f"route={self.route()!r}"
        )
