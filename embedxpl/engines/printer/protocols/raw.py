#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RAW Protocol Support for PrinterXPL-Forge
======================================
Direct TCP/IP printing on port 9100 (AppSocket / JetDirect).

Supports IPv4 and IPv6 transparently.
"""

# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from __future__ import annotations

import socket
import time
from typing import Optional


def _resolve_address(host: str) -> tuple:
    """
    Resolve *host* to a (family, addr) pair.

    Handles:
      - Plain IPv4 addresses / hostnames  → AF_INET
      - IPv6 literals (with or without [])→ AF_INET6
      - Dual-stack hostnames              → prefer IPv4, fall back to IPv6
    """
    # Strip brackets from IPv6 literals like [::1]
    host_clean = host.strip('[]')

    # Attempt getaddrinfo — returns list of (family, type, proto, canonname, sockaddr)
    try:
        infos = socket.getaddrinfo(host_clean, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ConnectionError(f"Cannot resolve host '{host}': {exc}") from exc

    if not infos:
        raise ConnectionError(f"No address found for host '{host}'")

    # Prefer IPv4 to avoid surprises on single-stack networks
    for info in infos:
        if info[0] == socket.AF_INET:
            return socket.AF_INET, info[4][0]

    # Fall back to first result (IPv6 or whatever is available)
    info = infos[0]
    return info[0], info[4][0]


class RAWProtocol:
    """
    RAW / AppSocket / JetDirect protocol implementation (default port 9100).

    This is the most common protocol for sending PJL, PostScript and PCL
    payloads directly to a network printer.

    Supports both IPv4 and IPv6.
    """

    DEFAULT_PORT = 9100

    def __init__(self, host: str, port: Optional[int] = None, timeout: float = 30.0):
        self.host    = host
        self.port    = port or self.DEFAULT_PORT
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._family: int = socket.AF_INET

    # ------------------------------------------------------------------
    def connect(self) -> bool:
        """
        Open a TCP connection to the printer.

        Returns True on success, False on failure.
        Auto-selects IPv4 or IPv6 based on host resolution.
        """
        try:
            family, addr = _resolve_address(self.host)
            self._family = family
            self.sock = socket.socket(family, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((addr, self.port))
            return True
        except Exception:
            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None
            return False

    def send(self, data: bytes | str) -> None:
        """Send raw bytes (or a string which will be UTF-8 encoded)."""
        if not self.sock:
            raise ConnectionError("Not connected — call connect() first")
        if isinstance(data, str):
            data = data.encode('utf-8', errors='replace')
        self.sock.sendall(data)

    def recv(self, size: int = 4096, timeout: Optional[float] = None) -> bytes:
        """
        Receive up to *size* bytes.

        *timeout* overrides the socket timeout for this single call.
        """
        if not self.sock:
            raise ConnectionError("Not connected")
        if timeout is not None:
            old = self.sock.gettimeout()
            self.sock.settimeout(timeout)
        try:
            return self.sock.recv(size)
        finally:
            if timeout is not None:
                self.sock.settimeout(old)

    def recv_all(self, timeout: float = 2.0) -> bytes:
        """
        Drain all available data with a short read-loop until the printer
        stops sending (identified by a read timeout).
        """
        buf = b''
        self.sock.settimeout(timeout)
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except (socket.timeout, BlockingIOError):
            pass
        return buf

    def close(self) -> None:
        """Close the underlying socket."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    @property
    def is_connected(self) -> bool:
        """Return True if the socket is currently open."""
        return self.sock is not None

    @property
    def is_ipv6(self) -> bool:
        """Return True if the active connection uses IPv6."""
        return self._family == socket.AF_INET6

    # ------------------------------------------------------------------
    def __enter__(self) -> 'RAWProtocol':
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def __repr__(self) -> str:
        proto = 'IPv6' if self.is_ipv6 else 'IPv4'
        state = 'connected' if self.is_connected else 'disconnected'
        return f"<RAWProtocol {self.host}:{self.port} [{proto}] {state}>"


# Backward-compatibility alias
RawProtocol = RAWProtocol
