#!/usr/bin/env python3
"""
CLI do NVR (Longse-style API v6):
- login-check: weryfikuje logowanie API
- list-records: pobiera listę nagrań dla kanału/dnia
- analyze: skan kanałów/dni + podgląd funkcji API
- check-webui-mode: diagnostyka LOCALSERVER vs H264/H265 fallback
- dump-cam-creds: skan kamer + odszyfrowanie user/pass (search-camera)
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import re
import socket
import sys
from dataclasses import dataclass
from typing import Any

import requests


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("latin1")).hexdigest()


def hex_to_str(hex_text: str) -> str:
    hex_text = hex_text.strip().lower()
    if hex_text.startswith("0x"):
        hex_text = hex_text[2:]
    return bytes.fromhex(hex_text).decode("latin1")


def now_ts_pair() -> tuple[str, str]:
    now = dt.datetime.now()
    raw = now.strftime("%Y-%m-%dT%H:%M:%S")
    b64 = base64.b64encode(raw.encode("ascii")).decode("ascii")
    return b64, raw


def build_password_hash(
    username: str, password: str, salt: str, challenge: str, iterations: int
) -> tuple[str, str]:
    # loginRoundTwo in JS
    b64_datetime, raw_datetime = now_ts_pair()
    step1 = sha256_hex(username + salt + b64_datetime + password)
    # roundThree in JS
    step2 = sha256_hex(hex_to_str(step1) + challenge)
    # roundFour in JS
    out = step2
    for _ in range(int(iterations)):
        out = sha256_hex(hex_to_str(out))
    return out, raw_datetime


def build_channel_crypto_key(username: str, salt: str, iterations: int) -> tuple[str, str]:
    # getEncryptionRequest in JS
    b64_datetime, raw_datetime = now_ts_pair()
    step1 = sha256_hex(username + salt + b64_datetime)  # roundTwo (without password)
    step2 = sha256_hex(hex_to_str(step1) + "World!@##$")  # reverseRoundThree
    out = step2
    for _ in range(int(iterations)):
        out = sha256_hex(hex_to_str(out))  # roundFour
    # roundFive
    key16 = "".join(list(out)[i + 1] for i in range(21, 37))
    return raw_datetime, key16


def aes128_cbc_zero_unpad_decrypt_b64(cipher_b64: str, key16: str) -> str:
    from Crypto.Cipher import AES  # optional dependency, imported lazily

    iv = b"afe13ds34cdjk08c"
    raw = base64.b64decode(cipher_b64)
    dec = AES.new(key16.encode("utf-8"), AES.MODE_CBC, iv).decrypt(raw)
    return dec.rstrip(b"\x00").decode("utf-8", errors="ignore")


def epoch_range_for_day(day: str) -> tuple[int, int]:
    d = dt.datetime.strptime(day, "%Y-%m-%d").date()
    start = dt.datetime(d.year, d.month, d.day, 0, 0, 0, tzinfo=dt.timezone.utc)
    end = dt.datetime(d.year, d.month, d.day, 23, 59, 59, tzinfo=dt.timezone.utc)
    return int(start.timestamp()), int(end.timestamp())


def fmt_epoch(v: Any) -> str:
    try:
        ts = int(v)
        return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except Exception:
        return str(v)


@dataclass
class NvrClient:
    host: str
    timeout: int = 8

    def __post_init__(self) -> None:
        self.base = f"http://{self.host}"
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"})
        self.s.headers.update(
            {
                "Api-Version": "v4.0.0",
                "Content-Type": "application/json",
            }
        )

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        h = {"Timestamp": dt.datetime.now().isoformat(timespec="seconds")}
        r = self.s.post(
            self.base + path, data=json.dumps(payload), timeout=self.timeout, headers=h
        )
        r.raise_for_status()
        return r.json()

    def action(self, path: str, action: str = "get", data: Any | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"action": action}
        if data is not None:
            payload["data"] = data
        return self._post(path, payload)

    def login(self, username: str, password: str) -> dict[str, Any]:
        cap = self._post(
            "/api/session/login-capabilities",
            {"action": "get", "data": {"username": username}},
        )
        if int(cap.get("code", -1)) != 0:
            raise RuntimeError(
                f"login-capabilities failed: code={cap.get('code')} msg={cap.get('msg')}"
            )
        data = cap.get("data", {}) or {}
        param = data.get("param", {}) or {}
        enc_types = data.get("encryptionType") or ["sha256-1"]
        enc = enc_types[0]
        session_id = data.get("sessionID")
        if not session_id:
            raise RuntimeError("Brak sessionID w login-capabilities")
        hashed, raw_datetime = build_password_hash(
            username=username,
            password=password,
            salt=str(param.get("salt", "")),
            challenge=str(param.get("challenge", "")),
            iterations=int(param.get("iterations", 0)),
        )
        payload = {
            "action": "set",
            "data": {
                "username": username,
                "loginEncryptionType": enc,
                "password": hashed,
                "sessionID": session_id,
                "datetime": raw_datetime,
            },
        }
        out = self._post("/api/session/login", payload)
        if int(out.get("code", -1)) != 0:
            raise RuntimeError(f"login failed: code={out.get('code')} msg={out.get('msg')}")
        # Niektóre NVR-y ustawiają Set-Cookie z path=/api/session, co nie działa
        # dla /api/record/*; wymuszamy to samo cookie na path=/.
        data_out = out.get("data") or {}
        cookie_pair = data_out.get("cookie")
        if isinstance(cookie_pair, str) and "=" in cookie_pair:
            k, v = cookie_pair.split("=", 1)
            self.s.cookies.set(k.strip(), v.strip(), path="/")
        return out

    def query_days(self, channel: int, stream: int, file_type: int, start: int, end: int) -> list[int]:
        out = self._post(
            "/api/record/query-days",
            {
                "action": "get",
                "data": {
                    "channel": channel,
                    "streamNo": stream,
                    "fileType": file_type,
                    "startTime": str(start),
                    "endTime": str(end),
                },
            },
        )
        if int(out.get("code", -1)) != 0:
            raise RuntimeError(
                f"query-days failed: code={out.get('code')} msg={out.get('msg')}"
            )
        return list((out.get("data") or {}).get("days") or [])

    def list_records(
        self,
        channel: int,
        stream: int,
        file_type: int,
        start: int,
        end: int,
        page_items: int,
    ) -> list[dict[str, Any]]:
        out = self._post(
            "/api/record/record-list",
            {
                "action": "get",
                "data": {
                    "channel": channel,
                    "streamNo": stream,
                    "fileType": file_type,
                    "pageIndex": 0,
                    "pageItems": page_items,
                    "startTime": str(start),
                    "endTime": str(end),
                },
            },
        )
        if int(out.get("code", -1)) != 0:
            raise RuntimeError(
                f"record-list failed: code={out.get('code')} msg={out.get('msg')}"
            )
        data = out.get("data") or {}
        return list(data.get("itemList") or [])

    def get_api_methods(self) -> list[str]:
        r = self.s.get(self.base + "/statics/js/api.js", timeout=self.timeout)
        r.raise_for_status()
        txt = r.text
        out = set()
        for m in re.finditer(r'paramConfig\("([^"]+)"', txt):
            out.add(m.group(1))
        for m in re.finditer(r'callHttp\("(/api/[^"]+)"', txt):
            out.add(m.group(1).removeprefix("/api/"))
        return sorted(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="NVR API CLI (Linux, bez wtyczki)")
    p.add_argument("--host", default="192.168.9.31", help="IP/host NVR")
    p.add_argument("-u", "--user", required=True, help="Użytkownik NVR")
    p.add_argument("-p", "--password", required=True, help="Hasło NVR")
    p.add_argument("--timeout", type=int, default=8, help="Timeout HTTP (s)")

    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("login-check", help="Sprawdza logowanie API")

    l = sub.add_parser("list-records", help="Lista nagrań dla dnia")
    l.add_argument("--channel", type=int, default=0, help="Kanał (0-based)")
    l.add_argument("--stream", type=int, default=0, help="Strumień (0=main,1=sub)")
    l.add_argument(
        "--file-type",
        type=int,
        default=99,
        help="Typ: 99=all, 5=timing, 2=motion, 46=alarm, 45=smart",
    )
    l.add_argument("--day", required=True, help="Dzień YYYY-MM-DD (UTC)")
    l.add_argument("--page-items", type=int, default=4000, help="Ile pozycji max")
    l.add_argument(
        "--json", action="store_true", help="Wypisz pełny JSON rekordów (surowo)"
    )

    a = sub.add_parser("analyze", help="Analyzer: kanały/dni/funkcje API")
    a.add_argument("--channels-max", type=int, default=16, help="Skan kanałów 0..N-1")
    a.add_argument("--months-back", type=int, default=2, help="Ile miesięcy wstecz skanować")
    a.add_argument("--stream", type=int, default=0, help="Strumień do skanu dni")
    a.add_argument(
        "--file-type",
        type=int,
        default=99,
        help="Typ nagrań do skanu dni (99=all)",
    )

    w = sub.add_parser("check-webui-mode", help="Diagnoza: LOCALSERVER czy fallback H264/H265")
    w.add_argument(
        "--port-range",
        default="",
        help="Ręczny zakres portów middleware, np. 53688-53697 (domyślnie auto z variable.js)",
    )
    w.add_argument("--localhost", default="127.0.0.1", help="Host lokalny do testu portów middleware")
    w.add_argument("--connect-timeout-ms", type=int, default=120, help="Timeout connect TCP na port")
    w.add_argument("--json", action="store_true", help="Wynik jako JSON")

    k = sub.add_parser(
        "dump-cam-creds",
        help="Skan /api/channel/search-camera i odszyfrowanie user/pass",
    )
    k.add_argument("--json", action="store_true", help="Wynik jako JSON")

    return p


def month_range_utc(year: int, month: int) -> tuple[int, int]:
    start = dt.datetime(year, month, 1, 0, 0, 0, tzinfo=dt.timezone.utc)
    if month == 12:
        n_year, n_month = year + 1, 1
    else:
        n_year, n_month = year, month + 1
    end = dt.datetime(n_year, n_month, 1, 0, 0, 0, tzinfo=dt.timezone.utc) - dt.timedelta(
        seconds=1
    )
    return int(start.timestamp()), int(end.timestamp())


def sub_months(year: int, month: int, delta: int) -> tuple[int, int]:
    idx = (year * 12 + (month - 1)) - delta
    y = idx // 12
    m = (idx % 12) + 1
    return y, m


def safe_action(
    client: NvrClient, path: str, action: str = "get", data: Any | None = None
) -> tuple[bool, str, Any]:
    try:
        out = client.action(path, action=action, data=data)
        code = str(out.get("code"))
        return True, code, out.get("data")
    except requests.HTTPError as e:
        status = getattr(e.response, "status_code", "http")
        return False, f"http_{status}", str(e)
    except Exception as e:  # pragma: no cover
        return False, "error", str(e)


def parse_port_range_spec(spec: str) -> list[int]:
    spec = (spec or "").strip()
    if not spec:
        return []
    if "-" in spec:
        a, b = spec.split("-", 1)
        start = int(a.strip())
        end = int(b.strip())
        if end < start:
            start, end = end, start
        return list(range(start, end + 1))
    return [int(spec)]


def parse_middleware_ports_from_variable_js(txt: str) -> list[int]:
    m = re.search(r"PORT_RANGE=\[([0-9,\s]+)\]", txt)
    if not m:
        return []
    out: list[int] = []
    for part in m.group(1).split(","):
        part = part.strip()
        if part.isdigit():
            out.append(int(part))
    return out


def scan_open_tcp_ports(host: str, ports: list[int], timeout_ms: int) -> list[int]:
    open_ports: list[int] = []
    timeout = max(1, timeout_ms) / 1000.0
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((host, int(port))) == 0:
                open_ports.append(int(port))
        except Exception:
            pass
        finally:
            sock.close()
    return open_ports


def main() -> int:
    args = build_parser().parse_args()
    c = NvrClient(host=args.host, timeout=args.timeout)
    try:
        c.login(args.user, args.password)
    except Exception as e:
        print(f"ERR login: {e}", file=sys.stderr)
        return 2

    if args.cmd == "login-check":
        print(f"OK login: {args.user}@{args.host}")
        return 0

    if args.cmd == "check-webui-mode":
        result: dict[str, Any] = {
            "host": args.host,
            "local_host": args.localhost,
            "play_mode_requires_for_download": ["PLAY_MODE_PLUGIN", "PLAY_MODE_LOCALSERVER"],
            "play_mode_fallback_non_ie": "PLAY_MODE_H264/H265",
            "ports_source": "",
            "ports_checked": [],
            "ports_open": [],
            "localserver_likely_available": False,
            "summary": "",
        }
        try:
            variable_js = c.s.get(c.base + "/statics/js/variable.js", timeout=args.timeout).text
            isplayer_js = c.s.get(c.base + "/statics/js/isPlayer.js", timeout=args.timeout).text
        except Exception as e:
            print(f"ERR webui fetch: {e}", file=sys.stderr)
            return 4

        if args.port_range:
            ports = parse_port_range_spec(args.port_range)
            result["ports_source"] = f"arg:{args.port_range}"
        else:
            ports = parse_middleware_ports_from_variable_js(variable_js)
            result["ports_source"] = "variable.js PORT_RANGE"
        result["ports_checked"] = ports

        open_ports = scan_open_tcp_ports(args.localhost, ports, args.connect_timeout_ms)
        result["ports_open"] = open_ports
        result["localserver_likely_available"] = len(open_ports) > 0

        has_download_guard = (
            "downloadRecordFileStart" in isplayer_js
            and "PLAY_MODE_LOCALSERVER" in isplayer_js
            and "PLAY_MODE_PLUGIN" in isplayer_js
        )
        result["download_via_plugin_or_localserver_only"] = has_download_guard

        if result["localserver_likely_available"]:
            result["summary"] = (
                "Wykryto otwarte porty middleware lokalnie. WebUI moze pracowac w LOCALSERVER, "
                "wiec download ma szanse dzialac."
            )
        else:
            result["summary"] = (
                "Nie wykryto lokalnych portow middleware. WebUI najpewniej pojdzie w fallback H264/H265, "
                "a download moze nie dzialac."
            )

        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0

        print(f"host={result['host']} local={result['local_host']}")
        print(f"ports_source={result['ports_source']}")
        print(f"ports_checked={result['ports_checked']}")
        print(f"ports_open={result['ports_open']}")
        print(
            "download_guard="
            f"{'plugin/localserver' if result['download_via_plugin_or_localserver_only'] else 'unknown'}"
        )
        print(result["summary"])
        return 0

    if args.cmd == "list-records":
        start, end = epoch_range_for_day(args.day)
        try:
            days = c.query_days(args.channel, args.stream, args.file_type, start, end)
            recs = c.list_records(
                channel=args.channel,
                stream=args.stream,
                file_type=args.file_type,
                start=start,
                end=end,
                page_items=args.page_items,
            )
        except Exception as e:
            print(f"ERR records: {e}", file=sys.stderr)
            return 3

        print(
            f"OK records: host={args.host} channel={args.channel} day={args.day} "
            f"days_in_month_hit={days} count={len(recs)}"
        )
        if args.json:
            print(json.dumps(recs, ensure_ascii=False, indent=2))
            return 0

        for i, r in enumerate(recs, start=1):
            s = fmt_epoch(r.get("startTime"))
            e = fmt_epoch(r.get("endTime"))
            ft = r.get("fileType")
            st = r.get("streamNo")
            print(f"{i:04d}  {s}  ->  {e}  fileType={ft} stream={st}")
        return 0

    if args.cmd == "analyze":
        now = dt.datetime.now(dt.timezone.utc)
        months: list[tuple[int, int]] = []
        for i in range(max(1, args.months_back)):
            months.append(sub_months(now.year, now.month, i))
        months = sorted(set(months))

        print(f"[analyze] host={args.host} user={args.user}")
        print(f"[analyze] scan_channels=0..{args.channels_max-1} months={','.join(f'{y:04d}-{m:02d}' for y,m in months)}")

        # Endpointy, które warto znać do automatyzacji
        checks = [
            ("/api/system/device-info", "get", None),
            ("/api/system/device-capabilities", "get", None),
            ("/api/system/language", "get", None),
            ("/api/channel/online-status", "get", None),
            ("/api/channel/priview-channel-name", "get", None),
            ("/api/storage/disk-manager", "get", None),
            ("/api/record/query-days", "get", {"channel": 0, "streamNo": args.stream, "fileType": args.file_type, "startTime": "0", "endTime": "1"}),
        ]
        print("\n[api_check]")
        for path, action, data in checks:
            ok, code, payload = safe_action(c, path, action, data)
            shape = type(payload).__name__ if ok else "n/a"
            print(f"{path:36s} code={code:>8s} data={shape}")

        print("\n[channel_days]")
        found_any = False
        channel_with_access: list[int] = []
        for ch in range(max(0, args.channels_max)):
            month_hits: list[str] = []
            ch_access = False
            for y, m in months:
                start, end = month_range_utc(y, m)
                ok, code, payload = safe_action(
                    c,
                    "/api/record/query-days",
                    "get",
                    {
                        "channel": ch,
                        "streamNo": args.stream,
                        "fileType": args.file_type,
                        "startTime": str(start),
                        "endTime": str(end),
                    },
                )
                if ok and code == "0":
                    ch_access = True
                    days = list((payload or {}).get("days") or [])
                    if days:
                        day_str = ",".join(str(d) for d in days)
                        month_hits.append(f"{y:04d}-{m:02d}:[{day_str}]")
            if ch_access:
                channel_with_access.append(ch)
            if month_hits:
                found_any = True
                print(f"ch{ch:02d}  " + "  ".join(month_hits))

        if not found_any:
            print("brak trafień dni (w podanym zakresie)")
        print(
            f"\n[dostepne_kanaly_api] {', '.join(str(x) for x in channel_with_access) if channel_with_access else 'brak/nieznane'}"
        )

        print("\n[api_methods_from_js]")
        try:
            methods = c.get_api_methods()
            print(f"count={len(methods)}")
            for name in methods[:80]:
                print(name)
            if len(methods) > 80:
                print(f"... +{len(methods)-80} kolejnych")
        except Exception as e:
            print(f"ERR api.js parse: {e}")

        print("\n[co_dalej]")
        print("1) export listy nagrań CSV/JSON per kanał/dzień")
        print("2) auto-skan wszystkich kanałów i alert gdy pojawią się nowe dni")
        print("3) pobieranie nagrań: API (jeśli endpoint dostępny) + fallback RTSP/ffmpeg")
        print("4) panel: heatmapa dni z nagraniami per kanał")
        return 0

    if args.cmd == "dump-cam-creds":
        try:
            cap = c.action("/api/security/capability", "get", {"username": args.user})
            if int(cap.get("code", -1)) != 0:
                raise RuntimeError(
                    f"security/capability failed: code={cap.get('code')} msg={cap.get('msg')}"
                )
            data = cap.get("data") or {}
            enc = (data.get("encryptionType") or ["aes128-1"])[0]
            param = (data.get("param") or {}).get(enc) or {}
            salt = str(param.get("salt", ""))
            iterations = int(param.get("iterations", 0))
            req_datetime, key16 = build_channel_crypto_key(args.user, salt, iterations)
            req = {
                "encryptionType": enc,
                "loginName": str(args.user),
                "datetime": req_datetime,
                "iv": "afe13ds34cdjk08c",
            }
            out = c.action("/api/channel/search-camera", "get", req)
            if int(out.get("code", -1)) != 0:
                raise RuntimeError(
                    f"search-camera failed: code={out.get('code')} msg={out.get('msg')}"
                )
            rows = []
            for item in (out.get("data") or {}).get("devList") or []:
                user_enc = item.get("username") or ""
                pass_enc = item.get("password") or ""
                try:
                    user_dec = (
                        aes128_cbc_zero_unpad_decrypt_b64(user_enc, key16) if user_enc else ""
                    )
                except Exception:
                    user_dec = ""
                try:
                    pass_dec = (
                        aes128_cbc_zero_unpad_decrypt_b64(pass_enc, key16) if pass_enc else ""
                    )
                except Exception:
                    pass_dec = ""
                rows.append(
                    {
                        "ip": item.get("ip"),
                        "mac": item.get("mac"),
                        "protocolType": item.get("protocolType"),
                        "port": item.get("port"),
                        "username": user_dec,
                        "password": pass_dec,
                    }
                )
        except Exception as e:
            print(f"ERR dump-cam-creds: {e}", file=sys.stderr)
            return 5

        if args.json:
            print(json.dumps(rows, ensure_ascii=False, indent=2))
            return 0

        print(f"OK camera creds: host={args.host} found={len(rows)}")
        for i, r in enumerate(rows, start=1):
            print(
                f"{i:02d}  ip={r.get('ip')}  proto={r.get('protocolType')}  "
                f"user={r.get('username')}  pass={r.get('password')}  mac={r.get('mac')}"
            )
        return 0

    print("ERR unknown command", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
