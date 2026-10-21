#!/usr/bin/env python3
"""
Search for Sony Bravia firmware download URLs for 2023-2026 Google TV models.
Uses Sony's update CDN, support pages, and known URL patterns.
Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
import os
import sys
import tempfile
import json
import re
import time
import hashlib
import datetime
import requests

_tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", ".tmp")
os.makedirs(_tmp, exist_ok=True)
tempfile.tempdir = _tmp

SESS = requests.Session()
SESS.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8",
})

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "..", "downloads", "tv", "sony")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Target models ──────────────────────────────────────────────────────────
MODELS = {
    # 2023 Google TV (XR series = Bravia XR)
    "XR-55A95L":  {"year": 2023, "platform": "Google TV", "panel": "QD-OLED"},
    "XR-65A95L":  {"year": 2023, "platform": "Google TV", "panel": "QD-OLED"},
    "XR-55A80L":  {"year": 2023, "platform": "Google TV", "panel": "OLED"},
    "XR-55X90L":  {"year": 2023, "platform": "Google TV", "panel": "Mini LED"},
    "XR-65X90L":  {"year": 2023, "platform": "Google TV", "panel": "Mini LED"},
    "XR-75X90L":  {"year": 2023, "platform": "Google TV", "panel": "Mini LED"},
    "KD-55X85L":  {"year": 2023, "platform": "Google TV", "panel": "LCD"},
    "KD-65X85L":  {"year": 2023, "platform": "Google TV", "panel": "LCD"},
    # 2024 Google TV
    "XR-55A95M":  {"year": 2024, "platform": "Google TV", "panel": "QD-OLED"},
    "XR-65X95M":  {"year": 2024, "platform": "Google TV", "panel": "Mini LED"},
    "KD-55X80M":  {"year": 2024, "platform": "Google TV", "panel": "LCD"},
    "KD-65X80M":  {"year": 2024, "platform": "Google TV", "panel": "LCD"},
    # 2025 (announced)
    "XR-55A95N":  {"year": 2025, "platform": "Google TV", "panel": "QD-OLED"},
}

# ── Sony firmware URL patterns ─────────────────────────────────────────────
# Pattern from older CDN: https://tv.update.sony.net/OND/2018/br/main/PS212879/sony_tvupdate_XXX.zip
# Newer models may use different paths

CDN_BASES = [
    "https://tv.update.sony.net",
    "https://www.sony.com",
]

# Sony Brazil support pages
SUPPORT_URLS = [
    "https://www.sony.com.br/pt/articles/downloads-de-atualizacao-de-software-para-televisores-bravia",
    "https://www.sony.com.br/electronics/suporte/televisores-lcd-led-bravia",
]


def probe_cdn(model: str) -> list:
    """Try to find firmware ZIP on Sony's CDN."""
    found = []
    # Older pattern: PSXXXXXX folder
    years = ["2023", "2024", "2025", "2026"]
    regions = ["br", "us", "gb", "de"]
    for year in years:
        for region in regions:
            base = f"https://tv.update.sony.net/OND/{year}/{region}/main/"
            try:
                r = SESS.get(base, timeout=5)
                if r.status_code == 200:
                    found.append({"url": base, "status": r.status_code, "model": model})
                    print(f"  CDN found: {base}")
            except Exception:
                pass
    return found


def check_sony_support(model: str) -> list:
    """Scrape Sony support pages for firmware links."""
    found = []
    search_urls = [
        "https://www.sony.com.br/pt/articles/downloads-de-atualizacao-de-software-para-televisores-bravia",
        f"https://www.sony.com/en/articles/firmware-update-for-{model.lower().replace('-', '-')}",
        "https://www.sony.com.br/electronics/suporte/televisores-lcd-led-bravia/bravia-xr-series/downloads",
    ]
    for url in search_urls:
        try:
            r = SESS.get(url, timeout=8)
            if r.status_code == 200:
                # Look for .zip links
                zips = re.findall(r'href=["\']([^"\']*\.zip)["\']', r.text)
                for z in zips:
                    if "sony" in z.lower() or "tv" in z.lower() or "bravia" in z.lower():
                        found.append({"source_page": url, "url": z, "model": model})
                        print(f"  Found zip: {z}")
                # Look for firmware links
                fw_links = re.findall(
                    r'https?://(?:tv\.update\.sony\.net|sdm\.downloads\.sony\.net)[^\s"\'<>]+',
                    r.text
                )
                for link in fw_links:
                    found.append({"source_page": url, "url": link, "model": model})
                    print(f"  Found CDN: {link}")
        except Exception as e:
            pass
    return found


def try_direct_cdns(model: str) -> list:
    """Try known CDN patterns for specific models."""
    found = []
    # Sony firmware naming: sony_tvupdate_YYYY_VVVV_...
    # For Google TV models the format may be different
    candidate_urls = [
        # XR-55A95L known firmware versions
        "https://tv.update.sony.net/OND/2023/us/main/XRA95L/sony_tvupdate_2023_A95L.zip",
        "https://tv.update.sony.net/OND/2023/br/main/XRA95L/sony_tvupdate_2023_A95L.zip",
        # X90L variants
        "https://tv.update.sony.net/OND/2023/us/main/XRX90L/sony_tvupdate_2023_X90L.zip",
        # Check if sdm.downloads.sony.net has newer
        "https://sdm.downloads.sony.net/bravia/XR-55A95L/firmware.zip",
        "https://sdm.downloads.sony.net/bravia/XR-65X90L/firmware.zip",
        # Sony global software download
        "https://www.sony.com/en/articles/software-downloads-for-bravia-tvs",
    ]
    for url in candidate_urls:
        try:
            r = SESS.head(url, timeout=5, allow_redirects=True)
            if r.status_code in (200, 206):
                size = int(r.headers.get("Content-Length", 0))
                found.append({
                    "url": url,
                    "status": r.status_code,
                    "size_mb": round(size / 1024 / 1024, 1),
                    "content_type": r.headers.get("Content-Type", ""),
                })
                print(f"  DIRECT HIT: {url} ({size//1024//1024} MB)")
        except Exception:
            pass
    return found


def search_archive_org(model: str) -> list:
    """Search archive.org Wayback Machine for cached firmware pages."""
    found = []
    try:
        api_url = "https://archive.org/wayback/available?url=tv.update.sony.net"
        r = SESS.get(api_url, timeout=8)
        if r.status_code == 200:
            data = r.json()
            if data.get("archived_snapshots"):
                snap = data["archived_snapshots"].get("closest", {})
                found.append({"archive": snap.get("url", ""), "model": model})
    except Exception:
        pass
    return found


def try_google_tv_ota_patterns():
    """Sony Google TV OTA update patterns (Android-based, different format)."""
    print("\n[*] Probing Google TV OTA patterns...")
    results = []

    # Google TV OTA: typically served via Google's infrastructure
    # but Sony also hosts on their CDN
    # Format: usually an OTA .zip with payload.bin
    ota_patterns = [
        "https://tv.update.sony.net/OND/2023/us/main/",
        "https://tv.update.sony.net/OND/2024/us/main/",
        "https://omahaproxy.appspot.com/",  # Chromium/Cast versions
    ]
    for url in ota_patterns:
        try:
            r = SESS.get(url, timeout=5)
            if r.status_code == 200:
                print(f"  OTA base reachable: {url}")
                results.append({"url": url, "status": r.status_code})
            else:
                print(f"  OTA base: {url} -> HTTP {r.status_code}")
        except Exception as e:
            print(f"  OTA base: {url} -> {str(e)[:60]}")

    return results


def check_nvd_cve_for_model(model: str) -> list:
    """Check NVD for known CVEs against this model."""
    cves = []
    try:
        r = SESS.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Sony+Bravia+{model}&resultsPerPage=20",
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                desc = cve.get("descriptions", [{}])[0].get("value", "")[:200]
                metrics = cve.get("metrics", {})
                cvss = None
                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV30" in metrics:
                    cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                cves.append({"id": cve_id, "cvss": cvss, "desc": desc})
    except Exception as e:
        print(f"  NVD lookup error: {e}")
    return cves


def main():
    results = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "models": {},
    }

    # 1. Try OTA patterns
    ota = try_google_tv_ota_patterns()
    results["ota_probe"] = ota

    # 2. Per-model analysis
    for model, info in list(MODELS.items())[:6]:  # top 6 models
        print(f"\n[*] Researching {model} ({info['year']}, {info['platform']})...")
        m_result = {"info": info, "firmware_urls": [], "cves": []}

        direct = try_direct_cdns(model)
        m_result["firmware_urls"].extend(direct)

        support = check_sony_support(model)
        m_result["firmware_urls"].extend(support)

        cves = check_nvd_cve_for_model(model)
        m_result["cves"] = cves
        if cves:
            print(f"  CVEs found for {model}: {[c['id'] for c in cves]}")

        results["models"][model] = m_result
        time.sleep(1)

    # Save
    out = os.path.join(OUTPUT_DIR, "newer_models_research.json")
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[*] Research saved -> {out}")

    # Print summary
    print("\n=== SUMMARY ===")
    for model, data in results["models"].items():
        urls = data["firmware_urls"]
        cves = data["cves"]
        print(f"  {model}: {len(urls)} fw URLs, {len(cves)} CVEs")
        for cve in cves[:3]:
            print(f"    {cve['id']} CVSS={cve['cvss']} {cve['desc'][:80]}")


if __name__ == "__main__":
    main()
