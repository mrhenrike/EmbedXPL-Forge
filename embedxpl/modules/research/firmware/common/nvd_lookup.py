#!/usr/bin/env python3
"""
nvd_lookup.py — NVD / CVE / CWE cross-reference utility
Author: Andre Henrique (@mrhenrike) | Uniao Geek — https://github.com/Uniao-Geek

Queries NVD API v2.0 for CVEs by keyword, CPE, or CVE-ID.
Returns: CVE ID, CVSS 3.1 vector+score, CWE, description, references.

Usage:
    python scripts/nvd_lookup.py --keyword "mikrotik routeros"
    python scripts/nvd_lookup.py --cve CVE-2023-30799
    python scripts/nvd_lookup.py --cpe "cpe:2.3:o:mikrotik:routeros:7.22.1:*:*:*:*:*:*:*"
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REPO_ROOT = Path(__file__).resolve().parent.parent

def _load_api_key() -> str | None:
    env_file = REPO_ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("NVD_API_KEY="):
                return line.split("=", 1)[1].strip()
    return os.environ.get("NVD_API_KEY")


def query_nvd(params: dict[str, str], api_key: str | None = None) -> list[dict[str, Any]]:
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    results: list[dict[str, Any]] = []
    start_index = 0
    while True:
        params["startIndex"] = str(start_index)
        params["resultsPerPage"] = "20"
        resp = requests.get(NVD_API, params=params, headers=headers, timeout=30)
        if resp.status_code == 403:
            print("[WARN] NVD rate-limited. Waiting 6s ...", file=sys.stderr)
            time.sleep(6)
            continue
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        results.extend(vulns)
        total = data.get("totalResults", 0)
        start_index += len(vulns)
        if start_index >= total or not vulns:
            break
        time.sleep(0.7)
    return results


def parse_cve(vuln: dict[str, Any]) -> dict[str, Any]:
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "?")
    desc_list = cve.get("descriptions", [])
    desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")

    # CVSS 3.1
    metrics = cve.get("metrics", {})
    cvss31 = None
    score = None
    severity = None
    for m in metrics.get("cvssMetricV31", []):
        cd = m.get("cvssData", {})
        cvss31 = cd.get("vectorString")
        score = cd.get("baseScore")
        severity = cd.get("baseSeverity")
        break
    if not cvss31:
        for m in metrics.get("cvssMetricV30", []):
            cd = m.get("cvssData", {})
            cvss31 = cd.get("vectorString")
            score = cd.get("baseScore")
            severity = cd.get("baseSeverity")
            break

    # CWE
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)

    # References
    refs = [r.get("url", "") for r in cve.get("references", [])[:5]]

    # CPEs affected
    configs = cve.get("configurations", [])
    cpes = []
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpes.append(match.get("criteria", ""))

    return {
        "id": cve_id,
        "description": desc[:300],
        "cvss31_vector": cvss31,
        "cvss31_score": score,
        "severity": severity,
        "cwes": cwes,
        "references": refs,
        "cpes": cpes[:5],
        "published": cve.get("published", ""),
        "modified": cve.get("lastModified", ""),
    }


def search_by_keyword(keyword: str, api_key: str | None = None) -> list[dict]:
    return [parse_cve(v) for v in query_nvd({"keywordSearch": keyword}, api_key)]


def search_by_cve_id(cve_id: str, api_key: str | None = None) -> list[dict]:
    return [parse_cve(v) for v in query_nvd({"cveId": cve_id}, api_key)]


def search_by_cpe(cpe: str, api_key: str | None = None) -> list[dict]:
    return [parse_cve(v) for v in query_nvd({"cpeName": cpe}, api_key)]


def print_results(results: list[dict], fmt: str = "table") -> None:
    if not results:
        print("No results found.")
        return
    if fmt == "json":
        print(json.dumps(results, indent=2, default=str))
        return
    for r in results:
        print(f"\n{'='*70}")
        print(f"  {r['id']}  |  CVSS: {r['cvss31_score']} ({r['severity'] or '?'})  |  CWE: {', '.join(r['cwes']) or '?'}")
        print(f"  Published: {r['published'][:10]}  |  Modified: {r['modified'][:10]}")
        print(f"  Vector: {r['cvss31_vector'] or 'N/A'}")
        print(f"  {r['description'][:200]}")
        if r['references']:
            print(f"  Refs: {r['references'][0]}")
        if r['cpes']:
            print(f"  CPE: {r['cpes'][0]}")


def main():
    parser = argparse.ArgumentParser(description="NVD CVE lookup utility")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--keyword", help="Search by keyword")
    group.add_argument("--cve", help="Lookup specific CVE ID")
    group.add_argument("--cpe", help="Search by CPE name")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    api_key = _load_api_key()
    fmt = "json" if args.json else "table"

    if args.keyword:
        results = search_by_keyword(args.keyword, api_key)
    elif args.cve:
        results = search_by_cve_id(args.cve, api_key)
    else:
        results = search_by_cpe(args.cpe, api_key)

    print_results(results, fmt)


if __name__ == "__main__":
    main()
