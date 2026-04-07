#!/usr/bin/env python3
"""Scan ExploitDB hardware folder for router CVEs not yet in RouterXPL."""
import os
import re
import json

MODULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "routerxpl", "modules",
)
EDB_BASE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "..", "third-party-router-poc",
    "exploit-database__exploitdb", "exploits", "hardware",
)
OUT_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "_edb_candidates.json",
)

ROUTER_KW = [
    "router", "gateway", "modem", "firewall", "switch", "vpn",
    "dlink", "d-link", "tp-link", "tplink", "netgear", "linksys",
    "cisco", "asus", "huawei", "zte", "zyxel", "trendnet",
    "ubiquiti", "fortinet", "sonicwall", "netis", "tenda",
    "mikrotik", "ruckus", "aruba", "citrix", "barracuda",
    "iqrouter", "comtrend", "wavlink", "totolink",
    "sd-wan", "nsx", "grandstream", "ucm",
    "f5", "big-ip", "pfsense", "openwrt", "telesquare",
    "seowon", "smartrg", "technicolor", "satellite",
]


def load_rxf_cves() -> set:
    cves = set()
    for root, _, files in os.walk(MODULES_DIR):
        for f in files:
            if not f.endswith(".py"):
                continue
            with open(os.path.join(root, f), "r", encoding="utf-8", errors="replace") as fh:
                for c in re.findall(r"CVE-\d{4}-\d+", fh.read(), re.I):
                    cves.add(c.upper())
    return cves


def main() -> None:
    rxf_cves = load_rxf_cves()
    print(f"Current RouterXPL CVE count: {len(rxf_cves)}")

    candidates = []
    for subdir in ("webapps", "remote", "local", "dos"):
        scan = os.path.join(EDB_BASE, subdir)
        if not os.path.isdir(scan):
            continue
        for f in os.listdir(scan):
            if not f.endswith((".py", ".rb", ".sh")):
                continue
            path = os.path.join(scan, f)
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()

            cves = list({c.upper() for c in re.findall(r"CVE-\d{4}-\d+", content, re.I)})
            new_cves = [c for c in cves if c not in rxf_cves]
            if not new_cves:
                continue

            title = ""
            for line in content.split("\n")[:15]:
                ll = line.lower()
                if "exploit title" in ll or "title:" in ll:
                    title = line.split(":", 1)[-1].strip().strip("#").strip()
                    break

            text_lower = (title + " " + content[:500]).lower()
            if not any(kw in text_lower for kw in ROUTER_KW):
                continue

            years = [int(c.split("-")[1]) for c in new_cves]
            candidates.append({
                "file": f,
                "subdir": subdir,
                "cves": new_cves,
                "title": title[:120],
                "newest_year": max(years),
                "path": path,
                "lang": f.rsplit(".", 1)[-1],
            })

    candidates.sort(key=lambda x: (-x["newest_year"], -len(x["cves"])))
    print(f"Router/network candidates: {len(candidates)}")
    print()
    for c in candidates:
        cvs = ",".join(c["cves"][:3])
        print(f"  {cvs:40s} | {c['file']:20s} | {c['title'][:70]}")

    with open(OUT_FILE, "w") as fh:
        json.dump(candidates, fh, indent=2)
    print(f"\nSaved to {OUT_FILE}")


if __name__ == "__main__":
    main()
