#!/usr/bin/env python3
"""Batch import of ExploitDB hardware exploits as RouterXPL stub modules.

Author: André Henrique (@mrhenrike) | União Geek
"""
import json
import os
import re
import textwrap

MODULES_BASE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "routerxpl", "modules", "exploits", "routers",
)
CANDIDATES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "_edb_candidates.json",
)

VENDOR_MAP = {
    "cisco": "cisco", "f5": "multi", "big-ip": "multi",
    "pfsense": "multi", "netis": "multi", "netgear": "netgear",
    "asus": "asus", "d-link": "dlink", "dlink": "dlink",
    "tp-link": "tplink", "tplink": "tplink", "linksys": "linksys",
    "huawei": "huawei", "zte": "zte", "zyxel": "zyxel",
    "trendnet": "trendnet", "ubiquiti": "ubiquiti",
    "fortinet": "multi", "sonicwall": "multi", "tenda": "tenda",
    "mikrotik": "mikrotik", "ruckus": "multi", "aruba": "multi",
    "citrix": "multi", "barracuda": "multi", "comtrend": "comtrend",
    "wavlink": "wavlink", "totolink": "totolink",
    "grandstream": "multi", "vmware": "multi", "nsx": "multi",
    "technicolor": "technicolor", "gl.inet": "multi", "gl-inet": "multi",
    "telesquare": "multi", "iqrouter": "multi", "asustor": "asus",
    "check point": "multi", "checkpoint": "multi",
    "seowon": "multi", "smartrg": "multi", "satellite": "multi",
    "livebox": "multi", "routeros": "mikrotik",
    "netusb": "multi", "hughes": "multi",
}

TEMPLATE = '''\
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """{title}."""

    __info__ = {{
        "name": "{name}",
        "description": (
            "{description}"
        ),
        "authors": (
{authors}
        ),
        "references": (
{references}
        ),
        "devices": (
{devices}
        ),
    }}

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort({port}, "Target HTTP port")

    def run(self):
        response = self.http_request(method="GET", path="{check_path}")
        if response is None:
            return
        if response.status_code == 200:
            print_success("Target responded - manual verification needed")
            print_info(response.text[:1000])
        else:
            print_error("Target returned status {{}}".format(response.status_code))

    @mute
    def check(self):
        response = self.http_request(method="GET", path="{check_path}")
        if response is not None and response.status_code == 200:
            return True
        return False
'''


def guess_vendor(title: str, content: str) -> str:
    text = (title + " " + content[:500]).lower()
    for keyword, vendor in VENDOR_MAP.items():
        if keyword in text:
            return vendor
    return "multi"


def extract_info(content: str) -> dict:
    info = {"authors": [], "edb_id": "", "date": ""}
    for line in content.split("\n")[:25]:
        ll = line.lower()
        if "exploit author" in ll:
            info["authors"].append(line.split(":", 1)[-1].strip().strip("#").strip())
        elif "author:" in ll and not info["authors"]:
            info["authors"].append(line.split(":", 1)[-1].strip().strip("#").strip())
        elif "date:" in ll and not info["date"]:
            info["date"] = line.split(":", 1)[-1].strip().strip("#").strip()
    return info


def sanitize_filename(title: str, cves: list) -> str:
    cve_part = cves[0].replace("CVE-", "cve_").replace("-", "_") if cves else ""
    title_part = re.sub(r"[^a-z0-9]+", "_", title.lower())[:60].strip("_")
    if cve_part and cve_part not in title_part:
        return f"{title_part}_{cve_part}.py"
    return f"{title_part}.py"


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)
    init_f = os.path.join(path, "__init__.py")
    if not os.path.exists(init_f):
        open(init_f, "w").close()


def main() -> None:
    with open(CANDIDATES, "r") as f:
        candidates = json.load(f)

    print(f"Processing {len(candidates)} ExploitDB candidates...\n")
    created = 0

    for c in candidates:
        with open(c["path"], "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        title = c["title"] or "ExploitDB {}".format(c["file"])
        vendor = guess_vendor(title, content)
        info = extract_info(content)

        cve_refs = "\n".join(
            f'            "https://nvd.nist.gov/vuln/detail/{cve}",' for cve in c["cves"]
        )
        edb_ref = f'            "https://www.exploit-db.com/exploits/{c["file"].replace(".py","").replace(".rb","").replace(".sh","")}",'
        all_refs = edb_ref + "\n" + cve_refs

        authors_list = info["authors"] or ["Unknown"]
        authors_list.append("André Henrique (@mrhenrike)")
        authors_str = "\n".join(f'            "{a}",' for a in authors_list)

        name = title[:80]
        description = title.replace('"', "'")
        if len(description) > 120:
            description = description[:117] + "..."

        devices_str = f'            "{title[:60]}",'.replace('"', '"')

        check_path = "/"
        path_patterns = [
            r'path\s*=\s*["\']([^"\']+)',
            r'url\s*=.*?["\']https?://[^/]+(/.+?)["\']',
            r'GET\s+(/.+?)\s',
        ]
        for pat in path_patterns:
            m = re.search(pat, content)
            if m:
                cp = m.group(1).strip()
                if len(cp) < 100 and not cp.startswith("http"):
                    check_path = cp
                    break

        filename = sanitize_filename(title, c["cves"])
        vendor_dir = os.path.join(MODULES_BASE, vendor)
        ensure_dir(vendor_dir)
        filepath = os.path.join(vendor_dir, filename)

        if os.path.exists(filepath):
            continue

        module_content = TEMPLATE.format(
            title=name,
            name=name,
            description=description,
            authors=authors_str,
            references=all_refs,
            devices=devices_str,
            port=80,
            check_path=check_path.split("?")[0][:80] if "?" in check_path else check_path[:80],
        )

        with open(filepath, "w", encoding="utf-8", newline="\n") as f:
            f.write(module_content)
        print(f"  [CREATED] {vendor}/{filename}")
        created += 1

    total = 0
    for root, _, files in os.walk(MODULES_BASE):
        total += sum(1 for ff in files if ff.endswith(".py") and ff != "__init__.py")

    print(f"\n=== Done: {created} EDB modules created ===")
    print(f"Total modules in routers/: {total}")


if __name__ == "__main__":
    main()
