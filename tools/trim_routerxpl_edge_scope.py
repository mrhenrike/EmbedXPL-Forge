#!/usr/bin/env python3
"""Remove NGFW-leaning modules from RouterXPL-Forge (edge: routers, switches, CPE, TAPs).

Deletes modules that are now maintained in FirewallXPL-Forge. Idempotent: missing paths
are skipped.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path


def _rm(path: Path, *, desc: str) -> None:
    if not path.exists():
        return
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()
    print("removed: {} -> {}".format(desc, path))


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    mods = root / "routerxpl" / "modules"
    edge_rm: list[tuple[str, str]] = [
        (str(mods / "exploits" / "routers" / "fortinet"), "exploits fortinet (NGFW)"),
        (str(mods / "exploits" / "misc" / "watchguard"), "exploits misc watchguard"),
        (str(mods / "scanners" / "routers" / "fortigate_sslvpn_scan.py"), "scanner fortigate sslvpn"),
        (str(mods / "creds" / "routers" / "fortinet"), "creds fortinet"),
        (str(mods / "creds" / "routers" / "pfsense"), "creds pfsense (firewall OS)"),
        (str(mods / "creds" / "routers" / "ipfire"), "creds ipfire (firewall OS)"),
    ]
    for p, d in edge_rm:
        _rm(Path(p), desc=d)

    zywall = mods / "exploits" / "routers" / "zyxel" / "zywall_usg_extract_hashes.py"
    _rm(zywall, desc="zywall USG (NGFW-style)")

    cisco_fwish = (
        "firepower_management60_rce.py",
        "firepower_management60_path_traversal.py",
        "ucs_manager_rce.py",
        "ucm_info_disclosure.py",
        "secure_acs_bypass.py",
        "unified_multi_path_traversal.py",
    )
    cdir = mods / "exploits" / "routers" / "cisco"
    for name in cisco_fwish:
        _rm(cdir / name, desc="cisco enterprise / firepower / UCM")

    scope = root / "routerxpl" / "resources" / "catalogs" / "module_target_scope.json"
    if scope.is_file():
        data = json.loads(scope.read_text(encoding="utf-8"))
        drop_prefixes = frozenset(
            {
                "routers/fortinet/",
                "misc/watchguard/",
                "routers/cisco/firepower",
            },
        )
        rules = data.get("prefix_rules") or []
        data["prefix_rules"] = [r for r in rules if (r.get("prefix") or "") not in drop_prefixes]
        data["description"] = (
            "Edge RouterXPL-Forge: routers, L2/L3 switches, ISP CPE, TAPs. "
            "NGFW / UTM / WAF / cloud perimeter modules: see FirewallXPL-Forge."
        )
        op = dict(data.get("operational_policy") or {})
        op["note"] = (
            "RouterXPL-Forge (edge) does not provide turnkey botnet/C2. "
            "Firewall / NGFW lab coverage lives in FirewallXPL-Forge."
        )
        for k in ("prohibited_in_project_scope",):
            if k in (data.get("operational_policy") or {}):
                op[k] = data["operational_policy"][k]
        data["operational_policy"] = op
        scope.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    print("trim_routerxpl_edge_scope: done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
