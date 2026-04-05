#!/usr/bin/env python3
"""Create FirewallXPL-Forge tree from RouterXPL-Forge (perimeter NGFW/UTM/WAF lab fork).

- Copies source excluding .git and common junk.
- Keeps only firewall-relevant vendor modules + shared generic/payloads/encoders.
- Drops vendored PoC arsenal mirror (``incorporated_third_party``, SOHO HTML catalog) to
  keep the FW repo lightweight.
- Renames Python package ``routerxpl`` -> ``firewallxpl`` and entrypoint ``fxf.py``.

Run once; requires ~5–10 minutes for copy+rewrite on a full tree.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path
from typing import FrozenSet, Iterable, List

TEXT_SUFFIXES: FrozenSet[str] = frozenset(
    {
        ".py",
        ".md",
        ".yml",
        ".yaml",
        ".json",
        ".toml",
        ".cfg",
        ".ini",
        ".in",
        ".txt",
        ".sh",
        ".gitignore",
    },
)

# Exploits under routers/: keep only these vendor directories (then filter files inside cisco/zyxel).
FW_EXPLOIT_VENDORS_KEPT: FrozenSet[str] = frozenset({"fortinet", "cisco"})

# After vendor trim, delete non-firewall Cisco modules by basename.
CISCO_REMOVE_ON_FW: FrozenSet[str] = frozenset(
    {
        "rv320_command_injection.py",
        "dpc2420_info_disclosure.py",
        "catalyst_2960_rocem.py",
        "ios_http_authorization_bypass.py",
    },
)

# Credentials: keep firewall-adjacent OS / NGFW vendors only.
FW_CREDS_VENDORS_KEPT: FrozenSet[str] = frozenset(
    {"fortinet", "juniper", "pfsense", "ipfire", "cisco"},
)


def _ignore_copy(_dir: str, names: list[str]) -> set[str]:
    """Skip VCS, caches, and multi‑GiB PoC mirrors (FW clone stays small)."""

    ignored: set[str] = set()
    if ".git" in names:
        ignored.add(".git")
    skip_leaves = frozenset({"incorporated_third_party", "soho_exploit_catalog"})
    for n in names:
        if n == "__pycache__" or n.endswith(".pyc"):
            ignored.add(n)
        if n in skip_leaves:
            ignored.add(n)
    return ignored


def _rm_tree(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
    elif path.is_file():
        path.unlink(missing_ok=True)


def _copy_source(src: Path, dest: Path) -> None:
    if dest.exists():
        raise SystemExit("Destination already exists: {} (remove or pick another path)".format(dest))
    shutil.copytree(src, dest, ignore=_ignore_copy)


def _trim_exploits_routers(er: Path) -> None:
    if not er.is_dir():
        return
    for child in list(er.iterdir()):
        if not child.is_dir():
            continue
        if child.name not in FW_EXPLOIT_VENDORS_KEPT:
            shutil.rmtree(child, ignore_errors=True)


def _trim_cisco_fw(cisco_dir: Path) -> None:
    if not cisco_dir.is_dir():
        return
    for fp in list(cisco_dir.glob("*.py")):
        if fp.name in CISCO_REMOVE_ON_FW:
            fp.unlink(missing_ok=True)


def _trim_zyxel_fw(zyxel_dir: Path) -> None:
    if not zyxel_dir.is_dir():
        return
    for fp in list(zyxel_dir.glob("*.py")):
        if fp.name != "zywall_usg_extract_hashes.py":
            fp.unlink(missing_ok=True)
    # drop empty __init__ if needed — keep __init__.py
    if not any(p.name != "__init__.py" for p in zyxel_dir.glob("*.py")):
        pass


def _trim_misc_exploits(misc: Path) -> None:
    if not misc.is_dir():
        return
    for child in list(misc.iterdir()):
        if child.is_dir() and child.name != "watchguard":
            shutil.rmtree(child, ignore_errors=True)


def _trim_creds_routers(cr: Path) -> None:
    if not cr.is_dir():
        return
    for child in list(cr.iterdir()):
        if child.is_dir() and child.name not in FW_CREDS_VENDORS_KEPT:
            shutil.rmtree(child, ignore_errors=True)


def _trim_scanners(smods: Path) -> None:
    rdir = smods / "routers"
    if rdir.is_dir():
        for fp in list(rdir.glob("*.py")):
            if fp.name != "fortigate_sslvpn_scan.py" and fp.name != "__init__.py":
                fp.unlink(missing_ok=True)
    misc = smods / "misc" / "soho_exploit_catalog_server.py"
    misc.unlink(missing_ok=True)


def _trim_heavy_resources(pkg_root: Path) -> None:
    pocs = pkg_root / "resources" / "arsenal" / "pocs"
    _rm_tree(pocs / "incorporated_third_party")
    _rm_tree(pocs / "soho_exploit_catalog")
    for name in (
        "incorporated_third_party_index.json",
        "soho_catalog_js_index.json",
    ):
        fp = pkg_root / "resources" / "catalogs" / name
        fp.unlink(missing_ok=True)
    # Core helpers that only served heavy trees
    for rel in (
        "core/incorporated_poc_tree.py",
        "core/soho_exploit_catalog.py",
        "modules/generic/external/exploitdb_embedded_lookup.py",
    ):
        (pkg_root / rel).unlink(missing_ok=True)

    integ = pkg_root / "core" / "integrations" / "__init__.py"
    if integ.is_file():
        t = integ.read_text(encoding="utf-8")
        if "exploitdb_embedded_lookup" in t:
            t = t.replace(
                "Exploit-DB offline search lives in ``generic/external/exploitdb_embedded_lookup``\n"
                "(embedded tree); this package does not wrap the ``searchsploit`` CLI.\n",
                "Optional Metasploit bridge only; vendored Exploit-DB tree is not shipped in "
                "FirewallXPL-Forge (lighter perimeter lab clone).\n",
            )
            integ.write_text(t, encoding="utf-8", newline="\n")


def _rewrite_text_files(pkg_dir: Path, extra_files: List[Path]) -> None:
    """Replace package prefix and branding (package tree + selected repo root files)."""

    old_mod = "routerxpl/modules/"
    new_mod = "firewallxpl/modules/"
    rx_word = (
        (re.compile(re.escape("routerxpl")), "firewallxpl"),
        (re.compile(r"\bRouterXPLInterpreter\b"), "FirewallXPLInterpreter"),
        (re.compile(r"\bRouterXPLException\b"), "FirewallXPLException"),
        (re.compile(r"\bRouterXPL\b"), "FirewallXPL"),
        (re.compile(r"RXF_RAW_PROMPT"), "FXF_RAW_PROMPT"),
        (re.compile(r"RXF_MODULE_PROMPT"), "FXF_MODULE_PROMPT"),
        (re.compile(r"RXF_METASPLOIT_CONSOLE"), "FXF_METASPLOIT_CONSOLE"),
    )

    skip_dirs = {".git", "__pycache__"}

    def _process_file(path: Path) -> None:
        suf = path.suffix.lower()
        if suf not in TEXT_SUFFIXES and path.name not in (".gitignore", "MANIFEST.in", "rxf.py"):
            return
        try:
            data = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return
        orig = data
        data = data.replace(old_mod.replace("/", os.sep), new_mod.replace("/", os.sep))
        for rx, rep in rx_word:
            data = rx.sub(rep, data)
        data = data.replace("RouterXPL-Forge", "FirewallXPL-Forge")
        data = data.replace("ROUTERXPL_SOHO_CATALOG_ROOT", "FIREWALLXPL_SOHO_CATALOG_ROOT")
        if data != orig:
            path.write_text(data, encoding="utf-8", newline="\n")

    for root, dirs, files in os.walk(pkg_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for name in files:
            _process_file(Path(root) / name)

    gh = pkg_dir.parent / ".github"
    if gh.is_dir():
        for root, dirs, files in os.walk(gh):
            for name in files:
                _process_file(Path(root) / name)

    docs = pkg_dir.parent / "docs"
    if docs.is_dir():
        for root, dirs, files in os.walk(docs):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for name in files:
                _process_file(Path(root) / name)

    for path in extra_files:
        if path.is_file():
            _process_file(path)


def _rename_package_dir(dest: Path) -> Path:
    src_pkg = dest / "routerxpl"
    dst_pkg = dest / "firewallxpl"
    if not src_pkg.is_dir():
        raise SystemExit("Expected package dir missing: {}".format(src_pkg))
    src_pkg.rename(dst_pkg)
    return dst_pkg


def _write_fxf(dest: Path) -> None:
    """Create fxf.py from rewritten rxf (imports FirewallXPL*)."""

    rxf = dest / "rxf.py"
    fxf = dest / "fxf.py"
    if rxf.is_file():
        text = rxf.read_text(encoding="utf-8")
        text = text.replace("routerxpl.log", "firewallxpl.log")
        fxf.write_text(text, encoding="utf-8", newline="\n")
        rxf.unlink(missing_ok=True)
    elif not fxf.is_file():
        raise SystemExit("Neither rxf.py nor fxf.py found at {}".format(dest))


def _write_module_scope(fw_root: Path) -> None:
    path = fw_root / "resources" / "catalogs" / "module_target_scope.json"
    if not path.is_file():
        return
    import json

    data = json.loads(path.read_text(encoding="utf-8"))
    data["version"] = "2.0.0-firewall"
    data["description"] = (
        "FirewallXPL-Forge: NGFW, UTM, WAF, and cloud perimeter lab classes "
        "(fw, ngfw, utm, waf, cloud_fw). Placeholder prefixes for AWS/Azure/GCP "
        "WAF map to future modules under exploits/cloud/."
    )
    data["default_allow_classes"] = ["fw", "ngfw", "utm", "waf", "cloud_fw"]
    data["domain_defaults"] = {
        "exploits": ["fw", "ngfw", "utm", "waf", "cloud_fw"],
        "creds": ["fw", "ngfw", "utm", "waf", "cloud_fw"],
    }
    # Keep generic + fortinet + watchguard misc + relevant cisco/juniper rules; drop pure-SOHO.
    keep_prefix_substrings = (
        "generic/",
        "routers/fortinet/",
        "misc/watchguard/",
        "routers/cisco/firepower",
        "routers/juniper/",
        "routers/paloalto/",
        "routers/checkpoint/",
        "routers/sonicwall/",
        "routers/sophos/",
        "routers/watchguard/",
    )
    old_rules = data.get("prefix_rules") or []
    pr: list[dict] = []
    for r in old_rules:
        p = r.get("prefix") or ""
        if any(p.startswith(s) or s in p for s in keep_prefix_substrings):
            pr.append(r)
    data["prefix_rules"] = pr
    path.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def _patch_setup_and_manifest(dest: Path) -> None:
    sp = dest / "setup.py"
    if sp.is_file():
        t = sp.read_text(encoding="utf-8")
        t = t.replace("name=\"routerxpl\"", "name=\"firewallxpl\"")
        t = t.replace("scripts=('rxf.py',)", "scripts=('fxf.py',)")
        t = t.replace("RouterXPL supports", "FirewallXPL supports")
        t = t.replace("RouterXPL requires", "FirewallXPL requires")
        sp.write_text(t, encoding="utf-8", newline="\n")
    mi = dest / "MANIFEST.in"
    if mi.is_file():
        t = mi.read_text(encoding="utf-8")
        t = t.replace("routerxpl/", "firewallxpl/")
        mi.write_text(t, encoding="utf-8", newline="\n")


def _rename_interpreter_class_file(pkg: Path) -> None:
    ip = pkg / "interpreter.py"
    if not ip.is_file():
        return
    t = ip.read_text(encoding="utf-8")
    t = t.replace("class FirewallXPLInterpreter", "class FirewallXPLInterpreter")
    ip.write_text(t, encoding="utf-8", newline="\n")


def _rename_exceptions(pkg: Path) -> None:
    ex = pkg / "core" / "exploit" / "exceptions.py"
    if not ex.is_file():
        return
    t = ex.read_text(encoding="utf-8")
    if "class FirewallXPLException" not in t:
        t = t.replace("class RouterXPLException", "class FirewallXPLException")
        t = t.replace("RouterXPLException", "FirewallXPLException")
    ex.write_text(t, encoding="utf-8", newline="\n")


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--source",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="RouterXPL-Forge root",
    )
    ap.add_argument("--dest", type=Path, required=True, help="New FirewallXPL-Forge root")
    args = ap.parse_args(list(argv) if argv is not None else None)
    src: Path = args.source.resolve()
    dest: Path = args.dest.resolve()
    if src == dest:
        return 2

    print("Copy {} -> {}".format(src, dest))
    _copy_source(src, dest)

    pkg_pre = dest / "routerxpl"
    _trim_exploits_routers(pkg_pre / "modules" / "exploits" / "routers")
    _trim_cisco_fw(pkg_pre / "modules" / "exploits" / "routers" / "cisco")
    _trim_zyxel_fw(pkg_pre / "modules" / "exploits" / "routers" / "zyxel")
    _trim_misc_exploits(pkg_pre / "modules" / "exploits" / "misc")
    _trim_creds_routers(pkg_pre / "modules" / "creds" / "routers")
    _trim_scanners(pkg_pre / "modules" / "scanners")
    _trim_heavy_resources(pkg_pre)

    extra = [
        dest / "setup.py",
        dest / "MANIFEST.in",
        dest / "README.md",
        dest / "README.pt-BR.md",
        dest / "requirements.txt",
        dest / "rxf.py",
        dest / "CONTRIBUTING.md",
        dest / "CONTRIBUTING.pt-BR.md",
        dest / "SECURITY.md",
    ]
    _rewrite_text_files(pkg_pre, extra)
    fw_pkg = _rename_package_dir(dest)
    _write_fxf(dest)
    _write_module_scope(fw_pkg)
    _patch_setup_and_manifest(dest)
    _rename_exceptions(fw_pkg)
    _rename_interpreter_class_file(fw_pkg)

    print("bootstrap_firewallxpl_forge: OK -> {}".format(dest))
    print("Next: cd {0} && git init && git add -A && git commit".format(dest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
