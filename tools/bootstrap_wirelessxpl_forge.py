#!/usr/bin/env python3
"""Create WirelessXPL-Forge tree from RouterXPL-Forge (802.11 / BLE lab fork).

- Copies source excluding .git and multi-GiB PoC mirrors (same skip set as FirewallXPL).
- Keeps payloads/encoders, generic/pcap, generic/bluetooth, generic/wordlist, generic/cve.
- Drops exploits/, creds/, scanners/, and unrelated generic/ subtrees (external, snmp, upnp).
- Renames package ``routerxpl`` -> ``wirelessxpl`` and entrypoint ``wxf.py``.

Run once on a workstation with free disk; copy skips ``incorporated_third_party`` and
``soho_exploit_catalog`` to avoid Windows long-path failures.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import argparse
import json
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

GENERIC_KEEP = frozenset({"pcap", "bluetooth", "wordlist", "cve", "external"})


def _ignore_copy(_dir: str, names: list[str]) -> set[str]:
    """Skip VCS, caches, and heavy PoC mirrors."""

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
        raise SystemExit(
            "Destination already exists: {} (remove or pick another path)".format(dest)
        )
    shutil.copytree(src, dest, ignore=_ignore_copy)


def _trim_module_domains(pkg: Path) -> None:
    """Remove router-style module trees; wireless lab uses generic + payloads + encoders."""

    for name in ("exploits", "creds", "scanners"):
        _rm_tree(pkg / "modules" / name)


def _trim_generic_only_wireless(gen: Path) -> None:
    if not gen.is_dir():
        return
    for child in list(gen.iterdir()):
        if not child.is_dir():
            continue
        if child.name not in GENERIC_KEEP:
            shutil.rmtree(child, ignore_errors=True)


def _trim_heavy_resources(pkg_root: Path) -> None:
    """Match FirewallXPL lightweight clone: no vendored Exploit-DB tree."""

    pocs = pkg_root / "resources" / "arsenal" / "pocs"
    _rm_tree(pocs / "incorporated_third_party")
    _rm_tree(pocs / "soho_exploit_catalog")
    for name in (
        "incorporated_third_party_index.json",
        "soho_catalog_js_index.json",
    ):
        fp = pkg_root / "resources" / "catalogs" / name
        fp.unlink(missing_ok=True)
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
                "WirelessXPL-Forge does not ship the vendored Exploit-DB tree; use upstream "
                "repositories and system tools (aircrack-ng, hcxtools, hashcat) as documented.\n",
            )
            integ.write_text(t, encoding="utf-8", newline="\n")


def _rewrite_text_files(pkg_dir: Path, extra_files: List[Path]) -> None:
    """Replace package prefix and branding."""

    old_mod = "routerxpl/modules/"
    new_mod = "wirelessxpl/modules/"
    rx_word = (
        (re.compile(re.escape("routerxpl")), "wirelessxpl"),
        (re.compile(r"\bRouterXPLInterpreter\b"), "WirelessXPLInterpreter"),
        (re.compile(r"\bRouterXPLException\b"), "WirelessXPLException"),
        (re.compile(r"\bRouterXPL\b"), "WirelessXPL"),
        (re.compile(r"RXF_RAW_PROMPT"), "WXF_RAW_PROMPT"),
        (re.compile(r"RXF_MODULE_PROMPT"), "WXF_MODULE_PROMPT"),
        (re.compile(r"RXF_METASPLOIT_CONSOLE"), "WXF_METASPLOIT_CONSOLE"),
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
        data = data.replace("RouterXPL-Forge", "WirelessXPL-Forge")
        data = data.replace("ROUTERXPL_SOHO_CATALOG_ROOT", "WIRELESSXPL_SOHO_CATALOG_ROOT")
        data = data.replace("routerxpl.log", "wirelessxpl.log")
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
    dst_pkg = dest / "wirelessxpl"
    if not src_pkg.is_dir():
        raise SystemExit("Expected package dir missing: {}".format(src_pkg))
    src_pkg.rename(dst_pkg)
    return dst_pkg


def _write_wxf(dest: Path) -> None:
    """Create ``wxf.py`` from rewritten ``rxf.py``."""

    rxf = dest / "rxf.py"
    wxf = dest / "wxf.py"
    if rxf.is_file():
        text = rxf.read_text(encoding="utf-8")
        text = text.replace("routerxpl", "wirelessxpl")
        text = text.replace("RouterXPL", "WirelessXPL")
        text = text.replace("def routerxpl", "def wirelessxpl")
        text = text.replace("routerxpl(sys.argv)", "wirelessxpl(sys.argv)")
        wxf.write_text(text, encoding="utf-8", newline="\n")
        rxf.unlink(missing_ok=True)
    elif not wxf.is_file():
        raise SystemExit("Neither rxf.py nor wxf.py found at {}".format(dest))


def _write_module_scope(w_root: Path) -> None:
    path = w_root / "resources" / "catalogs" / "module_target_scope.json"
    if not path.is_file():
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    data["version"] = "2.0.0-wireless"
    data["description"] = (
        "WirelessXPL-Forge: offline 802.11 / WPA / WPA3 / TKIP / WPE analysis, BLE tooling, "
        "and wordlist helpers. Live capture and cracking delegate to system tools "
        "(aircrack-ng, hcxtools, hashcat)."
    )
    data["default_allow_classes"] = ["wifi", "wlan", "ble", "80211", "wpa_lab"]
    data["domain_defaults"] = {
        "exploits": ["wifi", "wlan", "ble", "80211", "wpa_lab"],
        "creds": ["wifi", "wlan", "ble", "80211", "wpa_lab"],
    }
    keep_prefix_substrings = (
        "generic/pcap/",
        "generic/bluetooth/",
        "generic/wordlist/",
        "generic/cve/",
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
        t = t.replace('name="routerxpl"', 'name="wirelessxpl"')
        t = t.replace("scripts=('rxf.py',)", "scripts=('wxf.py',)")
        t = t.replace("RouterXPL supports", "WirelessXPL supports")
        t = t.replace("RouterXPL requires", "WirelessXPL requires")
        sp.write_text(t, encoding="utf-8", newline="\n")
    mi = dest / "MANIFEST.in"
    if mi.is_file():
        t = mi.read_text(encoding="utf-8")
        t = t.replace("routerxpl/", "wirelessxpl/")
        mi.write_text(t, encoding="utf-8", newline="\n")


def _rename_exceptions(pkg: Path) -> None:
    ex = pkg / "core" / "exploit" / "exceptions.py"
    if not ex.is_file():
        return
    t = ex.read_text(encoding="utf-8")
    if "class WirelessXPLException" not in t:
        t = t.replace("class RouterXPLException", "class WirelessXPLException")
        t = t.replace("RouterXPLException", "WirelessXPLException")
    ex.write_text(t, encoding="utf-8", newline="\n")


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--source",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="RouterXPL-Forge root",
    )
    ap.add_argument("--dest", type=Path, required=True, help="New WirelessXPL-Forge root")
    args = ap.parse_args(list(argv) if argv is not None else None)
    src: Path = args.source.resolve()
    dest: Path = args.dest.resolve()
    if src == dest:
        return 2

    print("Copy {} -> {}".format(src, dest))
    _copy_source(src, dest)

    pkg_pre = dest / "routerxpl"
    _trim_module_domains(pkg_pre)
    _trim_generic_only_wireless(pkg_pre / "modules" / "generic")
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
    wx_pkg = _rename_package_dir(dest)
    _write_wxf(dest)
    _write_module_scope(wx_pkg)
    _patch_setup_and_manifest(dest)
    _rename_exceptions(wx_pkg)

    print("bootstrap_wirelessxpl_forge: OK -> {}".format(dest))
    print("Next: cd {0} && git init && gh repo create mrhenrike/WirelessXPL-Forge --private".format(dest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
