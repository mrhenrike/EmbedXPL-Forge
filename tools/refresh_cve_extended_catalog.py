#!/usr/bin/env python3
"""Regenerate routerxpl/resources/catalogs/cve_extended_catalog.json from curated rows.

Merges, in order: (1) static rows from ``build_entries()``; (2) CVE IDs listed under
``related_cves_hint`` in ``external_tool_intel_sources.json`` (stubs keyed to source id);
(3) CVE strings found under ``routerxpl/modules/**/*.py`` that are not already covered
by (1) or by ``_EMBEDDED_CVES`` in ``cve_db.py`` (embedded wins — avoids replacing rich
rows with stubs).

(4) PoC repository URLs from vendored ``tg12__PoC_CVEs/cve_links.txt`` are merged **only**
for CVE IDs in scope: all IDs present after (1–3) plus ``_EMBEDDED_CVES`` and
``related_cves_hint`` in ``discord_requested_devices.json``. Appends ``references``
(web URLs) and sets ``exploit_available`` when links are added.

The tg12 index is global; filtering keeps the extended catalog aligned with monitored-edge scope.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

_RX_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_RX_TG12_CVE_LINE = re.compile(r"CVE-\d{4}-\d+")
_RX_GH_REF = re.compile(
    r"https?://github\.com/([\w.-]+)/([\w.,-]+)(?:\.git)?/?(?:[#?].*)?$",
    re.IGNORECASE,
)
_RX_GL_REF = re.compile(
    r"https?://gitlab\.com/([\w./-]+)/([\w.-]+)(?:\.git)?/?(?:[#?].*)?$",
    re.IGNORECASE,
)


def row(
    cve: str,
    vendor: str,
    product: str,
    ver: str,
    desc: str,
    cvss: float,
    av: str = "REMOTE",
    ref: Optional[str] = None,
    exploit_available: bool = False,
) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "cve_id": cve,
        "vendor": vendor,
        "product": product,
        "affected_versions": ver,
        "description": desc,
        "cvss_score": cvss,
        "access_vector": av,
        "exploit_available": exploit_available,
    }
    if ref:
        d["references"] = [ref]
    return d


def build_entries() -> List[Dict[str, Any]]:
    e: List[Dict[str, Any]] = []
    # Fortinet — pandemia e pós-pandemia (SSL-VPN / admin / SSO)
    e.extend(
        [
            row(
                "CVE-2018-13379",
                "fortinet",
                "fortigate",
                "FortiOS 5.6.3–6.0.4 SSL-VPN",
                "Path traversal / credenciais expostas na interface SSL VPN",
                9.1,
                ref="https://www.fortiguard.com/psirt/FG-IR-18-384",
                exploit_available=True,
            ),
            row(
                "CVE-2018-13382",
                "fortinet",
                "fortigate",
                "FortiOS 5.6.x–6.0.x",
                "Falha de autorização em SSL VPN",
                9.8,
                exploit_available=True,
            ),
            row("CVE-2018-13383", "fortinet", "fortigate", "FortiOS", "Heap overflow histórico SSL VPN", 8.8, exploit_available=True),
            row("CVE-2019-5598", "fortinet", "fortigate", "FortiOS", "Vulnerabilidade SSL VPN", 9.8, exploit_available=True),
            row("CVE-2020-12812", "fortinet", "fortigate", "FortiOS 6.4–6.4.1, 6.2.5–6.2.7", "Bypass de 2FA em SSL VPN", 9.8, exploit_available=True),
            row("CVE-2020-29015", "fortinet", "fortigate", "FortiOS", "Impacto CSRF / interface web", 7.5),
            row("CVE-2021-1722", "fortinet", "fortigate", "FortiOS SSL-VPN", "Heap buffer overflow", 7.5, exploit_available=True),
            row("CVE-2021-22123", "fortinet", "fortigate", "FortiWeb/FortiOS", "Stack buffer overflow", 9.3, exploit_available=True),
            row("CVE-2021-32589", "fortinet", "fortigate", "FortiOS SSL-VPN", "Use-after-free", 8.7, exploit_available=True),
            row("CVE-2022-26125", "fortinet", "fortigate", "FortiOS", "Escrita fora dos limites HTTP/HTTPS", 8.1),
            row(
                "CVE-2022-40684",
                "fortinet",
                "fortigate",
                "FortiOS 7.0.0–7.0.6, 7.2.0–7.2.1",
                "Bypass de autenticação via requisição HTTP(S) forjada",
                9.8,
                exploit_available=True,
            ),
            row("CVE-2022-42475", "fortinet", "fortigate", "FortiOS SSL-VPN (múltiplas branches)", "Heap overflow pré-auth RCE SSL VPN", 9.3, exploit_available=True),
            row(
                "CVE-2023-27997",
                "fortinet",
                "fortigate",
                "FortiOS SSL-VPN (várias séries)",
                "Heap overflow pré-autenticação em SSL VPN (XR variant amplamente explorada)",
                9.8,
                exploit_available=True,
            ),
            row("CVE-2023-28001", "fortinet", "fortigate", "FortiOS", "Sessão REST API / expiração insuficiente", 9.8),
            row("CVE-2023-33308", "fortinet", "fortigate", "FortiOS 7.0–7.2", "Stack overflow", 9.8),
            row("CVE-2023-36633", "fortinet", "fortigate", "FortiOS", "Corrupção de memória / format string class", 9.8),
            row("CVE-2023-42789", "fortinet", "fortigate", "FortiOS", "Escrita fora dos limites via HTTP", 9.8),
            row("CVE-2024-21762", "fortinet", "fortigate", "FortiOS 7.4–7.0 SSL-VPN", "Escrita fora dos limites SSL VPN RCE", 9.6, exploit_available=True),
            row("CVE-2024-23113", "fortinet", "fortigate", "FortiOS", "Format string", 9.8, exploit_available=True),
            row("CVE-2024-52965", "fortinet", "fortigate", "FortiOS", "Correção de memória ( advisories Fortinet)", 8.6),
            row("CVE-2024-55599", "fortinet", "fortigate", "FortiOS", "Advisory cumulativo FortiOS", 8.8),
            row("CVE-2025-24477", "fortinet", "fortigate", "FortiOS", "FortiOS security fix (verificar versão exata no PSIRT)", 8.5),
            row(
                "CVE-2025-59718",
                "fortinet",
                "fortigate",
                "FortiOS FortiCloud SSO (7.x)",
                "Falha em verificação SAML / bypass SSO administrativo",
                9.8,
                exploit_available=True,
            ),
            row("CVE-2025-59719", "fortinet", "fortigate", "FortiOS FortiCloud SSO", "Autenticação SSO fraca / chained impact", 9.1, exploit_available=True),
        ]
    )
    # Cisco, Juniper, PAN, edge SSL VPN / NGFW-adjacent
    e.extend(
        [
            row("CVE-2023-20198", "cisco", "ios_xe", "IOS XE Web UI", "Elevação de privilégio via Web UI (contas locais)", 10.0, exploit_available=True),
            row("CVE-2023-20273", "cisco", "ios_xe", "IOS XE Web UI", "Command injection pós-auth", 7.2, exploit_available=True),
            row("CVE-2024-20353", "cisco", "asa", "ASA", "Advisory VPN/SSL", 8.2),
            row("CVE-2024-20359", "cisco", "ios_xe", "IOS XE", "Elevação / hardening", 8.8),
            row("CVE-2023-36844", "juniper", "junos", "EX/SRX J-Web", "Cadeia RCE J-Web PHP", 9.8, exploit_available=True),
            row("CVE-2023-36845", "juniper", "junos", "EX/SRX J-Web", "Manipulação de ambiente PHP RCE", 9.8, exploit_available=True),
            row("CVE-2024-3400", "paloalto", "pan-os", "PAN-OS GlobalProtect", "Command injection GlobalProtect RCE", 10.0, exploit_available=True),
            row("CVE-2021-3064", "paloalto", "pan-os", "PAN-OS GlobalProtect", "Buffer overflow", 9.8, exploit_available=True),
            row("CVE-2021-20016", "sonicwall", "sma", "SMA 100", "SQLi / credenciais", 9.8, exploit_available=True),
            row("CVE-2021-20038", "sonicwall", "sonicwall", "SMA 100", "Stack buffer overflow RCE", 9.8, exploit_available=True),
            row("CVE-2022-1040", "sophos", "xg_firewall", "Sophos XG", "Bypass de autenticação / SQL", 9.8, exploit_available=True),
            row("CVE-2024-24919", "checkpoint", "quantum", "Check Point Gaia", "Path traversal / cadeia de impacto", 8.6, exploit_available=True),
            row("CVE-2022-1388", "f5", "bigip", "BIG-IP iControl REST", "Bypass de auth RCE", 9.8, exploit_available=True),
            row("CVE-2023-46747", "f5", "bigip", "BIG-IP", "Cadeia RCE iControl", 9.8, exploit_available=True),
            row("CVE-2024-26026", "ivanti", "connect_secure", "Ivanti Connect Secure", "Stack overflow SSL VPN", 9.0, exploit_available=True),
            row("CVE-2024-21887", "ivanti", "connect_secure", "Ivanti Connect Secure", "Command injection", 9.1, exploit_available=True),
            row("CVE-2024-21893", "ivanti", "connect_secure", "Ivanti Connect Secure", "SSRF", 8.2, exploit_available=True),
            row("CVE-2025-0282", "ivanti", "connect_secure", "Ivanti Connect Secure", "Heap overflow / RCE (patched versions no PSIRT)", 9.0, exploit_available=True),
            row("CVE-2021-35395", "zyxel", "firewall", "Múltiplos Zyxel", "Command injection", 9.8, exploit_available=True),
            row("CVE-2022-30525", "zyxel", "firewall", "USG FLEX", "OS command injection", 9.8, exploit_available=True),
            row("CVE-2023-28771", "zyxel", "multiple", "CPE Zyxel", "Format string via SMS / remoto", 9.1, exploit_available=True),
            row("CVE-2023-30799", "mikrotik", "routeros", "RouterOS", "Escalação admin→super-admin", 7.2, exploit_available=True),
            row("CVE-2021-34991", "netgear", "router", "Netgear Circle / Nighthawk class", "Buffer overflow RCE não autenticado", 9.8, exploit_available=True),
            row("CVE-2023-1389", "tplink", "router", "Archer AX21 family", "Command injection", 8.8, exploit_available=True),
            row("CVE-2022-25077", "tplink", "router", "WR841N family", "Buffer overflow HTTPD", 8.8, exploit_available=True),
            row("CVE-2017-14116", "pace", "5268ac", "Pace 5268AC", "Exposição de configuração / credenciais", 7.5),
            row("CVE-2018-10562", "generic", "gpon_onu", "ONU GPON classe Dasan", "Bypass massivo em ONU (classe CPE barata)", 9.8, exploit_available=True),
            row("CVE-2017-9833", "hitron", "modem", "Hitron CGNV / ISP CPE", "Bypass / config", 8.1),
            row("CVE-2022-26531", "draytek", "vigor", "Vigor", "Command injection", 9.8, exploit_available=True),
            row("CVE-2023-47218", "watchguard", "firebox", "Firebox", "Stack overflow", 9.8, exploit_available=True),
            row("CVE-2019-11510", "pulse", "pulse_secure", "Pulse Connect Secure", "Leitura arbitrária de ficheiros", 10.0, exploit_available=True),
            row("CVE-2021-22893", "pulse", "pulse_connect", "Pulse Secure", "RCE / memory safety", 9.9, exploit_available=True),
            row("CVE-2024-0012", "aruba", "instant_on", "Aruba Instant On", "Bypass de autenticação (verificar firmware)", 9.1),
            row("CVE-2020-10882", "tplink", "router", "Archer A7 v5", "tdpServer buffer overflow RCE (LAN)", 8.8, "ADJACENT"),
            row("CVE-2020-25506", "dlink", "router", "D-Link DSR/DWL", "Comand injection web", 9.8, exploit_available=True),
            row("CVE-2020-9325", "dlink", "router", "DIR seriado", "Stack overflow HTTP", 8.8),
            row("CVE-2021-4045", "realtek", "sdk", "Realtek RTL819x SDK", "RCE em firmware baseado RTL819x", 9.8, exploit_available=True),
            row("CVE-2021-44228", "generic", "log4j", "Apps com Log4j em CPE/gestão", "Log4Shell (cadeias de gestão / SDN)", 10.0, exploit_available=True),
            row("CVE-2022-30075", "tplink", "router", "Archer AX50 v1", "RCE autenticado via backup", 8.8, exploit_available=True),
            row("CVE-2022-41607", "cisco", "small_business", "Cisco RV routers", "Buffer overflow (advisory)", 8.2),
            row("CVE-2023-20025", "cisco", "small_business", "Cisco RV160/260/340", "Auth bypass (verificar)", 9.8, exploit_available=True),
            row("CVE-2024-20419", "cisco", "asa", "ASA", "VPN/SSL advisory", 8.1),
            row("CVE-2024-20464", "cisco", "ios_xe", "IOS XE", "DoS / hardening", 7.5),
            row("CVE-2024-45789", "mikrotik", "routeros", "RouterOS Winbox", "Correções Winbox/crypto chain", 7.8),
            row("CVE-2025-20194", "cisco", "ios_xe", "IOS XE SD-WAN", "Advisory Cisco (verificar)", 8.4),
            row("CVE-2020-5135", "sonicwall", "sonicwall", "SonicOS", "Buffer overflow VPN", 9.4),
            row("CVE-2021-3140", "fortinet", "fortimanager", "FortiManager", "RCE / auth issues", 8.6),
            row("CVE-2022-27482", "hirschmann", "switch", "Hirschmann HiOS", "Switch industrial hardening", 7.3),
            row("CVE-2023-22305", "moxa", "switch", "Moxa industrial switches", "Auth / web", 8.8),
            row("CVE-2024-3272", "dlink", "switch", "D-Link DGS", "Stack overflow web (verificar modelo)", 8.8),
            row("CVE-2024-3273", "dlink", "switch", "D-Link", "Backdoor / credenciais hardcoded class", 9.8, exploit_available=True),
            row("CVE-2021-20090", "arcadyan", "router", "Arcadyan-based ISP CPE", "Auth bypass (múltiplos ISP)", 9.9, exploit_available=True),
            row("CVE-2021-20091", "buffalo", "router", "Buffalo WSR", "Auth bypass", 9.6),
            row("CVE-2022-44149", "tenda", "router", "Tenda AC seriado", "Buffer overflow", 9.8, exploit_available=True),
            row("CVE-2023-27259", "tenda", "router", "Tenda", "RCE HTTPD", 8.1),
            row("CVE-2019-16920", "dlink", "router", "DIR-655 family", "RCE não autenticado", 9.8, exploit_available=True),
            row("CVE-2020-12105", "mikrotik", "routeros", "RouterOS", "Vulnerabilidade SMB RouterOS (corrigida em releases posteriores)", 5.5),
            row("CVE-2019-5456", "ubiquiti", "unifi", "UniFi Controller", "CSRF / alteração de configuração", 8.8, exploit_available=True),
        ]
    )
    return e


def _guess_vendor_from_intel_id(id_slug: str) -> str:
    """Best-effort vendor token from ``local-poc-*`` style source id."""

    s = id_slug.lower()
    pairs: Tuple[Tuple[str, str], ...] = (
        ("tp-link", "tplink"),
        ("tplink", "tplink"),
        ("cisco", "cisco"),
        ("trendnet", "trendnet"),
        ("mikrot", "mikrotik"),
        ("intelbras", "intelbras"),
        ("xiaomi", "xiaomi"),
        ("openwrt", "openwrt"),
        ("asus", "asus"),
        ("d-link", "dlink"),
        ("dlink", "dlink"),
        ("netgear", "netgear"),
        ("ubiquiti", "ubiquiti"),
        ("fortinet", "fortinet"),
        ("zyxel", "zyxel"),
        ("palo", "paloalto"),
        ("juniper", "juniper"),
        ("hirschmann", "hirschmann"),
        ("moxa", "moxa"),
        ("draytek", "draytek"),
        ("tenda", "tenda"),
        ("arcadyan", "arcadyan"),
        ("buffalo", "buffalo"),
        ("realtek", "realtek"),
        ("huawei", "huawei"),
        ("hitron", "hitron"),
        ("pace", "pace"),
    )
    for needle, vendor in pairs:
        if needle in s:
            return vendor
    return "multi"


def _vendor_product_from_module_path(rel_posix: str) -> Tuple[str, str]:
    """Derive vendor/product hints from ``modules`` relative path."""

    parts = rel_posix.split("/")
    if len(parts) >= 3 and parts[0] == "exploits":
        if parts[1] == "routers":
            return parts[2], "router"
        if parts[1] == "misc":
            return parts[2], "device"
        if parts[1] == "generic":
            return "generic", Path(parts[2]).stem
    if parts[0] == "creds" and len(parts) >= 3 and parts[1] == "routers":
        return parts[2], "router"
    if parts[0] == "scanners" and len(parts) >= 3 and parts[1] == "routers":
        return parts[2], "router"
    if parts[0] == "generic" and len(parts) >= 2:
        return "generic", parts[1]
    if parts[0] == "encoders":
        return "encoder", parts[1] if len(parts) > 1 else "generic"
    if parts[0] == "payloads":
        return "payload", parts[1] if len(parts) > 1 else "generic"
    return "routerxpl", parts[0]


def _entries_from_external_intel(repo_root: Path, seen: Set[str]) -> List[Dict[str, Any]]:
    path = repo_root / "routerxpl" / "resources" / "catalogs" / "external_tool_intel_sources.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: List[Dict[str, Any]] = []
    for source in data.get("sources") or []:
        sid = str(source.get("id") or "")
        name = str(source.get("name") or sid)
        dom = str(source.get("domain") or "")
        url = source.get("url")
        for raw_cve in source.get("related_cves_hint") or []:
            if not isinstance(raw_cve, str):
                continue
            m = _RX_CVE.search(raw_cve)
            if not m:
                continue
            cve = m.group(0).upper()
            if cve in seen:
                continue
            seen.add(cve)
            vendor = _guess_vendor_from_intel_id(sid)
            desc = (
                "Referenciado em external_tool_intel_sources (id={}); domínio catalogado: {}. "
                "PoC/repo local listado — validar com NVD/PSIRT."
            ).format(sid, dom or "n/d")
            ver = "Ver fonte: {} / NVD".format(name[:120])
            out.append(
                row(
                    cve,
                    vendor,
                    "edge_research",
                    ver,
                    desc,
                    0.0,
                    exploit_available=True,
                    ref=str(url) if url else None,
                ),
            )
    return out


def _entries_from_modules(repo_root: Path, seen: Set[str]) -> List[Dict[str, Any]]:
    mods = repo_root / "routerxpl" / "modules"
    if not mods.is_dir():
        return []
    out: List[Dict[str, Any]] = []
    for py in sorted(mods.rglob("*.py")):
        if py.name.startswith("__") or "__pycache__" in py.parts:
            continue
        rel = py.relative_to(mods).as_posix()
        try:
            text = py.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in _RX_CVE.findall(text):
            cve = m.upper()
            if cve in seen:
                continue
            seen.add(cve)
            vendor, prod = _vendor_product_from_module_path(rel)
            desc = (
                "CVE citado no módulo RouterXPL ``{}``. "
                "Confirmar produto/versões no fabricante (NVD).".format(rel)
            )
            out.append(
                row(
                    cve,
                    vendor,
                    prod,
                    "Ver módulo: {}".format(rel),
                    desc,
                    0.0,
                ),
            )
    return out


def _strip_tg12_cell(line: str) -> str:
    """Strip ASCII table padding and surrounding ``|`` cells (tg12 cve_links)."""

    return line.strip().strip("|").strip()


def _parse_tg12_txt_cve_url_blocks(path: Path) -> List[Dict[str, Any]]:
    """Return list of dicts with cve_id and urls from tg12 ``cve_links.txt``."""

    text = path.read_text(encoding="utf-8", errors="replace")
    entries: List[Dict[str, Any]] = []
    current: Optional[str] = None
    buf_urls: List[str] = []

    def flush() -> None:
        nonlocal current, buf_urls
        if current and buf_urls:
            entries.append({"cve_id": current, "urls": list(buf_urls)})
        buf_urls = []

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.startswith("|"):
            continue
        cell = _strip_tg12_cell(line)
        if not cell or cell.startswith("+") or set(cell) <= {"-", "+"}:
            continue
        if cell.startswith("CVE-"):
            flush()
            m = _RX_TG12_CVE_LINE.search(cell)
            current = m.group(0).upper() if m else None
            continue
        if cell.startswith("http") and current:
            buf_urls.append(cell.split()[0])
            continue

    flush()
    return entries


def _normalize_poc_repo_ref(url: str) -> Optional[str]:
    """Normalize GitHub/GitLab clone/browse URL to a stable https reference."""

    u = url.strip()
    mg = _RX_GH_REF.match(u)
    if mg:
        return "https://github.com/{}/{}".format(mg.group(1), mg.group(2).rstrip("/"))
    ml = _RX_GL_REF.match(u)
    if ml:
        op = ml.group(1).strip("/")
        repo = ml.group(2).rstrip("/")
        return "https://gitlab.com/{}/{}".format(op, repo)
    return None


def _tg12_cve_to_poc_refs(path: Path) -> Dict[str, List[str]]:
    """CVE upper-case -> ordered unique PoC repository URLs from tg12 ``cve_links.txt``."""

    if not path.is_file():
        return {}
    out: Dict[str, List[str]] = {}
    for block in _parse_tg12_txt_cve_url_blocks(path):
        cid = str(block["cve_id"]).upper()
        bucket = out.setdefault(cid, [])
        for raw_u in block.get("urls") or []:
            norm = _normalize_poc_repo_ref(raw_u)
            if norm and norm not in bucket:
                bucket.append(norm)
    return out


def _discord_related_cve_hints(repo_root: Path) -> Set[str]:
    path = repo_root / "routerxpl" / "resources" / "catalogs" / "discord_requested_devices.json"
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    out: Set[str] = set()
    for ent in data.get("entries") or []:
        for raw in ent.get("related_cves_hint") or []:
            if not isinstance(raw, str):
                continue
            m = _RX_CVE.search(raw)
            if m:
                out.add(m.group(0).upper())
    return out


def _ensure_refs_list(entry: Dict[str, Any]) -> List[str]:
    r = entry.get("references")
    if r is None:
        entry["references"] = []
        return entry["references"]
    if isinstance(r, list):
        return r
    entry["references"] = [str(r)]
    return entry["references"]


def _merge_tg12_poc_refs_for_scope(
    entries: List[Dict[str, Any]],
    tg12_map: Dict[str, List[str]],
    scope_cves: Set[str],
    embedded_by_id: Dict[str, Dict[str, Any]],
) -> Tuple[int, int, int]:
    """Merge tg12 URLs into ``entries`` for IDs in ``scope_cves``.

    Returns:
        (refs_appended_to_existing, new_rows_from_embedded, new_stub_rows)
    """

    by_id: Dict[str, Dict[str, Any]] = {str(e["cve_id"]).upper(): e for e in entries}
    added_refs = 0
    new_from_emb = 0
    new_stub = 0
    skip_canonical = "https://github.com/tg12/PoC_CVEs"

    for cve in sorted(scope_cves):
        urls = tg12_map.get(cve)
        if not urls:
            continue
        clean = [u for u in urls if not u.lower().startswith(skip_canonical.lower())]
        if not clean:
            continue
        if cve in by_id:
            refs = _ensure_refs_list(by_id[cve])
            for u in clean:
                if u not in refs:
                    refs.append(u)
                    added_refs += 1
            by_id[cve]["exploit_available"] = True
            continue
        emb = embedded_by_id.get(cve)
        if emb:
            neo = {k: v for k, v in emb.items() if k != "references"}
            neo["references"] = list(emb.get("references") or [])
            for u in clean:
                if u not in neo["references"]:
                    neo["references"].append(u)
            neo["exploit_available"] = True
            by_id[cve] = neo
            new_from_emb += 1
            continue
        neo = row(
            cve,
            "multi",
            "edge_research",
            "Ver NVD/PSIRT — linha derivada de tg12/cve_links (âmbito monitorado)",
            "PoC listado no índice tg12 para CVE em âmbito RouterXPL; validar impacto e licença.",
            0.0,
            exploit_available=True,
        )
        rfs = _ensure_refs_list(neo)
        for u in clean:
            if u not in rfs:
                rfs.append(u)
        by_id[cve] = neo
        new_stub += 1

    entries[:] = sorted(by_id.values(), key=lambda r: str(r.get("cve_id", "")))
    return added_refs, new_from_emb, new_stub


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))
    from routerxpl.core.cve.cve_db import _EMBEDDED_CVES

    embedded_ids: Set[str] = {str(x["cve_id"]).upper() for x in _EMBEDDED_CVES}
    embedded_by_id: Dict[str, Dict[str, Any]] = {
        str(x["cve_id"]).upper(): x for x in _EMBEDDED_CVES
    }

    base = build_entries()
    seen: Set[str] = {str(e["cve_id"]).upper() for e in base} | embedded_ids

    auto_intel = _entries_from_external_intel(root, seen)
    auto_mod = _entries_from_modules(root, seen)

    extra = auto_intel + sorted(auto_mod, key=lambda r: r["cve_id"])
    entries = base + extra

    tg12_txt = (
        root
        / "routerxpl"
        / "resources"
        / "arsenal"
        / "pocs"
        / "incorporated_third_party"
        / "tg12__PoC_CVEs"
        / "cve_links.txt"
    )
    tg12_map = _tg12_cve_to_poc_refs(tg12_txt)
    scope_cves: Set[str] = (
        {str(e["cve_id"]).upper() for e in entries} | embedded_ids | _discord_related_cve_hints(root)
    )
    tg_merged = _merge_tg12_poc_refs_for_scope(entries, tg12_map, scope_cves, embedded_by_id)

    payload = {
        "catalog_note": (
            "Índice estendido offline para RouterXPL-Forge (lookup). "
            "Não substitui NVD/CISA; cruze sempre com firmware e PSIRT do fabricante."
        ),
        "entry_count": len(entries),
        "entries": entries,
        "seed_sources_note": (
            "Linhas iniciais: matrix estática. Acrescimos: related_cves_hint em "
            "external_tool_intel_sources.json; CVEs em routerxpl/modules exceto IDs já "
            "presentes aqui ou em cve_db._EMBEDDED_CVES; referências PoC GitHub/GitLab a "
            "partir de tg12__PoC_CVEs/cve_links.txt (filtrado por IDs em âmbito)."
        ),
    }
    out = root / "routerxpl" / "resources" / "catalogs" / "cve_extended_catalog.json"
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(
        "wrote {} entries (+{} intel, +{} modules) tg12: +{} ref appends, +{} from embedded, "
        "+{} stubs -> {}".format(
            len(entries),
            len(auto_intel),
            len(auto_mod),
            tg_merged[0],
            tg_merged[1],
            tg_merged[2],
            out,
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
