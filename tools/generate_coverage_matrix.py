#!/usr/bin/env python3
"""Generate vendor/product capability coverage matrix from modules."""

from __future__ import annotations

# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

import ast
import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Set, Tuple


LOGGER = logging.getLogger("coverage_matrix")

REPO_ROOT = Path(__file__).resolve().parent.parent


def _matrix_source_revision(repo_root: Path) -> str:
    """Return git tree id for routerxpl/modules (stable for a checkout; not the commit hash)."""
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD:routerxpl/modules"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        rev = (completed.stdout or "").strip()
        if completed.returncode == 0 and rev:
            return rev
    except (OSError, subprocess.TimeoutExpired):
        pass
    return datetime.now(timezone.utc).isoformat()


RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
DISABLED_DOMAINS: Tuple[str, ...] = ("cameras", "printers", "dvr", "dvrs")

ATTACK_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    "rce": ("_rce", "remote code execution", "command injection", "shellshock"),
    "info_disclosure": ("info_disclosure", "information disclosure", "leak"),
    "creds_disclosure": ("creds_disclosure", "credential disclosure", "password disclosure", "extract_hashes"),
    "auth_bypass": ("auth_bypass", "authbypass", "authorization bypass", "authentication bypass"),
    "path_traversal": ("path_traversal", "directory traversal", "file traversal"),
    "backdoor": ("backdoor",),
    "dns_change": ("dns_change",),
    "password_reset_or_change": ("password_reset", "password_change"),
    "dos_or_crash": ("denial of service", "dos"),
}


@dataclass
class ModuleRecord:
    """Normalized metadata extracted from each module file."""

    module_path: str
    module_type: str
    domain: str
    vendor: str
    product: str
    module_name: str
    description: str
    cves: List[str]
    attack_classes: List[str]


@dataclass
class CoverageEntry:
    """Aggregated capability matrix row per vendor/product."""

    vendor: str
    product: str
    module_count: int = 0
    exploit_count: int = 0
    creds_count: int = 0
    scanner_count: int = 0
    generic_count: int = 0
    payload_count: int = 0
    encoder_count: int = 0
    cves: Set[str] = field(default_factory=set)
    attack_classes: Set[str] = field(default_factory=set)
    module_paths: List[str] = field(default_factory=list)


def _configure_logging() -> None:
    """Initialize logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _safe_literal_eval(node: ast.AST) -> object | None:
    """Evaluate literals safely from AST nodes."""
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def _extract_info_dict(source: str) -> Dict[str, object]:
    """Extract class-level __info__ dictionary from module source."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__info__":
                    data = _safe_literal_eval(node.value)
                    if isinstance(data, dict):
                        return data
    return {}


def _classify_attack(filename: str, description: str) -> List[str]:
    """Infer attack classes from filename and description."""
    normalized = f"{filename.lower()} {description.lower()}"
    found: List[str] = []
    for attack_class, keywords in ATTACK_KEYWORDS.items():
        if any(keyword in normalized for keyword in keywords):
            found.append(attack_class)
    return sorted(found)


def _split_module_parts(module_file: Path, modules_root: Path) -> Tuple[str, str, str, str]:
    """Resolve module_type/domain/vendor/product from path."""
    rel = module_file.relative_to(modules_root).as_posix()
    parts = rel.split("/")
    module_type = parts[0] if len(parts) > 0 else "unknown"
    domain = parts[1] if len(parts) > 1 else "global"

    vendor = "multi"
    product = module_file.stem

    if module_type in {"exploits", "creds"}:
        vendor = parts[2] if len(parts) > 2 else "multi"
        product = module_file.stem
    elif module_type == "scanners":
        vendor = domain if len(parts) > 2 else "scanners"
        product = module_file.stem
    elif module_type == "generic":
        vendor = domain
        product = module_file.stem
    elif module_type == "payloads":
        vendor = parts[1] if len(parts) > 1 else "multi"
        product = module_file.stem
    elif module_type == "encoders":
        vendor = parts[1] if len(parts) > 1 else "multi"
        product = module_file.stem

    return module_type, domain, vendor, product


def _extract_module_record(module_file: Path, modules_root: Path) -> ModuleRecord:
    """Extract normalized coverage data from a module file."""
    source: str = module_file.read_text(encoding="utf-8", errors="ignore")
    info = _extract_info_dict(source)

    module_type, domain, vendor, product = _split_module_parts(module_file, modules_root)
    module_name = str(info.get("name", module_file.stem))
    description = str(info.get("description", "")).replace("\n", " ").strip()
    cves = sorted({cve.upper() for cve in RE_CVE.findall(source)})
    attack_classes = _classify_attack(module_file.stem, description)

    rel_module = module_file.relative_to(modules_root.parent).as_posix()
    return ModuleRecord(
        module_path=rel_module,
        module_type=module_type,
        domain=domain,
        vendor=vendor,
        product=product,
        module_name=module_name,
        description=description,
        cves=cves,
        attack_classes=attack_classes,
    )


def _record_in_scope(record: ModuleRecord) -> bool:
    """Return True when module belongs to active product scope."""
    path_parts = record.module_path.split("/")
    return not any(part in DISABLED_DOMAINS for part in path_parts)


def _aggregate(records: List[ModuleRecord]) -> Dict[Tuple[str, str], CoverageEntry]:
    """Aggregate module records into vendor/product entries."""
    matrix: Dict[Tuple[str, str], CoverageEntry] = {}
    for record in records:
        key = (record.vendor.lower(), record.product.lower())
        if key not in matrix:
            matrix[key] = CoverageEntry(vendor=record.vendor, product=record.product)

        entry = matrix[key]
        entry.module_count += 1
        entry.module_paths.append(record.module_path)
        entry.cves.update(record.cves)
        entry.attack_classes.update(record.attack_classes)

        if record.module_type == "exploits":
            entry.exploit_count += 1
        elif record.module_type == "creds":
            entry.creds_count += 1
        elif record.module_type == "scanners":
            entry.scanner_count += 1
        elif record.module_type == "generic":
            entry.generic_count += 1
        elif record.module_type == "payloads":
            entry.payload_count += 1
        elif record.module_type == "encoders":
            entry.encoder_count += 1

    for entry in matrix.values():
        entry.module_paths = sorted(set(entry.module_paths))
    return matrix


def _platform_section() -> str:
    """Return current platform compatibility status text."""
    return (
        "## Product Scope\n\n"
        "- In scope: routers, switches, taps, fw and ngfw (residential, ISP, enterprise/corporate, industrial; IT/OT/AT/IoT/IIoT).\n"
        "- Out of scope: camera/printer/dvr modules (disabled in this product line).\n\n"
        "## Platform Compatibility Status\n\n"
        "| Platform | Status |\n"
        "|---|---|\n"
        "| Windows | Compatible (validated locally) |\n"
        "| WSL / Debian-based Linux | Compatible (validated locally) |\n"
        "| RHEL-based Linux | Compatible by design, not tested effectively yet |\n"
        "| macOS | Compatible by design, not tested effectively yet |\n"
        "| Termux / Android / NetHunter | Compatible by design, not tested effectively yet |\n"
    )


def _protocol_coverage(records: List[ModuleRecord]) -> str:
    """Summarize protocol coverage inferred from module paths/names."""
    protocol_tokens = {
        "ftp": ("ftp",),
        "ftps": ("ftps",),
        "sftp": ("sftp",),
        "ssh": ("ssh", "ssh_auth_keys"),
        "telnet": ("telnet",),
        "snmp": ("snmp",),
        "snmp_trap": ("snmptrap", "snmp_trap"),
        "api": ("api", "routeros"),
        "http": ("http", "webinterface"),
        "https": ("https",),
    }

    text_pool = []
    for item in records:
        text_pool.append("{} {} {}".format(item.module_path.lower(), item.module_name.lower(), item.description.lower()))
    whole = "\n".join(text_pool)

    lines = [
        "## Protocol Coverage (Inferred)",
        "",
        "| Protocol | Covered |",
        "|---|---|",
    ]
    for protocol, tokens in protocol_tokens.items():
        covered = any(token in whole for token in tokens)
        lines.append("| {} | {} |".format(protocol, "yes" if covered else "no"))
    return "\n".join(lines)


def _token_hits(records: List[ModuleRecord], tokens: List[str]) -> int:
    """Count module records matching any token in path/name/description."""
    if not tokens:
        return 0
    lowered_tokens = [token.lower() for token in tokens]
    hits = 0
    for rec in records:
        blob = "{} {} {}".format(rec.module_path.lower(), rec.module_name.lower(), rec.description.lower())
        if any(token in blob for token in lowered_tokens):
            hits += 1
    return hits


def _osi_tcpip_coverage_section(records: List[ModuleRecord], repo_root: Path) -> str:
    """Render OSI/TCP-IP coverage by layer, protocol and environment priority."""
    catalog_path = repo_root / "routerxpl" / "resources" / "catalogs" / "osi_tcpip_priority_matrix.json"
    if not catalog_path.exists():
        return "## OSI/TCP-IP Coverage Matrix\n\n- osi_tcpip_priority_matrix.json not found."

    payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    layers = payload.get("layers", [])
    envs = payload.get("environments", [])
    priorities = payload.get("priority_definitions", {})

    lines: List[str] = [
        "## OSI/TCP-IP Coverage Matrix",
        "",
        "### Priority Definitions",
        "",
    ]
    for key in sorted(priorities.keys()):
        lines.append("- {}: {}".format(key, priorities[key]))

    lines.extend(
        [
            "",
            "### Environment Focus",
            "",
            "| Environment | Priority Order | Focus |",
            "|---|---|---|",
        ]
    )
    for env in envs:
        lines.append(
            "| {} | {} | {} |".format(
                env.get("name", ""),
                env.get("priority_order", ""),
                str(env.get("focus", "")).replace("|", "/"),
            )
        )

    lines.extend(
        [
            "",
            "### Layer Attack/Test Matrix",
            "",
            "| OSI | Layer | Attack Vectors | Test Types |",
            "|---|---|---|---|",
        ]
    )
    for layer in layers:
        osi_layer = str(layer.get("osi_layer", ""))
        layer_name = str(layer.get("layer_name", ""))
        attacks = [str(item) for item in layer.get("attack_matrix", [])]
        tests = [str(item) for item in layer.get("test_matrix", [])]
        lines.append(
            "| {} | {} | {} | {} |".format(
                osi_layer,
                layer_name,
                ", ".join(attacks) if attacks else "-",
                ", ".join(tests) if tests else "-",
            )
        )

    lines.extend(
        [
            "",
            "### Layer and Protocol Coverage (Inferred)",
            "",
            "| OSI | TCP/IP | Layer | Protocol | Module Hits | Covered | Attack Vectors | Test Types | ISP | Corporate | OT_IIoT |",
            "|---|---|---|---|---:|---|---|---|---|---|---|",
        ]
    )

    layer_hit_totals: Dict[str, int] = {}
    for layer in layers:
        osi_layer = str(layer.get("osi_layer", ""))
        tcpip_layer = str(layer.get("tcpip_layer", ""))
        layer_name = str(layer.get("layer_name", ""))
        protocols = layer.get("protocols", [])
        layer_hits = 0
        layer_attacks = [str(item) for item in layer.get("attack_matrix", [])]
        layer_tests = [str(item) for item in layer.get("test_matrix", [])]
        for proto in protocols:
            name = str(proto.get("name", ""))
            tokens = [str(token) for token in proto.get("tokens", [])]
            hits = _token_hits(records, tokens)
            layer_hits += hits
            priority = proto.get("priority_by_env", {})
            proto_attacks = [str(item) for item in proto.get("attack_vectors", [])]
            proto_tests = [str(item) for item in proto.get("test_types", [])]
            lines.append(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                    osi_layer,
                    tcpip_layer,
                    layer_name,
                    name,
                    hits,
                    "yes" if hits > 0 else "no",
                    ", ".join(proto_attacks if proto_attacks else layer_attacks) if (proto_attacks or layer_attacks) else "-",
                    ", ".join(proto_tests if proto_tests else layer_tests) if (proto_tests or layer_tests) else "-",
                    priority.get("ISP", "-"),
                    priority.get("Corporate", "-"),
                    priority.get("OT_IIoT", "-"),
                )
            )
        layer_hit_totals["{} {}".format(osi_layer, layer_name)] = layer_hits

    lines.extend(
        [
            "",
            "### Layer Hit Totals",
            "",
            "| Layer | Total Protocol Hits |",
            "|---|---:|",
        ]
    )
    for layer_name, total in layer_hit_totals.items():
        lines.append("| {} | {} |".format(layer_name, total))

    return "\n".join(lines)


def _normalize_vendor_name(value: str) -> str:
    """Normalize vendor labels for matching coverage targets."""
    cleaned = (value or "").strip().lower()
    aliases = {
        "tp-link": "tplink",
        "d-link": "dlink",
        "rogers/shaw": "rogers",
        "isp multi-vendor": "multi",
    }
    return aliases.get(cleaned, cleaned)


def _normalize_keyword_token(value: str) -> str:
    """Normalize tokens to support hyphen/space/format variations."""
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


def _keyword_matches(blob: str, keyword: str) -> bool:
    """Return True when keyword matches raw or normalized blob."""
    raw_blob = (blob or "").lower()
    raw_kw = (keyword or "").lower().strip()
    if not raw_kw:
        return False
    if raw_kw in raw_blob:
        return True
    compact_blob = _normalize_keyword_token(raw_blob)
    compact_kw = _normalize_keyword_token(raw_kw)
    if not compact_kw:
        return False
    return compact_kw in compact_blob


def _market_priority_section(records: List[ModuleRecord], repo_root: Path) -> str:
    """Render market-priority coverage with yearly domestic/corporate/global splits."""
    catalog_path = repo_root / "routerxpl" / "resources" / "catalogs" / "market_priority_devices_2010_2026.json"
    if not catalog_path.exists():
        return "## Market Priority Coverage (2010-2026)\n\n- Catalog file not found."

    payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    minimums = payload.get("minimum_targets_per_year", {})
    device_pool = payload.get("device_pool", [])
    yearly_brazil = payload.get("yearly_brazil", [])
    yearly_global = payload.get("yearly_global", [])
    yearly = payload.get("yearly_reference_2010_2026", [])

    # Backward compatibility with previous schema.
    if not device_pool and payload.get("targets"):
        legacy_pool: List[Dict[str, object]] = []
        yearly_brazil = []
        yearly_global = []
        for idx, item in enumerate(payload.get("targets", [])):
            dev_id = "legacy_{}".format(idx)
            legacy_pool.append(
                {
                    "id": dev_id,
                    "vendor": item.get("vendor", ""),
                    "product": item.get("product", ""),
                    "segment": item.get("segment", ""),
                    "match_keywords": item.get("match_keywords", []),
                }
            )
            year = int(item.get("release_year", 0))
            if str(item.get("group", "")) == "global_top5":
                bucket = next((entry for entry in yearly_global if entry.get("year") == year), None)
                if not bucket:
                    bucket = {"year": year, "top": []}
                    yearly_global.append(bucket)
                bucket["top"].append(dev_id)
            else:
                bucket = next((entry for entry in yearly_brazil if entry.get("year") == year), None)
                if not bucket:
                    bucket = {"year": year, "domestic": [], "corporate": []}
                    yearly_brazil.append(bucket)
                bucket["domestic"].append(dev_id)
        device_pool = legacy_pool

    devices_by_id = {str(item.get("id", "")): item for item in device_pool if item.get("id")}

    def _device_metrics(device: Dict[str, object]) -> Dict[str, object]:
        vendor_raw = str(device.get("vendor", ""))
        product = str(device.get("product", ""))
        vendor_norm = _normalize_vendor_name(vendor_raw)
        keywords = [str(token).lower() for token in device.get("match_keywords", [])]
        if not keywords:
            keywords = [product.lower()]

        vendor_records = []
        for record in records:
            record_vendor_norm = _normalize_vendor_name(record.vendor)
            if vendor_norm == "multi":
                if record_vendor_norm in {"multi", "misc", "generic"}:
                    vendor_records.append(record)
            elif record_vendor_norm == vendor_norm:
                vendor_records.append(record)

        keyword_hits = 0
        for rec in vendor_records:
            blob = "{} {} {}".format(rec.module_path.lower(), rec.module_name.lower(), rec.description.lower())
            if any(_keyword_matches(blob, keyword) for keyword in keywords):
                keyword_hits += 1

        return {
            "vendor": vendor_raw,
            "product": product,
            "segment": str(device.get("segment", "")),
            "vendor_covered": "yes" if vendor_records else "no",
            "keyword_hits": keyword_hits,
        }

    def _render_year_rows(year_data: List[Dict[str, object]], field_name: str) -> List[str]:
        rows: List[str] = []
        for entry in sorted(year_data, key=lambda x: int(x.get("year", 0))):
            year = int(entry.get("year", 0))
            ids = [str(device_id) for device_id in entry.get(field_name, [])]
            required = int(minimums.get(field_name if field_name != "top" else "global", len(ids)))
            resolved = [devices_by_id[item] for item in ids if item in devices_by_id]
            covered_count = 0
            total_keyword_hits = 0
            for device in resolved:
                metric = _device_metrics(device)
                if metric["vendor_covered"] == "yes":
                    covered_count += 1
                total_keyword_hits += int(metric["keyword_hits"])
            rows.append(
                "| {} | {} | {} | {} | {} | {} |".format(
                    year,
                    required,
                    len(resolved),
                    "ok" if len(resolved) >= required else "gap",
                    covered_count,
                    total_keyword_hits,
                )
            )
        return rows

    def _render_detail_rows(year_data: List[Dict[str, object]], field_name: str, title: str) -> List[str]:
        rows: List[str] = ["### {}".format(title), "", "| Year | Vendor | Product | Segment | Vendor Covered | Keyword Hits |", "|---:|---|---|---|---|---:|"]
        for entry in sorted(year_data, key=lambda x: int(x.get("year", 0))):
            year = int(entry.get("year", 0))
            ids = [str(device_id) for device_id in entry.get(field_name, [])]
            for device_id in ids:
                device = devices_by_id.get(device_id)
                if not device:
                    continue
                metric = _device_metrics(device)
                rows.append(
                    "| {} | {} | {} | {} | {} | {} |".format(
                        year,
                        metric["vendor"],
                        metric["product"],
                        metric["segment"],
                        metric["vendor_covered"],
                        metric["keyword_hits"],
                    )
                )
        rows.append("")
        return rows

    lines = [
        "## Market Priority Coverage (2010-2026)",
        "",
        "### Yearly Minimum Validation",
        "",
        "- Brazil domestic minimum/year: {}".format(minimums.get("brazil_domestic", 10)),
        "- Brazil corporate minimum/year: {}".format(minimums.get("brazil_corporate", 10)),
        "- Global minimum/year: {}".format(minimums.get("global", 5)),
        "",
        "#### Brazil Domestic Coverage By Year",
        "",
        "| Year | Required | Cataloged | Status | Vendor Covered Count | Keyword Hits |",
        "|---:|---:|---:|---|---:|---:|",
    ]
    lines.extend(_render_year_rows(yearly_brazil, "domestic"))
    lines.extend(
        [
            "",
            "#### Brazil Corporate Coverage By Year",
            "",
            "| Year | Required | Cataloged | Status | Vendor Covered Count | Keyword Hits |",
            "|---:|---:|---:|---|---:|---:|",
        ]
    )
    lines.extend(_render_year_rows(yearly_brazil, "corporate"))
    lines.extend(
        [
            "",
            "#### Global Coverage By Year",
            "",
            "| Year | Required | Cataloged | Status | Vendor Covered Count | Keyword Hits |",
            "|---:|---:|---:|---|---:|---:|",
        ]
    )
    lines.extend(_render_year_rows(yearly_global, "top"))

    lines.extend(
        [
            "",
            *(_render_detail_rows(yearly_brazil, "domestic", "Brazil Domestic Device List (2010-2026)")),
            *(_render_detail_rows(yearly_brazil, "corporate", "Brazil Corporate Device List (2010-2026)")),
            *(_render_detail_rows(yearly_global, "top", "Global Device List (2010-2026)")),
            "### Yearly Reference (2010-2026)",
            "",
            "| Year | Vendor | Product |",
            "|---:|---|---|",
        ]
    )
    for item in sorted(yearly, key=lambda x: int(x.get("year", 0))):
        lines.append("| {} | {} | {} |".format(item.get("year", ""), item.get("vendor", ""), item.get("product", "")))

    return "\n".join(lines)


def _architecture_inventory_section(repo_root: Path) -> str:
    """Render architecture inventory snapshot from arsenal index."""
    index_path = repo_root / "routerxpl" / "resources" / "catalogs" / "arsenal_index.json"
    if not index_path.exists():
        return "## Architecture Inventory Snapshot\n\n- arsenal_index.json not found."

    payload = json.loads(index_path.read_text(encoding="utf-8"))
    metadata = payload.get("metadata", {})
    modules = payload.get("modules", {})
    curated = payload.get("curated_arsenal", {}).get("domains", {})
    lines = [
        "## Architecture Inventory Snapshot",
        "",
        "- Name: {}".format(metadata.get("name", "n/a")),
        "- Scope: {}".format(", ".join(metadata.get("scope", [])) if metadata.get("scope") else "n/a"),
        "- Out of scope: {}".format(", ".join(metadata.get("out_of_scope", [])) if metadata.get("out_of_scope") else "n/a"),
        "- Generated by: {}".format(metadata.get("generated_by", "n/a")),
        "",
        "| Domain | Count |",
        "|---|---:|",
        "| catalogs | {} |".format(len(payload.get("catalogs", []))),
        "| wordlists | {} |".format(len(payload.get("wordlists", []))),
        "| ssh_keys | {} |".format(len(payload.get("ssh_keys", []))),
        "| vendors datasets | {} |".format(len(payload.get("vendors", []))),
        "| mibs | {} |".format(len(payload.get("mibs", []))),
        "| modules.exploits | {} |".format(len(modules.get("exploits", []))),
        "| modules.creds | {} |".format(len(modules.get("creds", []))),
        "| modules.scanners | {} |".format(len(modules.get("scanners", []))),
        "| modules.generic | {} |".format(len(modules.get("generic", []))),
        "| modules.encoders | {} |".format(len(modules.get("encoders", []))),
        "| modules.payloads | {} |".format(len(modules.get("payloads", []))),
    ]
    if curated:
        lines.extend(["", "| curated_arsenal domain | Count |", "|---|---:|"])
        for domain in sorted(curated.keys()):
            lines.append("| {} | {} |".format(domain, len(curated.get(domain, []))))
    return "\n".join(lines)


def _workspace_reuse_inventory_section(repo_root: Path) -> str:
    """Render workspace reuse inventory summary for phase 2B traceability."""
    inv_path = repo_root / "routerxpl" / "resources" / "catalogs" / "workspace_reuse_inventory.json"
    if not inv_path.exists():
        return "## Workspace Reuse Inventory Snapshot\n\n- workspace_reuse_inventory.json not found."

    payload = json.loads(inv_path.read_text(encoding="utf-8"))
    summary = payload.get("summary", {})
    lines = [
        "## Workspace Reuse Inventory Snapshot",
        "",
        "- Total assets discovered: {}".format(payload.get("total", 0)),
        "",
        "| Classification | Count |",
        "|---|---:|",
    ]
    for key in sorted(summary.keys()):
        lines.append("| {} | {} |".format(key, summary[key]))
    return "\n".join(lines)


def _deep_intel_backlog_section(repo_root: Path) -> str:
    """Render deep-intel backlog summary for phase 6 tracking."""
    backlog_path = repo_root / "routerxpl" / "resources" / "catalogs" / "deep_intel_backlog.json"
    if not backlog_path.exists():
        return "## Deep Intel Backlog Snapshot\n\n- deep_intel_backlog.json not found."

    payload = json.loads(backlog_path.read_text(encoding="utf-8"))
    items = payload.get("items", [])
    counts: Dict[str, int] = {}
    total_kw_hits = 0
    for item in items:
        key = str(item.get("priority", "unknown"))
        counts[key] = counts.get(key, 0) + 1
        total_kw_hits += int(item.get("keyword_hits", 0))

    lines = [
        "## Deep Intel Backlog Snapshot",
        "",
        "- Total backlog items: {}".format(payload.get("total", len(items))),
        "- Total keyword hits across backlog: {}".format(total_kw_hits),
        "",
        "| Priority | Count |",
        "|---|---:|",
    ]
    for key in sorted(counts.keys()):
        lines.append("| {} | {} |".format(key, counts[key]))
    return "\n".join(lines)


def _honeypot_campaign_section(repo_root: Path) -> str:
    """Render phase6b honeypot campaign readiness snapshot."""
    campaign_path = repo_root / "routerxpl" / "resources" / "arsenal" / "intel" / "honeypot_validation_campaign.json"
    if not campaign_path.exists():
        return "## Honeypot Final Validation Snapshot\n\n- honeypot_validation_campaign.json not found."

    payload = json.loads(campaign_path.read_text(encoding="utf-8"))
    entries = payload.get("entries", [])
    platform_summary: Dict[str, Dict[str, int]] = {}
    for item in entries:
        platform = str(item.get("platform", "unknown"))
        status = str(item.get("status", "unknown"))
        if platform not in platform_summary:
            platform_summary[platform] = {"ready": 0, "blocked": 0}
        if status == "ready_for_live_run":
            platform_summary[platform]["ready"] += 1
        else:
            platform_summary[platform]["blocked"] += 1

    lines = [
        "## Honeypot Final Validation Snapshot",
        "",
        "- Campaign: {}".format(payload.get("campaign", "phase6b_final_honeypot_validation")),
        "- Checked at: {}".format(payload.get("checked_at", "n/a")),
        "",
        "| Platform | Ready Queries | Blocked Queries |",
        "|---|---:|---:|",
    ]
    for platform in sorted(platform_summary.keys()):
        lines.append(
            "| {} | {} | {} |".format(
                platform,
                platform_summary[platform]["ready"],
                platform_summary[platform]["blocked"],
            )
        )
    return "\n".join(lines)


def _build_summary(records: List[ModuleRecord], matrix: Dict[Tuple[str, str], CoverageEntry]) -> str:
    """Build textual summary with global counters."""
    module_types: Dict[str, int] = {}
    cves: Set[str] = set()
    attacks: Set[str] = set()
    for item in records:
        module_types[item.module_type] = module_types.get(item.module_type, 0) + 1
        cves.update(item.cves)
        attacks.update(item.attack_classes)

    lines: List[str] = [
        "## Global Capability Summary",
        "",
        f"- Module tree (routerxpl/modules): {_matrix_source_revision(REPO_ROOT)}",
        f"- Total modules indexed: {len(records)}",
        f"- Distinct vendor/product entries: {len(matrix)}",
        f"- Distinct CVEs mapped in modules: {len(cves)}",
        f"- Attack classes identified: {', '.join(sorted(attacks)) if attacks else 'none'}",
        "",
        "### Module Type Counts",
    ]
    for key in sorted(module_types):
        lines.append(f"- {key}: {module_types[key]}")
    lines.extend(["", _protocol_coverage(records)])
    return "\n".join(lines)


def _build_markdown(records: List[ModuleRecord], matrix: Dict[Tuple[str, str], CoverageEntry]) -> str:
    """Render matrix document in Markdown format."""
    lines: List[str] = [
        "# RouterXPL-Forge Coverage Matrix",
        "",
        _platform_section(),
        "",
        _build_summary(records, matrix),
        "",
        _osi_tcpip_coverage_section(records, Path(__file__).resolve().parent.parent),
        "",
        _market_priority_section(records, Path(__file__).resolve().parent.parent),
        "",
        "",
        "",
        _architecture_inventory_section(Path(__file__).resolve().parent.parent),
        "",
        _workspace_reuse_inventory_section(Path(__file__).resolve().parent.parent),
        "",
        _deep_intel_backlog_section(Path(__file__).resolve().parent.parent),
        "",
        _honeypot_campaign_section(Path(__file__).resolve().parent.parent),
        "",
        "## Vendor/Product Capability Matrix",
        "",
        "| Vendor | Product | Modules | Exploits | Creds | Scanners | Generic | Payloads | Encoders | CVEs | Attack Classes |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---|",
    ]

    entries = sorted(matrix.values(), key=lambda e: (e.vendor.lower(), e.product.lower()))
    for entry in entries:
        cves = ", ".join(sorted(entry.cves)) if entry.cves else "-"
        attacks = ", ".join(sorted(entry.attack_classes)) if entry.attack_classes else "-"
        lines.append(
            f"| {entry.vendor} | {entry.product} | {entry.module_count} | {entry.exploit_count} | "
            f"{entry.creds_count} | {entry.scanner_count} | {entry.generic_count} | "
            f"{entry.payload_count} | {entry.encoder_count} | {cves} | {attacks} |"
        )

    lines.extend(["", "## Modules By Vendor/Product", ""])
    for entry in entries:
        lines.append(f"### {entry.vendor} / {entry.product}")
        lines.append("")
        lines.append(
            f"- Totals: modules={entry.module_count}, exploits={entry.exploit_count}, creds={entry.creds_count}, "
            f"scanners={entry.scanner_count}, generic={entry.generic_count}, payloads={entry.payload_count}, encoders={entry.encoder_count}"
        )
        lines.append(f"- CVEs: {', '.join(sorted(entry.cves)) if entry.cves else 'none'}")
        lines.append(f"- Attack classes: {', '.join(sorted(entry.attack_classes)) if entry.attack_classes else 'none'}")
        lines.append("- Module paths:")
        for module_path in entry.module_paths:
            lines.append(f"  - `{module_path}`")
        lines.append("")

    return "\n".join(lines)


def _build_plain_text(records: List[ModuleRecord], matrix: Dict[Tuple[str, str], CoverageEntry]) -> str:
    """Render matrix document in plain text format."""
    lines: List[str] = [
        "RouterXPL-Forge Coverage Matrix",
        "=" * 33,
        "",
        "Platform Compatibility Status",
        "-" * 29,
        "Windows: Compatible (validated locally)",
        "WSL / Debian-based Linux: Compatible (validated locally)",
        "RHEL-based Linux: Compatible by design, not tested effectively yet",
        "macOS: Compatible by design, not tested effectively yet",
        "Termux / Android / NetHunter: Compatible by design, not tested effectively yet",
        "",
        _build_summary(records, matrix),
        "",
        _osi_tcpip_coverage_section(records, Path(__file__).resolve().parent.parent),
        "",
        _market_priority_section(records, Path(__file__).resolve().parent.parent),
        "",
        "",
        "",
        _architecture_inventory_section(Path(__file__).resolve().parent.parent),
        "",
        _workspace_reuse_inventory_section(Path(__file__).resolve().parent.parent),
        "",
        _deep_intel_backlog_section(Path(__file__).resolve().parent.parent),
        "",
        _honeypot_campaign_section(Path(__file__).resolve().parent.parent),
        "",
        "Vendor/Product Capability Matrix",
        "-" * 30,
    ]

    entries = sorted(matrix.values(), key=lambda e: (e.vendor.lower(), e.product.lower()))
    for entry in entries:
        lines.append(
            f"{entry.vendor}/{entry.product} | modules={entry.module_count} | "
            f"exploits={entry.exploit_count} creds={entry.creds_count} scanners={entry.scanner_count} "
            f"generic={entry.generic_count} payloads={entry.payload_count} encoders={entry.encoder_count}"
        )
        lines.append(f"  CVEs: {', '.join(sorted(entry.cves)) if entry.cves else 'none'}")
        lines.append(f"  Attacks: {', '.join(sorted(entry.attack_classes)) if entry.attack_classes else 'none'}")
        lines.append("  Module paths:")
        for module_path in entry.module_paths:
            lines.append(f"    - {module_path}")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    """Generate coverage matrix in Markdown and plain text."""
    _configure_logging()
    repo_root = Path(__file__).resolve().parent.parent
    modules_root = repo_root / "routerxpl" / "modules"

    records: List[ModuleRecord] = []
    for module_file in sorted(modules_root.rglob("*.py")):
        if module_file.name == "__init__.py":
            continue
        record = _extract_module_record(module_file, modules_root)
        if _record_in_scope(record):
            records.append(record)

    matrix = _aggregate(records)
    docs_dir = repo_root / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)

    md_path = docs_dir / "COVERAGE_MATRIX.md"
    txt_path = docs_dir / "COVERAGE_MATRIX.txt"

    md_path.write_text(_build_markdown(records, matrix), encoding="utf-8")
    txt_path.write_text(_build_plain_text(records, matrix), encoding="utf-8")

    LOGGER.info("Coverage matrix generated: %s and %s", md_path, txt_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())