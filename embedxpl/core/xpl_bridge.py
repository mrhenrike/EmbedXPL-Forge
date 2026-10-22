# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""EmbedXPL <-> xpl-core integration bridge.

Registers EmbedXPL modules in the xpl-core PluginRegistry,
converts exploit results to xpl-core Finding schema, and
provides ForgeConfig wrapper for persistent settings.
"""
from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Any

from xpl_core.config import ForgeConfig
from xpl_core.registry import PluginRegistry
from xpl_core.schemas import Finding, FindingEvidence, FindingTarget

logger = logging.getLogger(__name__)

_FORGE_NAME = "embedxpl"

_CATEGORY_MAP: dict[str, str] = {
    "exploits": "exploit",
    "scanners": "scanner",
    "creds": "credential",
    "payloads": "payload",
    "encoders": "encoder",
    "post": "post_exploitation",
    "autopwn": "autopwn",
}

_MODULE_ROOT = Path(__file__).resolve().parent.parent / "modules"


def _discover_modules() -> list[tuple[str, str, str]]:
    """Walk the modules directory and yield (name, category, import_path) tuples."""
    results: list[tuple[str, str, str]] = []
    for category_dir in sorted(_MODULE_ROOT.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("_"):
            continue
        category = _CATEGORY_MAP.get(category_dir.name, category_dir.name)
        for py_file in sorted(category_dir.rglob("*.py")):
            if py_file.name.startswith("_"):
                continue
            rel = py_file.relative_to(_MODULE_ROOT.parent)
            import_path = str(rel).replace("/", ".").removesuffix(".py")
            name = py_file.stem
            results.append((name, category, import_path))
    return results


def register_all(registry: PluginRegistry | None = None) -> PluginRegistry:
    """Register every EmbedXPL module in a PluginRegistry.

    If no registry is passed, a new one is created. Returns the registry.
    """
    if registry is None:
        registry = PluginRegistry()
    discovered = _discover_modules()
    for name, category, import_path in discovered:
        manifest = _build_manifest(import_path)
        registry.register(
            name=name,
            category=category,
            import_path=import_path,
            forge=_FORGE_NAME,
            manifest=manifest,
        )
    logger.info(
        "Registered %d EmbedXPL modules in %d categories",
        len(discovered),
        len(registry.list_categories()),
    )
    return registry


def _build_manifest(import_path: str) -> dict[str, Any]:
    """Try to extract __info__ from a module's Exploit class without full import."""
    try:
        mod = importlib.import_module(import_path)
    except Exception:
        return {}
    cls = getattr(mod, "Exploit", None)
    if cls is None:
        return {}
    mangled = f"_{cls.__name__}__info__"
    info: dict[str, Any] = getattr(cls, mangled, {})
    if not info:
        info = getattr(cls, "__info__", {})
    return {
        "name": info.get("name", ""),
        "description": info.get("description", ""),
        "authors": list(info.get("authors", ())),
        "references": list(info.get("references", ())),
    }


def exploit_result_to_finding(
    module_path: str,
    target_host: str,
    target_port: int = 0,
    *,
    title: str = "",
    description: str = "",
    severity: str = "high",
    cves: list[str] | None = None,
    mitre_techniques: list[str] | None = None,
    evidence_text: str = "",
    status: str = "confirmed",
) -> Finding:
    """Convert an EmbedXPL exploit result to a xpl-core Finding."""
    target = FindingTarget(
        host=target_host,
        port=target_port,
        service="embedded",
        protocol="tcp",
    )
    evidence: list[FindingEvidence] = []
    if evidence_text:
        evidence.append(FindingEvidence(
            type="output",
            data=evidence_text,
        ))

    mitre: dict[str, list[str]] = {}
    if mitre_techniques:
        mitre["attack"] = mitre_techniques

    return Finding(
        forge=_FORGE_NAME,
        severity=severity,
        title=title or f"Exploit: {module_path}",
        description=description,
        target=target,
        cve=cves or [],
        mitre=mitre,
        evidence=evidence,
        module=module_path,
        status=status,
    )


def get_config(config_dir: str | Path | None = None) -> ForgeConfig:
    """Get or create the EmbedXPL forge configuration."""
    defaults = {
        "forge_version": "7.0.0-dev",
        "default_timeout": 30,
        "max_threads": 10,
        "output_format": "json",
        "finding_schema": "xpl-core/v1",
    }
    return ForgeConfig(
        forge_name=_FORGE_NAME,
        config_dir=config_dir,
        defaults=defaults,
    )
