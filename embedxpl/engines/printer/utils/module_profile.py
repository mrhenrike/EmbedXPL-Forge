#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module install profiles — controls which xpl/ modules are active at runtime.

Default (pip install): modern — CVE/modules from 2020+ plus timeless scanners.

Profiles:
  modern          2020 → present (+ timeless generic/scanners)
  full-depth      last ~30 years (all modules in manifest)
  vendor-<name>   hp, ricoh, brother, xerox, lexmark, canon, epson, kyocera,
                  samsung, generic, konica, toshiba, sharp, oki, cups, microsoft
  modern-vendor-<name>  vendor filter + year >= 2020

Persisted: ~/.config/pxf/profile.json  (override with PXF_PROFILE env)
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

_MANIFEST_PATH = Path(__file__).resolve().parent.parent / "data" / "xpl_manifest.json"
_CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "pxf"
_PROFILE_FILE = _CONFIG_DIR / "profile.json"

VENDOR_SLUGS = (
    "hp", "ricoh", "brother", "xerox", "lexmark", "canon", "epson", "kyocera",
    "samsung", "generic", "konica", "toshiba", "sharp", "oki", "cups", "microsoft",
    "honeywell", "dell", "star", "bixolon",
)

PROFILE_HELP: Dict[str, str] = {
    "modern": "Exploits from 2020 onward + timeless scanners/generics (default pip focus)",
    "full-depth": "Full arsenal ~30 years — all modules shipped in the wheel",
    "native-only": "Only native_python / native_poly_c (no MSF orchestration wrappers)",
    "engines-rce": "Modules tagged rce, shell, or lpe",
}


@dataclass(frozen=True)
class ModuleProfile:
    name: str
    min_year: Optional[int] = None
    max_year: Optional[int] = None
    vendors: Optional[Set[str]] = None
    include_timeless: bool = True
    include_era: Optional[Set[str]] = None
    integrations: Optional[Set[str]] = None
    categories: Optional[Set[str]] = None

    def describe(self) -> str:
        return PROFILE_HELP.get(self.name, self.name)


def _vendor_profile(vendor: str, modern: bool = False) -> ModuleProfile:
    v = vendor.lower().strip()
    name = f"modern-vendor-{v}" if modern else f"vendor-{v}"
    return ModuleProfile(
        name=name,
        min_year=2020 if modern else None,
        vendors={v},
        include_timeless=not modern,
        include_era={"modern", "timeless"} if modern else None,
    )


def get_profile(name: str) -> ModuleProfile:
    n = (name or "modern").strip().lower()
    if n == "modern":
        return ModuleProfile(name="modern", min_year=2020, include_era={"modern", "timeless"})
    if n in ("full-depth", "full", "fullyear", "full30"):
        return ModuleProfile(name="full-depth", min_year=1990, include_era={"modern", "legacy", "timeless"})
    if n == "native-only":
        return ModuleProfile(
            name="native-only",
            integrations={"native_python", "native_poly_c"},
        )
    if n == "engines-rce":
        return ModuleProfile(name="engines-rce", categories={"rce", "shell", "lpe"})
    if n.startswith("modern-vendor-"):
        return _vendor_profile(n.replace("modern-vendor-", "", 1), modern=True)
    if n.startswith("vendor-"):
        return _vendor_profile(n.replace("vendor-", "", 1), modern=False)
    raise ValueError(f"Unknown profile: {name}")


def list_profiles() -> List[str]:
    names = ["modern", "full-depth", "native-only", "engines-rce"]
    for v in VENDOR_SLUGS:
        names.append(f"vendor-{v}")
        names.append(f"modern-vendor-{v}")
    return names


def load_manifest() -> dict:
    if not _MANIFEST_PATH.exists():
        return {"_meta": {}, "modules": []}
    return json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))


def read_active_profile_name() -> str:
    env = os.environ.get("PXF_PROFILE", "").strip()
    if env:
        return env
    if _PROFILE_FILE.exists():
        try:
            data = json.loads(_PROFILE_FILE.read_text(encoding="utf-8"))
            return str(data.get("active") or "modern")
        except Exception:
            pass
    return "modern"


def write_active_profile(name: str) -> Path:
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"active": name.strip().lower()}
    _PROFILE_FILE.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return _PROFILE_FILE


def module_allowed(entry: dict, profile: ModuleProfile) -> bool:
    year = entry.get("year")
    era = entry.get("era", "legacy")
    vendors = set(entry.get("vendors") or ["generic"])
    integration = entry.get("integration", "native_python")
    categories = set(entry.get("categories") or [])

    if profile.include_era is not None and era not in profile.include_era:
        if not (profile.include_timeless and era == "timeless"):
            return False

    if profile.min_year is not None and year is not None and year < profile.min_year:
        if not (profile.include_timeless and era == "timeless"):
            return False

    if profile.max_year is not None and year is not None and year > profile.max_year:
        return False

    if profile.vendors is not None:
        if not profile.vendors.intersection(vendors):
            return False

    if profile.integrations is not None and integration not in profile.integrations:
        return False

    if profile.categories is not None and not profile.categories.intersection(categories):
        return False

    return True


def allowed_module_paths(profile_name: Optional[str] = None) -> Optional[Set[str]]:
    """
    Return set of module directory paths (relative, e.g. xpl/edb-35151) allowed
    by the active profile. None means no filtering (load all on disk).
    """
    name = profile_name or read_active_profile_name()
    if name in ("all", "none", "full-disk"):
        return None
    try:
        profile = get_profile(name)
    except ValueError:
        profile = get_profile("modern")

    manifest = load_manifest()
    modules = manifest.get("modules") or []
    if not modules:
        return None

    allowed = {m["path"] for m in modules if module_allowed(m, profile)}
    return allowed


def profile_stats(profile_name: Optional[str] = None) -> dict:
    name = profile_name or read_active_profile_name()
    profile = get_profile(name)
    manifest = load_manifest()
    modules = manifest.get("modules") or []
    allowed = [m for m in modules if module_allowed(m, profile)]
    return {
        "profile": name,
        "description": profile.describe(),
        "total_shipped": len(modules),
        "active": len(allowed),
        "skipped": len(modules) - len(allowed),
        "config_file": str(_PROFILE_FILE),
    }


def apply_pip_extra(extra: str) -> str:
    """Map pip optional-extra name → profile name and persist."""
    mapping = {
        "modern": "modern",
        "full-depth": "full-depth",
        "full": "full-depth",
        "fullyear": "full-depth",
        "native-compilers": "modern",
        "native-all": "full-depth",
        "engines-rce": "engines-rce",
        "native-only": "native-only",
    }
    extra_l = extra.strip().lower()
    if extra_l in mapping:
        name = mapping[extra_l]
    elif extra_l.startswith("vendor-"):
        name = extra_l
    else:
        name = extra_l
    write_active_profile(name)
    return name
