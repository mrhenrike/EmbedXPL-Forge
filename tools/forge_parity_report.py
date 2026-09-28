#!/usr/bin/env python3
"""Compare module inventories across XPL-Forge repos."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
UG = REPO_ROOT / "submodules" / "Uniao-Geek"
OUT = REPO_ROOT / ".tmp" / "forge-parity-report.md"

FORGES = {
    "embedxpl": UG / "EmbedXPL-Forge" / "embedxpl" / "modules",
    "wirelessxpl": UG / "WirelessXPL-Forge" / "wirelessxpl" / "modules",
    "firewallxpl": UG / "FirewallXPL-Forge" / "firewallxpl" / "modules",
    "printerxpl": UG / "PrinterXPL-Forge" / "src" / "modules",
    "industrialxpl": UG / "IndustrialXPL-Forge" / "industrialxpl" / "modules",
    "mikrotik": UG / "MikrotikAPI-BF" / "modules",
}


def collect(root: Path) -> set[str]:
    if not root.is_dir():
        return set()
    return {p.stem for p in root.rglob("*.py") if p.name != "__init__.py"}


def main() -> int:
    inv = {k: collect(v) for k, v in FORGES.items()}
    embed = inv.get("embedxpl", set())
    lines = ["# Forge Parity Report", ""]
    total_missing = 0
    for name, mods in inv.items():
        if name == "embedxpl":
            continue
        missing = sorted(mods - embed)
        total_missing += len(missing)
        lines.append(f"## missing_in_embed from {name} ({len(missing)})")
        lines.append("")
        for m in missing[:40]:
            lines.append(f"- `{m}`")
        lines.append("")
    lines.insert(2, f"- **total missing_in_embed:** {total_missing}")
    lines.insert(3, "")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {OUT} (missing={total_missing})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
