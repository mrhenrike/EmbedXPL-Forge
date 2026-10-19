"""Discovery report generator with Rich output and JSON/CSV export.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import json
import logging
from typing import Any, List

from firewallxpl.core.tui.console import console, has_rich
from firewallxpl.core.discovery.scan_engines.base import DiscoveredHost

logger = logging.getLogger("firewallxpl.discovery.reporter")

if has_rich:
    from rich.panel import Panel
    from rich.table import Table


def print_discovery_report(hosts: List[DiscoveredHost], engine: str = "") -> None:
    """Print discovery results as a Rich table."""
    identified = [h for h in hosts if h.identification]
    in_scope = [h for h in identified if h.risk_score > 0]

    if has_rich:
        table = Table(show_lines=True, border_style="cyan")
        table.add_column("#", style="bold")
        table.add_column("IP", style="cyan")
        table.add_column("Vendor / Product", style="vendor")
        table.add_column("Class", style="module")
        table.add_column("Risk", style="bold")
        table.add_column("Modules", style="info")

        for i, host in enumerate(hosts, 1):
            if host.identification:
                ident = host.identification
                risk_style = "red" if host.risk_score >= 8 else "yellow" if host.risk_score >= 5 else "green"
                table.add_row(
                    str(i), host.ip,
                    f"{ident.vendor} {ident.product}",
                    ident.device_class,
                    f"[{risk_style}]{host.risk_score:.1f}[/{risk_style}]",
                    str(len(host.applicable_modules)),
                )
            else:
                table.add_row(str(i), host.ip, "Unidentified", "--", "--", "--")

        header = f"Target: {engine} | Hosts: {len(hosts)} | Identified: {len(identified)} | In scope: {len(in_scope)}"
        console.print(Panel(table, title="Network Discovery Report", subtitle=header, border_style="cyan"))
    else:
        print(f"\n--- Discovery Report ({len(hosts)} hosts) ---")
        for i, host in enumerate(hosts, 1):
            if host.identification:
                ident = host.identification
                print(f"  {i}. {host.ip} — {ident.vendor}/{ident.product} [{ident.device_class}] risk={host.risk_score:.1f} modules={len(host.applicable_modules)}")
            else:
                print(f"  {i}. {host.ip} — unidentified")


def export_json(hosts: List[DiscoveredHost], path: str) -> None:
    """Export discovery results to JSON."""
    data = []
    for h in hosts:
        entry = {"ip": h.ip, "mac": h.mac, "hostname": h.hostname, "open_ports": h.open_ports, "risk_score": h.risk_score}
        if h.identification:
            entry["identification"] = {
                "vendor": h.identification.vendor, "product": h.identification.product,
                "device_class": h.identification.device_class, "confidence": h.identification.confidence,
            }
        entry["applicable_modules"] = h.applicable_modules
        entry["applicable_cves"] = h.applicable_cves
        data.append(entry)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    logger.info("Exported %d hosts to %s", len(data), path)
