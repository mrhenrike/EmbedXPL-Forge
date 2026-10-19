"""Reusable Rich panels for system status, GPU, ML, and scan info.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

from typing import Any, Dict, List

from firewallxpl.core.tui.console import console, has_rich

if has_rich:
    from rich.panel import Panel
    from rich.text import Text


def show_system_panel(data: Dict[str, Any]) -> None:
    """Display system information panel."""
    if has_rich:
        lines = []
        lines.append(f"Python: {data.get('python', 'N/A')} | OS: {data.get('os', 'N/A')}")
        lines.append(f"GPU: {data.get('gpu', 'none detected')}")
        lines.append(f"ML Models: {data.get('ml', 'not loaded')}")
        lines.append(f"Modules: {data.get('modules', 0)} total")
        content = "\n".join(lines)
        console.print(Panel(content, title="System", border_style="cyan"))
    else:
        console.print(f"[System] Python: {data.get('python')} | Modules: {data.get('modules')}")


def show_gpu_panel(backends: List[str], mode: str = "cpu") -> None:
    """Display GPU/compute backends panel."""
    if has_rich:
        lines = []
        for b in backends:
            mark = "[green]OK[/green]" if b != "none" else "[red]N/A[/red]"
            lines.append(f"  {b}: {mark}")
        lines.append(f"\n  Compute Mode: {mode}")
        console.print(Panel("\n".join(lines), title="Compute Backends", border_style="magenta"))
    else:
        console.print(f"[GPU] Backends: {', '.join(backends)} | Mode: {mode}")


def show_ml_panel(status: Dict[str, bool]) -> None:
    """Display ML engine status panel."""
    if has_rich:
        lines = []
        for component, loaded in status.items():
            mark = "[green]loaded[/green]" if loaded else "[red]not loaded[/red]"
            lines.append(f"  {component}: {mark}")
        console.print(Panel("\n".join(lines), title="ML Engine", border_style="yellow"))
    else:
        loaded = [k for k, v in status.items() if v]
        console.print(f"[ML] Loaded: {', '.join(loaded) or 'none'}")


def show_scan_result_panel(target: str, vulns: int, creds: int) -> None:
    """Display scan result summary panel."""
    if has_rich:
        color = "green" if vulns > 0 else "red"
        content = (
            f"Target: {target}\n"
            f"Vulnerabilities: {vulns}\n"
            f"Default Credentials: {creds}"
        )
        console.print(Panel(content, title="Scan Results", border_style=color))
    else:
        console.print(f"[Results] {target}: {vulns} vulns, {creds} creds")
