"""Full-screen dashboard for live scan monitoring.

Uses Rich Live layout with 4 quadrants: progress, results, system, queue.
Activated with --dashboard flag or 'dashboard' REPL command.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from firewallxpl.core.tui.console import console, has_rich

logger = logging.getLogger("firewallxpl.tui.dashboard")

if has_rich:
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table


class ScanDashboard:
    """Live dashboard for monitoring scan progress."""

    def __init__(self) -> None:
        self._live: Optional[Any] = None
        self._scan_progress: str = "Idle"
        self._results: List[str] = []
        self._system_status: Dict[str, str] = {}
        self._queue: List[str] = []

    def start(self) -> None:
        """Start the live dashboard."""
        if not has_rich:
            logger.info("Rich not installed — dashboard disabled")
            return
        layout = self._build_layout()
        self._live = Live(layout, console=console, refresh_per_second=2)
        self._live.start()

    def stop(self) -> None:
        """Stop the live dashboard."""
        if self._live:
            self._live.stop()
            self._live = None

    def update_progress(self, text: str) -> None:
        self._scan_progress = text
        self._refresh()

    def add_result(self, text: str) -> None:
        self._results.append(text)
        if len(self._results) > 20:
            self._results = self._results[-20:]
        self._refresh()

    def update_system(self, data: Dict[str, str]) -> None:
        self._system_status = data
        self._refresh()

    def update_queue(self, items: List[str]) -> None:
        self._queue = items[:10]
        self._refresh()

    def _build_layout(self) -> Any:
        if not has_rich:
            return None
        layout = Layout()
        layout.split_column(
            Layout(name="top", ratio=1),
            Layout(name="bottom", ratio=1),
        )
        layout["top"].split_row(
            Layout(Panel(self._scan_progress, title="Scan Progress"), name="progress"),
            Layout(Panel("\n".join(self._results[-10:]) or "No results yet", title="Live Results"), name="results"),
        )
        layout["bottom"].split_row(
            Layout(Panel("\n".join(f"{k}: {v}" for k, v in self._system_status.items()) or "...", title="System Status"), name="system"),
            Layout(Panel("\n".join(self._queue) or "Empty", title="Module Queue"), name="queue"),
        )
        return layout

    def _refresh(self) -> None:
        if self._live and has_rich:
            self._live.update(self._build_layout())

    def __enter__(self) -> "ScanDashboard":
        self.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()
