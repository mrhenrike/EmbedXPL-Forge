"""Progress bars and spinners for scan operations.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import sys
from typing import Any, Optional

from firewallxpl.core.tui.console import has_rich

if has_rich:
    from rich.progress import (
        Progress,
        SpinnerColumn,
        BarColumn,
        TextColumn,
        TimeRemainingColumn,
        TaskProgressColumn,
    )


def create_scan_progress() -> Any:
    """Create a Rich progress bar for scan operations."""
    if has_rich:
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
        )
    return _FallbackProgress()


class _FallbackProgress:
    """Minimal progress display without Rich."""

    def __init__(self) -> None:
        self._tasks: dict = {}

    def add_task(self, description: str, total: int = 100, **kwargs: Any) -> int:
        task_id = len(self._tasks)
        self._tasks[task_id] = {"desc": description, "total": total, "done": 0}
        return task_id

    def update(self, task_id: int, advance: int = 1, **kwargs: Any) -> None:
        if task_id in self._tasks:
            self._tasks[task_id]["done"] += advance
            t = self._tasks[task_id]
            pct = (t["done"] / t["total"] * 100) if t["total"] > 0 else 0
            sys.stdout.write(f"\r  {t['desc']}: {pct:.0f}%")
            sys.stdout.flush()

    def __enter__(self) -> "_FallbackProgress":
        return self

    def __exit__(self, *args: Any) -> None:
        sys.stdout.write("\n")
        sys.stdout.flush()
