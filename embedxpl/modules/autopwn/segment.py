"""EmbedXPL AutoPwn — Generic Segment Autopwn Engine.

Discovers and runs all applicable exploit/scanner modules against a target
for a given device segment.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

import importlib
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from embedxpl.tools.search import search_category, ModuleRecord


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ModuleResult:
    module_path: str
    target: str
    status: str          # "vulnerable" | "not_vulnerable" | "error" | "skipped"
    detail: str = ""
    data: dict = field(default_factory=dict)
    elapsed_s: float = 0.0


@dataclass
class AutoPwnReport:
    segment: str
    target: str
    targets: list[str]
    modules_run: int = 0
    modules_vulnerable: int = 0
    modules_error: int = 0
    results: list[ModuleResult] = field(default_factory=list)
    elapsed_s: float = 0.0

    def summary(self) -> str:
        lines = [
            f"",
            f"{'='*70}",
            f"  EmbedXPL AutoPwn — {self.segment.upper()} Segment",
            f"  Target(s): {', '.join(self.targets)}",
            f"  Modules run: {self.modules_run}",
            f"  Vulnerable: {self.modules_vulnerable}",
            f"  Errors:     {self.modules_error}",
            f"  Elapsed:    {self.elapsed_s:.1f}s",
            f"{'='*70}",
        ]
        if self.results:
            vuln = [r for r in self.results if r.status == "vulnerable"]
            if vuln:
                lines.append(f"\n  [+] VULNERABLE ({len(vuln)}):")
                for r in vuln:
                    lines.append(f"      {r.module_path.split('.')[-1]} → {r.detail}")
        lines.append("")
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.summary()


# ---------------------------------------------------------------------------
# Core AutoPwn Engine
# ---------------------------------------------------------------------------

class SegmentAutoPwn:
    """Run all relevant modules against target(s) for a device segment.

    Args:
        segment:    Device category — "router", "printer", "firewall",
                    "camera", "ics", "wireless", "nas", "smart_tv"
        targets:    List of IP/host targets, or single string
        check_only: If True, only run check() — no exploitation
        verbose:    Print each module result
        timeout:    Per-module timeout in seconds
        max_modules: Max modules to run (0 = all)
    """

    SEGMENT_MAP = {
        "router":   "routers",
        "routers":  "routers",
        "printer":  "printers",
        "printers": "printers",
        "firewall": "firewalls",
        "firewalls":"firewalls",
        "camera":   "cameras",
        "cameras":  "cameras",
        "ics":      "ics",
        "ot":       "ics",
        "scada":    "ics",
        "wireless": "wireless",
        "wifi":     "wireless",
        "nas":      "nas",
        "smart_tv": "smart_tv",
        "tv":       "smart_tv",
        "mikrotik": "network_os",
    }

    def __init__(
        self,
        segment: str,
        targets: str | list[str],
        check_only: bool = True,
        verbose: bool = True,
        timeout: int = 30,
        max_modules: int = 0,
        db: Optional[Any] = None,        # EXFDatabase instance for persistence
    ) -> None:
        self.segment = segment.lower()
        self.category = self.SEGMENT_MAP.get(self.segment, self.segment)
        self.targets = [targets] if isinstance(targets, str) else list(targets)
        self.check_only = check_only
        self.verbose = verbose
        self.timeout = timeout
        self.max_modules = max_modules
        self._db = db  # optional EXFDatabase for persisting results

    def _get_modules(self) -> list[ModuleRecord]:
        """Get all modules for this segment via search engine."""
        records = search_category(self.category)
        if self.max_modules > 0:
            records = records[:self.max_modules]
        return records

    def _run_module(self, rec: ModuleRecord, target: str) -> ModuleResult:
        """Import and run (or check) a single module against a target."""
        t0 = time.time()
        try:
            mod = importlib.import_module(rec.path)
        except ImportError as e:
            return ModuleResult(rec.path, target, "error", f"ImportError: {e}")

        # Find exploit class
        exploit_cls = None
        import inspect
        for name, obj in inspect.getmembers(mod, inspect.isclass):
            if hasattr(obj, "check") or hasattr(obj, "run"):
                exploit_cls = obj
                break

        if not exploit_cls:
            return ModuleResult(rec.path, target, "skipped", "No exploit class found")

        try:
            instance = exploit_cls()
            # Set target
            for attr in ["rhost", "host", "target", "ip"]:
                if hasattr(instance, attr):
                    setattr(instance, attr, target)
                    break

            if self.check_only and hasattr(instance, "check"):
                result = instance.check()
                if result is True or (isinstance(result, dict) and result.get("vulnerable")):
                    status = "vulnerable"
                    detail = str(result) if isinstance(result, dict) else "check() returned True"
                else:
                    status = "not_vulnerable"
                    detail = ""
            elif not self.check_only and hasattr(instance, "run"):
                result = instance.run()
                if isinstance(result, dict):
                    status = "vulnerable" if result.get("success") or result.get("returncode") == 0 else "not_vulnerable"
                    detail = result.get("stdout", "")[:200]
                else:
                    status = "not_vulnerable"
                    detail = str(result)[:200]
            else:
                status = "skipped"
                detail = "No check() or run() method"
        except Exception as e:
            status = "error"
            detail = str(e)[:200]

        elapsed = time.time() - t0
        return ModuleResult(rec.path, target, status, detail, elapsed_s=elapsed)

    def run(self) -> AutoPwnReport:
        """Run AutoPwn against all targets."""
        t0 = time.time()
        modules = self._get_modules()
        report = AutoPwnReport(
            segment=self.segment,
            target=self.targets[0] if len(self.targets) == 1 else f"{len(self.targets)} targets",
            targets=self.targets,
        )

        mode = "check" if self.check_only else "exploit"
        if self.verbose:
            print(f"\n[*] AutoPwn {self.segment.upper()} — {len(modules)} modules, "
                  f"{len(self.targets)} target(s), mode={mode}")
            print(f"[*] Targets: {', '.join(self.targets)}")
            print()

        # Persist hosts to DB if available
        if self._db is not None:
            for t in self.targets:
                try:
                    self._db.add_host(t)
                except Exception:
                    pass

        for target in self.targets:
            for rec in modules:
                result = self._run_module(rec, target)
                report.results.append(result)
                report.modules_run += 1
                if result.status == "vulnerable":
                    report.modules_vulnerable += 1
                elif result.status == "error":
                    report.modules_error += 1

                # Persist to DB
                if self._db is not None and result.status == "vulnerable":
                    try:
                        cves = getattr(rec, "cves", [])
                        self._db.add_vuln(
                            target, module_path=rec.path,
                            cve_ids=cves, severity="",
                            detail=result.detail[:300],
                        )
                        self._db.add_run(target=target, module_path=rec.path,
                                         result=result.status, detail=result.detail[:200])
                    except Exception:
                        pass

                if self.verbose:
                    icon = {
                        "vulnerable":     "[+]",
                        "not_vulnerable": "[-]",
                        "error":          "[!]",
                        "skipped":        "[~]",
                    }.get(result.status, "[?]")
                    short = rec.path.split(".")[-1]
                    print(f"  {icon} {short:<50} {result.status}  {result.detail[:60]}")

        report.elapsed_s = time.time() - t0
        if self.verbose:
            print(report.summary())
        return report
