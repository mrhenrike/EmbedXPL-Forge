"""AutoPwn base engine for FirewallXPL-Forge.
# authorized use only
"""
from __future__ import annotations
import importlib, inspect, time
from dataclasses import dataclass, field

@dataclass
class AutoPwnReport:
    segment: str; targets: list
    modules_run: int = 0; modules_vulnerable: int = 0
    results: list = field(default_factory=list); elapsed_s: float = 0.0
    def summary(self):
        v = [r for r in self.results if r[2] == "vulnerable"]
        return f"\n{'='*60}\n  AutoPwn {self.segment.upper()} | {self.modules_run} modules | {self.modules_vulnerable} vulnerable\n{'='*60}"

class SegmentAutoPwn:
    """Base AutoPwn for firewallxpl."""
    def __init__(self, segment, targets, check_only=True, verbose=True, **kw):
        self.segment = segment.lower()
        self.targets = [targets] if isinstance(targets, str) else list(targets)
        self.check_only = check_only; self.verbose = verbose
    def _get_modules(self):
        try:
            from firewallxpl.tools.search import search_category
            return search_category(self.segment)
        except Exception: return []
    def run(self):
        t0 = time.time(); mods = self._get_modules()
        report = AutoPwnReport(segment=self.segment, targets=self.targets)
        if self.verbose: print(f"\n[*] AutoPwn {self.segment.upper()} — {len(mods)} modules")
        for target in self.targets:
            for rec in mods:
                try:
                    mod = importlib.import_module(rec.path)
                    cls = next((o for n,o in inspect.getmembers(mod,inspect.isclass) if hasattr(o,"check") or hasattr(o,"run")), None)
                    if not cls: continue
                    inst = cls()
                    for a in ["rhost","host","target","ip"]:
                        if hasattr(inst,a): setattr(inst,a,target); break
                    status = "not_vulnerable"
                    if self.check_only and hasattr(inst,"check"):
                        r = inst.check()
                        status = "vulnerable" if r is True or (isinstance(r,dict) and r.get("vulnerable")) else "not_vulnerable"
                    report.results.append((rec.path, target, status))
                    report.modules_run += 1
                    if status == "vulnerable": report.modules_vulnerable += 1
                    if self.verbose: print(f"  {'[+]' if status=='vulnerable' else '[-]'} {rec.path.split('.')[-1]:<50} {status}")
                except Exception as e:
                    report.results.append((rec.path, target, "error")); report.modules_run += 1
        report.elapsed_s = time.time() - t0
        if self.verbose: print(report.summary())
        return report
