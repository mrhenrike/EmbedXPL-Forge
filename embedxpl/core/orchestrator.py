"""EmbedXPL-Forge — Infrastructure Orchestrator.

Maps (infra, context) tuples to ordered module lists and generates
structured scan plans that the AsyncScanEngine can execute directly.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import importlib.resources
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

logger = logging.getLogger(__name__)

_PROFILES_RESOURCE = "infra_profiles.yaml"


@dataclass
class ScanPlan:
    """Structured scan plan produced by InfraOrchestrator.

    Attributes:
        target: IP address or CIDR range to scan.
        infra: Infrastructure type key (ot, it, iot).
        context: Operational context key within the infra type.
        modules: Resolved module paths relative to the modules/ root.
        priority_order: High-priority module paths to run first.
    """

    target: str
    infra: str
    context: str
    modules: List[Path] = field(default_factory=list)
    priority_order: List[str] = field(default_factory=list)

    def summary(self) -> str:
        """Return a human-readable summary of this scan plan.

        Returns:
            Multi-line string describing infra, context, target, and module count.
        """
        lines = [
            "ScanPlan Summary",
            "  Target  : {}".format(self.target),
            "  Infra   : {}".format(self.infra),
            "  Context : {}".format(self.context),
            "  Modules : {}".format(len(self.modules)),
        ]
        if self.priority_order:
            lines.append("  Priority: {}".format(", ".join(self.priority_order)))
        return "\n".join(lines)


class InfraOrchestrator:
    """Maps infrastructure/context pairs to EmbedXPL module paths.

    Loads ``infra_profiles.yaml`` from the embedded resources package and
    provides helpers to list available profiles, resolve module paths for a
    given (infra, context) pair, and build ready-to-run :class:`ScanPlan`
    objects.

    Author: André Henrique (@mrhenrike) | União Geek
    Version: 1.0.0

    Example::

        orch = InfraOrchestrator()
        plan = orch.build_scan_plan("192.168.1.0/24", "ot", "ics")
        print(plan.summary())
    """

    def __init__(self, modules_root: Optional[Path] = None) -> None:
        """Initialise the orchestrator.

        Args:
            modules_root: Base directory for EmbedXPL module files.
                          Defaults to the ``embedxpl/modules/`` package tree.
        """
        self._profiles: Optional[Dict] = None
        if modules_root is None:
            # Resolve relative to this file: embedxpl/core/ → embedxpl/modules/
            self._modules_root = Path(__file__).parent.parent / "modules"
        else:
            self._modules_root = Path(modules_root)

    # ------------------------------------------------------------------
    # Profile loading
    # ------------------------------------------------------------------

    def _profiles_path(self) -> Path:
        """Return the absolute path to infra_profiles.yaml.

        Returns:
            Path to the YAML taxonomy file.
        """
        return Path(__file__).parent.parent / "resources" / _PROFILES_RESOURCE

    def load_profiles(self) -> Dict:
        """Load and cache the YAML taxonomy.

        Returns:
            Parsed YAML dict with profile definitions.

        Raises:
            RuntimeError: If PyYAML is not installed.
            FileNotFoundError: If the profiles YAML file cannot be located.
        """
        if self._profiles is not None:
            return self._profiles

        if yaml is None:
            raise RuntimeError(
                "PyYAML is required for InfraOrchestrator: pip install pyyaml"
            )

        path = self._profiles_path()
        if not path.exists():
            raise FileNotFoundError(
                "infra_profiles.yaml not found at {}".format(path)
            )

        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

        self._profiles = data.get("profiles", {})
        logger.debug("Loaded %d infra profiles", len(self._profiles))
        return self._profiles

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_infra_types(self) -> List[str]:
        """List available infrastructure type keys.

        Returns:
            Sorted list of infra keys (e.g. ``['it', 'iot', 'ot']``).
        """
        return sorted(self.load_profiles().keys())

    def list_contexts(self, infra: str) -> List[str]:
        """List operational context keys for a given infra type.

        Args:
            infra: Infrastructure type key (e.g. ``'ot'``).

        Returns:
            Sorted list of context keys.

        Raises:
            KeyError: If ``infra`` is not a valid profile key.
        """
        profiles = self.load_profiles()
        if infra not in profiles:
            raise KeyError(
                "Unknown infra type '{}'. Valid: {}".format(
                    infra, self.list_infra_types()
                )
            )
        return sorted(profiles[infra].get("contexts", {}).keys())

    def resolve_modules(
        self,
        infra: str,
        context: str,
        scope: str = "all",
    ) -> List[Path]:
        """Resolve module file paths for a given (infra, context) pair.

        Walks the module_paths defined in the taxonomy and collects all
        ``*.py`` module files found on disk, excluding ``__init__.py``.

        Args:
            infra: Infrastructure type key.
            context: Operational context key.
            scope: ``'all'`` (default) returns every module found.
                   ``'exploits'`` returns only exploit modules.
                   ``'scanners'`` returns only scanner modules.
                   ``'creds'`` returns only credential modules.

        Returns:
            List of absolute :class:`Path` objects for discovered modules.

        Raises:
            KeyError: If infra or context is not found in the taxonomy.
        """
        profiles = self.load_profiles()
        if infra not in profiles:
            raise KeyError("Unknown infra '{}'".format(infra))
        contexts = profiles[infra].get("contexts", {})
        if context not in contexts:
            raise KeyError(
                "Unknown context '{}' for infra '{}'. Valid: {}".format(
                    context, infra, sorted(contexts.keys())
                )
            )

        raw_paths = contexts[context].get("module_paths", [])
        results: List[Path] = []

        for rel in raw_paths:
            if scope != "all" and not rel.startswith(scope):
                continue
            full = self._modules_root / rel
            if full.is_dir():
                for py in sorted(full.rglob("*.py")):
                    if py.name == "__init__.py":
                        continue
                    results.append(py)
            else:
                logger.debug("Module path not found on disk: %s", full)

        return results

    def build_scan_plan(
        self,
        target: str,
        infra: str,
        context: str,
    ) -> ScanPlan:
        """Build a :class:`ScanPlan` for a given target and (infra, context).

        Args:
            target: IP address, hostname, or CIDR range.
            infra: Infrastructure type key.
            context: Operational context key.

        Returns:
            A fully populated :class:`ScanPlan` instance.
        """
        modules = self.resolve_modules(infra, context)

        # High-priority paths: exploits come after scanners; creds last
        priority: List[str] = []
        for m in modules:
            rel = str(m.relative_to(self._modules_root))
            if rel.startswith("scanners"):
                priority.insert(0, rel)
            elif rel.startswith("exploits"):
                priority.append(rel)

        return ScanPlan(
            target=target,
            infra=infra,
            context=context,
            modules=modules,
            priority_order=priority[:5],  # top 5 only in summary
        )

    def interactive_wizard(self) -> ScanPlan:
        """Run an interactive terminal wizard to build a :class:`ScanPlan`.

        Prompts the user to choose infra type, context, and target via
        numbered menus.

        Returns:
            A :class:`ScanPlan` configured by the user's selections.
        """
        infra_types = self.list_infra_types()
        profiles = self.load_profiles()

        print("\n╔══════════════════════════════════════════════╗")
        print("║   EmbedXPL-Forge — Infrastructure Wizard     ║")
        print("╚══════════════════════════════════════════════╝\n")

        # Select infra type
        print("Select infrastructure type:")
        for i, key in enumerate(infra_types, 1):
            label = profiles[key].get("label", key)
            desc = profiles[key].get("description", "")
            print("  [{}] {}  —  {}".format(i, key.upper(), label))
            if desc:
                print("      {}".format(desc))

        while True:
            raw = input("\nInfra [1-{}]: ".format(len(infra_types))).strip()
            if raw.isdigit() and 1 <= int(raw) <= len(infra_types):
                infra = infra_types[int(raw) - 1]
                break
            if raw.lower() in infra_types:
                infra = raw.lower()
                break
            print("  Invalid choice, try again.")

        # Select context
        contexts = self.list_contexts(infra)
        ctx_map = profiles[infra].get("contexts", {})
        print("\nSelect operational context for [{}]:".format(infra.upper()))
        for i, key in enumerate(contexts, 1):
            label = ctx_map[key].get("label", key)
            print("  [{}] {}  —  {}".format(i, key, label))

        while True:
            raw = input("\nContext [1-{}]: ".format(len(contexts))).strip()
            if raw.isdigit() and 1 <= int(raw) <= len(contexts):
                context = contexts[int(raw) - 1]
                break
            if raw.lower() in contexts:
                context = raw.lower()
                break
            print("  Invalid choice, try again.")

        # Select target
        target = input("\nTarget IP / CIDR (e.g. 192.168.1.0/24): ").strip()
        if not target:
            target = "127.0.0.1"

        plan = self.build_scan_plan(target, infra, context)

        print("\n" + plan.summary())
        print("\n  Module paths resolved (showing first 10):")
        for m in plan.modules[:10]:
            print("    {}".format(m.relative_to(self._modules_root)))
        if len(plan.modules) > 10:
            print("    ... and {} more".format(len(plan.modules) - 10))

        return plan

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def describe(self) -> str:
        """Return a formatted table of all profiles and contexts.

        Returns:
            Multi-line string suitable for terminal output.
        """
        profiles = self.load_profiles()
        lines = [
            "\nEmbedXPL-Forge — Infrastructure Taxonomy",
            "=" * 55,
        ]
        for infra_key, infra_data in sorted(profiles.items()):
            lines.append(
                "\n[{}] {}".format(
                    infra_key.upper(), infra_data.get("label", infra_key)
                )
            )
            for ctx_key, ctx_data in sorted(
                infra_data.get("contexts", {}).items()
            ):
                paths = ctx_data.get("module_paths", [])
                lines.append(
                    "    {:20s}  {}  ({} paths)".format(
                        ctx_key,
                        ctx_data.get("label", ""),
                        len(paths),
                    )
                )
        return "\n".join(lines)
