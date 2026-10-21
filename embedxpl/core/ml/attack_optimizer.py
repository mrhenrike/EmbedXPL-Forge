"""Attack path optimizer — Multi-Armed Bandit for module sequencing.

Uses Thompson Sampling to learn which module types succeed most frequently
for a given target profile, optimizing the attack order over time.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import json
import logging
import random
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("embedxpl.ml.attack_optimizer")


class ScanOutcome:
    """Result of a single attack module execution against a target."""

    __slots__ = ("duration_ms", "findings_count", "module_id", "success")

    def __init__(
        self,
        module_id: str,
        success: bool,
        duration_ms: float = 0.0,
        findings_count: int = 0,
    ) -> None:
        self.module_id = module_id
        self.success = success
        self.duration_ms = duration_ms
        self.findings_count = findings_count

    def __repr__(self) -> str:
        return (
            f"ScanOutcome({self.module_id!r}, success={self.success}, "
            f"findings={self.findings_count})"
        )


class AttackOptimizer:
    """Multi-Armed Bandit optimizer for attack module sequencing."""

    def __init__(self, rewards_path: Optional[str] = None) -> None:
        self._alpha: Dict[str, float] = defaultdict(lambda: 1.0)
        self._beta: Dict[str, float] = defaultdict(lambda: 1.0)
        self._rewards_path = rewards_path
        if rewards_path:
            self._load_rewards(rewards_path)

    def _load_rewards(self, path: str) -> None:
        """Load historical reward data."""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            for k, v in data.get("alpha", {}).items():
                self._alpha[k] = v
            for k, v in data.get("beta", {}).items():
                self._beta[k] = v
        except (OSError, json.JSONDecodeError) as exc:
            logger.debug("Rewards file not loaded: %s", exc)

    def save_rewards(self, path: Optional[str] = None) -> None:
        """Persist learned rewards to disk."""
        target = path or self._rewards_path
        if not target:
            return
        data = {"alpha": dict(self._alpha), "beta": dict(self._beta)}
        Path(target).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def prioritize(self, module_names: List[str]) -> List[str]:
        """Return modules sorted by Thompson Sampling scores (best first)."""
        scored = []
        for name in module_names:
            sample = random.betavariate(self._alpha[name], self._beta[name])
            scored.append((name, sample))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [name for name, _ in scored]

    def update(self, module_name: str, success: bool) -> None:
        """Update reward model after a module execution."""
        if success:
            self._alpha[module_name] += 1.0
        else:
            self._beta[module_name] += 1.0

    def get_stats(self, module_name: str) -> Tuple[float, float, float]:
        """Return (alpha, beta, expected_success_rate) for a module."""
        a = self._alpha[module_name]
        b = self._beta[module_name]
        return a, b, a / (a + b)
