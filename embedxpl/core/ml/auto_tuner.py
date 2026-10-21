"""Auto-tuning of scan parameters based on target behavior.

Adjusts threads, timeout, batch size, and timing based on measured
latency and response patterns during scanning.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import logging
import statistics
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger("embedxpl.core.ml.auto_tuner")


@dataclass
class TuningProfile:
    """Recommended scan parameters after auto-tuning."""
    threads: int = 8
    timeout_s: float = 20.0
    delay_s: float = 0.0
    batch_size: int = 10
    timing_template: str = "T3"
    reasoning: str = ""


class AutoTuner:
    """Automatically adjusts scan parameters from observed target behavior."""

    def __init__(self) -> None:
        self._latencies: List[float] = []
        self._error_count: int = 0
        self._success_count: int = 0

    def record_latency(self, latency_ms: float) -> None:
        """Record a response latency measurement."""
        self._latencies.append(latency_ms)

    def record_result(self, success: bool) -> None:
        """Record module execution result."""
        if success:
            self._success_count += 1
        else:
            self._error_count += 1

    def recommend(self) -> TuningProfile:
        """Generate tuning recommendation from collected data."""
        if not self._latencies:
            return TuningProfile(reasoning="No data yet — using defaults")

        mean_lat = statistics.mean(self._latencies)
        total = self._success_count + self._error_count
        error_rate = self._error_count / max(total, 1)

        profile = TuningProfile()

        if mean_lat > 2000:
            profile.threads = 2
            profile.timeout_s = 30.0
            profile.delay_s = 1.0
            profile.timing_template = "T1"
            profile.reasoning = f"High latency ({mean_lat:.0f}ms) — slow/cautious mode"
        elif mean_lat > 500:
            profile.threads = 4
            profile.timeout_s = 20.0
            profile.delay_s = 0.2
            profile.timing_template = "T2"
            profile.reasoning = f"Moderate latency ({mean_lat:.0f}ms) — polite mode"
        elif error_rate > 0.5:
            profile.threads = 4
            profile.timeout_s = 25.0
            profile.delay_s = 0.5
            profile.timing_template = "T2"
            profile.reasoning = f"High error rate ({error_rate:.0%}) — backing off"
        elif mean_lat < 50:
            profile.threads = 32
            profile.timeout_s = 10.0
            profile.timing_template = "T5"
            profile.reasoning = f"Very low latency ({mean_lat:.0f}ms) — aggressive mode"
        else:
            profile.threads = 8
            profile.timeout_s = 20.0
            profile.timing_template = "T3"
            profile.reasoning = f"Normal latency ({mean_lat:.0f}ms) — balanced mode"

        return profile

    def reset(self) -> None:
        """Clear collected measurements."""
        self._latencies.clear()
        self._error_count = 0
        self._success_count = 0
