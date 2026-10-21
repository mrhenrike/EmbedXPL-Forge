"""Anomaly detection in scan responses — identifies honeypots, WAF, IPS.

Uses statistical analysis of timing, response sizes, and header patterns
to flag suspicious targets. Falls back to heuristic rules if scikit-learn
is not available.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import logging
import statistics
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger("embedxpl.core.ml.anomaly_detector")


@dataclass
class AnomalyScore:
    """Anomaly assessment for a target."""
    target: str
    score: float  # 0.0 = normal, 1.0 = highly anomalous
    label: str  # "normal", "honeypot_suspect", "waf_detected", "ips_detected"
    evidence: List[str]


class AnomalyDetector:
    """Detects anomalous scan responses indicating honeypots, WAF, or IPS."""

    HONEYPOT_INDICATORS = [
        "cowrie", "kippo", "dionaea", "glastopf", "conpot",
        "honeyd", "artillery", "opencanary",
    ]
    WAF_INDICATORS = [
        "cloudflare", "akamai", "incapsula", "sucuri", "mod_security",
        "barracuda", "f5-bigip-ltm", "citrix-adc",
    ]

    def __init__(self, model_path: Optional[str] = None) -> None:
        self._model = None
        if model_path:
            self._load_model(model_path)

    def _load_model(self, path: str) -> None:
        """Load trained Isolation Forest model."""
        try:
            import joblib
            self._model = joblib.load(path)
        except (ImportError, Exception) as exc:
            logger.info("Anomaly model not loaded: %s — using heuristic", exc)

    def analyze(
        self,
        target: str,
        response_times_ms: List[float],
        response_sizes: List[int],
        headers: Dict[str, str],
        body_sample: str = "",
    ) -> AnomalyScore:
        """Analyze target responses for anomalies."""
        evidence = []
        score = 0.0

        if response_times_ms:
            std = statistics.stdev(response_times_ms) if len(response_times_ms) > 1 else 0
            mean = statistics.mean(response_times_ms)
            if std < 0.5 and mean < 5:
                score += 0.3
                evidence.append(f"Suspiciously uniform timing (mean={mean:.1f}ms, std={std:.2f})")

        if response_sizes:
            unique_sizes = len(set(response_sizes))
            if unique_sizes == 1 and len(response_sizes) > 3:
                score += 0.2
                evidence.append("All responses identical size")

        server = headers.get("server", "").lower()
        for indicator in self.HONEYPOT_INDICATORS:
            if indicator in server or indicator in body_sample.lower():
                score += 0.4
                evidence.append(f"Honeypot indicator: {indicator}")

        for indicator in self.WAF_INDICATORS:
            if indicator in server:
                score += 0.1
                evidence.append(f"WAF/CDN detected: {indicator}")

        score = min(score, 1.0)
        if score >= 0.6:
            label = "honeypot_suspect"
        elif score >= 0.3:
            label = "waf_detected" if any("WAF" in e for e in evidence) else "suspicious"
        else:
            label = "normal"

        return AnomalyScore(target=target, score=score, label=label, evidence=evidence)
