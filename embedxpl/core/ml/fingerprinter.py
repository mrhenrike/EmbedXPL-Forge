"""ML-based service fingerprinter — classifies vendor/product from banners.

Uses TF-IDF + Random Forest (scikit-learn) trained on a corpus of security
appliance banners, HTTP headers, and SSH version strings.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("embedxpl.ml.fingerprinter")


@dataclass
class Prediction:
    """Single fingerprint prediction."""
    vendor: str
    product: str
    confidence: float
    evidence: str = ""


class ServiceFingerprinter:
    """Classifies target service/vendor/version from banners and headers."""

    def __init__(self, model_path: Optional[str] = None) -> None:
        self._model = None
        self._vectorizer = None
        self._model_path = model_path
        self._loaded = False

    def _load_model(self) -> bool:
        """Attempt to load trained model from disk."""
        if self._loaded:
            return self._model is not None
        self._loaded = True
        if not self._model_path:
            default = Path(__file__).resolve().parents[1] / "resources" / "ml" / "models" / "fingerprint.pkl"
            if not default.exists():
                logger.info("Fingerprint model not found at %s — using heuristic fallback", default)
                return False
            self._model_path = str(default)
        try:
            import joblib
            data = joblib.load(self._model_path)
            self._model = data.get("model")
            self._vectorizer = data.get("vectorizer")
            return self._model is not None
        except (ImportError, Exception) as exc:
            logger.warning("Could not load fingerprint model: %s", exc)
            return False

    def predict(self, banner: str) -> List[Prediction]:
        """Predict vendor/product from a single banner string."""
        if self._load_model() and self._vectorizer and self._model:
            try:
                vec = self._vectorizer.transform([banner])
                proba = self._model.predict_proba(vec)[0]
                classes = self._model.classes_
                results = []
                for cls, prob in zip(classes, proba):
                    if prob > 0.1:
                        parts = cls.split("/", 1)
                        results.append(Prediction(
                            vendor=parts[0],
                            product=parts[1] if len(parts) > 1 else "",
                            confidence=float(prob),
                            evidence=f"ML model ({prob:.1%})",
                        ))
                return sorted(results, key=lambda x: x.confidence, reverse=True)
            except Exception as exc:
                logger.debug("ML predict failed: %s", exc)

        return self._heuristic_predict(banner)

    def predict_batch(self, banners: List[str]) -> List[List[Prediction]]:
        """Predict for multiple banners."""
        return [self.predict(b) for b in banners]

    @staticmethod
    def _heuristic_predict(banner: str) -> List[Prediction]:
        """Fallback heuristic matching for common appliance signatures."""
        lower = banner.lower()
        signatures = [
            ("fortinet", "fortigate", ["fortios", "fortigate", "fgt_lang", "fortinet"]),
            ("cisco", "asa", ["cisco", "adaptive security", "webvpn", "asdm"]),
            ("paloalto", "pan-os", ["palo alto", "pan-os", "globalprotect"]),
            ("f5", "bigip", ["big-ip", "bigip", "f5", "tmui"]),
            ("citrix", "netscaler", ["citrix", "netscaler", "ns-root"]),
            ("checkpoint", "gaia", ["check point", "gaia", "cpuse"]),
            ("juniper", "junos", ["juniper", "junos", "j-web"]),
            ("sonicwall", "sonicos", ["sonicwall", "sonicos"]),
            ("sophos", "sfos", ["sophos", "sfos", "cyberoam"]),
            ("watchguard", "fireware", ["watchguard", "fireware"]),
            ("zyxel", "usg", ["zyxel", "zywall", "usg"]),
            ("pfsense", "pfsense", ["pfsense", "netgate"]),
            ("imperva", "securesphere", ["imperva", "securesphere"]),
            ("aruba", "clearpass", ["clearpass", "aruba"]),
            ("pulse", "connect-secure", ["pulse secure", "pulse connect", "dana-na"]),
        ]
        results = []
        for vendor, product, keywords in signatures:
            matching = [k for k in keywords if k in lower]
            if matching:
                conf = min(0.3 + 0.2 * len(matching), 0.9)
                results.append(Prediction(
                    vendor=vendor, product=product, confidence=conf,
                    evidence=f"heuristic: matched {matching}",
                ))
        return sorted(results, key=lambda x: x.confidence, reverse=True)
