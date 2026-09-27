"""HTTP response classifier -- ML-based vulnerability detection.

Classifies HTTP responses as vulnerable / not_vulnerable / honeypot / unknown
using TF-IDF + LogisticRegression. Replaces naive status-code-only ``check()``
stubs with data-driven classification.

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_SKLEARN_AVAILABLE = False
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    import numpy as np
    _SKLEARN_AVAILABLE = True
except ImportError:
    pass


class ResponseLabel:
    """Possible response classification labels."""
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    HONEYPOT = "honeypot"
    UNKNOWN = "unknown"


@dataclass
class ClassifiedResponse:
    """Result of classifying an HTTP response."""
    label: str
    confidence: float
    features_used: List[str] = field(default_factory=list)
    detail: str = ""


# Heuristic patterns when sklearn is unavailable
_VULN_PATTERNS = [
    re.compile(r"root:", re.IGNORECASE),
    re.compile(r"uid=\d+\(", re.IGNORECASE),
    re.compile(r"<pre>.*(?:passwd|shadow|config)", re.IGNORECASE | re.DOTALL),
    re.compile(r"command\s*(?:output|result|executed)", re.IGNORECASE),
    re.compile(r"(?:admin|root)\s*password\s*[:=]", re.IGNORECASE),
    re.compile(r"firmware\s*version", re.IGNORECASE),
    re.compile(r"(?:wget|curl|tftp|busybox)\s", re.IGNORECASE),
    re.compile(r"(?:Linux|BusyBox|OpenWrt)\s+\d+\.\d+", re.IGNORECASE),
    re.compile(r"\"success\"\s*:\s*true", re.IGNORECASE),
    re.compile(r"boa/\d|micro_httpd|GoAhead|mini_httpd", re.IGNORECASE),
]

_HONEYPOT_PATTERNS = [
    re.compile(r"cowrie|kippo|dionaea|conpot|honeyd", re.IGNORECASE),
    re.compile(r"glastopf|tanner|snare", re.IGNORECASE),
    re.compile(r"HoneyBadger|MHN|T-Pot", re.IGNORECASE),
]

_NOT_VULN_PATTERNS = [
    re.compile(r"<title>\s*(?:404|403|401|Not Found|Forbidden|Unauthorized)", re.IGNORECASE),
    re.compile(r"access\s*denied", re.IGNORECASE),
    re.compile(r"invalid\s*(?:credentials|login|password)", re.IGNORECASE),
    re.compile(r"authentication\s*(?:failed|required)", re.IGNORECASE),
]


class ResponseClassifier:
    """Classifies HTTP responses to detect vulnerability indicators.

    Uses sklearn TF-IDF + LogisticRegression when available,
    falls back to pattern-based heuristics otherwise.
    """

    def __init__(self, model_path: Optional[str] = None) -> None:
        self._pipeline: Optional[Any] = None
        self._heuristic_only = not _SKLEARN_AVAILABLE
        self._training_data: List[Tuple[str, str]] = []
        self._is_trained = False

        if model_path and _SKLEARN_AVAILABLE:
            self._load_model(model_path)

    @property
    def is_ml_available(self) -> bool:
        """True if sklearn is available for ML classification."""
        return _SKLEARN_AVAILABLE

    @property
    def is_trained(self) -> bool:
        """True if the ML pipeline has been trained."""
        return self._is_trained

    def _load_model(self, path: str) -> None:
        """Load a pre-trained model from disk."""
        try:
            import joblib
            self._pipeline = joblib.load(path)
            self._is_trained = True
            logger.info("Loaded response classifier from %s", path)
        except Exception as exc:
            logger.warning("Failed to load classifier from %s: %s", path, exc)

    def save_model(self, path: str) -> None:
        """Save the trained pipeline to disk."""
        if self._pipeline is None:
            logger.warning("No trained pipeline to save")
            return
        try:
            import joblib
            joblib.dump(self._pipeline, path)
            logger.info("Saved response classifier to %s", path)
        except Exception as exc:
            logger.warning("Failed to save classifier: %s", exc)

    def add_training_sample(self, response_text: str, label: str) -> None:
        """Add a labeled sample for future training.

        Args:
            response_text: Raw HTTP response body/headers text.
            label: One of ResponseLabel constants.
        """
        self._training_data.append((response_text, label))

    def train(self, min_samples: int = 20) -> bool:
        """Train the classifier on accumulated samples.

        Args:
            min_samples: Minimum samples required before training.

        Returns:
            True if training succeeded.
        """
        if not _SKLEARN_AVAILABLE:
            logger.warning("sklearn not available -- cannot train classifier")
            return False

        if len(self._training_data) < min_samples:
            logger.info(
                "Not enough training data (%d/%d). Collecting more samples.",
                len(self._training_data), min_samples,
            )
            return False

        texts = [t for t, _ in self._training_data]
        labels = [l for _, l in self._training_data]

        unique_labels = set(labels)
        if len(unique_labels) < 2:
            logger.warning("Need at least 2 distinct labels to train. Got: %s", unique_labels)
            return False

        self._pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 2),
                sublinear_tf=True,
                strip_accents="unicode",
                token_pattern=r"(?u)\b\w[\w./-]+\b",
            )),
            ("clf", LogisticRegression(
                max_iter=500,
                C=1.0,
                class_weight="balanced",
                solver="lbfgs",
            )),
        ])

        try:
            self._pipeline.fit(texts, labels)
            self._is_trained = True
            logger.info("Response classifier trained on %d samples", len(texts))
            return True
        except Exception as exc:
            logger.error("Classifier training failed: %s", exc)
            return False

    def classify(
        self,
        response_body: str,
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
    ) -> ClassifiedResponse:
        """Classify an HTTP response.

        Args:
            response_body: Raw response body text.
            status_code: HTTP status code.
            headers: Optional HTTP response headers.

        Returns:
            ClassifiedResponse with label and confidence.
        """
        if self._is_trained and self._pipeline is not None:
            return self._classify_ml(response_body, status_code, headers)
        return self._classify_heuristic(response_body, status_code, headers)

    def _classify_ml(
        self,
        body: str,
        status_code: int,
        headers: Optional[Dict[str, str]],
    ) -> ClassifiedResponse:
        """ML-based classification using trained TF-IDF + LR pipeline."""
        combined = self._build_feature_text(body, status_code, headers)

        try:
            pred = self._pipeline.predict([combined])[0]
            proba = self._pipeline.predict_proba([combined])[0]
            classes = self._pipeline.classes_
            conf = float(max(proba))

            return ClassifiedResponse(
                label=pred,
                confidence=conf,
                features_used=["tfidf_ml", "status_code", "headers"],
                detail="ML classification: {} (conf={:.3f})".format(pred, conf),
            )
        except Exception as exc:
            logger.debug("ML classification failed, falling back to heuristic: %s", exc)
            return self._classify_heuristic(body, status_code, headers)

    def _classify_heuristic(
        self,
        body: str,
        status_code: int,
        headers: Optional[Dict[str, str]],
    ) -> ClassifiedResponse:
        """Pattern-based heuristic classification."""
        features_used: List[str] = []
        combined = body
        if headers:
            combined = " ".join("{}: {}".format(k, v) for k, v in headers.items()) + " " + body

        # Honeypot check (highest priority)
        for pat in _HONEYPOT_PATTERNS:
            if pat.search(combined):
                return ClassifiedResponse(
                    label=ResponseLabel.HONEYPOT,
                    confidence=0.75,
                    features_used=["honeypot_pattern"],
                    detail="Honeypot indicator: {}".format(pat.pattern),
                )

        # Vulnerability indicators
        vuln_hits = 0
        for pat in _VULN_PATTERNS:
            if pat.search(combined):
                vuln_hits += 1
                features_used.append("vuln:{}".format(pat.pattern[:30]))

        # Not-vulnerable indicators
        notvuln_hits = 0
        for pat in _NOT_VULN_PATTERNS:
            if pat.search(combined):
                notvuln_hits += 1
                features_used.append("notvuln:{}".format(pat.pattern[:30]))

        # Status code heuristics
        if status_code in (401, 403):
            notvuln_hits += 1
            features_used.append("status:{}".format(status_code))
        elif status_code == 200 and vuln_hits > 0:
            features_used.append("status:200+vuln_content")

        # Empty/minimal response
        if len(body.strip()) < 10:
            return ClassifiedResponse(
                label=ResponseLabel.UNKNOWN,
                confidence=0.3,
                features_used=["empty_body"],
                detail="Response body too short for classification",
            )

        # Score
        if vuln_hits >= 2:
            conf = min(0.9, 0.5 + vuln_hits * 0.1)
            return ClassifiedResponse(
                label=ResponseLabel.VULNERABLE,
                confidence=conf,
                features_used=features_used,
                detail="{} vulnerability indicators found".format(vuln_hits),
            )
        elif vuln_hits == 1 and notvuln_hits == 0:
            return ClassifiedResponse(
                label=ResponseLabel.VULNERABLE,
                confidence=0.5,
                features_used=features_used,
                detail="Single vulnerability indicator (low confidence)",
            )
        elif notvuln_hits > 0:
            conf = min(0.85, 0.5 + notvuln_hits * 0.1)
            return ClassifiedResponse(
                label=ResponseLabel.NOT_VULNERABLE,
                confidence=conf,
                features_used=features_used,
                detail="{} not-vulnerable indicators found".format(notvuln_hits),
            )

        return ClassifiedResponse(
            label=ResponseLabel.UNKNOWN,
            confidence=0.3,
            features_used=features_used or ["no_match"],
            detail="No strong indicators matched",
        )

    @staticmethod
    def _build_feature_text(
        body: str,
        status_code: int,
        headers: Optional[Dict[str, str]],
    ) -> str:
        """Combine response components into a single feature string for TF-IDF."""
        parts = ["STATUS_{}".format(status_code)]
        if headers:
            server = headers.get("Server", headers.get("server", ""))
            if server:
                parts.append("SERVER_{}".format(server))
            content_type = headers.get("Content-Type", headers.get("content-type", ""))
            if content_type:
                parts.append("CTYPE_{}".format(content_type.split(";")[0].strip()))
            www_auth = headers.get("WWW-Authenticate", headers.get("www-authenticate", ""))
            if www_auth:
                parts.append("AUTH_{}".format(www_auth))
        parts.append(body[:8000])
        return " ".join(parts)
