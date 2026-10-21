"""Tests for ML modules absorbed from FirewallXPL-Forge.

Validates that anomaly_detector, attack_optimizer, auto_tuner,
credential_mutator, and fingerprinter are importable and functional.
"""

from __future__ import annotations

import pytest


class TestAnomalyDetector:
    def test_import(self) -> None:
        from embedxpl.core.ml.anomaly_detector import AnomalyDetector, AnomalyScore
        assert AnomalyDetector is not None
        assert AnomalyScore is not None

    def test_instantiate(self) -> None:
        from embedxpl.core.ml.anomaly_detector import AnomalyDetector
        detector = AnomalyDetector()
        assert detector is not None

    def test_score_dataclass(self) -> None:
        from embedxpl.core.ml.anomaly_detector import AnomalyScore
        score = AnomalyScore(
            target="192.168.1.1",
            score=0.85,
            label="honeypot_suspect",
            evidence=["timing_anomaly"],
        )
        assert score.target == "192.168.1.1"
        assert score.score == 0.85
        assert score.label == "honeypot_suspect"


class TestAttackOptimizer:
    def test_import(self) -> None:
        from embedxpl.core.ml.attack_optimizer import AttackOptimizer
        assert AttackOptimizer is not None

    def test_instantiate(self) -> None:
        from embedxpl.core.ml.attack_optimizer import AttackOptimizer
        opt = AttackOptimizer()
        assert opt is not None


class TestAutoTuner:
    def test_import(self) -> None:
        from embedxpl.core.ml.auto_tuner import AutoTuner, TuningProfile
        assert AutoTuner is not None
        assert TuningProfile is not None

    def test_instantiate(self) -> None:
        from embedxpl.core.ml.auto_tuner import AutoTuner
        tuner = AutoTuner()
        assert tuner is not None


class TestCredentialMutator:
    def test_import(self) -> None:
        from embedxpl.core.ml.credential_mutator import CredentialMutator
        assert CredentialMutator is not None

    def test_instantiate(self) -> None:
        from embedxpl.core.ml.credential_mutator import CredentialMutator
        mutator = CredentialMutator()
        assert mutator is not None


class TestServiceFingerprinter:
    def test_import(self) -> None:
        from embedxpl.core.ml.fingerprinter import Prediction, ServiceFingerprinter
        assert ServiceFingerprinter is not None
        assert Prediction is not None

    def test_instantiate(self) -> None:
        from embedxpl.core.ml.fingerprinter import ServiceFingerprinter
        fp = ServiceFingerprinter()
        assert fp is not None


class TestMLInitExports:
    def test_all_exports(self) -> None:
        from embedxpl.core.ml import __all__
        expected = {
            "AnomalyDetector", "AnomalyScore",
            "AttackOptimizer",
            "AutoTuner", "TuningProfile",
            "CredentialMutator",
            "Prediction", "ServiceFingerprinter",
            "AdvisorContext", "AttackAdvisor",
            "BannerFingerprinter", "FingerprintMatch",
            "ClassifiedResponse", "ResponseClassifier", "ResponseLabel",
            "ScanOutcome",
            "detect_all_backends", "gpu_capability_summary",
        }
        assert expected.issubset(set(__all__))
