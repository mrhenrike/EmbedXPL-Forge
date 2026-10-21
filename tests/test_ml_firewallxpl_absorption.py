"""Tests for ML modules absorbed from FirewallXPL-Forge."""

from __future__ import annotations


class TestAnomalyDetector:
    def test_import(self) -> None:
        from embedxpl.core.ml.anomaly_detector import AnomalyDetector, AnomalyScore
        assert AnomalyDetector is not None
        assert AnomalyScore is not None

    def test_instantiate(self) -> None:
        from embedxpl.core.ml.anomaly_detector import AnomalyDetector
        assert AnomalyDetector() is not None

    def test_score_dataclass(self) -> None:
        from embedxpl.core.ml.anomaly_detector import AnomalyScore
        s = AnomalyScore(target="10.0.0.1", score=0.9, label="honeypot_suspect", evidence=["a"])
        assert s.score == 0.9


class TestAttackOptimizer:
    def test_import_and_create(self) -> None:
        from embedxpl.core.ml.attack_optimizer import AttackOptimizer
        assert AttackOptimizer() is not None


class TestAutoTuner:
    def test_import_and_create(self) -> None:
        from embedxpl.core.ml.auto_tuner import AutoTuner, TuningProfile
        assert AutoTuner() is not None
        assert TuningProfile is not None


class TestCredentialMutator:
    def test_import_and_create(self) -> None:
        from embedxpl.core.ml.credential_mutator import CredentialMutator
        assert CredentialMutator() is not None


class TestServiceFingerprinter:
    def test_import_and_create(self) -> None:
        from embedxpl.core.ml.fingerprinter import Prediction, ServiceFingerprinter
        assert ServiceFingerprinter() is not None
        assert Prediction is not None


class TestMLInitExports:
    def test_all_exports(self) -> None:
        from embedxpl.core.ml import __all__
        expected = {"AnomalyDetector", "AnomalyScore", "AttackOptimizer",
                    "AutoTuner", "TuningProfile", "CredentialMutator",
                    "Prediction", "ServiceFingerprinter"}
        assert expected.issubset(set(__all__))
