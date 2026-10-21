"""ML attack advisor, response classifier, banner fingerprinter, GPU hints,
anomaly detection, attack optimization, auto-tuning, credential mutation,
and service fingerprinting.

Author: Andre Henrique (@mrhenrike) | Uniao Geek  -  https://github.com/Uniao-Geek
"""

from embedxpl.core.ml.advisor import AdvisorContext, AttackAdvisor, ScanOutcome
from embedxpl.core.ml.anomaly_detector import AnomalyDetector, AnomalyScore
from embedxpl.core.ml.attack_optimizer import AttackOptimizer
from embedxpl.core.ml.auto_tuner import AutoTuner, TuningProfile
from embedxpl.core.ml.banner_fingerprint import BannerFingerprinter, FingerprintMatch
from embedxpl.core.ml.credential_mutator import CredentialMutator
from embedxpl.core.ml.fingerprinter import Prediction, ServiceFingerprinter
from embedxpl.core.ml.gpu import detect_all_backends, gpu_capability_summary
from embedxpl.core.ml.response_classifier import ClassifiedResponse, ResponseClassifier, ResponseLabel

__all__ = (
    "AdvisorContext",
    "AnomalyDetector",
    "AnomalyScore",
    "AttackAdvisor",
    "AttackOptimizer",
    "AutoTuner",
    "BannerFingerprinter",
    "ClassifiedResponse",
    "CredentialMutator",
    "FingerprintMatch",
    "Prediction",
    "ResponseClassifier",
    "ResponseLabel",
    "ScanOutcome",
    "ServiceFingerprinter",
    "TuningProfile",
    "detect_all_backends",
    "gpu_capability_summary",
)
