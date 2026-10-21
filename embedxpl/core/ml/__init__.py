"""Machine Learning engine for EmbedXPL-Forge.

Provides trained models for attack prioritization, service fingerprinting,
credential mutation, anomaly detection, and attack path optimization.

Author: André Henrique (@mrhenrike) | União Geek
"""

__all__ = [
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
]

_LAZY_IMPORTS = {
    "AdvisorContext": ("embedxpl.core.ml.advisor", "AdvisorContext"),
    "AttackAdvisor": ("embedxpl.core.ml.advisor", "AttackAdvisor"),
    "AnomalyDetector": ("embedxpl.core.ml.anomaly_detector", "AnomalyDetector"),
    "AnomalyScore": ("embedxpl.core.ml.anomaly_detector", "AnomalyScore"),
    "AttackOptimizer": ("embedxpl.core.ml.attack_optimizer", "AttackOptimizer"),
    "ScanOutcome": ("embedxpl.core.ml.attack_optimizer", "ScanOutcome"),
    "AutoTuner": ("embedxpl.core.ml.auto_tuner", "AutoTuner"),
    "TuningProfile": ("embedxpl.core.ml.auto_tuner", "TuningProfile"),
    "BannerFingerprinter": ("embedxpl.core.ml.banner_fingerprint", "BannerFingerprinter"),
    "FingerprintMatch": ("embedxpl.core.ml.banner_fingerprint", "FingerprintMatch"),
    "CredentialMutator": ("embedxpl.core.ml.credential_mutator", "CredentialMutator"),
    "Prediction": ("embedxpl.core.ml.fingerprinter", "Prediction"),
    "ServiceFingerprinter": ("embedxpl.core.ml.fingerprinter", "ServiceFingerprinter"),
    "detect_all_backends": ("embedxpl.core.ml.gpu", "detect_all_backends"),
    "gpu_capability_summary": ("embedxpl.core.ml.gpu", "gpu_capability_summary"),
    "ClassifiedResponse": ("embedxpl.core.ml.response_classifier", "ClassifiedResponse"),
    "ResponseClassifier": ("embedxpl.core.ml.response_classifier", "ResponseClassifier"),
    "ResponseLabel": ("embedxpl.core.ml.response_classifier", "ResponseLabel"),
}


def __getattr__(name: str):
    if name in _LAZY_IMPORTS:
        module_path, attr = _LAZY_IMPORTS[name]
        import importlib
        mod = importlib.import_module(module_path)
        val = getattr(mod, attr)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
