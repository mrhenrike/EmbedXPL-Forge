"""ML attack advisor, response classifier, banner fingerprinter, and GPU hints.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from routerxpl.core.ml.advisor import AttackAdvisor, AdvisorContext, ScanOutcome
from routerxpl.core.ml.gpu import gpu_capability_summary, detect_all_backends
from routerxpl.core.ml.response_classifier import ResponseClassifier, ClassifiedResponse, ResponseLabel
from routerxpl.core.ml.banner_fingerprint import BannerFingerprinter, FingerprintMatch

__all__ = (
    "AttackAdvisor",
    "AdvisorContext",
    "ScanOutcome",
    "gpu_capability_summary",
    "detect_all_backends",
    "ResponseClassifier",
    "ClassifiedResponse",
    "ResponseLabel",
    "BannerFingerprinter",
    "FingerprintMatch",
)
