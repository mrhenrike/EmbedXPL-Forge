"""ML attack advisor, response classifier, banner fingerprinter, and GPU hints.

Author: André Henrique (@mrhenrike) | União Geek  -  https://github.com/Uniao-Geek
"""

from embedxpl.core.ml.advisor import AdvisorContext, AttackAdvisor, ScanOutcome
from embedxpl.core.ml.banner_fingerprint import BannerFingerprinter, FingerprintMatch
from embedxpl.core.ml.gpu import detect_all_backends, gpu_capability_summary
from embedxpl.core.ml.response_classifier import ClassifiedResponse, ResponseClassifier, ResponseLabel

__all__ = (
    "AdvisorContext",
    "AttackAdvisor",
    "BannerFingerprinter",
    "ClassifiedResponse",
    "FingerprintMatch",
    "ResponseClassifier",
    "ResponseLabel",
    "ScanOutcome",
    "detect_all_backends",
    "gpu_capability_summary",
)
