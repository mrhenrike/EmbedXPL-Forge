"""Optional attack advisor (lightweight ML/heuristics + GPU hints).

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from routerxpl.core.ml.advisor import AttackAdvisor, AdvisorContext
from routerxpl.core.ml.gpu import gpu_capability_summary, detect_all_backends

__all__ = (
    "AttackAdvisor",
    "AdvisorContext",
    "gpu_capability_summary",
    "detect_all_backends",
)
