"""GPU compute backends for EmbedXPL-Forge.

Author: André Henrique (LinkedIn/X: @mrhenrike)
"""

from embedxpl.core.gpu.backend import ComputeBackend, auto_select_backend
from embedxpl.core.gpu.cpu_backend import CPUBackend

__all__ = [
    "ComputeBackend",
    "auto_select_backend",
    "CPUBackend",
]
