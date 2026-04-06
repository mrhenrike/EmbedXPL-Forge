"""GPU compute backends for RouterXPL-Forge.

Author: André Henrique (LinkedIn/X: @mrhenrike)
"""

from routerxpl.core.gpu.backend import ComputeBackend, auto_select_backend
from routerxpl.core.gpu.cpu_backend import CPUBackend

__all__ = [
    "ComputeBackend",
    "auto_select_backend",
    "CPUBackend",
]
