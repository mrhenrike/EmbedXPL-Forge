"""ComputeBackend -- abstract base class for GPU/CPU compute backends.

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, List, Optional

import numpy as np

if TYPE_CHECKING:
    from routerxpl.core.hw_profiler import HWProfile

logger = logging.getLogger(__name__)


class ComputeBackend(ABC):
    """Abstract base class for compute backends (CUDA, ROCm, OpenCL, CPU).

    Each backend implements the same operations so callers (hash_cracker,
    payload_mutator, fingerprint matcher) can dispatch transparently.
    """

    name: str = "abstract"

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this backend is usable on the current system."""

    @abstractmethod
    def device_info(self) -> str:
        """Return a human-readable device description."""

    @abstractmethod
    def array_from_numpy(self, arr: np.ndarray):
        """Convert a NumPy array to the backend's native array type."""

    @abstractmethod
    def to_numpy(self, arr) -> np.ndarray:
        """Convert backend array back to NumPy."""

    @abstractmethod
    def matmul(self, a, b):
        """Matrix multiplication on the backend."""

    @abstractmethod
    def cosine_similarity_batch(self, queries, corpus) -> np.ndarray:
        """Compute cosine similarity between query vectors and a corpus matrix.

        Args:
            queries: (N, D) array of query vectors.
            corpus: (M, D) array of corpus vectors.

        Returns:
            (N, M) NumPy array of cosine similarity scores.
        """

    def hash_batch(self, data_list: List[bytes], algorithm: str = "md5") -> List[str]:
        """Hash a batch of byte strings. Default CPU implementation.

        GPU backends can override with parallel hashing.

        Args:
            data_list: List of byte strings to hash.
            algorithm: Hash algorithm name (md5, sha1, sha256).

        Returns:
            List of hex digest strings.
        """
        import hashlib
        return [hashlib.new(algorithm, d).hexdigest() for d in data_list]


def auto_select_backend(hw_profile: Optional[HWProfile] = None, compute_mode: str = "auto") -> ComputeBackend:
    """Select the best available compute backend.

    Args:
        hw_profile: Optional HWProfile with detected GPUs.
        compute_mode: User preference -- cpu, gpu, hybrid, auto.

    Returns:
        An instantiated ComputeBackend.
    """
    if compute_mode == "cpu":
        from routerxpl.core.gpu.cpu_backend import CPUBackend
        return CPUBackend()

    from routerxpl.core.gpu.cuda_backend import CUDABackend
    from routerxpl.core.gpu.rocm_backend import ROCmBackend
    from routerxpl.core.gpu.opencl_backend import OpenCLBackend
    from routerxpl.core.gpu.cpu_backend import CPUBackend

    candidates = [CUDABackend(), ROCmBackend(), OpenCLBackend()]

    for backend in candidates:
        if backend.is_available():
            logger.info("Auto-selected compute backend: %s", backend.name)
            return backend

    if compute_mode == "gpu":
        logger.warning(
            "compute_mode=gpu requested but no GPU backend available. "
            "Install PyTorch (CUDA/ROCm) or PyOpenCL. Falling back to CPU."
        )

    return CPUBackend()
