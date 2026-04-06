"""CPU fallback compute backend using NumPy.

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import numpy as np

from routerxpl.core.gpu.backend import ComputeBackend


class CPUBackend(ComputeBackend):
    """Pure CPU compute backend using NumPy. Always available."""

    name = "cpu"

    def is_available(self) -> bool:
        return True

    def device_info(self) -> str:
        import os
        return "CPU ({} threads, NumPy)".format(os.cpu_count() or 1)

    def array_from_numpy(self, arr: np.ndarray):
        return arr

    def to_numpy(self, arr) -> np.ndarray:
        return np.asarray(arr)

    def matmul(self, a, b):
        return np.matmul(a, b)

    def cosine_similarity_batch(self, queries, corpus) -> np.ndarray:
        q = np.asarray(queries, dtype=np.float32)
        c = np.asarray(corpus, dtype=np.float32)
        q_norm = q / (np.linalg.norm(q, axis=1, keepdims=True) + 1e-10)
        c_norm = c / (np.linalg.norm(c, axis=1, keepdims=True) + 1e-10)
        return q_norm @ c_norm.T
