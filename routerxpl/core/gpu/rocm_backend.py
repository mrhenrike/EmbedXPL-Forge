"""AMD ROCm compute backend via PyTorch-ROCm or CuPy-ROCm.

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import logging

import numpy as np

from routerxpl.core.gpu.backend import ComputeBackend

logger = logging.getLogger(__name__)


class ROCmBackend(ComputeBackend):
    """AMD ROCm backend. Uses PyTorch compiled with HIP/ROCm support."""

    name = "rocm"

    def __init__(self):
        self._torch = None

    def is_available(self) -> bool:
        try:
            import torch
            if hasattr(torch.version, "hip") and torch.version.hip is not None:
                if torch.cuda.is_available():
                    self._torch = torch
                    return True
        except ImportError:
            pass
        return False

    def device_info(self) -> str:
        if self._torch:
            dev = self._torch.cuda.get_device_name(0)
            return "ROCm [PyTorch-HIP] {}".format(dev)
        return "ROCm (not available)"

    def array_from_numpy(self, arr: np.ndarray):
        if self._torch:
            return self._torch.tensor(arr, device="cuda", dtype=self._torch.float32)
        return arr

    def to_numpy(self, arr) -> np.ndarray:
        if self._torch:
            return arr.detach().cpu().numpy()
        return np.asarray(arr)

    def matmul(self, a, b):
        if self._torch:
            return self._torch.matmul(a, b)
        return np.matmul(a, b)

    def cosine_similarity_batch(self, queries, corpus) -> np.ndarray:
        q = self.array_from_numpy(np.asarray(queries, dtype=np.float32))
        c = self.array_from_numpy(np.asarray(corpus, dtype=np.float32))

        if self._torch:
            q_n = q / (q.norm(dim=1, keepdim=True) + 1e-10)
            c_n = c / (c.norm(dim=1, keepdim=True) + 1e-10)
            sim = self._torch.mm(q_n, c_n.t())
            return self.to_numpy(sim)
        return np.zeros((len(queries), len(corpus)), dtype=np.float32)
