"""NVIDIA CUDA compute backend via PyTorch or CuPy.

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import logging

import numpy as np

from routerxpl.core.gpu.backend import ComputeBackend

logger = logging.getLogger(__name__)

_torch = None
_cupy = None


def _try_torch():
    global _torch
    if _torch is not None:
        return _torch
    try:
        import torch
        if torch.cuda.is_available():
            _torch = torch
            return _torch
    except ImportError:
        pass
    return None


def _try_cupy():
    global _cupy
    if _cupy is not None:
        return _cupy
    try:
        import cupy
        if cupy.cuda.runtime.getDeviceCount() > 0:
            _cupy = cupy
            return _cupy
    except (ImportError, Exception):
        pass
    return None


class CUDABackend(ComputeBackend):
    """NVIDIA CUDA backend. Prefers PyTorch, falls back to CuPy."""

    name = "cuda"

    def __init__(self):
        self._lib = None  # 'torch' or 'cupy'

    def is_available(self) -> bool:
        if _try_torch():
            self._lib = "torch"
            return True
        if _try_cupy():
            self._lib = "cupy"
            return True
        return False

    def device_info(self) -> str:
        torch = _try_torch()
        if torch:
            dev = torch.cuda.get_device_name(0)
            vram = torch.cuda.get_device_properties(0).total_mem // (1024 * 1024)
            return "CUDA [PyTorch] {} ({}MB)".format(dev, vram)
        cupy = _try_cupy()
        if cupy:
            dev = cupy.cuda.Device(0)
            return "CUDA [CuPy] Device {}".format(dev.id)
        return "CUDA (not available)"

    def array_from_numpy(self, arr: np.ndarray):
        if self._lib == "torch":
            return _torch.tensor(arr, device="cuda", dtype=_torch.float32)
        if self._lib == "cupy":
            return _cupy.asarray(arr, dtype=_cupy.float32)
        return arr

    def to_numpy(self, arr) -> np.ndarray:
        if self._lib == "torch":
            return arr.detach().cpu().numpy()
        if self._lib == "cupy":
            return _cupy.asnumpy(arr)
        return np.asarray(arr)

    def matmul(self, a, b):
        if self._lib == "torch":
            return _torch.matmul(a, b)
        if self._lib == "cupy":
            return _cupy.matmul(a, b)
        return np.matmul(a, b)

    def cosine_similarity_batch(self, queries, corpus) -> np.ndarray:
        q = self.array_from_numpy(np.asarray(queries, dtype=np.float32))
        c = self.array_from_numpy(np.asarray(corpus, dtype=np.float32))

        if self._lib == "torch":
            q_n = q / (q.norm(dim=1, keepdim=True) + 1e-10)
            c_n = c / (c.norm(dim=1, keepdim=True) + 1e-10)
            sim = _torch.mm(q_n, c_n.t())
            return self.to_numpy(sim)
        if self._lib == "cupy":
            q_n = q / (_cupy.linalg.norm(q, axis=1, keepdims=True) + 1e-10)
            c_n = c / (_cupy.linalg.norm(c, axis=1, keepdims=True) + 1e-10)
            sim = q_n @ c_n.T
            return _cupy.asnumpy(sim)
        return np.zeros((len(queries), len(corpus)), dtype=np.float32)
