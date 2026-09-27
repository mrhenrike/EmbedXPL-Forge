"""OpenCL compute backend via PyOpenCL (Intel, AMD, NVIDIA legacy).

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import logging

import numpy as np

from embedxpl.core.gpu.backend import ComputeBackend

logger = logging.getLogger(__name__)


class OpenCLBackend(ComputeBackend):
    """OpenCL backend. Falls back to CPU-style NumPy for complex ops.

    OpenCL is used primarily for hash cracking and simple element-wise
    operations; full matrix ops are delegated to NumPy since pyopencl
    does not provide high-level linear algebra.
    """

    name = "opencl"

    def __init__(self):
        self._cl = None
        self._ctx = None
        self._queue = None

    def is_available(self) -> bool:
        try:
            import pyopencl as cl
            platforms = cl.get_platforms()
            for p in platforms:
                gpus = p.get_devices(device_type=cl.device_type.GPU)
                if gpus:
                    self._cl = cl
                    self._ctx = cl.Context([gpus[0]])
                    self._queue = cl.CommandQueue(self._ctx)
                    return True
        except (ImportError, Exception):
            pass
        return False

    def device_info(self) -> str:
        if self._ctx:
            dev = self._ctx.devices[0]
            vram = dev.global_mem_size // (1024 * 1024)
            return "OpenCL [{}] {}MB".format(dev.name.strip(), vram)
        return "OpenCL (not available)"

    def array_from_numpy(self, arr: np.ndarray):
        return np.asarray(arr, dtype=np.float32)

    def to_numpy(self, arr) -> np.ndarray:
        return np.asarray(arr)

    def matmul(self, a, b):
        return np.matmul(np.asarray(a), np.asarray(b))

    def cosine_similarity_batch(self, queries, corpus) -> np.ndarray:
        q = np.asarray(queries, dtype=np.float32)
        c = np.asarray(corpus, dtype=np.float32)
        q_norm = q / (np.linalg.norm(q, axis=1, keepdims=True) + 1e-10)
        c_norm = c / (np.linalg.norm(c, axis=1, keepdims=True) + 1e-10)
        return q_norm @ c_norm.T
