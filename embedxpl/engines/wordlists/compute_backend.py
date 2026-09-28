"""
compute_backend.py - Compute backend abstraction for WFH ML acceleration.

Provides a unified interface for CPU and GPU compute operations used by
the ML pattern model (ml_patterns.py) and future accelerated modules.

Backend selection order:
  1. CUDA (NVIDIA)  - PyTorch / CuPy
  2. ROCm (AMD)     - PyTorch ROCm
  3. MPS  (Apple)   - PyTorch MPS
  4. OpenCL         - PyOpenCL
  5. CPU            - NumPy (always available)

Adapted from RouterXPL-Forge patterns (github.com/mrhenrike/RouterXPL-Forge).

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger(__name__)


# ── Abstract Backend ──────────────────────────────────────────────────────────

class ComputeBackend(ABC):
    """
    Abstract base for compute backends.

    All backends expose the same interface so ML code is backend-agnostic.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Backend identifier string (cuda | rocm | mps | opencl | cpu)."""

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """True if this backend can be used on the current machine."""

    @property
    @abstractmethod
    def device_info(self) -> str:
        """Human-readable device description."""

    def dot_product_batch(self, a: list[float], B: list[list[float]]) -> list[float]:
        """
        Compute dot products between vector a and each row of B.

        Used for candidate scoring in ml_patterns.PatternModel.

        Args:
            a: Feature vector (1-D).
            B: Matrix where each row is a candidate feature vector.

        Returns:
            List of dot product scores, one per row of B.
        """
        # Default pure-Python implementation (overridden by fast backends)
        return [sum(x * y for x, y in zip(a, row)) for row in B]

    def rank_by_weights(
        self,
        candidates:   list[str],
        feature_vecs: list[list[float]],
        weight_vec:   list[float],
    ) -> list[tuple[str, float]]:
        """
        Rank candidates by weighted feature dot product.

        Args:
            candidates:   Candidate strings (same length as feature_vecs).
            feature_vecs: Per-candidate feature vectors.
            weight_vec:   Global weight vector.

        Returns:
            List of (candidate, score) sorted descending.
        """
        scores = self.dot_product_batch(weight_vec, feature_vecs)
        ranked = sorted(zip(candidates, scores), key=lambda x: -x[1])
        return ranked


# ── CPU Backend ───────────────────────────────────────────────────────────────

class CPUBackend(ComputeBackend):
    """Pure-CPU backend using NumPy for vectorized operations."""

    @property
    def name(self) -> str:
        return "cpu"

    @property
    def is_available(self) -> bool:
        return True  # always available

    @property
    def device_info(self) -> str:
        try:
            import platform
            import os
            cores = os.cpu_count() or 1
            return f"CPU ({platform.processor() or 'unknown'}, {cores} threads)"
        except Exception:
            return "CPU"

    def dot_product_batch(self, a: list[float], B: list[list[float]]) -> list[float]:
        try:
            import numpy as np
            a_arr = np.array(a, dtype=np.float32)
            B_arr = np.array(B, dtype=np.float32)
            return (B_arr @ a_arr).tolist()
        except ImportError:
            return super().dot_product_batch(a, B)

    def rank_by_weights(
        self,
        candidates:   list[str],
        feature_vecs: list[list[float]],
        weight_vec:   list[float],
    ) -> list[tuple[str, float]]:
        try:
            import numpy as np
            w = np.array(weight_vec, dtype=np.float32)
            F = np.array(feature_vecs, dtype=np.float32)
            scores = F @ w
            order  = np.argsort(-scores)
            return [(candidates[i], float(scores[i])) for i in order]
        except ImportError:
            return super().rank_by_weights(candidates, feature_vecs, weight_vec)


# ── CUDA Backend ──────────────────────────────────────────────────────────────

class CUDABackend(ComputeBackend):
    """NVIDIA CUDA backend via PyTorch."""

    def __init__(self, device_index: int = 0) -> None:
        self._device_index = device_index
        self._device_str   = f"cuda:{device_index}"

    @property
    def name(self) -> str:
        return "cuda"

    @property
    def is_available(self) -> bool:
        try:
            import torch
            return torch.cuda.is_available()
        except ImportError:
            return False

    @property
    def device_info(self) -> str:
        try:
            import torch
            if torch.cuda.is_available():
                props = torch.cuda.get_device_properties(self._device_index)
                vram  = props.total_memory // (1024 * 1024)
                return f"CUDA {props.name} ({vram}MB VRAM, CC {props.major}.{props.minor})"
        except Exception:
            pass
        return "CUDA (unavailable)"

    def dot_product_batch(self, a: list[float], B: list[list[float]]) -> list[float]:
        try:
            import torch
            device = torch.device(self._device_str)
            a_t    = torch.tensor(a, dtype=torch.float32, device=device)
            B_t    = torch.tensor(B, dtype=torch.float32, device=device)
            result = (B_t @ a_t).cpu().tolist()
            return result
        except Exception as exc:
            logger.warning("CUDA dot_product failed (%s), falling back to CPU", exc)
            return CPUBackend().dot_product_batch(a, B)

    def rank_by_weights(
        self,
        candidates:   list[str],
        feature_vecs: list[list[float]],
        weight_vec:   list[float],
    ) -> list[tuple[str, float]]:
        try:
            import torch
            device = torch.device(self._device_str)
            w = torch.tensor(weight_vec, dtype=torch.float32, device=device)
            F = torch.tensor(feature_vecs, dtype=torch.float32, device=device)
            scores = (F @ w).cpu()
            order  = torch.argsort(scores, descending=True).tolist()
            return [(candidates[i], float(scores[i])) for i in order]
        except Exception as exc:
            logger.warning("CUDA rank_by_weights failed (%s), falling back to CPU", exc)
            return CPUBackend().rank_by_weights(candidates, feature_vecs, weight_vec)


# ── ROCm Backend ──────────────────────────────────────────────────────────────

class ROCmBackend(ComputeBackend):
    """AMD ROCm backend via PyTorch (hip device)."""

    @property
    def name(self) -> str:
        return "rocm"

    @property
    def is_available(self) -> bool:
        try:
            import torch
            return torch.cuda.is_available() and "rocm" in torch.__version__.lower()
        except ImportError:
            return False

    @property
    def device_info(self) -> str:
        try:
            import torch
            if torch.cuda.is_available():
                props = torch.cuda.get_device_properties(0)
                return f"ROCm {props.name}"
        except Exception:
            pass
        return "ROCm (unavailable)"

    def dot_product_batch(self, a: list[float], B: list[list[float]]) -> list[float]:
        try:
            import torch
            device = torch.device("cuda")
            a_t    = torch.tensor(a, dtype=torch.float32, device=device)
            B_t    = torch.tensor(B, dtype=torch.float32, device=device)
            return (B_t @ a_t).cpu().tolist()
        except Exception as exc:
            logger.warning("ROCm dot_product failed (%s), CPU fallback", exc)
            return CPUBackend().dot_product_batch(a, B)


# ── MPS Backend (Apple Silicon) ───────────────────────────────────────────────

class MPSBackend(ComputeBackend):
    """Apple Silicon MPS backend via PyTorch."""

    @property
    def name(self) -> str:
        return "mps"

    @property
    def is_available(self) -> bool:
        try:
            import torch
            return (
                hasattr(torch.backends, "mps")
                and torch.backends.mps.is_available()
            )
        except ImportError:
            return False

    @property
    def device_info(self) -> str:
        return "Apple Metal (MPS)"

    def dot_product_batch(self, a: list[float], B: list[list[float]]) -> list[float]:
        try:
            import torch
            device = torch.device("mps")
            a_t    = torch.tensor(a, dtype=torch.float32, device=device)
            B_t    = torch.tensor(B, dtype=torch.float32, device=device)
            return (B_t @ a_t).cpu().tolist()
        except Exception as exc:
            logger.warning("MPS dot_product failed (%s), CPU fallback", exc)
            return CPUBackend().dot_product_batch(a, B)


# ── Backend selection ─────────────────────────────────────────────────────────

def auto_select_backend(
    compute_mode: str = "auto",
    hw_profile=None,
) -> ComputeBackend:
    """
    Select and return the best available compute backend.

    Args:
        compute_mode: One of 'auto' | 'cpu' | 'gpu' | 'cuda' | 'rocm' | 'mps' | 'hybrid'.
                      'hybrid' = GPU for large batches, CPU for small (returns best GPU).
        hw_profile: Optional HWProfile (detected automatically if None).

    Returns:
        Instantiated ComputeBackend.
    """
    mode = compute_mode.lower().strip()

    # Explicit CPU request
    if mode == "cpu":
        return CPUBackend()

    # Explicit backend requests
    if mode == "cuda":
        b = CUDABackend()
        if b.is_available:
            return b
        logger.warning("CUDA requested but not available. Falling back to CPU.")
        return CPUBackend()

    if mode == "rocm":
        b = ROCmBackend()
        if b.is_available:
            return b
        logger.warning("ROCm requested but not available. Falling back to CPU.")
        return CPUBackend()

    if mode == "mps":
        b = MPSBackend()
        if b.is_available:
            return b
        logger.warning("MPS requested but not available. Falling back to CPU.")
        return CPUBackend()

    # Auto / GPU / Hybrid - try in priority order
    for backend_cls in (CUDABackend, ROCmBackend, MPSBackend):
        try:
            b = backend_cls()
            if b.is_available:
                if mode == "gpu":
                    logger.info("GPU backend selected: %s", b.device_info)
                return b
        except Exception:
            continue

    if mode == "gpu":
        logger.warning(
            "compute_mode=gpu requested but no GPU detected. "
            "Install PyTorch (CUDA/ROCm) or check GPU drivers. Falling back to CPU."
        )

    return CPUBackend()


# ── Session singleton ─────────────────────────────────────────────────────────

_SESSION_BACKEND: Optional[ComputeBackend] = None


def get_backend(compute_mode: str = "auto") -> ComputeBackend:
    """
    Return the session-level compute backend singleton.

    Call this from any module that needs compute acceleration.
    The backend is selected once and reused for the session lifetime.

    Args:
        compute_mode: 'auto' | 'cpu' | 'gpu' | 'cuda' | 'rocm' | 'mps' | 'hybrid'.
                      If the singleton is already set, this arg is ignored.

    Returns:
        ComputeBackend instance.
    """
    global _SESSION_BACKEND
    if _SESSION_BACKEND is None:
        _SESSION_BACKEND = auto_select_backend(compute_mode)
        logger.info("Compute backend: %s [%s]", _SESSION_BACKEND.name, _SESSION_BACKEND.device_info)
    return _SESSION_BACKEND


def set_backend(compute_mode: str) -> ComputeBackend:
    """
    Force-set the session backend (replaces existing singleton).

    Args:
        compute_mode: Backend mode string.

    Returns:
        New ComputeBackend instance.
    """
    global _SESSION_BACKEND
    _SESSION_BACKEND = auto_select_backend(compute_mode)
    return _SESSION_BACKEND
