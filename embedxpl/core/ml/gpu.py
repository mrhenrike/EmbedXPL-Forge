"""GPU detection and compute backend integration for EmbedXPL workflows.

Uses the HWProfiler for hardware discovery and ComputeBackend for
backend abstraction. Maintains backward-compatible ``gpu_capability_summary()``.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import logging
from typing import List, Optional, Tuple

from embedxpl.core.hw_profiler import HWProfiler, HWProfile
from embedxpl.core.gpu.backend import ComputeBackend, auto_select_backend

logger = logging.getLogger(__name__)


def torch_cuda_available() -> bool:
    """Return True if PyTorch reports a CUDA device."""
    try:
        import torch  # type: ignore
        return bool(torch.cuda.is_available())
    except ImportError:
        return False


def gpu_capability_summary(hw_profile: Optional[HWProfile] = None) -> Tuple[bool, bool, List[str]]:
    """Summarize GPU/compute capabilities for user messaging.

    Now uses HWProfiler for detection, providing richer information
    about all detected backends (CUDA, ROCm, OpenCL, CPU).

    Args:
        hw_profile: Optional pre-detected profile. If None, runs detection.

    Returns:
        Tuple of (any_gpu_detected, torch_cuda, advisory_lines).
    """
    if hw_profile is None:
        hw_profile = HWProfiler.detect()

    lines: List[str] = []
    has_gpu = hw_profile.has_gpu()
    cuda_torch = torch_cuda_available()

    if has_gpu:
        for gpu in hw_profile.gpus:
            lines.append("GPU: {} [{}]".format(gpu.summary(), gpu.backend))
    else:
        lines.append("No GPU detected on this host.")

    if cuda_torch:
        lines.append("PyTorch CUDA: available (useful for batch numeric inference, not for I/O HTTP).")
    else:
        lines.append(
            "PyTorch+CUDA: not available. The advisor uses small vectors; GPU gain is marginal. "
            "For mass hash cracking (WPA/PMKID, etc.), use hashcat with `-d` / OpenCL."
        )

    lines.append("Best backend: {} | compute_mode: {}".format(
        hw_profile.best_backend, hw_profile.compute_mode,
    ))
    lines.append(
        "Note: network modules (HTTP/SSH/SNMP) are latency-bound, not FLOPS-bound; "
        "GPU accelerates cryptographic workloads, not HTTP requests."
    )
    return has_gpu, cuda_torch, lines


def detect_all_backends(hw_profile: Optional[HWProfile] = None) -> List[ComputeBackend]:
    """Instantiate and probe all available compute backends.

    Args:
        hw_profile: Optional pre-detected profile.

    Returns:
        List of available ComputeBackend instances (always includes CPUBackend).
    """
    from embedxpl.core.gpu.cuda_backend import CUDABackend
    from embedxpl.core.gpu.rocm_backend import ROCmBackend
    from embedxpl.core.gpu.opencl_backend import OpenCLBackend
    from embedxpl.core.gpu.cpu_backend import CPUBackend

    backends: List[ComputeBackend] = []
    for cls in (CUDABackend, ROCmBackend, OpenCLBackend, CPUBackend):
        try:
            instance = cls()
            if instance.is_available():
                backends.append(instance)
        except Exception as exc:
            logger.debug("Backend %s probe failed: %s", cls.name, exc)

    return backends
