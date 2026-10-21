"""GPU detection bridge — delegates to core.gpu.hw_discovery.

Maintains backward compatibility with autopwn.py and advisor.py imports.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

from typing import List, Tuple

from embedxpl.core.gpu.hw_discovery import HardwareDiscovery


def torch_cuda_available() -> bool:
    """Return True if PyTorch reports a CUDA device."""
    try:
        import torch
        return bool(torch.cuda.is_available())
    except ImportError:
        return False


def detect_all_backends() -> List[str]:
    """Return names of all available compute backends (CUDA, ROCm, MPS, CPU)."""
    discovery = HardwareDiscovery()
    return discovery.available_backends()


def gpu_capability_summary() -> Tuple[bool, bool, List[str]]:
    """Summarize GPU-related capabilities for user messaging.

    Returns:
        Tuple of (nvidia_driver_visible, torch_cuda, advisory_lines).
    """
    discovery = HardwareDiscovery()
    profile = discovery.discover()

    nvidia_ok = any(g.vendor == "nvidia" for g in profile.gpus)
    cuda_torch = any(g.python_backend_ok and g.compute_api == "cuda" for g in profile.gpus)

    lines = discovery.summary_lines()
    lines.append(
        "Compute backends: {}".format(", ".join(discovery.available_backends()))
    )
    return nvidia_ok, cuda_torch, lines
