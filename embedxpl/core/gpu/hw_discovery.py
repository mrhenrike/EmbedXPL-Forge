"""Hardware discovery adapter for GPU compute backends.

Bridges embedxpl.core.hw_profiler (system-level detection) with the
GPU subsystem, adding Python backend reachability checks.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List

from embedxpl.core.hw_profiler import GPUDevice, HWProfile, HWProfiler

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredGPU:
    """GPU device enriched with Python backend reachability."""
    name: str
    vendor: str
    vram_mb: int = 0
    compute_api: str = ""
    python_backend_ok: bool = False

    @classmethod
    def from_device(cls, dev: GPUDevice) -> DiscoveredGPU:
        backend_ok = False
        api = dev.backend or "cpu"
        if api == "cuda":
            backend_ok = _check_cuda_python()
        elif api == "rocm":
            backend_ok = _check_rocm_python()
        elif api == "opencl":
            backend_ok = _check_opencl_python()
        return cls(
            name=dev.name,
            vendor=dev.vendor,
            vram_mb=dev.vram_mb,
            compute_api=api,
            python_backend_ok=backend_ok,
        )


@dataclass
class DiscoveryResult:
    """Discovery output matching the interface gpu.py expects."""
    gpus: List[DiscoveredGPU] = field(default_factory=list)
    hw_profile: HWProfile = field(default_factory=HWProfile)


class HardwareDiscovery:
    """Facade over HWProfiler that adds per-GPU Python backend checks."""

    def __init__(self) -> None:
        self._result: DiscoveryResult | None = None

    def discover(self) -> DiscoveryResult:
        if self._result is not None:
            return self._result
        profile = HWProfiler.detect()
        gpus = [DiscoveredGPU.from_device(g) for g in profile.gpus]
        self._result = DiscoveryResult(gpus=gpus, hw_profile=profile)
        return self._result

    def available_backends(self) -> List[str]:
        result = self.discover()
        backends = ["cpu"]
        for g in result.gpus:
            if g.python_backend_ok and g.compute_api not in backends:
                backends.append(g.compute_api)
        return backends

    def summary_lines(self) -> List[str]:
        result = self.discover()
        lines: List[str] = []
        if not result.gpus:
            lines.append("No GPU detected; using CPU backend")
        for g in result.gpus:
            ok = "OK" if g.python_backend_ok else "driver only"
            vram = "{}MB".format(g.vram_mb) if g.vram_mb else "? VRAM"
            lines.append("{} [{}] {} ({})".format(g.name, g.compute_api, vram, ok))
        return lines


def _check_cuda_python() -> bool:
    try:
        import torch
        return bool(torch.cuda.is_available())
    except ImportError:
        pass
    try:
        import cupy
        return cupy.cuda.runtime.getDeviceCount() > 0
    except (ImportError, Exception):
        pass
    return False


def _check_rocm_python() -> bool:
    try:
        import torch
        return (
            hasattr(torch.version, "hip")
            and torch.version.hip is not None
            and torch.cuda.is_available()
        )
    except ImportError:
        return False


def _check_opencl_python() -> bool:
    try:
        import pyopencl as cl
        for p in cl.get_platforms():
            if p.get_devices(device_type=cl.device_type.GPU):
                return True
    except (ImportError, Exception):
        pass
    return False
