"""Tests for embedxpl.core.hw_profiler hardware detection."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from embedxpl.core.hw_profiler import GPUDevice, HWProfile, HWProfiler


def test_gpu_device_summary():
    gpu = GPUDevice(name="RTX 4090", vendor="nvidia", vram_mb=24576,
                    driver="535.86", compute_cap="8.9", backend="cuda")
    s = gpu.summary()
    assert "RTX 4090" in s
    assert "cuda" in s
    assert "24576 MB" in s


def test_gpu_device_summary_no_vram():
    gpu = GPUDevice(name="Unknown GPU", vendor="other", backend="opencl")
    s = gpu.summary()
    assert "unknown VRAM" in s


def test_hwprofile_defaults():
    p = HWProfile()
    assert p.cpu_model == "Unknown"
    assert p.cpu_cores == 1
    assert p.ram_total_mb == 0
    assert not p.has_gpu()
    assert p.compute_mode == "auto"


def test_hwprofile_has_gpu():
    p = HWProfile(gpus=[GPUDevice(name="Test", vendor="nvidia")])
    assert p.has_gpu()


def test_hwprofile_gpu_summary_no_gpu():
    p = HWProfile()
    assert "No GPU" in p.gpu_summary()


def test_hwprofile_gpu_summary_with_gpu():
    p = HWProfile(gpus=[
        GPUDevice(name="RTX 4090", vendor="nvidia", vram_mb=24576),
    ])
    s = p.gpu_summary()
    assert "RTX 4090" in s
    assert "24576MB" in s


def test_hwprofile_one_liner():
    p = HWProfile(
        cpu_model="i9-14900K", cpu_threads=32,
        ram_total_mb=65536, compute_mode="auto",
    )
    line = p.one_liner()
    assert "i9-14900K" in line
    assert "32T" in line
    assert "65536MB" in line
    assert "cpu" in line


def test_hwprofile_one_liner_gpu():
    p = HWProfile(
        cpu_model="Ryzen", cpu_threads=16, ram_total_mb=32768,
        gpus=[GPUDevice(name="RX 7900", vendor="amd")],
        compute_mode="auto",
    )
    line = p.one_liner()
    assert "hybrid" in line


def test_profiler_detect_returns_profile():
    HWProfiler.reset_cache()
    profile = HWProfiler.detect()
    assert isinstance(profile, HWProfile)
    assert profile.cpu_threads >= 1


def test_profiler_caching():
    HWProfiler.reset_cache()
    p1 = HWProfiler.detect()
    p2 = HWProfiler.detect()
    assert p1 is p2


def test_profiler_force_re_detect():
    HWProfiler.reset_cache()
    p1 = HWProfiler.detect()
    p2 = HWProfiler.detect(force=True)
    assert p1 is not p2


def test_profiler_reset_cache():
    HWProfiler.reset_cache()
    HWProfiler.detect()
    HWProfiler.reset_cache()
    assert HWProfiler._cached is None
