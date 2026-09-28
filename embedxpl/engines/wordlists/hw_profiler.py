"""
hw_profiler.py - Hardware profile detection for WFH compute and threading.

Detects available CPU, RAM and GPU resources to inform:
  - Optimal compute backend selection (CPU / CUDA / ROCm / OpenCL)
  - Thread count recommendations
  - ML acceleration availability

Adapted from RouterXPL-Forge patterns (github.com/mrhenrike/RouterXPL-Forge).

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
import os
import platform
import subprocess
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class GPUDevice:
    """Represents a single detected GPU device."""
    name:        str
    vendor:      str   # nvidia | amd | intel | apple | unknown
    vram_mb:     int   # VRAM in MB (0 if unknown)
    driver:      str
    compute_cap: str   # CUDA compute capability or equivalent
    backend:     str   # cuda | rocm | opencl | metal | cpu
    index:       int

    def one_liner(self) -> str:
        vram = f"{self.vram_mb}MB" if self.vram_mb else "?"
        return f"[{self.index}] {self.vendor.upper()} {self.name} ({vram} VRAM, {self.backend})"


@dataclass
class HWProfile:
    """Full hardware profile for the current machine."""
    cpu_model:    str  = "Unknown"
    cpu_arch:     str  = platform.machine()
    cpu_cores:    int  = 1    # physical cores
    cpu_threads:  int  = 1    # logical threads (hyperthreading)
    ram_total_mb: int  = 0
    ram_avail_mb: int  = 0
    gpus:         list = field(default_factory=list)
    best_backend: str  = "cpu"     # cuda | rocm | opencl | metal | cpu
    compute_mode: str  = "auto"    # auto | cpu | gpu | hybrid

    def has_gpu(self) -> bool:
        """Return True if at least one non-CPU GPU is detected."""
        return any(g.backend != "cpu" for g in self.gpus)

    def gpu_count(self) -> int:
        return len([g for g in self.gpus if g.backend != "cpu"])

    def primary_gpu(self) -> Optional[GPUDevice]:
        gpus = [g for g in self.gpus if g.backend != "cpu"]
        return gpus[0] if gpus else None

    def recommended_threads(self) -> int:
        """
        Suggest a safe default thread count for wordlist generation.

        Uses cpu_threads as base, capped conservatively.
        """
        return max(1, min(self.cpu_threads, 16))

    def one_liner(self) -> str:
        gpu_info = f" | GPU: {self.primary_gpu().one_liner()}" if self.has_gpu() else " | No GPU"
        return (
            f"CPU: {self.cpu_model} ({self.cpu_cores}c/{self.cpu_threads}t) "
            f"| RAM: {self.ram_total_mb}MB{gpu_info} "
            f"| backend: {self.best_backend}"
        )


# ── Profiler ──────────────────────────────────────────────────────────────────

class HWProfiler:
    """
    Detects hardware capabilities and selects the best compute backend.

    Singleton-style: use HWProfiler.detect() to get a cached HWProfile.
    """

    _cached: Optional[HWProfile] = None

    @classmethod
    def detect(cls, force: bool = False) -> HWProfile:
        """
        Detect hardware and return a HWProfile.

        Args:
            force: Re-detect even if cached result exists.

        Returns:
            HWProfile instance with CPU, RAM and GPU information.
        """
        if cls._cached is not None and not force:
            return cls._cached

        profile = HWProfile()
        cls._detect_cpu(profile)
        cls._detect_ram(profile)
        cls._detect_gpus(profile)
        cls._select_best_backend(profile)

        cls._cached = profile
        logger.debug("HWProfile: %s", profile.one_liner())
        return profile

    @classmethod
    def _detect_cpu(cls, profile: HWProfile) -> None:
        """Detect CPU model, core count and thread count."""
        try:
            profile.cpu_cores   = os.cpu_count() or 1
            profile.cpu_threads = profile.cpu_cores

            # Physical core count via psutil (if available)
            try:
                import psutil
                profile.cpu_cores   = psutil.cpu_count(logical=False) or profile.cpu_cores
                profile.cpu_threads = psutil.cpu_count(logical=True)  or profile.cpu_threads
            except ImportError:
                pass

            # CPU model name
            sys_plat = platform.system()
            if sys_plat == "Windows":
                import winreg
                try:
                    key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                    )
                    profile.cpu_model = winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
                    winreg.CloseKey(key)
                except Exception:
                    profile.cpu_model = platform.processor() or "Unknown"
            elif sys_plat == "Linux":
                try:
                    with open("/proc/cpuinfo") as f:
                        for line in f:
                            if "model name" in line:
                                profile.cpu_model = line.split(":", 1)[1].strip()
                                break
                except Exception:
                    profile.cpu_model = platform.processor() or "Unknown"
            elif sys_plat == "Darwin":
                try:
                    out = subprocess.check_output(
                        ["sysctl", "-n", "machdep.cpu.brand_string"],
                        stderr=subprocess.DEVNULL,
                    ).decode().strip()
                    profile.cpu_model = out or "Apple Silicon"
                except Exception:
                    profile.cpu_model = platform.processor() or "Apple"
            else:
                profile.cpu_model = platform.processor() or "Unknown"

        except Exception as exc:
            logger.debug("CPU detection error: %s", exc)

    @classmethod
    def _detect_ram(cls, profile: HWProfile) -> None:
        """Detect total and available RAM."""
        try:
            import psutil
            vm = psutil.virtual_memory()
            profile.ram_total_mb = vm.total // (1024 * 1024)
            profile.ram_avail_mb = vm.available // (1024 * 1024)
        except Exception:
            try:
                import ctypes
                if platform.system() == "Windows":
                    class MEMSTATUS(ctypes.Structure):
                        _fields_ = [
                            ("dwLength",                ctypes.c_ulong),
                            ("dwMemoryLoad",            ctypes.c_ulong),
                            ("ullTotalPhys",            ctypes.c_ulonglong),
                            ("ullAvailPhys",            ctypes.c_ulonglong),
                            ("ullTotalPageFile",        ctypes.c_ulonglong),
                            ("ullAvailPageFile",        ctypes.c_ulonglong),
                            ("ullTotalVirtual",         ctypes.c_ulonglong),
                            ("ullAvailVirtual",         ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                        ]
                    ms = MEMSTATUS()
                    ms.dwLength = ctypes.sizeof(ms)
                    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
                    profile.ram_total_mb = ms.ullTotalPhys // (1024 * 1024)
                    profile.ram_avail_mb = ms.ullAvailPhys // (1024 * 1024)
            except Exception as exc:
                logger.debug("RAM detection error: %s", exc)

    @classmethod
    def _detect_gpus(cls, profile: HWProfile) -> None:
        """Detect GPUs via nvidia-smi, rocm-smi, PyTorch, and OpenCL."""
        # ── NVIDIA via nvidia-smi ────────────────────────────────────────────
        try:
            out = subprocess.check_output(
                ["nvidia-smi",
                 "--query-gpu=index,name,memory.total,driver_version,compute_cap",
                 "--format=csv,noheader,nounits"],
                stderr=subprocess.DEVNULL,
                timeout=5,
            ).decode()
            for line in out.strip().splitlines():
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 4:
                    profile.gpus.append(GPUDevice(
                        index       = int(parts[0]) if parts[0].isdigit() else 0,
                        name        = parts[1],
                        vram_mb     = int(parts[2]) if parts[2].isdigit() else 0,
                        driver      = parts[3],
                        compute_cap = parts[4] if len(parts) > 4 else "",
                        vendor      = "nvidia",
                        backend     = "cuda",
                    ))
        except Exception:
            pass

        # ── AMD via ROCm ────────────────────────────────────────────────────
        if not profile.gpus:
            try:
                out = subprocess.check_output(
                    ["rocm-smi", "--showproductname", "--csv"],
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                ).decode()
                for i, line in enumerate(out.strip().splitlines()[1:]):
                    parts = line.split(",")
                    if len(parts) >= 2:
                        profile.gpus.append(GPUDevice(
                            index=i, name=parts[-1].strip(),
                            vram_mb=0, driver="rocm",
                            compute_cap="", vendor="amd", backend="rocm",
                        ))
            except Exception:
                pass

        # ── PyTorch fallback (CUDA / MPS) ────────────────────────────────────
        if not profile.gpus:
            try:
                import torch
                if torch.cuda.is_available():
                    for i in range(torch.cuda.device_count()):
                        props = torch.cuda.get_device_properties(i)
                        profile.gpus.append(GPUDevice(
                            index=i, name=props.name,
                            vram_mb=props.total_memory // (1024 * 1024),
                            driver="", vendor="nvidia",
                            compute_cap=f"{props.major}.{props.minor}",
                            backend="cuda",
                        ))
                elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                    profile.gpus.append(GPUDevice(
                        index=0, name="Apple Metal (MPS)",
                        vram_mb=0, driver="metal",
                        compute_cap="", vendor="apple", backend="metal",
                    ))
            except Exception:
                pass

        # ── OpenCL fallback ──────────────────────────────────────────────────
        if not profile.gpus:
            try:
                import pyopencl as cl
                for i, plat in enumerate(cl.get_platforms()):
                    for dev in plat.get_devices(device_type=cl.device_type.GPU):
                        vram = getattr(dev, "global_mem_size", 0) // (1024 * 1024)
                        profile.gpus.append(GPUDevice(
                            index=i, name=dev.name.strip(),
                            vram_mb=vram, driver=plat.name.strip(),
                            compute_cap="", vendor="opencl", backend="opencl",
                        ))
            except Exception:
                pass

    @classmethod
    def _select_best_backend(cls, profile: HWProfile) -> None:
        """Select best compute backend based on available GPU devices."""
        if not profile.gpus:
            profile.best_backend = "cpu"
            return

        priority = {"cuda": 0, "rocm": 1, "metal": 2, "opencl": 3, "cpu": 99}
        best = min(profile.gpus, key=lambda g: priority.get(g.backend, 99))
        profile.best_backend = best.backend


# ── Singleton helper ──────────────────────────────────────────────────────────

_hw_cache: Optional[HWProfile] = None


def get_hw_profile(force: bool = False) -> HWProfile:
    """
    Return a cached HWProfile (detect on first call).

    Args:
        force: Re-detect hardware.

    Returns:
        HWProfile for the current machine.
    """
    global _hw_cache
    if _hw_cache is None or force:
        _hw_cache = HWProfiler.detect(force=force)
    return _hw_cache


def sysinfo_summary() -> str:
    """
    Return a single-line hardware summary string for display.

    Returns:
        Human-readable system info line.
    """
    try:
        hw = get_hw_profile()
        return hw.one_liner()
    except Exception as exc:
        return f"HW detection failed: {exc}"
