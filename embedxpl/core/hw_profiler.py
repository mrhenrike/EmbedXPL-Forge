"""System Hardware Profiler -- CPU, RAM, and GPU discovery.

Detects available compute resources on the host machine and provides
a unified ``HWProfile`` for backend selection and user reporting.

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class GPUDevice:
    """Single GPU device detected on the host."""
    name: str
    vendor: str          # nvidia, amd, intel, other
    vram_mb: int = 0
    driver: str = ""
    compute_cap: str = ""  # e.g. "8.6" (CUDA), "gfx1030" (ROCm)
    backend: str = ""      # cuda, rocm, opencl
    index: int = 0

    def summary(self) -> str:
        """One-line summary for display."""
        vram = "{} MB".format(self.vram_mb) if self.vram_mb else "unknown VRAM"
        cc = " ({})".format(self.compute_cap) if self.compute_cap else ""
        return "{} [{}] {} {}{}".format(self.name, self.backend, vram, self.driver, cc)


@dataclass
class HWProfile:
    """Aggregated hardware profile of the host machine."""
    cpu_model: str = "Unknown"
    cpu_arch: str = ""
    cpu_cores: int = 1
    cpu_threads: int = 1
    cpu_freq_mhz: int = 0
    ram_total_mb: int = 0
    ram_available_mb: int = 0
    gpus: List[GPUDevice] = field(default_factory=list)
    best_backend: str = "cpu"
    compute_mode: str = "auto"  # cpu | gpu | hybrid | auto

    def has_gpu(self) -> bool:
        """True if at least one GPU was detected."""
        return len(self.gpus) > 0

    def gpu_summary(self) -> str:
        """Compact GPU summary for startup line."""
        if not self.gpus:
            return "No GPU detected"
        parts = []
        for g in self.gpus:
            vram = " {}MB".format(g.vram_mb) if g.vram_mb else ""
            parts.append("{}{}".format(g.name, vram))
        return " | ".join(parts)

    def one_liner(self) -> str:
        """Single-line system summary for startup display."""
        cpu = "{} ({}T)".format(self.cpu_model, self.cpu_threads)
        ram = "{}MB RAM".format(self.ram_total_mb) if self.ram_total_mb else "? RAM"
        gpu = self.gpu_summary()
        mode = self.compute_mode
        if mode == "auto":
            mode = "auto->{}".format("hybrid" if self.has_gpu() else "cpu")
        return "{} | {} | {} | compute_mode: {}".format(cpu, ram, gpu, mode)


class HWProfiler:
    """Detects CPU, RAM, and GPU hardware on the current host."""

    _cached: Optional[HWProfile] = None

    @classmethod
    def detect(cls, force: bool = False) -> HWProfile:
        """Run hardware detection. Results are cached across calls.

        Args:
            force: If True, re-run detection even if cached.

        Returns:
            HWProfile with all detected hardware.
        """
        if cls._cached is not None and not force:
            return cls._cached

        profile = HWProfile()
        cls._detect_cpu(profile)
        cls._detect_ram(profile)
        cls._detect_gpus(profile)
        cls._select_best_backend(profile)

        cls._cached = profile
        return profile

    @classmethod
    def reset_cache(cls) -> None:
        """Clear cached profile (useful for testing)."""
        cls._cached = None

    # ------------------------------------------------------------------
    # CPU detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_cpu(profile: HWProfile) -> None:
        """Detect CPU model, architecture, cores, threads, frequency."""
        profile.cpu_arch = platform.machine() or "unknown"
        profile.cpu_threads = os.cpu_count() or 1
        profile.cpu_cores = profile.cpu_threads  # refined below if possible

        system = platform.system()

        if system == "Windows":
            HWProfiler._detect_cpu_windows(profile)
        elif system == "Linux":
            HWProfiler._detect_cpu_linux(profile)
        elif system == "Darwin":
            HWProfiler._detect_cpu_macos(profile)
        else:
            profile.cpu_model = platform.processor() or "Unknown CPU"

    @staticmethod
    def _detect_cpu_windows(profile: HWProfile) -> None:
        """CPU detection via registry / environment on Windows."""
        model = os.environ.get("PROCESSOR_IDENTIFIER", "")
        if not model:
            model = platform.processor() or "Unknown CPU"

        brand = HWProfiler._win_reg_cpu_brand()
        if brand:
            profile.cpu_model = brand
        else:
            profile.cpu_model = model.strip()

        freq = HWProfiler._win_reg_cpu_freq()
        if freq > 0:
            profile.cpu_freq_mhz = freq

        cores = os.environ.get("NUMBER_OF_PROCESSORS", "")
        if cores.isdigit():
            profile.cpu_threads = int(cores)

    @staticmethod
    def _win_reg_cpu_brand() -> str:
        """Read CPU brand string from Windows registry."""
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            )
            val, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            winreg.CloseKey(key)
            return val.strip()
        except Exception:
            return ""

    @staticmethod
    def _win_reg_cpu_freq() -> int:
        """Read CPU frequency (MHz) from Windows registry."""
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            )
            val, _ = winreg.QueryValueEx(key, "~MHz")
            winreg.CloseKey(key)
            return int(val)
        except Exception:
            return 0

    @staticmethod
    def _detect_cpu_linux(profile: HWProfile) -> None:
        """CPU detection via /proc/cpuinfo on Linux."""
        try:
            with open("/proc/cpuinfo", "r") as f:
                content = f.read()
            model_match = re.search(r"model name\s*:\s*(.+)", content)
            if model_match:
                profile.cpu_model = model_match.group(1).strip()
            else:
                profile.cpu_model = platform.processor() or "Unknown CPU"

            freq_match = re.search(r"cpu MHz\s*:\s*([\d.]+)", content)
            if freq_match:
                profile.cpu_freq_mhz = int(float(freq_match.group(1)))

            cores_match = re.search(r"cpu cores\s*:\s*(\d+)", content)
            if cores_match:
                profile.cpu_cores = int(cores_match.group(1))
        except Exception as exc:
            logger.debug("/proc/cpuinfo read failed: %s", exc)
            profile.cpu_model = platform.processor() or "Unknown CPU"

    @staticmethod
    def _detect_cpu_macos(profile: HWProfile) -> None:
        """CPU detection via sysctl on macOS."""
        try:
            out = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            profile.cpu_model = (out.stdout or "").strip() or "Unknown CPU"

            out2 = subprocess.run(
                ["sysctl", "-n", "hw.physicalcpu"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if (out2.stdout or "").strip().isdigit():
                profile.cpu_cores = int(out2.stdout.strip())

            out3 = subprocess.run(
                ["sysctl", "-n", "hw.cpufrequency"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            freq_str = (out3.stdout or "").strip()
            if freq_str.isdigit():
                profile.cpu_freq_mhz = int(freq_str) // 1_000_000
        except Exception as exc:
            logger.debug("sysctl cpu query failed: %s", exc)
            profile.cpu_model = platform.processor() or "Unknown CPU"

    # ------------------------------------------------------------------
    # RAM detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_ram(profile: HWProfile) -> None:
        """Detect total and available RAM."""
        try:
            import psutil
            mem = psutil.virtual_memory()
            profile.ram_total_mb = int(mem.total / (1024 * 1024))
            profile.ram_available_mb = int(mem.available / (1024 * 1024))
            return
        except ImportError:
            pass

        system = platform.system()
        if system == "Linux":
            HWProfiler._detect_ram_linux(profile)
        elif system == "Windows":
            HWProfiler._detect_ram_windows(profile)

    @staticmethod
    def _detect_ram_linux(profile: HWProfile) -> None:
        """RAM via /proc/meminfo."""
        try:
            with open("/proc/meminfo", "r") as f:
                content = f.read()
            total_match = re.search(r"MemTotal:\s+(\d+)\s+kB", content)
            avail_match = re.search(r"MemAvailable:\s+(\d+)\s+kB", content)
            if total_match:
                profile.ram_total_mb = int(total_match.group(1)) // 1024
            if avail_match:
                profile.ram_available_mb = int(avail_match.group(1)) // 1024
        except Exception as exc:
            logger.debug("/proc/meminfo read failed: %s", exc)

    @staticmethod
    def _detect_ram_windows(profile: HWProfile) -> None:
        """RAM via ctypes kernel32 on Windows (works on Win10/11 without wmic)."""
        try:
            import ctypes
            import ctypes.wintypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.wintypes.DWORD),
                    ("dwMemoryLoad", ctypes.wintypes.DWORD),
                    ("ullTotalPhys", ctypes.c_uint64),
                    ("ullAvailPhys", ctypes.c_uint64),
                    ("ullTotalPageFile", ctypes.c_uint64),
                    ("ullAvailPageFile", ctypes.c_uint64),
                    ("ullTotalVirtual", ctypes.c_uint64),
                    ("ullAvailVirtual", ctypes.c_uint64),
                    ("ullAvailExtendedVirtual", ctypes.c_uint64),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                profile.ram_total_mb = int(stat.ullTotalPhys / (1024 * 1024))
                profile.ram_available_mb = int(stat.ullAvailPhys / (1024 * 1024))
        except Exception as exc:
            logger.debug("ctypes RAM query failed: %s", exc)

    # ------------------------------------------------------------------
    # GPU detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_gpus(profile: HWProfile) -> None:
        """Detect all GPUs: NVIDIA (nvidia-smi), AMD (rocm-smi), OpenCL (pyopencl)."""
        HWProfiler._detect_nvidia(profile)
        HWProfiler._detect_rocm(profile)
        HWProfiler._detect_opencl(profile)
        HWProfiler._detect_torch_fallback(profile)

    @staticmethod
    def _detect_nvidia(profile: HWProfile) -> None:
        """Detect NVIDIA GPUs via nvidia-smi."""
        binary = shutil.which("nvidia-smi")
        if not binary:
            return
        try:
            out = subprocess.run(
                [binary, "--query-gpu=index,name,memory.total,driver_version,compute_cap",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if out.returncode != 0:
                return
            for line in (out.stdout or "").strip().splitlines():
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 5:
                    continue
                idx = int(parts[0]) if parts[0].isdigit() else 0
                name = parts[1]
                vram = int(float(parts[2])) if parts[2].replace(".", "").isdigit() else 0
                driver = parts[3]
                cc = parts[4]
                gpu = GPUDevice(
                    name=name, vendor="nvidia", vram_mb=vram,
                    driver=driver, compute_cap=cc, backend="cuda", index=idx,
                )
                if not any(g.name == name and g.vendor == "nvidia" for g in profile.gpus):
                    profile.gpus.append(gpu)
        except Exception as exc:
            logger.debug("nvidia-smi query failed: %s", exc)

    @staticmethod
    def _detect_rocm(profile: HWProfile) -> None:
        """Detect AMD GPUs via rocm-smi."""
        binary = shutil.which("rocm-smi")
        if not binary:
            return
        try:
            out = subprocess.run(
                [binary, "--showproductname", "--showmeminfo", "vram", "--csv"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if out.returncode != 0:
                return
            for line in (out.stdout or "").strip().splitlines()[1:]:
                parts = [p.strip() for p in line.split(",")]
                if not parts:
                    continue
                name = parts[0] if parts else "AMD GPU"
                vram = 0
                if len(parts) > 1 and parts[1].isdigit():
                    vram = int(parts[1]) // (1024 * 1024)
                gpu = GPUDevice(
                    name=name, vendor="amd", vram_mb=vram,
                    backend="rocm", index=len(profile.gpus),
                )
                if not any(g.name == name and g.vendor == "amd" for g in profile.gpus):
                    profile.gpus.append(gpu)
        except Exception as exc:
            logger.debug("rocm-smi query failed: %s", exc)

    @staticmethod
    def _detect_opencl(profile: HWProfile) -> None:
        """Detect OpenCL-capable GPUs via pyopencl."""
        try:
            import pyopencl as cl
        except ImportError:
            return
        try:
            for plat in cl.get_platforms():
                for dev in plat.get_devices(device_type=cl.device_type.GPU):
                    name = dev.name.strip()
                    vram = int(dev.global_mem_size / (1024 * 1024))
                    vendor_str = dev.vendor.strip().lower()
                    if "nvidia" in vendor_str:
                        vendor = "nvidia"
                    elif "amd" in vendor_str or "advanced micro" in vendor_str:
                        vendor = "amd"
                    elif "intel" in vendor_str:
                        vendor = "intel"
                    else:
                        vendor = "other"
                    if any(g.name == name and g.backend == "opencl" for g in profile.gpus):
                        continue
                    if any(g.name == name and g.vendor == vendor for g in profile.gpus):
                        continue
                    gpu = GPUDevice(
                        name=name, vendor=vendor, vram_mb=vram,
                        driver=plat.version.strip(), backend="opencl",
                        index=len(profile.gpus),
                    )
                    profile.gpus.append(gpu)
        except Exception as exc:
            logger.debug("pyopencl detection failed: %s", exc)

    @staticmethod
    def _detect_torch_fallback(profile: HWProfile) -> None:
        """If no NVIDIA GPU found via nvidia-smi, try PyTorch as fallback."""
        if any(g.vendor == "nvidia" for g in profile.gpus):
            return
        try:
            import torch
            if not torch.cuda.is_available():
                return
            for i in range(torch.cuda.device_count()):
                name = torch.cuda.get_device_name(i)
                props = torch.cuda.get_device_properties(i)
                # PyTorch >=2.11 renamed total_mem -> total_memory
                raw_mem = getattr(props, "total_memory", None) or getattr(props, "total_mem", 0)
                vram = int(raw_mem / (1024 * 1024))
                cc = "{}.{}".format(props.major, props.minor)
                gpu = GPUDevice(
                    name=name, vendor="nvidia", vram_mb=vram,
                    compute_cap=cc, backend="cuda", index=i,
                )
                profile.gpus.append(gpu)
        except ImportError:
            pass
        except Exception as exc:
            logger.debug("torch CUDA fallback failed: %s", exc)

        try:
            import torch
            if hasattr(torch.version, "hip") and torch.version.hip is not None:
                if not any(g.vendor == "amd" for g in profile.gpus):
                    for i in range(torch.cuda.device_count()):
                        name = torch.cuda.get_device_name(i)
                        gpu = GPUDevice(
                            name=name, vendor="amd", backend="rocm", index=i,
                        )
                        profile.gpus.append(gpu)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Backend selection
    # ------------------------------------------------------------------

    @staticmethod
    def _select_best_backend(profile: HWProfile) -> None:
        """Choose the best available backend based on detected GPUs."""
        for g in profile.gpus:
            if g.backend == "cuda":
                profile.best_backend = "cuda"
                return
        for g in profile.gpus:
            if g.backend == "rocm":
                profile.best_backend = "rocm"
                return
        for g in profile.gpus:
            if g.backend == "opencl":
                profile.best_backend = "opencl"
                return
        profile.best_backend = "cpu"
