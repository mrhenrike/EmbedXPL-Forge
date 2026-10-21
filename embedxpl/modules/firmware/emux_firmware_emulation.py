#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""EMUX Firmware Emulation Framework Integration.

Integrates EMUX (Saumil Shah, formerly ARM-X) firmware emulation
capabilities for security analysis of embedded device firmware.
EMUX provides QEMU-based emulation of ARM, MIPS, and other
architectures with NFS-backed root filesystems, GDB support,
and network emulation.

This module orchestrates firmware emulation workflows:
  - Configure QEMU emulation parameters (arch, machine, kernel, DTB)
  - Set up NFS-backed hostfs for the emulated firmware
  - Launch emulated firmware with network forwarding
  - Provide GDB attach points for debugging
  - Port-forward services from emulated environment

Supported architectures: ARM (versatile, vexpress), MIPS (Malta),
  MIPSEL, PowerPC, x86

Emulation workflow:
  1. Extract firmware filesystem (binwalk/unsquashfs)
  2. Identify architecture and kernel requirements
  3. Configure QEMU launch with appropriate kernel/DTB
  4. Mount extracted filesystem via NFS hostfs
  5. Boot emulated firmware; forward ports to host
  6. Enable GDB remote debugging (port 1234)

HW_REQ: Docker (for full EMUX), QEMU for local mode.

References:
  - Repository: https://github.com/therealsaumil/emux
  - Original ARM-X: https://armx.exploitlab.net/
  - EMUX docs: https://emux.exploitlab.net/
  - License: MPL-2.0

MITRE ATT&CK:
  - T1588.005: Obtain Capabilities: Exploits
  - T1592.002: Gather Victim Host Information: Software
  - T1082: System Information Discovery

Version: 1.0.0
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from embedxpl.core.exploit import (
    Exploit,
    OptBool,
    OptInteger,
    OptString,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)

logger = logging.getLogger(__name__)

# QEMU system binaries per architecture
QEMU_SYSTEM_BINARIES: Dict[str, str] = {
    "arm": "qemu-system-arm",
    "arm64": "qemu-system-aarch64",
    "mips": "qemu-system-mips",
    "mipsel": "qemu-system-mipsel",
    "ppc": "qemu-system-ppc",
    "x86": "qemu-system-i386",
    "x86_64": "qemu-system-x86_64",
}

# Default QEMU machine types per architecture
QEMU_MACHINES: Dict[str, str] = {
    "arm": "virt",
    "arm64": "virt",
    "mips": "malta",
    "mipsel": "malta",
    "ppc": "ppce500",
    "x86": "pc",
    "x86_64": "pc",
}

# Architecture detection from ELF e_machine field
ELF_ARCH_TO_QEMU: Dict[int, str] = {
    0x03: "x86",
    0x08: "mips",
    0x14: "ppc",
    0x28: "arm",
    0x3E: "x86_64",
    0xB7: "arm64",
    0xF3: "riscv64",
}


class EMUXFirmwareEmulation(Exploit):
    """EMUX firmware emulation framework for EmbedXPL.

    Provides QEMU-based firmware emulation for security testing.
    Operates in Docker mode (full EMUX) or local mode (direct QEMU).
    """

    __info__ = {
        "name": "EMUX Firmware Emulation Framework",
        "description": (
            "Firmware emulation for security analysis using QEMU. "
            "Supports ARM, MIPS, MIPSEL, PPC, x86 architectures. "
            "NFS-backed rootfs, GDB debugging, port forwarding."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/therealsaumil/emux",
            "https://emux.exploitlab.net/",
        ),
        "devices": ("Firmware", "Routers", "IoT"),
        "cve": "N/A (emulation tool)",
        "cvss": "N/A",
        "severity": "INFO",
        "mitre_techniques": ["T1588.005", "T1592.002", "T1082"],
        "mitre_tactics": [
            "Resource Development",
            "Reconnaissance",
            "Discovery",
        ],
        "license": "MPL-2.0",
    }

    firmware_path = OptString("", "Path to firmware image or extracted rootfs")
    arch = OptString("", "Target architecture (arm, mips, mipsel, ppc, x86); auto-detect if empty")
    kernel_path = OptString("", "Path to Linux kernel image for QEMU (optional)")
    dtb_path = OptString("", "Path to Device Tree Blob (optional)")
    mode = OptString("local", "'docker' for full EMUX container, 'local' for direct QEMU")
    port_forward = OptString("80:80,22:22,443:443", "Port forwarding: host:guest pairs")
    gdb_port = OptInteger(1234, "GDB remote debugging port")
    enable_gdb = OptBool(True, "Enable GDB server for debugging")
    output_dir = OptString("/tmp/emux_work", "Working directory for emulation")
    qemu_memory = OptString("256M", "QEMU RAM allocation")

    # ------------------------------------------------------------------
    # Architecture detection
    # ------------------------------------------------------------------

    @staticmethod
    def detect_arch_from_elf(data: bytes) -> Optional[str]:
        """Detect architecture from ELF binary header."""
        elf_pos = data.find(b"\x7fELF")
        if elf_pos == -1:
            return None

        endian_byte = data[elf_pos + 5]
        byte_order = "<" if endian_byte == 1 else ">"

        try:
            e_machine = struct.unpack(
                f"{byte_order}H", data[elf_pos + 18:elf_pos + 20]
            )[0]
        except struct.error:
            return None

        qemu_arch = ELF_ARCH_TO_QEMU.get(e_machine)
        if qemu_arch and qemu_arch == "mips" and endian_byte == 1:
            qemu_arch = "mipsel"
        return qemu_arch

    @staticmethod
    def detect_arch_from_directory(rootfs_dir: str) -> Optional[str]:
        """Detect architecture by scanning ELF binaries in rootfs."""
        search_dirs = ["bin", "sbin", "usr/bin", "usr/sbin", "lib"]
        for subdir in search_dirs:
            full_path = os.path.join(rootfs_dir, subdir)
            if not os.path.isdir(full_path):
                continue
            for entry in os.listdir(full_path):
                fpath = os.path.join(full_path, entry)
                if not os.path.isfile(fpath):
                    continue
                try:
                    with open(fpath, "rb") as f:
                        header = f.read(64)
                    arch = EMUXFirmwareEmulation.detect_arch_from_elf(header)
                    if arch:
                        return arch
                except (OSError, PermissionError):
                    continue
        return None

    # ------------------------------------------------------------------
    # Firmware extraction
    # ------------------------------------------------------------------

    def _extract_firmware(self, firmware_path: str, output_dir: str) -> Optional[str]:
        """Extract firmware filesystem using binwalk or unsquashfs."""
        extract_dir = os.path.join(output_dir, "rootfs")
        os.makedirs(extract_dir, exist_ok=True)

        # Try unsquashfs first (most common firmware format)
        try:
            result = subprocess.run(
                ["unsquashfs", "-d", extract_dir, "-f", firmware_path],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                print_success("SquashFS extraction successful")
                return extract_dir
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback to binwalk
        try:
            result = subprocess.run(
                ["binwalk", "-e", "-C", output_dir, firmware_path],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0:
                # Find the largest extracted directory
                for entry in sorted(os.listdir(output_dir)):
                    candidate = os.path.join(output_dir, entry)
                    if os.path.isdir(candidate) and entry.startswith("_"):
                        # Look for rootfs inside
                        for sub in os.listdir(candidate):
                            subpath = os.path.join(candidate, sub)
                            if os.path.isdir(subpath):
                                bin_check = os.path.join(subpath, "bin")
                                if os.path.isdir(bin_check):
                                    return subpath
                        return candidate
                print_success("Binwalk extraction completed")
                return extract_dir
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        print_warning("No extraction tool available; treating path as rootfs directory")
        return firmware_path if os.path.isdir(firmware_path) else None

    # ------------------------------------------------------------------
    # QEMU configuration
    # ------------------------------------------------------------------

    def _build_qemu_args(
        self, rootfs_dir: str, arch: str
    ) -> List[str]:
        """Build QEMU command line arguments."""
        qemu_bin = QEMU_SYSTEM_BINARIES.get(arch)
        if not qemu_bin:
            raise ValueError(f"Unsupported architecture: {arch}")

        machine = QEMU_MACHINES.get(arch, "virt")
        args = [
            qemu_bin,
            "-M", machine,
            "-m", self.qemu_memory,
            "-nographic",
        ]

        # Kernel
        if self.kernel_path and os.path.isfile(self.kernel_path):
            args.extend(["-kernel", self.kernel_path])

        # DTB
        if self.dtb_path and os.path.isfile(self.dtb_path):
            args.extend(["-dtb", self.dtb_path])

        # Network with port forwarding
        hostfwd_rules = []
        for mapping in self.port_forward.split(","):
            parts = mapping.strip().split(":")
            if len(parts) == 2:
                hostfwd_rules.append(
                    f"hostfwd=tcp::{parts[0]}-:{parts[1]}"
                )
        net_opts = ",".join(["user"] + hostfwd_rules)
        args.extend(["-netdev", f"{net_opts},id=net0"])
        args.extend(["-device", "virtio-net-pci,netdev=net0"])

        # GDB
        if self.enable_gdb:
            args.extend(["-gdb", f"tcp::{self.gdb_port}"])

        # NFS-style rootfs via 9p virtfs
        args.extend([
            "-fsdev", f"local,id=rootfs,path={rootfs_dir},security_model=none",
            "-device", "virtio-9p-pci,fsdev=rootfs,mount_tag=hostfs",
        ])

        # Append kernel command line
        if self.kernel_path:
            args.extend(["-append", "root=/dev/ram0 console=ttyS0"])

        return args

    def _generate_emux_config(
        self, arch: str, rootfs_dir: str
    ) -> Dict[str, Any]:
        """Generate EMUX-style device configuration."""
        return {
            "device_name": os.path.basename(self.firmware_path),
            "architecture": arch,
            "qemu_machine": QEMU_MACHINES.get(arch, "virt"),
            "rootfs_path": rootfs_dir,
            "kernel": self.kernel_path or "auto",
            "dtb": self.dtb_path or "auto",
            "memory": self.qemu_memory,
            "network": {
                "type": "user",
                "port_forward": self.port_forward,
            },
            "gdb": {
                "enabled": self.enable_gdb,
                "port": self.gdb_port,
            },
        }

    # ------------------------------------------------------------------
    # Docker mode
    # ------------------------------------------------------------------

    def _run_emux_docker(self, rootfs_dir: str, arch: str) -> bool:
        """Run firmware emulation via EMUX Docker container."""
        print_status("Launching EMUX Docker container...")
        port_args = []
        for mapping in self.port_forward.split(","):
            parts = mapping.strip().split(":")
            if len(parts) == 2:
                port_args.extend(["-p", f"{parts[0]}:{parts[1]}"])

        cmd = [
            "docker", "run", "--rm", "-it",
            "--privileged",
            "-v", f"{rootfs_dir}:/emux/workspace/rootfs",
            *port_args,
            "emux/emux:latest",
        ]

        print_info(f"Docker command: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, timeout=600)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            print_error(f"Docker execution failed: {e}")
            return False

    # ------------------------------------------------------------------
    # Main
    # ------------------------------------------------------------------

    def run(self):
        """Set up and launch firmware emulation."""
        if not self.firmware_path:
            print_error("No firmware path specified")
            return

        os.makedirs(self.output_dir, exist_ok=True)

        # Determine if we have a directory (already extracted) or file
        if os.path.isdir(self.firmware_path):
            rootfs_dir = self.firmware_path
            print_info(f"Using existing rootfs: {rootfs_dir}")
        elif os.path.isfile(self.firmware_path):
            print_status("Extracting firmware filesystem...")
            rootfs_dir = self._extract_firmware(
                self.firmware_path, self.output_dir
            )
            if not rootfs_dir:
                print_error("Firmware extraction failed")
                return
        else:
            print_error(f"Path not found: {self.firmware_path}")
            return

        # Detect architecture
        arch = self.arch
        if not arch:
            print_status("Auto-detecting architecture...")
            arch = self.detect_arch_from_directory(rootfs_dir)
            if not arch:
                # Try reading a common binary
                with open(self.firmware_path, "rb") as f:
                    arch = self.detect_arch_from_elf(f.read(4096))
            if arch:
                print_success(f"Detected architecture: {arch}")
            else:
                print_error(
                    "Could not detect architecture; set 'arch' option manually"
                )
                return

        # Generate config
        config = self._generate_emux_config(arch, rootfs_dir)
        config_path = os.path.join(self.output_dir, "emux_config.json")
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        print_info(f"Emulation config saved: {config_path}")

        if self.mode == "docker":
            self._run_emux_docker(rootfs_dir, arch)
            return

        # Local QEMU launch
        try:
            qemu_args = self._build_qemu_args(rootfs_dir, arch)
        except ValueError as e:
            print_error(str(e))
            return

        print_status("QEMU launch command:")
        print_info(f"  {' '.join(qemu_args)}")

        if self.enable_gdb:
            print_info(f"  GDB: target remote :{self.gdb_port}")

        print_info("Port forwarding:")
        for mapping in self.port_forward.split(","):
            print_info(f"  {mapping.strip()}")

        # Check QEMU availability
        qemu_bin = qemu_args[0]
        if not shutil.which(qemu_bin):
            print_warning(f"{qemu_bin} not found in PATH")
            print_info("Install: apt install qemu-system-arm qemu-system-mips")
            print_info("Or use mode=docker for containerized emulation")
            return

        if not self.kernel_path:
            print_warning(
                "No kernel specified; QEMU requires a kernel image. "
                "Provide kernel_path or use Docker mode."
            )
            print_info(
                "Tip: download pre-built kernels from "
                "https://people.debian.org/~aurel32/qemu/"
            )
            return

        print_status("Launching QEMU emulation (Ctrl+A, X to exit)...")
        try:
            subprocess.run(qemu_args)
        except KeyboardInterrupt:
            print_info("Emulation terminated by user")
