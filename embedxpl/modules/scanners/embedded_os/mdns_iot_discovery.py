# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""mDNS/DNS-SD IoT Device Discovery Scanner.

Sends mDNS PTR queries to the multicast group 224.0.0.251:5353 for a
curated list of IoT-relevant service types (HomeKit, Matter, MQTT,
CoAP, AirPlay, Chromecast, etc.) and parses DNS response records
(PTR, SRV, TXT, A, AAAA) from raw UDP packets to enumerate devices.

No external DNS libraries are required; packet construction and parsing
use ``struct`` exclusively to keep the dependency footprint minimal.

Protocol: mDNS / DNS-SD (RFC 6762, RFC 6763)
Transport: UDP multicast 224.0.0.251:5353

Version: 1.0.0
"""

import socket
import struct
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

QTYPE_A = 1
QTYPE_PTR = 12
QTYPE_TXT = 16
QTYPE_AAAA = 28
QTYPE_SRV = 33
QCLASS_IN = 1

DEFAULT_SERVICE_TYPES = (
    "_http._tcp.local",
    "_hap._tcp.local",
    "_matter._tcp.local",
    "_ipp._tcp.local",
    "_mqtt._tcp.local",
    "_coap._udp.local",
    "_airplay._tcp.local",
    "_googlecast._tcp.local",
    "_amzn-wplay._tcp.local",
    "_smb._tcp.local",
    "_ftp._tcp.local",
    "_ssh._tcp.local",
    "_workstation._tcp.local",
)

SERVICE_LABELS: Dict[str, str] = {
    "_hap._tcp":        "HomeKit",
    "_matter._tcp":     "Matter",
    "_ipp._tcp":        "Printer (IPP)",
    "_mqtt._tcp":       "MQTT Broker",
    "_coap._udp":       "CoAP Device",
    "_airplay._tcp":    "AirPlay",
    "_googlecast._tcp": "Chromecast",
    "_amzn-wplay._tcp": "Amazon Device",
    "_smb._tcp":        "SMB/CIFS",
    "_ftp._tcp":        "FTP Server",
    "_ssh._tcp":        "SSH Server",
    "_workstation._tcp":"Workstation",
    "_http._tcp":       "HTTP Device",
}


# ---------------------------------------------------------------------------
# DNS packet construction and parsing (struct-only, no external deps)
# ---------------------------------------------------------------------------

def _encode_dns_name(name: str) -> bytes:
    """Encode a dotted DNS name into wire format labels."""
    parts = name.rstrip(".").split(".")
    buf = b""
    for label in parts:
        encoded = label.encode("utf-8")
        if len(encoded) > 63:
            encoded = encoded[:63]
        buf += struct.pack("B", len(encoded)) + encoded
    buf += b"\x00"
    return buf


def _build_mdns_query(service: str, tx_id: int = 0) -> bytes:
    """Build a minimal mDNS PTR query packet for one service type.

    Args:
        service: Fully qualified service name (e.g. '_http._tcp.local').
        tx_id:   Transaction ID (typically 0 for mDNS).

    Returns:
        Raw bytes of the DNS query packet.
    """
    flags = 0x0000
    header = struct.pack(">HHHHHH", tx_id, flags, 1, 0, 0, 0)
    question = _encode_dns_name(service) + struct.pack(">HH", QTYPE_PTR, QCLASS_IN)
    return header + question


def _decode_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Decode a DNS name from wire format, handling compression pointers.

    Args:
        data:   Full DNS packet bytes.
        offset: Starting byte offset of the name.

    Returns:
        Tuple of (decoded dotted name, new offset past the name).
    """
    labels: List[str] = []
    jumped = False
    resume_offset = offset
    seen_offsets = set()
    max_jumps = 32

    for _ in range(max_jumps):
        if offset >= len(data):
            break
        length = data[offset]
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = struct.unpack_from(">H", data, offset)[0] & 0x3FFF
            if ptr in seen_offsets or ptr >= len(data):
                break
            seen_offsets.add(ptr)
            if not jumped:
                resume_offset = offset + 2
            offset = ptr
            jumped = True
        elif length == 0:
            if not jumped:
                resume_offset = offset + 1
            break
        else:
            offset += 1
            end = offset + length
            if end > len(data):
                break
            labels.append(data[offset:end].decode("utf-8", errors="replace"))
            offset = end

    return ".".join(labels), resume_offset


def _parse_txt_record(rdata: bytes) -> Dict[str, str]:
    """Parse a DNS TXT record into key-value pairs.

    Args:
        rdata: Raw TXT record data section.

    Returns:
        Dictionary of decoded TXT key-value pairs.
    """
    result: Dict[str, str] = {}
    pos = 0
    while pos < len(rdata):
        tlen = rdata[pos]
        pos += 1
        if tlen == 0 or pos + tlen > len(rdata):
            break
        entry = rdata[pos:pos + tlen].decode("utf-8", errors="replace")
        pos += tlen
        if "=" in entry:
            k, v = entry.split("=", 1)
            result[k.strip()] = v.strip()
        else:
            result[entry.strip()] = ""
    return result


def _parse_mdns_response(data: bytes) -> List[dict]:
    """Parse a full mDNS response packet and extract all resource records.

    Args:
        data: Raw bytes received from the mDNS multicast socket.

    Returns:
        List of dicts, each representing one parsed resource record.
    """
    if len(data) < 12:
        return []

    records: List[dict] = []
    try:
        (tx_id, flags, qd_count, an_count,
         ns_count, ar_count) = struct.unpack_from(">HHHHHH", data, 0)
    except struct.error:
        return []

    offset = 12
    for _ in range(qd_count):
        if offset >= len(data):
            return records
        _, offset = _decode_dns_name(data, offset)
        offset += 4  # QTYPE(2) + QCLASS(2)

    total_rr = an_count + ns_count + ar_count
    for _ in range(total_rr):
        if offset + 10 > len(data):
            break
        rr_name, offset = _decode_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rr_type, rr_class, rr_ttl, rd_len = struct.unpack_from(">HHIH", data, offset)
        offset += 10
        rr_class &= 0x7FFF  # strip cache-flush bit
        rdata_start = offset
        offset += rd_len

        rr = {"name": rr_name, "type": rr_type, "ttl": rr_ttl}

        if rr_type == QTYPE_PTR:
            ptr_name, _ = _decode_dns_name(data, rdata_start)
            rr["ptr"] = ptr_name

        elif rr_type == QTYPE_SRV:
            if rd_len >= 6:
                priority, weight, port = struct.unpack_from(">HHH", data, rdata_start)
                srv_target, _ = _decode_dns_name(data, rdata_start + 6)
                rr["priority"] = priority
                rr["weight"] = weight
                rr["port"] = port
                rr["target"] = srv_target

        elif rr_type == QTYPE_A:
            if rd_len == 4:
                rr["address"] = socket.inet_ntoa(data[rdata_start:rdata_start + 4])

        elif rr_type == QTYPE_AAAA:
            if rd_len == 16:
                rr["address"] = socket.inet_ntop(
                    socket.AF_INET6, data[rdata_start:rdata_start + 16]
                )

        elif rr_type == QTYPE_TXT:
            rr["txt"] = _parse_txt_record(data[rdata_start:rdata_start + rd_len])

        records.append(rr)

    return records


def _classify_service(service_name: str) -> str:
    """Map a discovered service type string to a human-friendly label.

    Args:
        service_name: The service portion (e.g. '_hap._tcp').

    Returns:
        Human-readable device type label.
    """
    lower = service_name.lower()
    for pattern, label in SERVICE_LABELS.items():
        if pattern in lower:
            return label
    return "Generic"


# ---------------------------------------------------------------------------
# Exploit class (framework convention)
# ---------------------------------------------------------------------------

class Exploit(BaseExploit):
    """mDNS/DNS-SD IoT Device Discovery Scanner.

    Sends mDNS PTR queries on multicast 224.0.0.251:5353 for common IoT
    service types and parses DNS response records to enumerate devices on
    the local network segment. No credentials or special hardware required.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "mDNS/DNS-SD IoT Device Discovery",
        "description": (
            "Sends mDNS PTR queries to 224.0.0.251:5353 for common IoT "
            "service types (HomeKit, Matter, MQTT, CoAP, AirPlay, "
            "Chromecast, printers, SSH, SMB, etc.) and parses DNS response "
            "records (PTR, SRV, TXT, A, AAAA) to enumerate and fingerprint "
            "IoT devices on the local network. Dependency-light: uses raw "
            "struct-based DNS packet construction."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) - EmbedXPL-Forge",
        ),
        "references": (
            "https://tools.ietf.org/html/rfc6762",
            "https://tools.ietf.org/html/rfc6763",
        ),
        "devices": (
            "Apple HomeKit accessories",
            "Matter/Thread smart home devices",
            "Google Chromecast / Nest",
            "Amazon Echo / Fire TV",
            "AirPlay speakers and displays",
            "MQTT brokers and IoT gateways",
            "CoAP-enabled sensors",
            "Network printers (IPP/AirPrint)",
            "Generic mDNS-announcing devices",
        ),
        "status": "confirmed",
        "required_hardware": [],
    }

    target = OptIP("", "Target IP (empty = local multicast scan)")
    timeout = OptInteger(5, "mDNS listen timeout in seconds")
    service_types = OptString(
        "",
        "Comma-separated service types to query (empty = all defaults)",
    )

    def _get_service_list(self) -> Tuple[str, ...]:
        """Resolve the effective service type list from user options."""
        custom = str(self.service_types).strip()
        if custom:
            return tuple(
                s.strip() for s in custom.split(",") if s.strip()
            )
        return DEFAULT_SERVICE_TYPES

    def _create_multicast_socket(self) -> Optional[socket.socket]:
        """Create and configure a UDP socket for mDNS multicast.

        Returns:
            Configured socket or None on failure.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_MULTICAST_TTL,
                struct.pack("B", 255),
            )
            sock.settimeout(float(self.timeout))
            return sock
        except OSError as exc:
            print_error("Failed to create multicast socket: {}".format(exc))
            return None

    def _send_queries(self, sock: socket.socket, services: Tuple[str, ...]) -> None:
        """Send mDNS PTR queries for each service type.

        Args:
            sock:     Configured UDP multicast socket.
            services: Tuple of service type strings to query.
        """
        for svc in services:
            pkt = _build_mdns_query(svc)
            try:
                sock.sendto(pkt, (MDNS_ADDR, MDNS_PORT))
            except OSError as exc:
                print_warning("Failed to send query for {}: {}".format(svc, exc))

    def _collect_responses(self, sock: socket.socket) -> List[dict]:
        """Listen for mDNS responses until timeout expires.

        Args:
            sock: Configured UDP multicast socket.

        Returns:
            Aggregated list of parsed resource records from all responses.
        """
        all_records: List[dict] = []
        deadline = time.time() + float(self.timeout)

        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            sock.settimeout(max(remaining, 0.1))
            try:
                data, addr = sock.recvfrom(8192)
                src_ip = addr[0]
                records = _parse_mdns_response(data)
                for rr in records:
                    rr["src_ip"] = src_ip
                all_records.extend(records)
            except socket.timeout:
                break
            except OSError:
                break

        return all_records

    def _aggregate_devices(self, records: List[dict]) -> Dict[str, dict]:
        """Group raw DNS records into per-IP device summaries.

        Args:
            records: List of parsed resource record dicts.

        Returns:
            Dict keyed by IP address with aggregated device information.
        """
        devices: Dict[str, dict] = {}
        name_to_ip: Dict[str, str] = {}
        ip_services: Dict[str, set] = defaultdict(set)
        ip_txt: Dict[str, Dict[str, str]] = defaultdict(dict)
        ip_hostnames: Dict[str, set] = defaultdict(set)
        ip_ports: Dict[str, set] = defaultdict(set)
        ip_ipv6: Dict[str, set] = defaultdict(set)

        for rr in records:
            src = rr.get("src_ip", "")
            rr_type = rr.get("type", 0)

            if rr_type == QTYPE_A and rr.get("address"):
                addr = rr["address"]
                name_to_ip[rr["name"]] = addr
                ip_hostnames[addr].add(rr["name"])

            if rr_type == QTYPE_AAAA and rr.get("address"):
                if src:
                    ip_ipv6[src].add(rr["address"])

        for rr in records:
            src = rr.get("src_ip", "")
            rr_type = rr.get("type", 0)
            rr_name = rr.get("name", "")

            resolved_ip = name_to_ip.get(rr_name, src)

            if rr_type == QTYPE_PTR:
                svc_label = _classify_service(rr_name)
                if resolved_ip:
                    ip_services[resolved_ip].add(svc_label)
                if src:
                    ip_services[src].add(svc_label)

            elif rr_type == QTYPE_SRV:
                target_name = rr.get("target", "")
                port = rr.get("port", 0)
                target_ip = name_to_ip.get(target_name, src)
                if target_ip and port:
                    ip_ports[target_ip].add(port)
                    ip_hostnames[target_ip].add(target_name)

            elif rr_type == QTYPE_TXT:
                txt = rr.get("txt", {})
                if src:
                    ip_txt[src].update(txt)
                if resolved_ip and resolved_ip != src:
                    ip_txt[resolved_ip].update(txt)

        all_ips = set()
        all_ips.update(ip_services.keys())
        all_ips.update(ip_hostnames.keys())
        all_ips.update(ip_txt.keys())
        all_ips.update(ip_ports.keys())

        for ip in all_ips:
            txt = ip_txt.get(ip, {})
            model = txt.get("md", txt.get("model", txt.get("am", "")))
            firmware = txt.get("fw", txt.get("fv", txt.get("sw", "")))
            manufacturer = txt.get("manufacturer", txt.get("mf", ""))
            hostname = ", ".join(sorted(ip_hostnames.get(ip, set()))[:3])
            services = ", ".join(sorted(ip_services.get(ip, set())))
            ports = ", ".join(str(p) for p in sorted(ip_ports.get(ip, set())))
            v6 = ", ".join(sorted(ip_ipv6.get(ip, set()))[:2])

            devices[ip] = {
                "ip": ip,
                "hostname": hostname or "-",
                "services": services or "-",
                "model": model or "-",
                "firmware": firmware or "-",
                "manufacturer": manufacturer or "-",
                "ports": ports or "-",
                "ipv6": v6 or "-",
            }

        return devices

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Discover IoT devices via mDNS/DNS-SD multicast queries.

        Sends PTR queries for each configured service type, collects all
        responses within the timeout window, aggregates results by IP,
        and displays a summary table.
        """
        services = self._get_service_list()
        print_status(
            "Starting mDNS/DNS-SD discovery ({} service types, timeout {}s)...".format(
                len(services), self.timeout
            )
        )
        for svc in services:
            print_info("  Query: {}".format(svc))

        sock = self._create_multicast_socket()
        if sock is None:
            return

        try:
            self._send_queries(sock, services)
            print_status("Queries sent. Listening for responses...")
            records = self._collect_responses(sock)
        finally:
            try:
                sock.close()
            except OSError:
                pass

        if not records:
            print_error("No mDNS responses received.")
            print_info("Ensure you are on the same network segment as the target devices.")
            return

        print_success("Received {} DNS record(s). Aggregating devices...".format(len(records)))
        devices = self._aggregate_devices(records)

        if not devices:
            print_warning("Responses received but no devices could be identified.")
            return

        headers = ("IP", "Hostname", "Services", "Model", "Firmware", "Manufacturer", "Ports", "IPv6")
        rows = []
        for ip in sorted(devices.keys(), key=lambda x: tuple(int(o) for o in x.split(".") if o.isdigit())):
            dev = devices[ip]
            rows.append((
                dev["ip"],
                dev["hostname"][:40],
                dev["services"][:50],
                dev["model"][:30],
                dev["firmware"][:20],
                dev["manufacturer"][:25],
                dev["ports"][:20],
                dev["ipv6"][:40],
            ))

        print_success("Discovered {} device(s):".format(len(rows)))
        print_table(headers, *rows)

        for ip, dev in sorted(devices.items()):
            txt_services = dev["services"]
            if txt_services != "-":
                print_info("{} - {}".format(ip, txt_services))

    @mute
    def check(self) -> bool:
        """Verify that a multicast UDP socket for mDNS can be created.

        Returns:
            True if the socket was successfully created and configured.
        """
        sock = self._create_multicast_socket()
        if sock is None:
            return False
        try:
            sock.close()
        except OSError:
            pass
        return True
