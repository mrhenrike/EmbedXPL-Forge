# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Smart Home Assistant Discovery Scanner.

Detects Amazon Echo, Google Home/Nest, and Samsung SmartThings Hub
devices on the local network using multiple discovery protocols:

  - mDNS (multicast DNS) queries for _googlecast._tcp, _amzn-wplay._tcp,
    and _smartthings._tcp service types.
  - SSDP (Simple Service Discovery Protocol) M-SEARCH for UPnP devices
    matching Alexa, Chromecast, and SmartThings signatures.
  - HTTP banner probing on characteristic ports (8008 for Google Cast,
    8443 for Google Home, 39500 for SmartThings hubCore).

The scanner identifies device model, firmware version, and exposed
services to map the smart home attack surface.

No special hardware required; operates over standard Wi-Fi/Ethernet.

References:
  - https://developers.google.com/cast/docs/reference/messages
  - https://developer.amazon.com/en-US/docs/alexa/alexa-voice-service/api-overview.html
  - https://developer.smartthings.com/docs/devices/hub/
  - https://tools.ietf.org/html/rfc6762 (mDNS)
  - https://tools.ietf.org/html/rfc6763 (DNS-SD)

Version: 1.0.0
"""

import socket
import struct
import time
import re

from embedxpl.core.exploit import *


class Exploit(Exploit):
    """Smart Home Assistant Discovery Scanner.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Smart Home Assistant Discovery Scanner",
        "description": (
            "Discovers Amazon Echo, Google Home/Nest, and Samsung SmartThings "
            "on local networks using mDNS, SSDP, and HTTP banner detection. "
            "Identifies model, firmware, and exposed service ports."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://tools.ietf.org/html/rfc6762",
            "https://tools.ietf.org/html/rfc6763",
            "https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf",
        ),
        "devices": (
            "Amazon Echo (all generations)",
            "Amazon Echo Dot / Show / Plus / Studio",
            "Google Home / Home Mini / Home Max",
            "Google Nest Hub / Nest Mini / Nest Audio",
            "Chromecast (all generations)",
            "Samsung SmartThings Hub v2/v3",
        ),
        "status": "confirmed",
    }

    target = OptIP("", "Target IP or empty for broadcast discovery")
    timeout = OptInteger(5, "Discovery timeout in seconds")
    mdns_enabled = OptBool(True, "Enable mDNS discovery")
    ssdp_enabled = OptBool(True, "Enable SSDP discovery")
    http_probe = OptBool(True, "Enable HTTP banner probing")

    _MDNS_ADDR = "224.0.0.251"
    _MDNS_PORT = 5353

    _SSDP_ADDR = "239.255.255.250"
    _SSDP_PORT = 1900

    _MDNS_SERVICES = [
        ("_googlecast._tcp.local.", "Google Cast"),
        ("_amzn-wplay._tcp.local.", "Amazon Alexa"),
        ("_smartthings._tcp.local.", "SmartThings"),
        ("_googlezone._tcp.local.", "Google Home"),
        ("_airplay._tcp.local.", "AirPlay"),
    ]

    _HTTP_PROBES = [
        (8008, "/setup/eureka_info", "Google Cast"),
        (8443, "/setup/eureka_info", "Google Home"),
        (39500, "/api/status", "SmartThings Hub"),
        (8080, "/api/v1/device-info", "Amazon Echo"),
        (55443, "/device-desc.xml", "Smart Speaker"),
    ]

    _SSDP_KEYWORDS = {
        "alexa": "Amazon Alexa",
        "amazon": "Amazon Echo",
        "echo": "Amazon Echo",
        "chromecast": "Google Chromecast",
        "google": "Google Home/Nest",
        "smartthings": "Samsung SmartThings",
    }

    def _build_mdns_query(self, service_name):
        """Build a DNS query packet for mDNS service discovery.

        Args:
            service_name: Service type string (e.g. _googlecast._tcp.local.).

        Returns:
            DNS query packet as bytes.
        """
        transaction_id = b"\x00\x00"
        flags = b"\x00\x00"
        questions = struct.pack(">H", 1)
        answers = b"\x00\x00\x00\x00\x00\x00"

        qname = b""
        for part in service_name.rstrip(".").split("."):
            qname += struct.pack("B", len(part)) + part.encode("utf-8")
        qname += b"\x00"

        qtype = struct.pack(">H", 12)  # PTR
        qclass = struct.pack(">H", 1)  # IN

        return transaction_id + flags + questions + answers + qname + qtype + qclass

    def _parse_mdns_response(self, data):
        """Extract service names and IPs from mDNS response.

        Args:
            data: Raw UDP payload bytes.

        Returns:
            List of extracted name strings from the response.
        """
        names = []
        try:
            text = data.decode("utf-8", errors="replace")
            for pattern in [
                r"([\w\-]+\._[\w\-]+\._tcp\.local)",
                r"([\w\- ]+)\.local",
            ]:
                for match in re.finditer(pattern, text):
                    names.append(match.group(1))
        except Exception:
            pass
        return names

    def _discover_mdns(self):
        """Run mDNS discovery for smart home services.

        Returns:
            List of dicts with discovered device info.
        """
        results = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)
            sock.bind(("", self._MDNS_PORT))

            mreq = struct.pack(
                "4s4s",
                socket.inet_aton(self._MDNS_ADDR),
                socket.inet_aton("0.0.0.0"),
            )
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            for svc_name, svc_label in self._MDNS_SERVICES:
                query = self._build_mdns_query(svc_name)
                sock.sendto(query, (self._MDNS_ADDR, self._MDNS_PORT))

            deadline = time.monotonic() + int(self.timeout)
            while time.monotonic() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                names = self._parse_mdns_response(data)
                device_type = "Smart Home Device"
                for svc_name, svc_label in self._MDNS_SERVICES:
                    if any(svc_name.split(".")[0] in n for n in names):
                        device_type = svc_label
                        break
                if names:
                    results.append({
                        "ip": addr[0],
                        "method": "mDNS",
                        "type": device_type,
                        "detail": "; ".join(names[:3]),
                    })
            sock.close()
        except (OSError, socket.error) as exc:
            print_error("mDNS scan error: {}".format(exc))
        return results

    def _discover_ssdp(self):
        """Run SSDP M-SEARCH for UPnP smart home devices.

        Returns:
            List of dicts with discovered device info.
        """
        results = []
        msearch = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 3\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        ).encode("utf-8")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)
            sock.sendto(msearch, (self._SSDP_ADDR, self._SSDP_PORT))

            deadline = time.monotonic() + int(self.timeout)
            seen = set()
            while time.monotonic() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue

                if addr[0] in seen:
                    continue

                text = data.decode("utf-8", errors="replace").lower()
                device_type = None
                for keyword, dtype in self._SSDP_KEYWORDS.items():
                    if keyword in text:
                        device_type = dtype
                        break

                if device_type:
                    seen.add(addr[0])
                    server = ""
                    server_match = re.search(r"server:\s*(.+?)[\r\n]", text)
                    if server_match:
                        server = server_match.group(1).strip()[:80]
                    results.append({
                        "ip": addr[0],
                        "method": "SSDP",
                        "type": device_type,
                        "detail": server or "UPnP response",
                    })
            sock.close()
        except (OSError, socket.error) as exc:
            print_error("SSDP scan error: {}".format(exc))
        return results

    def _probe_http_banners(self, targets):
        """Probe HTTP ports on discovered IPs for service banners.

        Args:
            targets: Set of IP address strings to probe.

        Returns:
            List of dicts with banner probe results.
        """
        results = []
        for ip in targets:
            for port, path, label in self._HTTP_PROBES:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0)
                    sock.connect((ip, port))
                    request = "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n".format(
                        path, ip
                    ).encode("utf-8")
                    sock.sendall(request)
                    response = b""
                    while True:
                        try:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                            if len(response) > 8192:
                                break
                        except socket.timeout:
                            break
                    sock.close()

                    if not response:
                        continue

                    text = response.decode("utf-8", errors="replace")
                    status_match = re.search(r"HTTP/1\.\d\s+(\d+)", text)
                    status = int(status_match.group(1)) if status_match else 0

                    if status in (200, 301, 302, 401, 403):
                        detail = "{} port {} - HTTP {}".format(label, port, status)

                        model_match = re.search(
                            r'"(?:name|model|device_name)"\s*:\s*"([^"]+)"', text
                        )
                        fw_match = re.search(
                            r'"(?:version|firmware|build_version|cast_build_revision)"\s*:\s*"([^"]+)"',
                            text,
                        )
                        if model_match:
                            detail += " | Model: {}".format(model_match.group(1))
                        if fw_match:
                            detail += " | FW: {}".format(fw_match.group(1))

                        results.append({
                            "ip": ip,
                            "method": "HTTP",
                            "type": label,
                            "detail": detail,
                        })
                except (OSError, socket.error):
                    continue
        return results

    @mute
    def check(self) -> bool:
        """Quick check if any smart home device responds on the target."""
        if self.target:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                sock.connect((self.target, 8008))
                sock.close()
                return True
            except (OSError, socket.error):
                pass
        return False

    @multi
    def run(self) -> None:
        """Execute smart home assistant discovery scan."""
        print_status("Smart Home Assistant Discovery Scanner")
        if self.target:
            print_info("Target: {}".format(self.target))
        else:
            print_info("Mode: broadcast discovery (all local network)")

        all_results = []
        discovered_ips = set()

        if self.mdns_enabled:
            print_status("Running mDNS service discovery...")
            mdns_results = self._discover_mdns()
            if mdns_results:
                for r in mdns_results:
                    discovered_ips.add(r["ip"])
                all_results.extend(mdns_results)
                print_success("mDNS: {} device(s) found".format(len(mdns_results)))
            else:
                print_info("mDNS: no responses received")

        if self.ssdp_enabled:
            print_status("Running SSDP M-SEARCH discovery...")
            ssdp_results = self._discover_ssdp()
            if ssdp_results:
                for r in ssdp_results:
                    discovered_ips.add(r["ip"])
                all_results.extend(ssdp_results)
                print_success("SSDP: {} device(s) found".format(len(ssdp_results)))
            else:
                print_info("SSDP: no responses received")

        if self.target:
            discovered_ips.add(self.target)

        if self.http_probe and discovered_ips:
            print_status("Probing HTTP banners on {} host(s)...".format(
                len(discovered_ips)
            ))
            http_results = self._probe_http_banners(discovered_ips)
            if http_results:
                all_results.extend(http_results)
                print_success("HTTP: {} service(s) identified".format(
                    len(http_results)
                ))

        if all_results:
            unique = {}
            for r in all_results:
                key = "{}:{}".format(r["ip"], r["type"])
                if key not in unique:
                    unique[key] = r

            headers = ("IP Address", "Method", "Device Type", "Detail")
            rows = [
                (r["ip"], r["method"], r["type"], r["detail"][:60])
                for r in unique.values()
            ]
            print_table(headers, *rows)
            print_success("Total: {} unique device(s) discovered".format(len(unique)))
        else:
            print_warning("No smart home assistants discovered on the network")

        print_info(
            "Recommendation: segment IoT devices on dedicated VLANs, "
            "disable UPnP where not needed, and monitor mDNS/SSDP traffic."
        )
