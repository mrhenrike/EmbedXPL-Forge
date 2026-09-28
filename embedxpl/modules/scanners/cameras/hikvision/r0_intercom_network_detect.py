# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Hikvision R0 Indoor Station — Network Detection and Fingerprinting.

Network-based scanner to discover and fingerprint Hikvision R0 Video
Intercom Indoor Station devices. Probes HTTP (ISAPI), SSH (Dropbear
banner), SIP (5060/5065), RTSP (554), and SADP (UDP 37020) to identify
models, firmware versions, and activation status.

Version: 1.0.0
"""

import ipaddress
import re
import socket
import struct
from typing import Dict, List, Optional, Tuple

from embedxpl.core.exploit import *

_HTTP_TIMEOUT = 8
_SSH_TIMEOUT = 5
_SIP_TIMEOUT = 3
_RTSP_TIMEOUT = 3
_SADP_TIMEOUT = 3
_SADP_PORT = 37020
_SADP_MULTICAST = "239.255.255.250"

_R0_MODELS = (
    "DS-KH6320",
    "DS-KH6350",
    "DS-KH6360",
    "DS-KH6320-LE1",
    "DS-KH6320Y-WTE2",
    "KH6320",
    "KH6350",
    "KH6360",
)

_VULNERABLE_FW_RANGES = [
    {
        "description": "Static SSH host keys (CWE-321)",
        "cvss": "7.4",
        "check": lambda v: v is not None,
    },
    {
        "description": "Developer NFS artifacts (CWE-489)",
        "cvss": "5.3",
        "check": lambda v: v is not None,
    },
]


def _parse_xml_tag(xml_str, tag):
    """Extract content from an XML tag."""
    match = re.search(
        "<{0}>(.*?)</{0}>".format(tag), xml_str, re.DOTALL
    )
    return match.group(1).strip() if match else None


def _build_http_request(host, port, path):
    """Build a raw HTTP GET request string."""
    request = (
        "GET {path} HTTP/1.1\r\n"
        "Host: {host}:{port}\r\n"
        "User-Agent: EmbedXPL/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).format(path=path, host=host, port=port)
    return request.encode("ascii")


def _http_get(host, port, path, timeout=_HTTP_TIMEOUT):
    """Perform raw HTTP GET via socket. Returns (status_code, headers_dict, body)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.sendall(_build_http_request(host, port, path))

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 65536:
                    break
            except socket.timeout:
                break
        sock.close()

        resp_str = response.decode("ascii", errors="replace")

        status_match = re.match(r"HTTP/\d\.\d (\d{3})", resp_str)
        status_code = int(status_match.group(1)) if status_match else 0

        header_end = resp_str.find("\r\n\r\n")
        if header_end == -1:
            return status_code, {}, ""

        header_block = resp_str[:header_end]
        body = resp_str[header_end + 4:]

        headers = {}
        for line in header_block.split("\r\n")[1:]:
            if ": " in line:
                key, val = line.split(": ", 1)
                headers[key.lower()] = val

        return status_code, headers, body
    except (socket.error, socket.timeout, OSError):
        return 0, {}, ""


def _expand_targets(target_str):
    """Expand target string to list of IP addresses. Supports single IP and CIDR."""
    targets = []
    target_str = target_str.strip()

    if "/" in target_str:
        try:
            network = ipaddress.ip_network(target_str, strict=False)
            for host in network.hosts():
                targets.append(str(host))
        except ValueError:
            targets.append(target_str)
    else:
        targets.append(target_str)

    return targets


class Exploit(Exploit):
    """Hikvision R0 Indoor Station Network Detection and Fingerprinting.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Hikvision R0 Intercom Network Detector",
        "description": (
            "Network-based detection and fingerprinting of Hikvision R0 Video "
            "Intercom Indoor Station devices. Probes HTTP/ISAPI, SSH, SIP, "
            "RTSP, and SADP (UDP 37020) to identify models, firmware versions, "
            "serial numbers, and activation status. Flags vulnerable versions."
        ),
        "authors": (
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "references": (
            "https://www.hikvision.com/en/products/Video-Intercom/",
        ),
        "devices": (
            "Hikvision DS-KH6320-LE1(B) — R0 Indoor Station",
            "Hikvision DS-KH6350 — R0 Indoor Station",
            "Hikvision DS-KH6360 — R0 Indoor Station",
            "Hikvision DS-KH6320Y-WTE2 — R0 Indoor Station",
        ),
    }

    target = OptIP("", "Target IP address or CIDR range")
    port = OptPort(80, "HTTP port (default 80)")
    scan_ssh = OptBool(True, "Also check SSH port 22")
    scan_sip = OptBool(False, "Also check SIP ports 5060/5065")
    scan_rtsp = OptBool(False, "Also check RTSP port 554")

    def _probe_isapi_device_info(self, host, http_port):
        """GET /ISAPI/System/deviceInfo — parse model, firmware, serial."""
        result = {
            "model": None,
            "firmware": None,
            "serial": None,
            "device_type": None,
            "mac": None,
            "isapi_available": False,
        }

        status, headers, body = _http_get(host, http_port, "/ISAPI/System/deviceInfo")

        if status == 0:
            return result

        if status in (200, 401):
            result["isapi_available"] = True

        if status == 200 and body:
            for tag, key in [
                ("model", "model"),
                ("firmwareVersion", "firmware"),
                ("serialNumber", "serial"),
                ("deviceType", "device_type"),
                ("macAddress", "mac"),
                ("deviceName", "device_name"),
            ]:
                val = _parse_xml_tag(body, tag)
                if val:
                    result[key] = val

        return result

    def _probe_activate_status(self, host, http_port):
        """GET /SDK/activateStatus — check if device is activated."""
        status, _headers, body = _http_get(host, http_port, "/SDK/activateStatus")

        if status == 200 and body:
            if "true" in body.lower() or "activated" in body.lower():
                return "Activated"
            elif "false" in body.lower() or "not" in body.lower():
                return "NOT Activated"
            return "Unknown (response: {})".format(body[:80].strip())

        return None

    def _probe_ssh(self, host, ssh_port=22):
        """Grab SSH banner, check for Dropbear."""
        result = {
            "ssh_available": False,
            "banner": None,
            "is_dropbear": False,
            "version": None,
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(_SSH_TIMEOUT)
            sock.connect((host, int(ssh_port)))

            banner = b""
            while True:
                chunk = sock.recv(1)
                if not chunk:
                    break
                banner += chunk
                if banner.endswith(b"\n"):
                    break
                if len(banner) > 256:
                    break
            sock.close()

            banner_str = banner.decode("ascii", errors="replace").strip()
            result["ssh_available"] = True
            result["banner"] = banner_str

            if "dropbear" in banner_str.lower():
                result["is_dropbear"] = True
                ver = re.search(r"dropbear[_\s-]*(\d[\d.]*)", banner_str, re.IGNORECASE)
                if ver:
                    result["version"] = ver.group(1)

        except (socket.error, socket.timeout, OSError):
            pass

        return result

    def _probe_sip(self, host, sip_port):
        """Send SIP OPTIONS probe and check response."""
        result = {
            "sip_available": False,
            "server": None,
            "user_agent": None,
        }

        sip_request = (
            "OPTIONS sip:{host}:{port} SIP/2.0\r\n"
            "Via: SIP/2.0/UDP {host}:{port};branch=z9hG4bK-embedxpl\r\n"
            "From: <sip:scan@{host}>;tag=embedxpl\r\n"
            "To: <sip:{host}:{port}>\r\n"
            "Call-ID: embedxpl-detect@{host}\r\n"
            "CSeq: 1 OPTIONS\r\n"
            "Max-Forwards: 0\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        ).format(host=host, port=sip_port)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(_SIP_TIMEOUT)
            sock.sendto(sip_request.encode("ascii"), (host, int(sip_port)))

            data, _ = sock.recvfrom(4096)
            sock.close()

            resp = data.decode("ascii", errors="replace")
            if "SIP/2.0" in resp:
                result["sip_available"] = True
                server_match = re.search(r"Server:\s*(.+)", resp)
                if server_match:
                    result["server"] = server_match.group(1).strip()
                ua_match = re.search(r"User-Agent:\s*(.+)", resp)
                if ua_match:
                    result["user_agent"] = ua_match.group(1).strip()

        except (socket.error, socket.timeout, OSError):
            pass

        return result

    def _probe_rtsp(self, host, rtsp_port=554):
        """Send RTSP OPTIONS probe and check response."""
        result = {
            "rtsp_available": False,
            "server": None,
        }

        rtsp_request = (
            "OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\n"
            "CSeq: 1\r\n"
            "User-Agent: EmbedXPL/1.0\r\n"
            "\r\n"
        ).format(host=host, port=rtsp_port)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(_RTSP_TIMEOUT)
            sock.connect((host, int(rtsp_port)))
            sock.sendall(rtsp_request.encode("ascii"))

            data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"\r\n\r\n" in data:
                        break
                except socket.timeout:
                    break
            sock.close()

            resp = data.decode("ascii", errors="replace")
            if "RTSP/1.0" in resp:
                result["rtsp_available"] = True
                server_match = re.search(r"Server:\s*(.+)", resp)
                if server_match:
                    result["server"] = server_match.group(1).strip()

        except (socket.error, socket.timeout, OSError):
            pass

        return result

    def _probe_sadp(self):
        """Send SADP discovery broadcast (UDP 37020)."""
        results = []

        sadp_probe = bytearray(32)
        sadp_probe[0] = 0x21
        sadp_probe[1] = 0x02
        struct.pack_into(">H", sadp_probe, 2, 32)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(_SADP_TIMEOUT)

            sock.sendto(bytes(sadp_probe), (_SADP_MULTICAST, _SADP_PORT))
            sock.sendto(bytes(sadp_probe), ("255.255.255.255", _SADP_PORT))

            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    if len(data) < 32:
                        continue

                    device = {
                        "ip": addr[0],
                        "sadp_available": True,
                        "raw_size": len(data),
                    }

                    resp_str = data.decode("ascii", errors="replace")
                    for model in _R0_MODELS:
                        if model in resp_str:
                            device["model"] = model
                            break

                    ip_match = re.search(
                        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                        resp_str[20:] if len(resp_str) > 20 else resp_str,
                    )
                    if ip_match:
                        device["reported_ip"] = ip_match.group(1)

                    results.append(device)
                except socket.timeout:
                    break

            sock.close()
        except (socket.error, OSError) as exc:
            print_warning("SADP probe failed: {}".format(exc))

        return results

    def _is_r0_model(self, model_str):
        """Check if model string matches known R0 models."""
        if not model_str:
            return False
        for r0 in _R0_MODELS:
            if r0 in model_str:
                return True
        return False

    def _scan_host(self, host):
        """Perform full multi-port scan on a single host."""
        result = {
            "host": host,
            "model": None,
            "firmware": None,
            "serial": None,
            "activated": None,
            "is_r0": False,
            "services": [],
            "vulnerabilities": [],
        }

        isapi = self._probe_isapi_device_info(host, self.port)
        if isapi["isapi_available"]:
            result["services"].append("HTTP/ISAPI (port {})".format(self.port))
            if isapi["model"]:
                result["model"] = isapi["model"]
                result["is_r0"] = self._is_r0_model(isapi["model"])
            if isapi["firmware"]:
                result["firmware"] = isapi["firmware"]
            if isapi["serial"]:
                result["serial"] = isapi["serial"]

            activate = self._probe_activate_status(host, self.port)
            if activate:
                result["activated"] = activate

        if self.scan_ssh:
            ssh = self._probe_ssh(host)
            if ssh["ssh_available"]:
                result["services"].append("SSH (port 22)")
                if ssh["is_dropbear"]:
                    result["services"][-1] = "SSH/Dropbear (port 22)"
                    result["vulnerabilities"].append(
                        "Dropbear detected — likely static host keys (CWE-321)"
                    )
                    if not result["is_r0"] and not result["model"]:
                        result["is_r0"] = True

        if self.scan_sip:
            for sip_port in (5060, 5065):
                sip = self._probe_sip(host, sip_port)
                if sip["sip_available"]:
                    svc = "SIP (port {})".format(sip_port)
                    if sip["server"]:
                        svc += " — {}".format(sip["server"])
                    result["services"].append(svc)

        if self.scan_rtsp:
            rtsp = self._probe_rtsp(host)
            if rtsp["rtsp_available"]:
                svc = "RTSP (port 554)"
                if rtsp["server"]:
                    svc += " — {}".format(rtsp["server"])
                result["services"].append(svc)
                if rtsp["server"] and "hikvision" in rtsp["server"].lower():
                    if not result["model"]:
                        result["model"] = "Hikvision (via RTSP)"

        if result["is_r0"]:
            for vuln in _VULNERABLE_FW_RANGES:
                if vuln["check"](result["firmware"]):
                    result["vulnerabilities"].append(
                        "{} (CVSS {})".format(vuln["description"], vuln["cvss"])
                    )

        return result

    def run(self):
        if not self.target:
            print_error("target is required")
            return

        targets = _expand_targets(self.target)
        print_status("Scanning {} host(s) for Hikvision R0 Indoor Stations...".format(
            len(targets)
        ))

        all_results = []

        for host in targets:
            print_status("Probing {}...".format(host))
            result = self._scan_host(host)
            all_results.append(result)

            if result["services"]:
                if result["is_r0"]:
                    print_success("R0 Indoor Station detected: {} ({})".format(
                        host, result["model"] or "model unknown"
                    ))
                else:
                    print_info("Services found on {}: {}".format(
                        host, ", ".join(result["services"])
                    ))

        print_status("Attempting SADP discovery (UDP broadcast)...")
        sadp_results = self._probe_sadp()
        if sadp_results:
            print_success("SADP discovered {} device(s)".format(len(sadp_results)))
            for dev in sadp_results:
                ip = dev.get("reported_ip", dev.get("ip", "?"))
                model = dev.get("model", "Unknown")
                print_info("  SADP: {} — {}".format(ip, model))

                existing = None
                for r in all_results:
                    if r["host"] == ip:
                        existing = r
                        break
                if existing is None:
                    all_results.append({
                        "host": ip,
                        "model": model,
                        "firmware": None,
                        "serial": None,
                        "activated": None,
                        "is_r0": self._is_r0_model(model),
                        "services": ["SADP (UDP {})".format(_SADP_PORT)],
                        "vulnerabilities": [],
                    })
                else:
                    existing["services"].append("SADP (UDP {})".format(_SADP_PORT))
                    if model and model != "Unknown" and not existing["model"]:
                        existing["model"] = model

        detected = [r for r in all_results if r["services"]]
        r0_devices = [r for r in all_results if r["is_r0"]]

        if not detected:
            print_error("No devices found on scanned host(s)")
            return

        rows = []
        for r in detected:
            rows.append((
                r["host"],
                r["model"] or "-",
                r["firmware"] or "-",
                r["serial"] or "-",
                r["activated"] or "-",
                "Yes" if r["is_r0"] else "No",
                str(len(r["services"])),
            ))

        print_table(
            ("Host", "Model", "Firmware", "Serial", "Activated", "R0?", "Services"),
            *rows,
            title="Detected Devices",
        )

        if r0_devices:
            print_success("{} R0 Indoor Station(s) detected".format(len(r0_devices)))

            vuln_rows = []
            for r in r0_devices:
                for vuln in r["vulnerabilities"]:
                    vuln_rows.append((r["host"], r["model"] or "-", vuln))

            if vuln_rows:
                print_table(
                    ("Host", "Model", "Vulnerability"),
                    *vuln_rows,
                    title="Potential Vulnerabilities",
                )
            else:
                print_info("No specific version-based vulnerabilities flagged")

            print_info("Services detail:")
            for r in r0_devices:
                print_info("  {} :".format(r["host"]))
                for svc in r["services"]:
                    print_info("    - {}".format(svc))
        else:
            print_info(
                "No R0 Indoor Station models identified. "
                "Devices may be other Hikvision products."
            )

    @mute
    def check(self):
        """Check if target responds to ISAPI deviceInfo."""
        try:
            status, _headers, body = _http_get(
                self.target, self.port, "/ISAPI/System/deviceInfo",
                timeout=_HTTP_TIMEOUT,
            )
            return status in (200, 401)
        except Exception:
            return False
