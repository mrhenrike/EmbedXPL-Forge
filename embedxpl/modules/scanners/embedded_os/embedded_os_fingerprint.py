"""Embedded OS Fingerprinting Scanner.

Identifies the operating system running on embedded/IoT devices by analyzing
TCP/IP stack behavior, service banners, HTTP server headers, SNMP sysDescr,
UPnP/SSDP responses, and mDNS service announcements. No credentials required.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 1.0.0
"""
# Author: Andre Henrique (LinkedIn/X: @mrhenrike)

from __future__ import annotations

import re
import socket
import struct
import time

from embedxpl.core.exploit import *


_BANNER_PORTS = {
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    21: "FTP",
    161: "SNMP",
}

_TTL_MAP = {
    (60, 68): "Linux/Embedded Linux",
    (110, 130): "Windows/Windows CE",
    (240, 255): "Cisco IOS, VxWorks, QNX, or BSD",
}

_HTTP_SERVER_SIGNATURES = {
    "lighttpd": "OpenWrt / LEDE",
    "boa": "Embedded Linux (Boa)",
    "goahead": "Generic IoT / Embedded (GoAhead)",
    "mini_httpd": "Embedded Linux (mini_httpd)",
    "micro_httpd": "Embedded Linux (micro_httpd)",
    "busybox": "BusyBox Linux",
    "uhttpd": "OpenWrt (uHTTPd)",
    "mongoose": "Embedded (Mongoose)",
    "lwip": "lwIP RTOS stack",
    "thttpd": "Embedded Linux (thttpd)",
    "civetweb": "Embedded (CivetWeb)",
    "httpd/cgi-bin": "Generic Embedded CGI",
    "apache": "Linux / General purpose",
    "nginx": "Linux / General purpose",
    "iis": "Windows / Windows CE",
    "cisco": "Cisco IOS HTTP",
    "allegro": "Allegro RomPager (Embedded)",
    "rompager": "Allegro RomPager (Embedded)",
    "netgear": "Netgear (Embedded Linux)",
    "dlink": "D-Link (Embedded Linux)",
    "realtek": "Realtek SDK (Embedded Linux)",
    "tornado": "VxWorks (Wind River Tornado)",
    "vxworks": "VxWorks RTOS",
    "qnx": "QNX Neutrino RTOS",
    "nucleus": "Nucleus RTOS",
    "contiki": "Contiki-NG",
    "riot": "RIOT OS",
    "zephyr": "Zephyr RTOS",
    "freertos": "FreeRTOS",
    "threadx": "Azure RTOS / ThreadX",
    "nuttx": "NuttX RTOS",
    "ecos": "eCos RTOS",
}

_SSH_BANNER_HINTS = {
    "dropbear": "Embedded Linux (Dropbear SSH)",
    "openssh": "Linux / BSD (OpenSSH)",
    "cisco": "Cisco IOS SSH",
    "vxworks": "VxWorks SSH",
    "routeros": "MikroTik RouterOS",
    "libssh": "Embedded (libssh)",
}

_FTP_BANNER_HINTS = {
    "vxworks": "VxWorks RTOS",
    "busybox": "BusyBox Linux",
    "pure-ftpd": "Linux (Pure-FTPd)",
    "vsftpd": "Linux (vsftpd)",
    "proftpd": "Linux (ProFTPD)",
    "cisco": "Cisco IOS",
    "dlink": "D-Link Embedded",
    "netgear": "Netgear Embedded",
}

_SSDP_ADDR = "239.255.255.250"
_SSDP_PORT = 1900

_SNMP_SYSDESCR_OID = b"\x30\x29\x02\x01\x01\x04\x06public\xa0\x1c" \
                      b"\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00" \
                      b"\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"


def _tcp_connect(host: str, port: int, timeout: int) -> socket.socket | None:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        return sock
    except (OSError, socket.error):
        return None


def _grab_banner(host: str, port: int, timeout: int) -> str:
    sock = _tcp_connect(host, port, timeout)
    if sock is None:
        return ""
    try:
        if port == 80:
            request = "HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n".format(host)
            sock.sendall(request.encode("ascii", errors="replace"))
        banner = b""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and len(banner) < 4096:
            try:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                banner += chunk
            except socket.timeout:
                break
            except OSError:
                break
        return banner.decode("latin-1", errors="replace")
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _probe_ttl(host: str, port: int, timeout: int) -> int:
    sock = _tcp_connect(host, port, timeout)
    if sock is None:
        return -1
    try:
        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        return ttl
    except OSError:
        return -1
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _guess_os_from_ttl(ttl: int) -> str:
    if ttl <= 0:
        return "Unknown"
    for (low, high), label in _TTL_MAP.items():
        if low <= ttl <= high:
            return label
    return "Unknown (TTL={})".format(ttl)


def _parse_http_server(banner: str) -> str:
    match = re.search(r"[Ss]erver:\s*(.+)", banner)
    if not match:
        return ""
    return match.group(1).strip()


def _identify_http_os(server_header: str) -> str:
    lower = server_header.lower()
    for sig, os_label in _HTTP_SERVER_SIGNATURES.items():
        if sig in lower:
            return os_label
    return ""


def _identify_ssh_os(banner: str) -> str:
    lower = banner.lower()
    for sig, os_label in _SSH_BANNER_HINTS.items():
        if sig in lower:
            return os_label
    return ""


def _identify_ftp_os(banner: str) -> str:
    lower = banner.lower()
    for sig, os_label in _FTP_BANNER_HINTS.items():
        if sig in lower:
            return os_label
    return ""


def _send_ssdp_discover(host: str, timeout: int) -> str:
    msearch = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: {}:{}\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).format(_SSDP_ADDR, _SSDP_PORT)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.sendto(msearch.encode("ascii"), (host, _SSDP_PORT))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return data.decode("latin-1", errors="replace")
    except (OSError, socket.error):
        return ""


def _parse_ssdp_server(response: str) -> str:
    match = re.search(r"[Ss][Ee][Rr][Vv][Ee][Rr]:\s*(.+)", response)
    if match:
        return match.group(1).strip()
    return ""


def _snmp_get_sysdescr(host: str, timeout: int) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_SNMP_SYSDESCR_OID, (host, 161))
        data, _ = sock.recvfrom(4096)
        sock.close()
        decoded = data.decode("latin-1", errors="replace")
        printable = re.sub(r"[^\x20-\x7e]", " ", decoded)
        return printable.strip()
    except (OSError, socket.error):
        return ""


def _mdns_query(host: str, timeout: int) -> str:
    query = (
        b"\x00\x00"
        b"\x00\x00"
        b"\x00\x01"
        b"\x00\x00\x00\x00\x00\x00"
        b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
        b"\x00\x0c\x00\x01"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (host, 5353))
        data, _ = sock.recvfrom(4096)
        sock.close()
        decoded = data.decode("latin-1", errors="replace")
        printable = re.sub(r"[^\x20-\x7e]", " ", decoded)
        return printable.strip()
    except (OSError, socket.error):
        return ""


class Exploit(Exploit):
    """Network-based Embedded OS Fingerprinting Scanner.

    Probes a target device across multiple protocols to build a composite
    fingerprint identifying the embedded operating system.

    Author: Andre Henrique (@mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Embedded OS Fingerprinting Scanner",
        "description": (
            "Network-based embedded operating system fingerprinting. "
            "Analyzes TCP/IP stack TTL, service banners (SSH, Telnet, FTP), "
            "HTTP Server headers, SNMP sysDescr, UPnP/SSDP, and mDNS to "
            "identify the OS running on IoT and embedded devices."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://nmap.org/book/osdetect.html",
            "https://www.iana.org/assignments/service-names-port-numbers",
        ),
        "devices": (
            "Generic IoT",
            "Embedded Linux",
            "OpenWrt",
            "VxWorks",
            "QNX",
            "FreeRTOS",
            "Zephyr",
            "RIOT OS",
            "Contiki-NG",
        ),
        "status": "confirmed",
        "required_hardware": [],
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Primary HTTP port for probing")
    timeout = OptInteger(5, "Socket timeout in seconds per probe")

    def _probe_http(self, host: str, http_port: int, tout: int) -> dict:
        result = {"server_header": "", "os_guess": "", "raw_banner": ""}
        banner = _grab_banner(host, http_port, tout)
        if not banner:
            return result
        result["raw_banner"] = banner[:256]
        server = _parse_http_server(banner)
        if server:
            result["server_header"] = server
            os_guess = _identify_http_os(server)
            if os_guess:
                result["os_guess"] = os_guess
        return result

    def _probe_ssh(self, host: str, tout: int) -> dict:
        result = {"banner": "", "os_guess": ""}
        banner = _grab_banner(host, 22, tout)
        if banner:
            result["banner"] = banner.strip()[:128]
            os_guess = _identify_ssh_os(banner)
            if os_guess:
                result["os_guess"] = os_guess
        return result

    def _probe_telnet(self, host: str, tout: int) -> dict:
        result = {"banner": ""}
        banner = _grab_banner(host, 23, tout)
        if banner:
            printable = re.sub(r"[^\x20-\x7e\r\n]", "", banner)
            result["banner"] = printable.strip()[:128]
        return result

    def _probe_ftp(self, host: str, tout: int) -> dict:
        result = {"banner": "", "os_guess": ""}
        banner = _grab_banner(host, 21, tout)
        if banner:
            result["banner"] = banner.strip()[:128]
            os_guess = _identify_ftp_os(banner)
            if os_guess:
                result["os_guess"] = os_guess
        return result

    @multi
    def run(self) -> None:
        host = str(self.target)
        http_port = int(self.port)
        tout = int(self.timeout)

        print_banner("Embedded OS Fingerprint - {}".format(host))
        print_status("Starting fingerprint probes against {}".format(host))

        findings = []
        os_candidates = []

        # 1. TTL probe
        print_status("Probing TCP/IP stack TTL on port {}...".format(http_port))
        ttl = _probe_ttl(host, http_port, tout)
        if ttl > 0:
            ttl_guess = _guess_os_from_ttl(ttl)
            findings.append(("TCP TTL", "Port {}".format(http_port), str(ttl), ttl_guess))
            if "Unknown" not in ttl_guess:
                os_candidates.append(ttl_guess)
            print_success("TTL={} -> {}".format(ttl, ttl_guess))
        else:
            print_warning("TTL probe failed (port {} unreachable)".format(http_port))

        # 2. HTTP Server header
        print_status("Probing HTTP Server header on port {}...".format(http_port))
        http_result = self._probe_http(host, http_port, tout)
        if http_result["server_header"]:
            findings.append((
                "HTTP Server", "Port {}".format(http_port),
                http_result["server_header"],
                http_result["os_guess"] or "Unrecognized",
            ))
            if http_result["os_guess"]:
                os_candidates.append(http_result["os_guess"])
            print_success("Server: {} -> {}".format(
                http_result["server_header"],
                http_result["os_guess"] or "Unrecognized",
            ))
        else:
            print_info("No HTTP Server header retrieved on port {}".format(http_port))

        # 3. SSH banner
        print_status("Probing SSH banner on port 22...")
        ssh_result = self._probe_ssh(host, tout)
        if ssh_result["banner"]:
            findings.append((
                "SSH Banner", "Port 22",
                ssh_result["banner"],
                ssh_result["os_guess"] or "Unrecognized",
            ))
            if ssh_result["os_guess"]:
                os_candidates.append(ssh_result["os_guess"])
            print_success("SSH: {}".format(ssh_result["banner"]))
        else:
            print_info("SSH not available on port 22")

        # 4. Telnet banner
        print_status("Probing Telnet banner on port 23...")
        telnet_result = self._probe_telnet(host, tout)
        if telnet_result["banner"]:
            findings.append(("Telnet Banner", "Port 23", telnet_result["banner"], "-"))
            print_success("Telnet: {}".format(telnet_result["banner"]))
        else:
            print_info("Telnet not available on port 23")

        # 5. FTP banner
        print_status("Probing FTP banner on port 21...")
        ftp_result = self._probe_ftp(host, tout)
        if ftp_result["banner"]:
            findings.append((
                "FTP Banner", "Port 21",
                ftp_result["banner"],
                ftp_result["os_guess"] or "Unrecognized",
            ))
            if ftp_result["os_guess"]:
                os_candidates.append(ftp_result["os_guess"])
            print_success("FTP: {}".format(ftp_result["banner"]))
        else:
            print_info("FTP not available on port 21")

        # 6. SNMP sysDescr
        print_status("Probing SNMP sysDescr (community: public) on port 161...")
        snmp_resp = _snmp_get_sysdescr(host, tout)
        if snmp_resp and len(snmp_resp) > 4:
            findings.append(("SNMP sysDescr", "Port 161/UDP", snmp_resp[:128], "-"))
            print_success("SNMP sysDescr: {}".format(snmp_resp[:128]))
        else:
            print_info("SNMP not available or community rejected")

        # 7. UPnP/SSDP
        print_status("Sending SSDP M-SEARCH to {}:{}...".format(host, _SSDP_PORT))
        ssdp_resp = _send_ssdp_discover(host, tout)
        if ssdp_resp:
            ssdp_server = _parse_ssdp_server(ssdp_resp)
            if ssdp_server:
                findings.append(("SSDP/UPnP Server", "Port 1900/UDP", ssdp_server, "-"))
                print_success("SSDP Server: {}".format(ssdp_server))
            else:
                print_info("SSDP response received but no Server header found")
        else:
            print_info("No SSDP/UPnP response")

        # 8. mDNS
        print_status("Probing mDNS on port 5353/UDP...")
        mdns_resp = _mdns_query(host, tout)
        if mdns_resp and len(mdns_resp) > 8:
            findings.append(("mDNS Response", "Port 5353/UDP", mdns_resp[:128], "-"))
            print_success("mDNS: {}".format(mdns_resp[:80]))
        else:
            print_info("No mDNS response")

        # Summary
        if findings:
            print_table(
                ("Probe", "Source", "Value", "OS Guess"),
                *findings,
                title="Fingerprint Results - {}".format(host),
            )
        else:
            print_error("No probes returned data. Target may be offline or heavily filtered.")
            return

        if os_candidates:
            unique = list(dict.fromkeys(os_candidates))
            print_success("Candidate OS(es): {}".format(", ".join(unique)))
        else:
            print_warning("Could not determine OS. Manual analysis of raw banners recommended.")

    @mute
    def check(self) -> bool:
        host = str(self.target)
        tout = int(self.timeout)
        http_port = int(self.port)

        probe_targets = [
            (host, http_port),
            (host, 22),
            (host, 23),
            (host, 21),
        ]

        for addr, port in probe_targets:
            sock = _tcp_connect(addr, port, tout)
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
                return True

        snmp_resp = _snmp_get_sysdescr(host, tout)
        if snmp_resp and len(snmp_resp) > 4:
            return True

        ssdp_resp = _send_ssdp_discover(host, min(tout, 3))
        if ssdp_resp:
            return True

        return False
