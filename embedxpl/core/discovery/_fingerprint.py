"""Network discovery - fingerprinting and catalog matching."""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

from embedxpl.core.discovery._models import (
    TimingProfile, DiscoveredHost, _detect_oem_encoding,
    PROBE_PORTS, PROBE_PORTS_EXTENDED, _HOST_DISCOVERY_ARGS,
)
from embedxpl.core.discovery._scanning import _NetworkDiscoveryScanning


class NetworkDiscovery(_NetworkDiscoveryScanning):
    """Network discovery engine - fingerprinting, catalog matching, wireless."""

    def _probe_ports_parallel(self, callback=None) -> None:
        """Probe all configured ports on discovered hosts."""
        def probe(host: DiscoveredHost, port: int) -> Optional[Tuple[DiscoveredHost, int, str]]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                if s.connect_ex((host.ip, port)) == 0:
                    banner = ""
                    try:
                        if port in (22, 23, 21):
                            s.settimeout(2.0)
                            banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                        elif port in (80, 8080, 8081, 8443, 8888, 443):
                            req = "GET / HTTP/1.0\r\nHost: {}\r\n\r\n".format(host.ip)
                            s.sendall(req.encode())
                            s.settimeout(3.0)
                            resp = s.recv(4096).decode("utf-8", errors="replace")
                            server_match = re.search(r"Server:\s*(.+)", resp, re.IGNORECASE)
                            title_match = re.search(r"<title>(.+?)</title>", resp, re.IGNORECASE | re.DOTALL)
                            parts = []
                            if server_match:
                                parts.append(server_match.group(1).strip())
                            if title_match:
                                parts.append(title_match.group(1).strip())
                            banner = " | ".join(parts)
                    except Exception:
                        pass
                    s.close()
                    return (host, port, banner)
                s.close()
            except (socket.error, OSError):
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = []
            for host in self._hosts:
                for port in self.ports:
                    futures.append(pool.submit(probe, host, port))
            for f in as_completed(futures):
                try:
                    result = f.result()
                    if result:
                        host, port, banner = result
                        if port not in host.open_ports:
                            host.open_ports.append(port)
                            host.open_ports.sort()
                        if banner:
                            host.banners[port] = banner
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Fingerprinting
    # ------------------------------------------------------------------

    def _fingerprint_all(self, callback: Optional[Callable] = None) -> None:
        """Run fingerprinting on all discovered hosts.

        Includes aggressive HTTP/HTTPS banner grabbing to extract model info
        from web management interfaces common on routers and switches.
        """
        for host in self._hosts:
            self._deep_banner_grab(host, callback)
            self._fingerprint_host(host)
        if callback:
            identified = sum(1 for h in self._hosts if h.vendor_guess)
            callback("fingerprint", "Identified {} out of {} hosts".format(identified, len(self._hosts)))

    def _deep_banner_grab(self, host: DiscoveredHost, callback: Optional[Callable] = None) -> None:
        """Aggressive HTTP/HTTPS banner grab to extract device model from web UI."""
        http_ports = [p for p in host.open_ports if p in (80, 8080, 8081, 8888, 8090, 443, 8443, 4567, 10000)]
        if not http_ports:
            http_ports = [80, 443]

        for port in http_ports:
            use_ssl = port in (443, 8443)
            banner = self._http_banner(host.ip, port, use_ssl)
            if banner:
                if port not in host.banners or len(banner) > len(host.banners.get(port, "")):
                    host.banners[port] = banner
                if port not in host.open_ports:
                    host.open_ports.append(port)
                    host.open_ports.sort()

    def _http_banner(self, ip: str, port: int, use_ssl: bool = False) -> str:
        """Raw HTTP/HTTPS request to grab server headers and HTML title/model info."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout + 2)
            s.connect((ip, port))

            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=ip)

            req = "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n".format(ip)
            s.sendall(req.encode())

            chunks = []
            while True:
                try:
                    chunk = s.recv(8192)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if len(b"".join(chunks)) > 32768:
                        break
                except (socket.timeout, ssl.SSLError):
                    break
            s.close()

            raw = b"".join(chunks).decode("utf-8", errors="replace")
            parts = []

            server_m = re.search(r"Server:\s*(.+?)[\r\n]", raw, re.IGNORECASE)
            if server_m:
                parts.append("Server: " + server_m.group(1).strip())

            title_m = re.search(r"<title>(.+?)</title>", raw, re.IGNORECASE | re.DOTALL)
            if title_m:
                parts.append("Title: " + title_m.group(1).strip()[:120])

            model_patterns = [
                r"(?:modelName|ProductName|product_name|DeviceModel|deviceModel)\s*[:=]\s*['\"]?([^'\"<>\r\n;,]+)",
                r"(?:HG\d{4}[A-Z]*|EG\d{4}[A-Z]*\d*|ZXHN\s*[A-Z]\d+[A-Z]*|DG\d{3,4}[A-Z]*)",
                r"(?:RT-[A-Z]{2,4}\d+|DIR-\d{3,4}|TL-[A-Z]{2,3}\d+|Archer\s*[A-Z]\d+)",
                r"(?:RB\d{3,4}|CCR\d{4}|CRS\d{3}|hAP\s*\w+)",
                r"(?:USG|UDM|EdgeRouter\s*\w+|UniFi\s*\w+)",
                r"(?:FortiGate-?\d+[A-Z]*|FG-?\d+[A-Z]*)",
                r"(?:RV\d{3}[A-Z]*|SG\d{3}[A-Z]*|Catalyst\s*\d+)",
            ]
            for pat in model_patterns:
                m = re.search(pat, raw, re.IGNORECASE)
                if m:
                    model_str = m.group(0) if not m.lastindex else m.group(1)
                    parts.append("Model: " + model_str.strip()[:80])
                    break

            return " | ".join(parts) if parts else ""

        except Exception:
            return ""

    def _fingerprint_host(self, host: DiscoveredHost) -> None:
        """Fingerprint a single host using banners, MAC OUI, and ML."""
        if host.mac and not host.vendor_guess:
            host.vendor_guess = self._oui_lookup(host.mac)

        best_confidence = host.fingerprint_confidence
        for port, banner in host.banners.items():
            vendor, model, conf = self._match_banner(banner)
            if conf > best_confidence:
                best_confidence = conf
                if vendor:
                    host.vendor_guess = vendor
                if model:
                    host.model_guess = model
                host.fingerprint_confidence = conf

        if not host.vendor_guess and host.banners:
            self._ml_fingerprint(host)

    @staticmethod
    def _oui_lookup(mac: str) -> str:
        """Look up vendor from MAC address OUI prefix via IEEE database."""
        from embedxpl.core.oui import lookup
        return lookup(mac)

    def _match_banner(self, banner: str) -> Tuple[str, str, float]:
        """Match a banner string against known patterns.

        Returns:
            (vendor, model, confidence)
        """
        if not banner:
            return ("", "", 0.0)

        try:
            from embedxpl.core.ml.banner_fingerprint import BannerFingerprinter
            fp = BannerFingerprinter()
            matches = fp.match(banner)
            if matches and matches[0].confidence >= 0.5:
                top = matches[0]
                return (top.vendor, top.model, top.confidence)
        except Exception as exc:
            logger.debug("BannerFingerprinter failed: %s", exc)

        banner_lower = banner.lower()

        model_extracted = ""
        model_m = re.search(r"Model:\s*(.+?)(?:\s*\||$)", banner, re.IGNORECASE)
        if model_m:
            model_extracted = model_m.group(1).strip()

        vendor_keywords = {
            "dlink": ["d-link", "dlink", "dir-", "dsl-", "dap-", "dcs-", "dwr-"],
            "tplink": ["tp-link", "tplink", "archer", "tl-wr", "tl-mr", "tl-wa", "deco"],
            "netgear": ["netgear", "nighthawk", "orbi"],
            "asus": ["asus", "rt-ac", "rt-ax", "rt-n", "rt-be", "zenwifi"],
            "linksys": ["linksys", "cisco-linksys", "velop"],
            "cisco": ["cisco", "catalyst", "isr", "asr"],
            "huawei": ["huawei", "hg8245", "hg8240", "hg8546", "hg8010",
                       "eg8145", "eg8245", "echolife", "optixstar",
                       "ar161", "ar169", "s5700", "s5720", "s6720",
                       "usg6", "ce6800", "ne40e"],
            "zte": ["zte", "zxhn", "zxv10", "zxa10"],
            "mikrotik": ["mikrotik", "routeros", "routerboard", "hap", "ccr", "crs"],
            "ubiquiti": ["ubiquiti", "unifi", "edgerouter", "airos", "udm", "usg", "uap"],
            "fortinet": ["fortinet", "fortigate", "fortiswitch", "fortiap"],
            "tenda": ["tenda"],
            "arris": ["arris", "touchstone", "surfboard"],
            "comtrend": ["comtrend"],
            "trendnet": ["trendnet"],
            "belkin": ["belkin"],
            "draytek": ["draytek", "vigor"],
            "totolink": ["totolink"],
            "wavlink": ["wavlink"],
            "xiaomi": ["xiaomi", "miwifi", "redmi router"],
            "intelbras": ["intelbras", "action", "wrn"],
            "fiberhome": ["fiberhome", "an5506"],
            "sagem": ["sagem", "sagemcom", "livebox"],
            "juniper": ["juniper", "junos", "srx", "ex2", "ex3", "ex4"],
            "sonicwall": ["sonicwall", "sonicpoint", "tz", "nsa"],
            "ruckus": ["ruckus", "unleashed", "zonedirector"],
        }

        for vendor, keywords in vendor_keywords.items():
            for kw in keywords:
                if kw in banner_lower:
                    return (vendor, model_extracted, 0.7 if model_extracted else 0.6)

        return ("", model_extracted, 0.3 if model_extracted else 0.0)

    def _ml_fingerprint(self, host: DiscoveredHost) -> None:
        """Use ML banner fingerprinter as last resort."""
        try:
            from embedxpl.core.ml.banner_fingerprint import BannerFingerprinter
            fp = BannerFingerprinter()
            all_banners = " ".join(host.banners.values())
            matches = fp.match(all_banners)
            if matches:
                top = matches[0]
                if top.confidence > host.fingerprint_confidence:
                    host.vendor_guess = top.vendor
                    host.model_guess = top.model
                    host.fingerprint_confidence = top.confidence
        except Exception as exc:
            logger.debug("ML fingerprint failed: %s", exc)

    # ------------------------------------------------------------------
    # Catalog matching
    # ------------------------------------------------------------------

    def _match_catalog(self) -> None:
        """Match discovered hosts against the EmbedXPL module catalog.

        Strict matching rules to avoid false positives:
          1. Vendor modules: only if the host vendor matches the module vendor
             folder (e.g. ``huawei/`` modules only for Huawei devices).
          2. Generic scanners (``generic/``): matched by detected protocol/tech
             (UPnP scanner for any host with UPnP, etc.).  These are tools,
             not exploits, so vendor doesn't matter.
          3. GPON category modules: only for hosts positively identified as
             GPON/ONT/ONU devices.  Vendor-specific GPON modules (e.g.
             Alcatel, Skyworth) are excluded unless vendor matches.
          4. Multi-vendor modules (``multi/``): only if the module name or
             ``__info__`` references the detected vendor or is explicitly
             vendor-agnostic (e.g. ``gpon_home_gateway_rce``).
        """
        for host in self._hosts:
            matched: List[str] = []
            vendor = host.vendor_guess.lower()
            is_gpon = self._host_is_gpon(host)

            if vendor:
                vendor_mods = [
                    m for m in self._module_index.get(vendor, [])
                    if self._module_is_under_vendor(m, vendor)
                ]
                matched.extend(vendor_mods)

            if is_gpon:
                gpon_mods = self._module_index.get("gpon", [])
                for m in gpon_mods:
                    if m in matched:
                        continue
                    if self._gpon_module_applies(m, vendor):
                        matched.append(m)

            multi_mods = self._module_index.get("multi", [])
            for m in multi_mods:
                if m in matched:
                    continue
                if self._multi_module_applies(m, vendor, is_gpon):
                    matched.append(m)

            generic_mods = self._module_index.get("generic", [])
            for m in generic_mods:
                if m in matched:
                    continue
                if self._generic_tool_applies(m, host):
                    matched.append(m)

            host.matched_modules = sorted(set(matched))

    def _host_is_gpon(self, host: DiscoveredHost) -> bool:
        """Determine if a host is a GPON/ONT/ONU device."""
        all_text = " ".join([
            host.model_guess or "",
            host.vendor_guess or "",
            " ".join(host.banners.values()),
        ]).lower()

        gpon_indicators = [
            "gpon", "ont", "onu", "epon", "xpon", "ftth",
            "optical network", "echolife", "optixstar",
            "eg8", "hg8", "an5506", "zxa10",
        ]
        return any(kw in all_text for kw in gpon_indicators)

    @staticmethod
    def _module_is_under_vendor(module_path: str, vendor: str) -> bool:
        """Check if a module lives under the given vendor's directory."""
        parts = module_path.lower().replace("\\", "/").split("/")
        dot_parts = module_path.lower().split(".")
        all_parts = parts + dot_parts
        return vendor in all_parts

    @staticmethod
    def _gpon_module_applies(module_path: str, host_vendor: str) -> bool:
        """Check if a GPON-category module applies to the given host.

        Generic GPON modules (no vendor in name) apply to any GPON device.
        Vendor-specific GPON modules only apply if vendor matches.
        """
        m_lower = module_path.lower()

        other_vendors_in_gpon = [
            "alcatel", "nokia", "skyworth", "fiberhome", "calix",
            "zhone", "genexis", "technicolor",
        ]
        for ov in other_vendors_in_gpon:
            if ov in m_lower:
                return host_vendor and ov in host_vendor
        return True

    @staticmethod
    def _multi_module_applies(
        module_path: str, host_vendor: str, is_gpon: bool
    ) -> bool:
        """Check if a multi-vendor module applies to the host.

        Only include if the module explicitly references the host vendor
        or a technology the host uses (e.g. gpon for GPON devices).
        """
        m_lower = module_path.lower()

        if host_vendor and host_vendor in m_lower:
            return True

        if is_gpon and "gpon" in m_lower:
            other_vendors = [
                "genexis", "plc_wireless", "techview", "ruckus",
                "f5_big", "citrix",
            ]
            return not any(ov in m_lower for ov in other_vendors)

        return False

    @staticmethod
    def _generic_tool_applies(module_path: str, host: DiscoveredHost) -> bool:
        """Check if a generic tool/scanner applies to the host by protocol."""
        m_lower = module_path.lower()

        protocol_port_map = {
            "upnp": [1900, 49152, 37443, 37215, 5000],
            "ssdp": [1900, 49152, 37443],
            "snmp": [161, 162],
            "tr069": [7547],
            "cwmp": [7547],
        }

        for proto, ports in protocol_port_map.items():
            if proto in m_lower:
                if any(p in host.open_ports for p in ports):
                    return True
                all_text = " ".join(host.banners.values()).lower()
                if proto in all_text:
                    return True

        return False

    # ------------------------------------------------------------------
    # Wireless capability detection & WirelessXPL-Forge recommendation
    # ------------------------------------------------------------------

    _WIRELESS_INDICATORS = [
        "wireless", "wifi", "wi-fi", "wlan", "ssid", "wpa",
        "802.11", "radio", "antenna", "channel",
        "2.4ghz", "5ghz", "6ghz", "2,4ghz",
    ]

    _ROUTER_VENDOR_TYPES = {
        "huawei", "zte", "tplink", "dlink", "netgear", "asus", "linksys",
        "cisco", "mikrotik", "ubiquiti", "arris", "comtrend", "tenda",
        "totolink", "xiaomi", "intelbras", "fiberhome", "sagem",
        "draytek", "wavlink", "trendnet", "belkin", "ruckus",
        "fortinet", "sonicwall",
    }

    def _detect_wireless_capability(self, callback: Optional[Callable] = None) -> None:
        """Identify hosts that likely have wireless/WiFi capabilities.

        Checks banners, model names, vendor type, and nearby SSIDs
        associated with the host MAC (via BSSID correlation).
        """
        nearby_ssids = self._scan_nearby_ssids()

        for host in self._hosts:
            reasons: List[str] = []

            # 1. Banner analysis
            all_banners = " ".join(host.banners.values()).lower()
            for kw in self._WIRELESS_INDICATORS:
                if kw in all_banners:
                    reasons.append("banner:{}".format(kw))
                    break

            # 2. Known router/AP vendor (virtually all have WiFi)
            vendor_lower = host.vendor_guess.lower()
            if vendor_lower in self._ROUTER_VENDOR_TYPES:
                reasons.append("vendor:{}".format(vendor_lower))

            # 3. Model name contains WiFi/wireless hint
            model_lower = (host.model_guess or "").lower()
            wifi_model_patterns = [
                "wap", "wrt", "wlan", "wifi", "wireless",
                "archer", "deco", "nighthawk", "orbi", "velop",
                "unifi", "airos", "hap", "eg8", "hg8",
                "ont", "gpon", "echolife", "optixstar",
            ]
            for pat in wifi_model_patterns:
                if pat in model_lower:
                    reasons.append("model:{}".format(pat))
                    break

            # 4. BSSID/MAC correlation with nearby SSIDs
            if host.mac:
                mac_prefix = host.mac.replace(":", "").replace("-", "")[:6].upper()
                for ssid_name, ssid_bssid in nearby_ssids:
                    bssid_prefix = ssid_bssid.replace(":", "").replace("-", "")[:6].upper()
                    if mac_prefix == bssid_prefix:
                        host.has_wireless = True
                        if ssid_name and ssid_name not in host.wireless_ssids:
                            host.wireless_ssids.append(ssid_name)
                        reasons.append("bssid_match:{}".format(ssid_name or ssid_bssid))

            if reasons:
                host.has_wireless = True

        if callback:
            wifi_count = sum(1 for h in self._hosts if h.has_wireless)
            if wifi_count:
                callback("wireless", "{} host(s) with wireless capability detected".format(wifi_count))

    @staticmethod
    def _scan_nearby_ssids() -> List[Tuple[str, str]]:
        """Return (ssid, bssid) pairs from the OS wireless scan cache."""
        result: List[Tuple[str, str]] = []
        if sys.platform != "win32":
            return result
        try:
            r = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True, timeout=10,
            )
            output = r.stdout.decode(_OEM_ENCODING, errors="replace")
        except Exception:
            return result

        current_ssid = ""
        for line in output.splitlines():
            ssid_m = re.match(r"\s*SSID\s+\d+\s*:\s*(.+)", line, re.IGNORECASE)
            if ssid_m:
                current_ssid = ssid_m.group(1).strip()
            bssid_m = re.match(r"\s*BSSID\s+\d+\s*:\s*([\da-fA-F:]+)", line, re.IGNORECASE)
            if bssid_m:
                bssid = bssid_m.group(1).strip().upper()
                result.append((current_ssid, bssid))
        return result

    _WXPL_RECOMMENDATION = (
        "This device has wireless (WiFi) capabilities but EmbedXPL-Forge "
        "focuses on wired/web-based exploit testing. For wireless-specific "
        "attacks (WPA/WPA2/WPA3 cracking, deauth, evil twin, PMKID capture, "
        "handshake sniffing, rogue AP, and other active/passive wireless "
        "attacks), use WirelessXPL-Forge — a dedicated tool for online/offline "
        "wireless security testing. See: submodules/IoT/WirelessXPL-Forge"
    )

    def _generate_wireless_recommendations(self) -> None:
        """Add WirelessXPL-Forge recommendation for wireless-capable hosts.

        Targets two scenarios:
          1. Host has WiFi but NO EmbedXPL exploit modules matched
             -> strong recommendation (primary attack surface is wireless)
          2. Host has WiFi AND EmbedXPL modules matched
             -> complementary note (wireless is an additional attack surface)
        """
        for host in self._hosts:
            if not host.has_wireless:
                continue

            ssid_note = ""
            if host.wireless_ssids:
                ssid_note = " Detected SSIDs: {}.".format(", ".join(host.wireless_ssids))

            if not host.matched_modules:
                host.wireless_recommendation = (
                    "[RECOMMENDED] No wired/web exploits matched for this device, "
                    "but it has wireless capabilities.{} {}".format(
                        ssid_note, self._WXPL_RECOMMENDATION,
                    )
                )
            else:
                host.wireless_recommendation = (
                    "[COMPLEMENTARY] This device has {} EmbedXPL module(s) for "
                    "wired/web testing, but also exposes wireless interfaces.{} "
                    "For a comprehensive assessment, complement with "
                    "WirelessXPL-Forge for wireless-layer attacks "
                    "(WPA cracking, deauth, PMKID, evil twin, etc.). "
                    "See: submodules/IoT/WirelessXPL-Forge".format(
                        len(host.matched_modules), ssid_note,
                    )
                )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_vendor(vendor_str: str) -> str:
        """Normalize a vendor name to match module naming conventions."""
        from embedxpl.core.oui import normalize_vendor
        return normalize_vendor(vendor_str)

    @property
    def hosts(self) -> List[DiscoveredHost]:
        """Return discovered hosts."""
        return list(self._hosts)

    def hosts_with_modules(self) -> List[DiscoveredHost]:
        """Return only hosts that have matching exploit modules."""
        return [h for h in self._hosts if h.matched_modules]

    def hosts_with_wireless(self) -> List[DiscoveredHost]:
        """Return hosts that have wireless capabilities."""
        return [h for h in self._hosts if h.has_wireless]


def scan_from_file(
    targets_file: str,
    *,
    timing: int = 3,
    callback: Optional[Callable] = None,
    max_file_workers: int = 4,
) -> Dict[str, List[DiscoveredHost]]:
    """Scan multiple targets listed in a file, one IP/CIDR per line.

    Lines beginning with ``#`` and blank lines are skipped.  Each unique
    target is scanned in parallel up to ``max_file_workers`` concurrent
    :class:`NetworkDiscovery` instances.

    Args:
        targets_file: Path to a plain-text file with one IP or CIDR per line.
        timing: Nmap-style timing level (0–5) passed to each :class:`NetworkDiscovery`.
        callback: Optional ``(target, stage, detail)`` progress callback.
        max_file_workers: Maximum number of targets scanned concurrently.

    Returns:
        Mapping of *target* string → list of :class:`DiscoveredHost` objects.
    """
    targets = _parse_targets_file(targets_file)
    if not targets:
        logger.warning("scan_from_file: no targets parsed from '%s'", targets_file)
        return {}

    results: Dict[str, List[DiscoveredHost]] = {}
    lock = threading.Lock()

    def _scan_one(target: str) -> None:
        def _cb(stage: str, detail: str) -> None:
            if callback:
                callback(target, stage, detail)

        try:
            nd = NetworkDiscovery(target, timing=timing)
            hosts = nd.scan(callback=_cb)
        except Exception as exc:
            logger.warning("scan_from_file: scan of '%s' failed: %s", target, exc)
            hosts = []

        with lock:
            results[target] = hosts

        if callback:
            callback(target, "done", "{} host(s) found".format(len(hosts)))

    with ThreadPoolExecutor(max_workers=max_file_workers) as pool:
        futures = {pool.submit(_scan_one, t): t for t in targets}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                logger.warning("scan_from_file worker error: %s", exc)

    return results


def _parse_targets_file(path: str) -> List[str]:
    """Read a targets file and return a deduplicated list of IP/CIDR strings.

    Skips blank lines and lines whose first non-whitespace character is ``#``.
    Validates each entry as an IPv4/IPv6 address or network in CIDR notation.
    """
    targets: List[str] = []
    seen: Set[str] = set()

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                # Strip inline comments
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                # Validate
                try:
                    ipaddress.ip_network(line, strict=False)
                    entry = line
                except ValueError:
                    try:
                        ipaddress.ip_address(line)
                        entry = line
                    except ValueError:
                        logger.warning("scan_from_file: invalid entry '%s' -- skipped", line)
                        continue
                if entry not in seen:
                    seen.add(entry)
                    targets.append(entry)
    except OSError as exc:
        logger.error("scan_from_file: cannot open '%s': %s", path, exc)

    return targets

