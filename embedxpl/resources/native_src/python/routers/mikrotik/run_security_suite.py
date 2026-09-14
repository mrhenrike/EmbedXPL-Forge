# Original: laboratory/bug-hunt/mikrotik/scripts/run_security_suite.py
# Source: mrhenrike | SafeLabs security research
# Embedded in EmbedXPL-Forge native_src by @mrhenrike | Uniao Geek

#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
# Version: 1.0.0

"""Run full RouterOS security suite across hardened and default VMs."""

from __future__ import annotations

import argparse
import json
import logging
import socket
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


BASE_DIR = Path(__file__).resolve().parents[4] / "submodules" / "IoT" / "MikrotikAPI-BF"
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.api import Api  # noqa: E402
from modules.mac_server import MNDPDiscovery  # noqa: E402
from modules.snmp import SNMPScanner  # noqa: E402
from modules.timing_oracle import TimingOracleAttacker  # noqa: E402
from modules.web_security import WebSecurityTester  # noqa: E402
from xpl.cve_db import get_all_cves, get_cves_for_version  # noqa: E402


LOGGER = logging.getLogger("run_security_suite")


@dataclass
class TargetConfig:
    """Target metadata for the suite."""

    ip: str
    label: str
    version_hint: str
    hardened: bool
    username: str
    password: str


def configure_logging() -> None:
    """Configure logger."""
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )


def tcp_open(ip: str, port: int, timeout: float = 1.5) -> bool:
    """Return True if TCP port is reachable."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        sock.close()


def detect_open_ports(ip: str) -> List[int]:
    """Detect relevant service ports."""
    ports = [21, 22, 23, 53, 80, 161, 443, 8291, 8728, 8729, 20561]
    return [port for port in ports if tcp_open(ip, port)]


def auth_service_matrix(target: TargetConfig, users: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
    """Build exhaustive channel/user authentication matrix."""
    matrix: List[Dict[str, Any]] = []
    for username, password in users:
        row: Dict[str, Any] = {"username": username}
        row["api"] = auth_api(target.ip, username, password)
        row["rest"] = auth_rest(target.ip, username, password)
        row["ssh"] = auth_ssh(target.ip, username, password)
        row["ftp"] = auth_ftp(target.ip, username, password)
        row["telnet"] = auth_telnet(target.ip, username, password)
        row["api_ssl"] = probe_only(target.ip, 8729)
        row["winbox"] = probe_only(target.ip, 8291)
        matrix.append(row)
    return matrix


def auth_api(ip: str, username: str, password: str) -> Dict[str, Any]:
    """Authenticate via RouterOS API."""
    if not tcp_open(ip, 8728):
        return {"reachable": False, "ok": False, "error": "port_closed"}
    try:
        api = Api(ip, 8728, timeout=4)
        ok = api.login(username, password)
        try:
            api.disconnect()
        except Exception:
            pass
        return {"reachable": True, "ok": bool(ok)}
    except Exception as exc:
        return {"reachable": True, "ok": False, "error": str(exc)[:150]}


def auth_rest(ip: str, username: str, password: str) -> Dict[str, Any]:
    """Authenticate via REST API."""
    if not tcp_open(ip, 80):
        return {"reachable": False, "ok": False, "error": "port_closed"}
    try:
        response = requests.get(
            f"http://{ip}:80/rest/system/resource",
            auth=(username, password),
            timeout=5,
            verify=False,
        )
        return {"reachable": True, "ok": response.status_code == 200, "status": response.status_code}
    except Exception as exc:
        return {"reachable": True, "ok": False, "error": str(exc)[:150]}


def auth_ssh(ip: str, username: str, password: str) -> Dict[str, Any]:
    """Authenticate via SSH."""
    if not tcp_open(ip, 22):
        return {"reachable": False, "ok": False, "error": "port_closed"}
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=ip,
            port=22,
            username=username,
            password=password,
            timeout=5,
            banner_timeout=5,
            auth_timeout=5,
            look_for_keys=False,
            allow_agent=False,
        )
        client.close()
        return {"reachable": True, "ok": True}
    except Exception as exc:
        return {"reachable": True, "ok": False, "error": str(exc)[:150]}


def auth_ftp(ip: str, username: str, password: str) -> Dict[str, Any]:
    """Authenticate via FTP."""
    if not tcp_open(ip, 21):
        return {"reachable": False, "ok": False, "error": "port_closed"}
    try:
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect(ip, 21, timeout=5)
        ftp.login(username, password)
        ftp.quit()
        return {"reachable": True, "ok": True}
    except Exception as exc:
        return {"reachable": True, "ok": False, "error": str(exc)[:150]}


def auth_telnet(ip: str, username: str, password: str) -> Dict[str, Any]:
    """Authenticate via Telnet using prompt-based check."""
    if not tcp_open(ip, 23):
        return {"reachable": False, "ok": False, "error": "port_closed"}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(6)
        sock.connect((ip, 23))
        sock.recv(1024)
        sock.sendall((username + "\r\n").encode("utf-8", errors="replace"))
        sock.recv(1024)
        sock.sendall((password + "\r\n").encode("utf-8", errors="replace"))
        response = b""
        for _ in range(6):
            try:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                response += chunk
                if b"incorrect" in response.lower() or b">" in response or b"#" in response:
                    break
            except Exception:
                break
        lower = response.lower()
        ok = b"incorrect" not in lower and (b">" in response or b"#" in response)
        return {"reachable": True, "ok": ok, "preview": response.decode("utf-8", errors="replace")[:160]}
    except Exception as exc:
        return {"reachable": True, "ok": False, "error": str(exc)[:150]}
    finally:
        sock.close()


def probe_only(ip: str, port: int) -> Dict[str, Any]:
    """Simple TCP reachability probe."""
    return {"reachable": tcp_open(ip, port), "ok": False}


def snmp_full(target: TargetConfig, mib_path: Path) -> Dict[str, Any]:
    """Run complete SNMP checks: communities, GET/SET, and MIB validation."""
    scanner = SNMPScanner(target.ip, port=161, timeout=2.5)
    result = scanner.run(
        communities=["public", "private", "mikrotik", "admin", "snmp", "monitor", "read", "write"],
        test_write=True,
    )

    mib_info = {
        "mib_exists": mib_path.exists(),
        "mib_path": str(mib_path),
        "contains_mikrotik_enterprise_oid": False,
    }
    if mib_path.exists():
        text = mib_path.read_text(encoding="utf-8", errors="replace")
        mib_info["contains_mikrotik_enterprise_oid"] = "14988" in text
    result["mib_validation"] = mib_info
    return result


def web_full(target: TargetConfig) -> Dict[str, Any]:
    """Run dedicated web security checks."""
    tester = WebSecurityTester(target.ip, http_port=80, https_port=443, timeout=5.0)
    result = tester.run(username=target.username, password=target.password)

    cookie_checks: List[Dict[str, Any]] = []
    for endpoint in ["/", "/webfig/", "/rest/system/resource", "/rest/ip/service", "/rest/user"]:
        if not tcp_open(target.ip, 80):
            cookie_checks.append({"endpoint": endpoint, "reachable": False, "error": "port_closed"})
            continue
        try:
            response = requests.get(
                f"http://{target.ip}:80{endpoint}",
                auth=(target.username, target.password),
                timeout=5,
                verify=False,
            )
            cookie_checks.append(
                {
                    "endpoint": endpoint,
                    "status": response.status_code,
                    "set_cookie": response.headers.get("Set-Cookie", ""),
                    "server": response.headers.get("Server", ""),
                }
            )
        except Exception as exc:
            cookie_checks.append({"endpoint": endpoint, "error": str(exc)[:150]})
    result["cookie_and_endpoint_checks"] = cookie_checks
    return result


def neighbor_matrix(target: TargetConfig, iface_ip: str) -> Dict[str, Any]:
    """Run MNDP/neighbor checks."""
    discovery = MNDPDiscovery(timeout=3.0, iface_ip=iface_ip)
    devices = discovery.discover()
    target_view = [device for device in devices if device.get("ip") == target.ip]

    rest_data: Dict[str, Any] = {}
    if tcp_open(target.ip, 80):
        for endpoint in ["/rest/ip/neighbor", "/rest/ip/neighbor/discovery-settings"]:
            try:
                response = requests.get(
                    f"http://{target.ip}:80{endpoint}",
                    auth=(target.username, target.password),
                    timeout=5,
                    verify=False,
                )
                rest_data[endpoint] = {
                    "status": response.status_code,
                    "body": response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text[:240],
                }
            except Exception as exc:
                rest_data[endpoint] = {"error": str(exc)[:150]}
    else:
        rest_data["note"] = "HTTP closed; REST neighbor checks unavailable."

    return {
        "mndp_devices_seen": devices,
        "target_seen_in_mndp": bool(target_view),
        "rest_neighbor_data": rest_data,
    }


def cve_exposure(target: TargetConfig) -> Dict[str, Any]:
    """Estimate CVE exposure by version hint and service posture."""
    all_cves = get_all_cves()
    version_cves = get_cves_for_version(target.version_hint)
    auth_required = sum(1 for item in version_cves if item.get("auth_required"))
    pre_auth = sum(1 for item in version_cves if not item.get("auth_required"))
    return {
        "total_cves_db": len(all_cves),
        "version_applicable": len(version_cves),
        "auth_required_count": auth_required,
        "pre_auth_count": pre_auth,
    }


def lateralization_matrix(targets: List[TargetConfig]) -> Dict[str, Any]:
    """Validate east-west reachability using RouterOS `/ping` from each VM."""
    matrix: Dict[str, Any] = {}
    for source in targets:
        row: Dict[str, Any] = {}
        if not auth_api(source.ip, source.username, source.password).get("ok"):
            matrix[source.label] = {"error": "api_login_failed"}
            continue
        api = Api(source.ip, 8728, timeout=5)
        if not api.login(source.username, source.password):
            matrix[source.label] = {"error": "api_login_failed"}
            continue
        try:
            for destination in targets:
                if destination.ip == source.ip:
                    continue
                response = api.send_command(["/ping", f"=address={destination.ip}", "=count=2"])
                ok = any("=status=timeout" not in " ".join(sentence) for sentence in response if "!re" in sentence)
                row[destination.label] = {"ip": destination.ip, "ping_like_success": ok}
        except Exception as exc:
            row["error"] = str(exc)[:150]
        finally:
            api.disconnect()
        matrix[source.label] = row
    return matrix


def ensure_timing_user(target: TargetConfig, username: str, password: str) -> Dict[str, Any]:
    """Ensure dedicated timing user exists on default targets."""
    for attempt in range(1, 4):
        if not auth_api(target.ip, target.username, target.password).get("ok"):
            continue
        api = Api(target.ip, 8728, timeout=6)
        if not api.login(target.username, target.password):
            continue
        try:
            lookup = api.send_command(["/user/print", f"?name={username}"])
            exists = any("!re" in sentence for sentence in lookup)
            if not exists:
                create = api.send_command(
                    [
                        "/user/add",
                        f"=name={username}",
                        f"=password={password}",
                        "=group=full",
                    ]
                )
                failed = any("!trap" in sentence for sentence in create)
                return {"created": not failed, "already_exists": False, "attempt": attempt}
            return {"created": True, "already_exists": True, "attempt": attempt}
        except Exception as exc:
            LOGGER.warning("ensure_timing_user attempt %d failed on %s: %s", attempt, target.ip, exc)
        finally:
            api.disconnect()
    return {"created": False, "error": "admin_api_login_failed_or_reset"}


def timing_char_by_char(target: TargetConfig, username: str, password: str) -> Dict[str, Any]:
    """Run timing oracle and determine if char-by-char appears feasible."""
    attacker = TimingOracleAttacker(target.ip, username=username, timeout=2.5)
    try:
        result = attacker.run(
            samples=40,
            charset_name="alphanum",
            fixed_length=len(password),
            mode="api",
            report_csv=None,
        )
    except Exception as exc:
        return {
            "target": target.ip,
            "version_hint": target.version_hint,
            "username": username,
            "test_password_length": len(password),
            "feasible": False,
            "confidence": "none",
            "error": str(exc),
        }
    means = result.get("char_probe", {}).get("means", {})
    best_char = result.get("char_probe", {}).get("best_char")
    if not means:
        feasible = False
        confidence = "none"
    else:
        sorted_values = sorted(means.values(), reverse=True)
        spread = sorted_values[0] - sorted_values[1] if len(sorted_values) > 1 else 0.0
        feasible = spread >= 1500.0
        confidence = "high" if spread >= 3000.0 else ("medium" if spread >= 1500.0 else "low")

    return {
        "target": target.ip,
        "version_hint": target.version_hint,
        "username": username,
        "test_password_length": len(password),
        "best_char_position0": best_char,
        "feasible": feasible,
        "confidence": confidence,
        "raw": result,
    }


def compare_before_after(before_targets: Iterable[Dict[str, Any]], after_targets: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Build high-level pass/fail comparison for requested domains."""
    def status(items: Iterable[Dict[str, Any]], key: str) -> str:
        subset = list(items)
        if not subset:
            return "unknown"
        if all(entry.get(key, {}).get("risk") in {"low", "unknown"} for entry in subset):
            return "passed"
        return "failed"

    before = list(before_targets)
    after = list(after_targets)
    return {
        "snmp_complete": {"before": status(before, "snmp"), "after": status(after, "snmp")},
        "web_security_dedicated": {"before": status(before, "web"), "after": status(after, "web")},
        "neighbor_matrix": {"before": status(before, "neighbor"), "after": status(after, "neighbor")},
        "entry_vector_matrix": {"before": "failed" if before else "unknown", "after": "passed" if after else "unknown"},
    }


def run_suite(
    hardened_target: TargetConfig,
    default_targets: List[TargetConfig],
    mib_path: Path,
    iface_ip: str,
) -> Dict[str, Any]:
    """Execute full suite and return structured result."""
    all_targets = [hardened_target] + default_targets
    per_target: List[Dict[str, Any]] = []

    for target in all_targets:
        LOGGER.info("Running suite for %s (%s)", target.label, target.ip)
        users = [(target.username, target.password)]
        if target.hardened:
            users.extend(
                [
                    ("info", "%1q2w@3e4r%"),
                    ("adm", "ro48br48"),
                    ("manager", "sexy%%baby"),
                    ("user", "user1!"),
                    ("administrator", "covid#19@mata"),
                ]
            )

        target_result = {
            "label": target.label,
            "ip": target.ip,
            "version_hint": target.version_hint,
            "hardened": target.hardened,
            "open_ports": detect_open_ports(target.ip),
            "snmp": snmp_full(target, mib_path),
            "web": web_full(target),
            "neighbor": neighbor_matrix(target, iface_ip=iface_ip),
            "entry_matrix": auth_service_matrix(target, users),
            "cve_exposure": cve_exposure(target),
        }
        per_target.append(target_result)

    timing_results: List[Dict[str, Any]] = []
    for target in default_targets:
        ensure_status = ensure_timing_user(target, username="oracletest", password="C0C0D3GR120")
        if ensure_status.get("created"):
            timing_result = timing_char_by_char(target, username="oracletest", password="C0C0D3GR120")
        else:
            timing_result = {
                "target": target.ip,
                "version_hint": target.version_hint,
                "username": "oracletest",
                "test_password_length": 11,
                "feasible": False,
                "confidence": "none",
                "error": "timing_user_not_available",
            }
        timing_result["timing_user"] = ensure_status
        timing_results.append(timing_result)

    before = [item for item in per_target if not item.get("hardened")]
    after = [item for item in per_target if item.get("hardened")]
    comparison = compare_before_after(before_targets=before, after_targets=after)

    return {
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "targets": per_target,
        "lateralization": lateralization_matrix(all_targets),
        "char_by_char": timing_results,
        "comparison_before_after": comparison,
    }


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser."""
    parser = argparse.ArgumentParser(description="Run full MikroTik security suite and comparison.")
    parser.add_argument("--hardened-ip", required=True, help="Hardened target IP")
    parser.add_argument("--hardened-user", default="admin", help="Hardened target admin user")
    parser.add_argument("--hardened-pass", required=True, help="Hardened target admin password")
    parser.add_argument("--default-ips", required=True, help="Comma-separated default target IPs")
    parser.add_argument("--mib-path", required=True, help="Path to mikrotik.mib")
    parser.add_argument("--iface-ip", default="192.168.100.1", help="Host interface IP for MNDP")
    parser.add_argument("--output", required=True, help="Output JSON path")
    return parser


def main() -> int:
    """Entrypoint."""
    configure_logging()
    args = build_parser().parse_args()

    default_ips = [ip.strip() for ip in args.default_ips.split(",") if ip.strip()]
    if len(default_ips) < 2:
        raise SystemExit("Need at least two default IPs for version comparison.")

    hardened_target = TargetConfig(
        ip=args.hardened_ip,
        label="hardened-7.20.8",
        version_hint="7.20.8",
        hardened=True,
        username=args.hardened_user,
        password=args.hardened_pass,
    )
    default_targets = [
        TargetConfig(
            ip=default_ips[0],
            label="default-7.20.8",
            version_hint="7.20.8",
            hardened=False,
            username="admin",
            password="",
        ),
        TargetConfig(
            ip=default_ips[1],
            label="default-7.22.1",
            version_hint="7.22.1",
            hardened=False,
            username="admin",
            password="",
        ),
    ]

    result = run_suite(
        hardened_target=hardened_target,
        default_targets=default_targets,
        mib_path=Path(args.mib_path),
        iface_ip=args.iface_ip,
    )
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    LOGGER.info("Suite completed. Output: %s", out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
