# Original: laboratory/bug-hunt/mikrotik/scripts/harden_chr.py
# Source: mrhenrike | SafeLabs security research
# Embedded in EmbedXPL-Forge native_src by @mrhenrike | Uniao Geek

#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
# Version: 1.0.0

"""Apply baseline hardening controls to MikroTik CHR targets via REST API."""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


LOGGER = logging.getLogger("harden_chr")


@dataclass
class HardeningConfig:
    """Hardening settings for a CHR target."""

    target: str
    username: str
    password: str
    management_cidr: str = "192.168.100.0/24"
    http_port: int = 80
    use_ssl: bool = False
    timeout: int = 8
    dry_run: bool = False


class RouterOSHardener:
    """Apply hardening controls using RouterOS API commands."""

    def __init__(self, cfg: HardeningConfig) -> None:
        self.cfg = cfg
        self.scheme = "https" if cfg.use_ssl else "http"
        self.base_url = f"{self.scheme}://{cfg.target}:{cfg.http_port}/rest"
        self.auth = (cfg.username, cfg.password)

    def run(self) -> Dict[str, object]:
        """Run complete hardening pipeline."""
        if not self._auth_ok():
            raise RuntimeError(f"REST authentication failed for target {self.cfg.target}")
        return {
            "target": self.cfg.target,
            "service_changes": self._harden_services(),
            "dns_hardened": self._set_dns(),
            "ssh_hardened": self._set_ssh(),
            "neighbor_hardened": self._set_neighbor_discovery(),
            "snmp_hardened": self._set_snmp(),
            "firewall_hardened": self._set_firewall_baseline(),
            "dry_run": self.cfg.dry_run,
        }

    def _harden_services(self) -> List[Dict[str, str]]:
        services = self._get_list("/ip/service")
        by_name = {service.get("name", ""): service for service in services}
        desired: Dict[str, Dict[str, str]] = {
            "ftp": {"disabled": "true"},
            "telnet": {"disabled": "true"},
            "www": {"disabled": "true"},
            "www-ssl": {"disabled": "true"},
            "api-ssl": {"disabled": "true"},
            "api": {"address": self.cfg.management_cidr},
            "ssh": {"address": self.cfg.management_cidr},
            "winbox": {"address": self.cfg.management_cidr},
        }
        changes: List[Dict[str, str]] = []
        for svc_name, attrs in desired.items():
            item = by_name.get(svc_name)
            if not item:
                continue
            item_id = item.get(".id", "")
            for key, value in attrs.items():
                if item.get(key) == value:
                    continue
                self._patch(f"/ip/service/{item_id}", {key: value})
                changes.append({"service": svc_name, "field": key, "value": value})
        return changes

    def _set_dns(self) -> bool:
        return self._post_set("/ip/dns/set", {"allow-remote-requests": "false"})

    def _set_ssh(self) -> bool:
        return self._post_set("/ip/ssh/set", {"strong-crypto": "yes"})

    def _set_neighbor_discovery(self) -> bool:
        return self._post_set("/ip/neighbor/discovery-settings/set", {"discover-interface-list": "none"})

    def _set_snmp(self) -> bool:
        return self._post_set("/snmp/set", {"enabled": "no"})

    def _set_firewall_baseline(self) -> bool:
        rule_specs = [
            {
                "comment": "SAFELABS: allow established,related",
                "words": [
                    "/ip/firewall/filter/add",
                    "=chain=input",
                    "=connection-state=established,related",
                    "=action=accept",
                    "=comment=SAFELABS: allow established,related",
                ],
            },
            {
                "comment": "SAFELABS: allow mgmt from lab cidr",
                "words": [
                    "/ip/firewall/filter/add",
                    "=chain=input",
                    f"=src-address={self.cfg.management_cidr}",
                    "=action=accept",
                    "=comment=SAFELABS: allow mgmt from lab cidr",
                ],
            },
            {
                "comment": "SAFELABS: drop all input",
                "words": [
                    "/ip/firewall/filter/add",
                    "=chain=input",
                    "=action=drop",
                    "=comment=SAFELABS: drop all input",
                ],
            },
        ]

        current = self._get_list("/ip/firewall/filter")
        existing_comments = {item.get("comment", "") for item in current}
        ok = True
        for rule in rule_specs:
            if rule["comment"] in existing_comments:
                continue
            payload = self._words_to_payload(rule["words"][1:])
            ok = self._post_set("/ip/firewall/filter/add", payload) and ok
        return ok

    def _auth_ok(self) -> bool:
        if self.cfg.dry_run:
            return True
        response = self._request("GET", "/system/resource")
        return response is not None and response.status_code == 200

    def _request(self, method: str, endpoint: str, payload: Optional[Dict[str, str]] = None) -> Optional[requests.Response]:
        url = f"{self.base_url}{endpoint}"
        if self.cfg.dry_run:
            LOGGER.info("[dry-run] %s %s %s", method, endpoint, payload or {})
            return requests.Response()
        try:
            response = requests.request(
                method=method,
                url=url,
                auth=self.auth,
                timeout=self.cfg.timeout,
                verify=False,
                json=payload,
            )
            return response
        except Exception as exc:
            LOGGER.error("REST request failed %s %s: %s", method, endpoint, exc)
            return None

    def _get_list(self, endpoint: str) -> List[Dict[str, str]]:
        response = self._request("GET", endpoint)
        if response is None:
            return []
        if response.status_code != 200:
            LOGGER.warning("GET %s returned HTTP %s", endpoint, response.status_code)
            return []
        data = response.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []

    def _patch(self, endpoint: str, payload: Dict[str, str]) -> bool:
        response = self._request("PATCH", endpoint, payload)
        if self.cfg.dry_run:
            return True
        return response is not None and response.status_code in {200, 201, 204}

    def _post(self, endpoint: str, payload: Dict[str, str]) -> bool:
        response = self._request("POST", endpoint, payload)
        if self.cfg.dry_run:
            return True
        return response is not None and response.status_code in {200, 201, 204}

    def _post_set(self, endpoint: str, payload: Dict[str, str]) -> bool:
        """POST helper for RouterOS `/set` and `/add` REST commands."""
        return self._post(endpoint, payload)

    @staticmethod
    def _words_to_payload(words: List[str]) -> Dict[str, str]:
        payload: Dict[str, str] = {}
        for word in words:
            if not word.startswith("="):
                continue
            key, _, value = word[1:].partition("=")
            payload[key] = value
        return payload


def build_parser() -> argparse.ArgumentParser:
    """Build command-line parser."""
    parser = argparse.ArgumentParser(description="Apply RouterOS CHR hardening controls.")
    parser.add_argument("--target", required=True, help="Router target IP/hostname")
    parser.add_argument("-U", "--user", default="admin", help="Username")
    parser.add_argument("-P", "--passw", required=True, help="Password")
    parser.add_argument("--management-cidr", default="192.168.100.0/24", help="Allowed management CIDR")
    parser.add_argument("--http-port", type=int, default=80, help="RouterOS REST HTTP port")
    parser.add_argument("--ssl", action="store_true", help="Use HTTPS for REST requests")
    parser.add_argument("--timeout", type=int, default=8, help="API timeout (seconds)")
    parser.add_argument("--dry-run", action="store_true", help="Show commands without applying")
    return parser


def configure_logging() -> None:
    """Configure script logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )


def main() -> int:
    """Entrypoint."""
    configure_logging()
    args = build_parser().parse_args()
    cfg = HardeningConfig(
        target=args.target,
        username=args.user,
        password=args.passw,
        management_cidr=args.management_cidr,
        http_port=args.http_port,
        use_ssl=args.ssl,
        timeout=args.timeout,
        dry_run=args.dry_run,
    )
    try:
        summary = RouterOSHardener(cfg).run()
        LOGGER.info("Hardening summary: %s", summary)
        return 0
    except Exception as exc:
        LOGGER.error("Hardening failed: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
