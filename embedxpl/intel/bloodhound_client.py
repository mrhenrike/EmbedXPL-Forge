"""BloodHound CE REST client — query attack paths and high-value AD principals.

Requires a running BloodHound Community Edition instance (local or remote).
Deploy BH CE: https://github.com/SpecterOps/BloodHound#quick-start-using-docker-compose

Collect data with bloodhound-python:
  pip install bloodhound
  bloodhound-python -u user -p pass -d domain.local -c All -ns <dc-ip>
"""
from __future__ import annotations

from typing import Any

import requests


class BloodHoundClient:
    """REST client for BloodHound Community Edition API (v2)."""

    def __init__(self, host: str = "http://localhost:8080", token: str = "") -> None:
        self.base = host.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        })

    # ------------------------------------------------------------------
    # Domain helpers
    # ------------------------------------------------------------------

    def get_domains(self) -> list[dict[str, Any]]:
        r = self.session.get(f"{self.base}/api/v2/domains", timeout=15)
        r.raise_for_status()
        return r.json().get("data", [])

    def get_high_value_principals(self, domain_id: str) -> list[dict[str, Any]]:
        """Return high-value targets in a domain (DAs, DCs, Tier-0 assets)."""
        r = self.session.get(
            f"{self.base}/api/v2/domains/{domain_id}/principals",
            params={"high_value": "true"},
            timeout=15,
        )
        r.raise_for_status()
        return r.json().get("data", [])

    # ------------------------------------------------------------------
    # Attack paths
    # ------------------------------------------------------------------

    def get_shortest_path(self, start_node: str, end_node: str) -> dict[str, Any]:
        """Return the shortest attack path between two graph nodes (object IDs or names)."""
        r = self.session.get(
            f"{self.base}/api/v2/attack-paths/shortest",
            params={"start_node": start_node, "end_node": end_node},
            timeout=20,
        )
        r.raise_for_status()
        return r.json()

    def find_path_to_da(self, start_node: str, domain_id: str) -> dict[str, Any]:
        """Shortest path from any node to Domain Admins in the target domain."""
        r = self.session.get(
            f"{self.base}/api/v2/attack-paths/shortest",
            params={"start_node": start_node, "edge_filter": "MemberOf,AdminTo,GenericAll,DCSync"},
            timeout=20,
        )
        r.raise_for_status()
        return r.json()

    def get_attack_paths(self, domain_id: str, finding_type: str = "HVT") -> list[dict[str, Any]]:
        """Return all attack path findings for a domain (HVT = High Value Target)."""
        r = self.session.get(
            f"{self.base}/api/v2/domains/{domain_id}/attack-paths",
            params={"finding": finding_type},
            timeout=20,
        )
        r.raise_for_status()
        return r.json().get("data", [])

    # ------------------------------------------------------------------
    # Node queries
    # ------------------------------------------------------------------

    def search_nodes(self, query: str, node_type: str = "") -> list[dict[str, Any]]:
        """Full-text search across BH graph nodes."""
        params: dict[str, str] = {"q": query}
        if node_type:
            params["type"] = node_type
        r = self.session.get(f"{self.base}/api/v2/search", params=params, timeout=15)
        r.raise_for_status()
        return r.json().get("data", [])

    def get_computers_in_domain(self, domain_id: str) -> list[dict[str, Any]]:
        r = self.session.get(
            f"{self.base}/api/v2/domains/{domain_id}/computers", timeout=15
        )
        r.raise_for_status()
        return r.json().get("data", [])

    def get_kerberoastable_users(self, domain_id: str) -> list[dict[str, Any]]:
        r = self.session.get(
            f"{self.base}/api/v2/domains/{domain_id}/users",
            params={"has_spn": "true"},
            timeout=15,
        )
        r.raise_for_status()
        return r.json().get("data", [])

    # ------------------------------------------------------------------
    # Custom Cypher
    # ------------------------------------------------------------------

    def cypher(self, query: str) -> dict[str, Any]:
        """Run a raw Cypher query against the BH graph (requires admin token)."""
        r = self.session.post(
            f"{self.base}/api/v2/graphs/cypher",
            json={"query": query},
            timeout=30,
        )
        r.raise_for_status()
        return r.json()

    def kerberoastable_to_da(self, domain: str = "") -> dict[str, Any]:
        """Find kerberoastable users with a path to Domain Admin."""
        q = (
            "MATCH p=shortestPath((u:User {hasspn:true})-[*1..]->(g:Group {name:$da})) "
            "RETURN u.name, length(p) ORDER BY length(p)"
        )
        da_name = f"DOMAIN ADMINS@{domain.upper()}" if domain else "DOMAIN ADMINS"
        return self.cypher(q.replace("$da", f'"{da_name}"'))
