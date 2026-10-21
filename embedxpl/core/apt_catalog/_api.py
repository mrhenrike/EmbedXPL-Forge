# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""APT catalog query API."""

from __future__ import annotations

from typing import Dict, List, Optional

from ._models import APT_CATALOG, APTGroup
from ._groups_russia import _register_russia
from ._groups_china import _register_china
from ._groups_other import _register_other


def _build_catalog() -> None:
    """Build the full APT catalog from all regional data modules."""
    _register_russia()
    _register_china()
    _register_other()


def get_catalog() -> Dict[str, APTGroup]:
    """Return the full APT catalog, building it on first access."""
    if not APT_CATALOG:
        _build_catalog()
    return APT_CATALOG


def get_group(group_id: str) -> Optional[APTGroup]:
    """Retrieve a specific APT group by ID."""
    catalog = get_catalog()
    return catalog.get(group_id.lower().replace("-", "_").replace(" ", "_"))


def list_groups() -> List[APTGroup]:
    """Return all APT groups sorted by name."""
    return sorted(get_catalog().values(), key=lambda g: g.name)


def find_groups_by_device(device_keyword: str) -> List[APTGroup]:
    """Find APT groups that target devices matching a keyword."""
    keyword = device_keyword.lower()
    results = []
    for group in get_catalog().values():
        for attack in group.attacks:
            if any(keyword in d.lower() for d in attack.target_devices):
                if group not in results:
                    results.append(group)
    return results


def find_groups_by_cve(cve_id: str) -> List[APTGroup]:
    """Find APT groups associated with a specific CVE."""
    cve_upper = cve_id.upper()
    results = []
    for group in get_catalog().values():
        for attack in group.attacks:
            if cve_upper in attack.cves:
                if group not in results:
                    results.append(group)
    return results

