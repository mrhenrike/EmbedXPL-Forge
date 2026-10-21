# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""APT catalog data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class APTAttack:
    """Single attack/technique within an APT campaign."""
    name: str
    description: str
    cves: List[str] = field(default_factory=list)
    modules: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    target_devices: List[str] = field(default_factory=list)
    phase: str = ""
    requires_auth: bool = False


@dataclass
class APTGroup:
    """APT group profile with associated attacks reproducible by EmbedXPL."""
    id: str
    name: str
    aliases: List[str]
    country: str
    description: str
    campaigns: List[str] = field(default_factory=list)
    attacks: List[APTAttack] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    mitre_id: str = ""


APT_CATALOG: Dict[str, APTGroup] = {}
