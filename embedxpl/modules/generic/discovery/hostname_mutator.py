"""
embedxpl/modules/generic/discovery/hostname_mutator.py - Hostname Mutation Engine.

Generates hostname variations from observed IoT/embedded device hostnames
to discover related devices through DNS guessing.

Native Python reimplementation of alterx pattern mutation and clustering.
  submodules/Wordlists/alterx/mutator.go + patternmining.go

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import re
from typing import Dict, List, Set

__version__ = "1.0.0"

# Common IoT/embedded hostname prefixes and suffixes
_IOT_PREFIXES = [
    "cam", "camera", "nvr", "dvr", "printer", "ap", "router",
    "switch", "plc", "hmi", "scada", "gateway", "sensor",
    "mqtt", "iot", "admin", "mgmt", "management",
]

_COMMON_SEPARATORS = ["-", "_", ".", ""]

# Sequence pattern templates
_SEQ_PATTERNS = [
    "{base}-{n:02d}",
    "{base}-{n}",
    "{base}{n:02d}",
    "{base}{n}",
    "{base}.{n}",
]


def _extract_base_seq(hostname: str) -> tuple:
    """Extract base name and sequence number from hostname.

    Example: "cam-01" -> ("cam", 1), "printer02" -> ("printer", 2)

    Returns:
        (base: str, seq: int or None)
    """
    m = re.match(r"^(.*?)[-_.]?(\d+)$", hostname.lower())
    if m:
        return m.group(1).rstrip("-_."), int(m.group(2))
    return hostname.lower(), None


def mutate(hostnames: List[str], seq_range: int = 10) -> List[str]:
    """Generate hostname mutations from observed hostnames.

    For each hostname:
    1. If it has a sequence number, generate nearby numbers
    2. Try common IoT prefix combinations
    3. Apply separator variants

    Args:
        hostnames: List of observed hostnames.
        seq_range: Range of sequence numbers to generate (+/- range).

    Returns:
        Sorted list of unique mutations.
    """
    results: Set[str] = set(hostnames)

    for hostname in hostnames:
        h_lower = hostname.lower()
        base, seq = _extract_base_seq(h_lower)

        if seq is not None:
            # Generate sequence variants
            start = max(0, seq - seq_range)
            end = seq + seq_range + 1
            for n in range(start, end):
                for tmpl in _SEQ_PATTERNS:
                    results.add(tmpl.format(base=base, n=n))
            # Also try without numbers
            results.add(base)
        else:
            # Try adding sequence numbers
            for n in range(1, min(seq_range + 1, 6)):
                for sep in _COMMON_SEPARATORS:
                    results.add(f"{h_lower}{sep}{n:02d}")

        # Try common IoT prefix additions
        for prefix in _IOT_PREFIXES:
            if prefix not in h_lower:
                for sep in ["-", ""]:
                    results.add(f"{prefix}{sep}{h_lower}")

    # Filter: only valid DNS labels
    filtered = [
        h for h in results
        if re.match(r"^[a-z0-9][a-z0-9.-]{0,62}$", h) and ".." not in h
    ]
    return sorted(set(filtered))


def mine_patterns(observed: List[str]) -> List[str]:
    """Discover naming patterns from observed hostnames.

    Identifies:
    - Sequential patterns (cam-01..cam-10 -> generate cam-11, cam-12)
    - Prefix patterns (same base, different suffixes)

    Args:
        observed: List of observed hostnames.

    Returns:
        List of inferred pattern templates.
    """
    patterns = []
    bases: Dict[str, List[int]] = {}

    for h in observed:
        base, seq = _extract_base_seq(h)
        if seq is not None:
            if base not in bases:
                bases[base] = []
            bases[base].append(seq)

    for base, seqs in bases.items():
        if len(seqs) >= 2:
            seqs.sort()
            step = seqs[1] - seqs[0] if len(seqs) > 1 else 1
            patterns.append(
                f"{base}-{{n:02d}} (detected range: {min(seqs)}-{max(seqs)}, step={step})"
            )

    return patterns
