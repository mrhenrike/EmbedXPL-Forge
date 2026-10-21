#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vendor profiles for PJL shell — INFO categories and command restrictions."""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

# ── Normalization ─────────────────────────────────────────────────────────────

_VENDOR_ALIASES: Dict[str, str] = {
    'hp': 'hp',
    'hewlett-packard': 'hp',
    'hewlett packard': 'hp',
    'hpe': 'hp',
    'brother': 'brother',
    'epson': 'epson',
    'ricoh': 'ricoh',
    'xerox': 'xerox',
    'kyocera': 'kyocera',
    'kyocera mita': 'kyocera',
    'canon': 'canon',
    'lexmark': 'lexmark',
    'oki': 'oki',
    'samsung': 'samsung',
    'konica': 'konica',
    'konica minolta': 'konica',
    'generic': 'generic',
    'unknown': 'generic',
    '': 'generic',
}

VENDOR_NAMES: Tuple[str, ...] = (
    'hp', 'brother', 'epson', 'ricoh', 'xerox', 'kyocera',
    'canon', 'lexmark', 'oki', 'samsung', 'konica', 'generic',
)

# ── PJL INFO categories ───────────────────────────────────────────────────────

PJL_INFO_GENERIC: List[Tuple[str, str]] = [
    ('ID',        'Device identification'),
    ('STATUS',    'Current status'),
    ('CONFIG',    'Configuration'),
    ('FILESYS',   'Filesystem information'),
    ('MEMORY',    'Memory information'),
    ('PAGECOUNT', 'Page counter'),
    ('VARIABLES', 'Environment variables'),
    ('USTATUS',   'Unsolicited status'),
    ('PRODUCT',   'Product information'),
]

PJL_INFO_BY_VENDOR: Dict[str, List[Tuple[str, str]]] = {
    'hp': [
        ('LOG',      'Event log (HP / undocumented)'),
        ('PRODINFO', 'Product info extended (HP)'),
        ('TRACKING', 'Tracking data (HP / undocumented)'),
        ('SUPPLIES', 'Supplies/toner status (HP / undocumented)'),
    ],
    'brother': [
        ('BRFIRMWARE', 'Firmware version (Brother)'),
    ],
    'xerox': [
        ('LOG',      'Event log (Xerox / may apply)'),
        ('SUPPLIES', 'Supplies status (Xerox / may apply)'),
    ],
    'lexmark': [
        ('SUPPLIES', 'Supplies status (Lexmark / may apply)'),
    ],
}

# Shell commands restricted to specific vendors (empty = any RAW/PJL host)
VENDOR_COMMANDS: Dict[str, Set[str]] = {
    'nvram': {'brother'},
}

_HELP_CATEGORIES: Set[str] = {
    'filesystem', 'system', 'information', 'control', 'security',
    'attacks', 'network', 'monitoring', 'test',
}


def normalize_vendor(name: Optional[str]) -> str:
    """Map make/model string to canonical vendor slug."""
    if not name:
        return 'generic'
    key = str(name).strip().lower()
    if key in _VENDOR_ALIASES:
        return _VENDOR_ALIASES[key]
    for alias, slug in _VENDOR_ALIASES.items():
        if alias and alias in key:
            return slug
    # first token fallback (e.g. "Epson L6190" → epson)
    token = key.split()[0] if key.split() else 'generic'
    return _VENDOR_ALIASES.get(token, 'generic')


def info_categories_for_vendor(
    vendor: str,
    *,
    include_all: bool = False,
) -> List[Tuple[str, str]]:
    """
    Return PJL INFO categories to query for *vendor*.

    include_all=True  → generic + every vendor-specific block (audit spray).
    vendor=generic    → generic only (no HP/Brother noise).
    vendor=hp         → generic + HP block, etc.
    """
    if include_all:
        out = list(PJL_INFO_GENERIC)
        seen = {c[0] for c in out}
        for block in PJL_INFO_BY_VENDOR.values():
            for cat in block:
                if cat[0] not in seen:
                    out.append(cat)
                    seen.add(cat[0])
        return out

    slug = normalize_vendor(vendor)
    out = list(PJL_INFO_GENERIC)
    out.extend(PJL_INFO_BY_VENDOR.get(slug, []))
    return out


def vendor_allows_command(command: str, vendor: str) -> bool:
    """True if *command* may run for the given vendor (or vendor unknown)."""
    required = VENDOR_COMMANDS.get(command.lower())
    if not required:
        return True
    slug = normalize_vendor(vendor)
    if slug == 'generic':
        return False
    return slug in required


def vendor_command_hint(command: str) -> str:
    required = VENDOR_COMMANDS.get(command.lower())
    if not required:
        return ''
    return ', '.join(sorted(required))
