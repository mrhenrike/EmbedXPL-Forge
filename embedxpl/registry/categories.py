# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Category-to-module mapping for EmbedXPL-Forge PyPI extras.

Maps logical device categories to module glob patterns under
embedxpl/modules/, enabling selective installation via pip extras
(e.g., pip install embedxpl[routers]) and programmatic module
discovery by category.

Each category targets a specific vertical of embedded, perimeter,
or IoT devices. The "all" category unions every vertical. The
"network-only" meta-category filters modules whose
required_hardware list is empty, meaning they need no physical
adapters beyond standard network connectivity.

Usage:
    from embedxpl.registry.categories import resolve_category
    from embedxpl.registry.categories import list_categories

    modules = resolve_category("routers")
    cats = list_categories()

Version: 1.0.0
"""

import importlib
import pkgutil
from collections import OrderedDict


CATEGORY_MODULES = {
    "iot": [
        "embedxpl.modules.exploits.cameras.*",
        "embedxpl.modules.exploits.smart_tv.*",
        "embedxpl.modules.exploits.voip.*",
        "embedxpl.modules.exploits.nas.*",
        "embedxpl.modules.exploits.ups.*",
        "embedxpl.modules.scanners.cameras.*",
        "embedxpl.modules.scanners.smart_tv.*",
        "embedxpl.modules.scanners.voip.*",
        "embedxpl.modules.scanners.nas.*",
        "embedxpl.modules.scanners.ups.*",
        "embedxpl.modules.creds.cameras.*",
        "embedxpl.modules.creds.iot.*",
        "embedxpl.modules.creds.smart_tv.*",
        "embedxpl.modules.creds.voip.*",
        "embedxpl.modules.creds.nas.*",
        "embedxpl.modules.creds.ups.*",
    ],
    "ot": [
        "embedxpl.modules.exploits.ics.*",
        "embedxpl.modules.exploits.ot_iiot.*",
        "embedxpl.modules.exploits.bms.*",
        "embedxpl.modules.exploits.smart_meters.*",
        "embedxpl.modules.scanners.ics.*",
        "embedxpl.modules.scanners.ot_iiot.*",
        "embedxpl.modules.scanners.bms.*",
        "embedxpl.modules.scanners.smart_meters.*",
        "embedxpl.modules.creds.ics.*",
        "embedxpl.modules.creds.smart_meters.*",
    ],
    "iiot": [
        "embedxpl.modules.exploits.ot_iiot.*",
        "embedxpl.modules.exploits.ics.*",
        "embedxpl.modules.exploits.bmc.*",
        "embedxpl.modules.scanners.ot_iiot.*",
        "embedxpl.modules.scanners.ics.*",
        "embedxpl.modules.scanners.bmc.*",
        "embedxpl.modules.creds.ics.*",
        "embedxpl.modules.creds.bmc.*",
    ],
    "at": [
        "embedxpl.modules.exploits.specialized.vehicles.*",
        "embedxpl.modules.exploits.specialized.elevator.*",
        "embedxpl.modules.exploits.specialized.gates.*",
    ],
    "routers": [
        "embedxpl.modules.exploits.routers.*",
        "embedxpl.modules.exploits.ispcpes.*",
        "embedxpl.modules.exploits.cisco.*",
        "embedxpl.modules.exploits.aps.*",
        "embedxpl.modules.exploits.soho_edge.*",
        "embedxpl.modules.exploits.sdwan.*",
        "embedxpl.modules.scanners.routers.*",
        "embedxpl.modules.scanners.soho_edge.*",
        "embedxpl.modules.creds.routers.*",
        "embedxpl.modules.creds.ispcpes.*",
        "embedxpl.modules.creds.soho_edge.*",
    ],
    "printers": [
        "embedxpl.modules.exploits.printers.*",
        "embedxpl.modules.scanners.printers.*",
        "embedxpl.modules.creds.printers.*",
    ],
    "firewalls": [
        "embedxpl.modules.exploits.firewalls.*",
        "embedxpl.modules.exploits.ngfw.*",
        "embedxpl.modules.scanners.firewalls.*",
        "embedxpl.modules.creds.firewalls.*",
    ],
    "network-perimeter": [
        "embedxpl.modules.exploits.firewalls.*",
        "embedxpl.modules.exploits.ngfw.*",
        "embedxpl.modules.exploits.vpn.*",
        "embedxpl.modules.exploits.switches.*",
        "embedxpl.modules.exploits.taps.*",
        "embedxpl.modules.exploits.network_os.*",
        "embedxpl.modules.scanners.firewalls.*",
        "embedxpl.modules.scanners.vpn.*",
        "embedxpl.modules.scanners.switches.*",
        "embedxpl.modules.scanners.taps.*",
        "embedxpl.modules.scanners.network_os.*",
        "embedxpl.modules.creds.firewalls.*",
        "embedxpl.modules.creds.switches.*",
        "embedxpl.modules.creds.taps.*",
    ],
    "medical": [
        "embedxpl.modules.exploits.specialized.medical.*",
    ],
    "smart-home": [
        "embedxpl.modules.exploits.smart_home.*",
        "embedxpl.modules.exploits.appliances.*",
        "embedxpl.modules.exploits.specialized.thermostat.*",
        "embedxpl.modules.exploits.specialized.hvac.*",
        "embedxpl.modules.scanners.smart_home.*",
    ],
    "wearables": [
        "embedxpl.modules.exploits.wearables.*",
        "embedxpl.modules.scanners.wearables.*",
    ],
    "vehicles": [
        "embedxpl.modules.exploits.specialized.vehicles.*",
    ],
    "hvac": [
        "embedxpl.modules.exploits.specialized.hvac.*",
        "embedxpl.modules.exploits.specialized.thermostat.*",
        "embedxpl.modules.exploits.bms.*",
        "embedxpl.modules.scanners.bms.*",
    ],
    "access-control": [
        "embedxpl.modules.exploits.specialized.access_control.*",
        "embedxpl.modules.exploits.specialized.gates.*",
        "embedxpl.modules.exploits.specialized.elevator.*",
    ],
    "specialized": [
        "embedxpl.modules.exploits.specialized.*",
    ],
}

_ALL_GLOBS = []
for _globs in CATEGORY_MODULES.values():
    for _g in _globs:
        if _g not in _ALL_GLOBS:
            _ALL_GLOBS.append(_g)

_ALL_GLOBS.extend([
    "embedxpl.modules.exploits.generic.*",
    "embedxpl.modules.exploits.firmware.*",
    "embedxpl.modules.exploits.embedded_os.*",
    "embedxpl.modules.exploits.hypervisors.*",
    "embedxpl.modules.exploits.servers.*",
    "embedxpl.modules.exploits.lateral.*",
    "embedxpl.modules.exploits.protocols.*",
    "embedxpl.modules.exploits.misc.*",
    "embedxpl.modules.scanners.misc.*",
    "embedxpl.modules.scanners.embedded_os.*",
    "embedxpl.modules.scanners.hypervisors.*",
    "embedxpl.modules.scanners.protocols.*",
    "embedxpl.modules.scanners.threat_detection.*",
    "embedxpl.modules.creds.generic.*",
    "embedxpl.modules.encoders.*",
    "embedxpl.modules.payloads.*",
    "embedxpl.modules.tools.*",
])

CATEGORY_MODULES["all"] = list(_ALL_GLOBS)
CATEGORY_MODULES["network-only"] = []


CATEGORY_DESCRIPTIONS = OrderedDict([
    ("iot", "IoT devices: cameras, smart TVs, VoIP phones, NAS, UPS"),
    ("ot", "Operational Technology: ICS/SCADA, BMS, smart meters"),
    ("iiot", "Industrial IoT: ICS, BMC/IPMI, OT/IIoT controllers"),
    ("at", "Automotive Technology: vehicles, elevators, gates"),
    ("routers", "Routers, CPEs, access points, SOHO edge, SD-WAN"),
    ("printers", "Network printers: CUPS, HP, Lexmark, Kyocera, Brother"),
    ("firewalls", "Firewalls and NGFW appliances"),
    ("network-perimeter", "Full perimeter: firewalls, VPN, switches, taps, NOS"),
    ("medical", "Medical/healthcare embedded devices"),
    ("smart-home", "Smart home: assistants, appliances, thermostats, HVAC"),
    ("wearables", "Wearable devices: fitness bands, smartwatches"),
    ("vehicles", "Automotive CAN bus and infotainment systems"),
    ("hvac", "HVAC controllers, thermostats, BMS"),
    ("access-control", "Physical access: RFID readers, gates, elevators"),
    ("specialized", "All specialized verticals (medical, vehicles, HVAC, etc.)"),
    ("network-only", "Modules that require NO physical hardware adapters"),
    ("all", "Every module in the framework"),
])


def _expand_glob(pattern):
    """Expand a dotted-path glob into importable module paths.

    Args:
        pattern: String like 'embedxpl.modules.exploits.routers.*'.
            Trailing '.*' is treated as a recursive walk of that package.

    Returns:
        List of importable dotted module paths found under the pattern.
    """
    if not pattern.endswith(".*"):
        return [pattern]

    base_pkg = pattern[:-2]
    try:
        base = importlib.import_module(base_pkg)
    except ImportError:
        return []

    if not hasattr(base, "__path__"):
        return [base_pkg]

    paths = []
    for _importer, modname, ispkg in pkgutil.walk_packages(
        base.__path__, prefix=base_pkg + "."
    ):
        if ispkg:
            continue
        if modname.endswith("__init__"):
            continue
        paths.append(modname)
    return paths


def resolve_category(category_name):
    """Resolve a category name to a deduplicated list of module paths.

    Args:
        category_name: String key from CATEGORY_MODULES (e.g., "routers").

    Returns:
        Sorted list of importable dotted module path strings.

    Raises:
        ValueError: If category_name is not a recognized category.
    """
    if not isinstance(category_name, str) or not category_name.strip():
        raise ValueError("category_name must be a non-empty string")

    normalized = category_name.strip().lower()

    if normalized == "network-only":
        return resolve_network_only()

    if normalized not in CATEGORY_MODULES:
        valid = ", ".join(sorted(CATEGORY_MODULES.keys()))
        raise ValueError(
            "Unknown category '{cat}'. Valid categories: {v}".format(
                cat=category_name, v=valid,
            )
        )

    globs = CATEGORY_MODULES[normalized]
    seen = set()
    result = []
    for pattern in globs:
        for mod_path in _expand_glob(pattern):
            if mod_path not in seen:
                seen.add(mod_path)
                result.append(mod_path)

    return sorted(result)


def resolve_network_only():
    """Resolve modules that require no physical hardware adapters.

    Walks every module in the "all" category, imports each, extracts
    __info__["required_hardware"], and returns only those where the
    list is empty or missing (pure network/software modules).

    Returns:
        Sorted list of importable dotted module path strings that
        have no hardware dependencies.
    """
    all_modules = resolve_category("all")
    network_modules = []

    for mod_path in all_modules:
        try:
            mod = importlib.import_module(mod_path)
        except Exception:
            network_modules.append(mod_path)
            continue

        hw_found = False
        for attr_name in dir(mod):
            obj = getattr(mod, attr_name, None)
            if not isinstance(obj, type):
                continue
            info = getattr(obj, "__info__", None)
            if not isinstance(info, dict):
                continue
            hw_list = info.get("required_hardware", [])
            if hw_list:
                hw_found = True
                break

        if not hw_found:
            network_modules.append(mod_path)

    return sorted(network_modules)


def list_categories():
    """Return all available categories with human-readable descriptions.

    Returns:
        OrderedDict mapping category name strings to description strings.
    """
    return OrderedDict(CATEGORY_DESCRIPTIONS)


def get_category_globs(category_name):
    """Return raw glob patterns for a category without expanding.

    Args:
        category_name: String key from CATEGORY_MODULES.

    Returns:
        List of glob pattern strings, or empty list if unknown.
    """
    if not isinstance(category_name, str):
        return []
    normalized = category_name.strip().lower()
    return list(CATEGORY_MODULES.get(normalized, []))


def count_modules_by_category():
    """Count discovered modules in each category.

    Returns:
        OrderedDict mapping category names to integer module counts.
        Categories are sorted by the order in CATEGORY_DESCRIPTIONS.
    """
    counts = OrderedDict()
    for cat_name in CATEGORY_DESCRIPTIONS:
        if cat_name == "network-only":
            counts[cat_name] = -1
            continue
        try:
            modules = resolve_category(cat_name)
            counts[cat_name] = len(modules)
        except (ValueError, ImportError):
            counts[cat_name] = 0
    return counts
