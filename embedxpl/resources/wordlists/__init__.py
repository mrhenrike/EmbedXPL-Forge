"""Wordlist path resolvers with Python 3.8+ compatibility."""

from pathlib import Path
from importlib import resources
from typing import List, Optional
from urllib.parse import unquote, urlparse
import re


def _wordlist_uri(filename: str) -> str:
    """Return a normalized ``file://`` URI for a bundled wordlist resource."""
    base_path: Path

    if hasattr(resources, "files"):
        # Python 3.9+: importlib.resources.files
        base_path = Path(str(resources.files(__package__)))
    else:
        # Python 3.8 fallback: resolve from current package file.
        base_path = Path(__file__).resolve().parent

    return base_path.joinpath(filename).resolve().as_uri()


def _file_uri_to_path(file_uri: str) -> str:
    """Convert ``file://`` URI to local path, handling Windows drive prefixes."""
    parsed = urlparse(file_uri)
    path = unquote(parsed.path or "")
    if re.match(r"^/[a-zA-Z]:/", path):
        path = path[1:]
    return path


def _load_entries(source: str) -> List[str]:
    """Load entries from ``file://`` URI or CSV-like inline content."""
    if source.startswith("file://"):
        path = _file_uri_to_path(source)
        with open(path, "r") as handler:
            return [line.strip() for line in handler.readlines() if line.strip()]
    return [item.strip() for item in source.split(",") if item.strip()]


def _infer_protocol(module_name: str) -> Optional[str]:
    leaf = module_name.rsplit(".", 1)[-1].lower()
    if "ssh" in leaf:
        return "ssh"
    if "sftp" in leaf:
        return "sftp"
    if "telnet" in leaf:
        return "telnet"
    if "ftp" in leaf:
        return "ftp"
    if "http" in leaf or "webinterface" in leaf:
        return "http"
    return None


# All device categories that support vendor-specific wordlist resolution
_VENDOR_CATEGORIES = frozenset([
    "routers",
    "switches",
    "firewalls",
    "printers",
    "nas",
    "voip",
    "ics",
    "cameras",
    "ispcpes",
    "soho_edge",
    "taps",
])


def _resolve_vendor_uri(module_name: str) -> Optional[str]:
    """Resolve a vendor-specific wordlist URI for any supported device category.

    Searches for ``{vendor}_{protocol}_defaults.txt`` then ``{vendor}_defaults.txt``
    inside the ``vendors/`` sub-directory.  Returns ``None`` if no wordlist is found
    so that the caller can fall back to inline defaults.
    """
    vendors_dir = Path(__file__).resolve().parent / "vendors"

    # Detect which category marker is in the module name
    category: Optional[str] = None
    for cat in _VENDOR_CATEGORIES:
        marker = f".modules.creds.{cat}."
        if marker in module_name:
            category = cat
            break

    if category is None:
        return None

    marker = f".modules.creds.{category}."
    suffix = module_name.split(marker, 1)[1]
    if "." not in suffix:
        return None

    vendor = suffix.split(".", 1)[0].strip().lower()
    if not vendor:
        return None

    protocol = _infer_protocol(module_name)
    if protocol is None:
        return None

    if category == "routers" and vendor == "mikrotik":
        return mikrotik_api

    candidates = (
        vendors_dir / f"{vendor}_{protocol}_defaults.txt",
        vendors_dir / f"{vendor}_defaults.txt",
    )

    for path in candidates:
        if path.exists():
            return path.resolve().as_uri()

    # For router category always fall back to generic router defaults
    if category == "routers":
        return defaults

    return None


def _resolve_router_vendor_uri(module_name: str) -> Optional[str]:
    """Legacy router-only resolver — kept for backwards compatibility."""
    return _resolve_vendor_uri(module_name)


def resolve_default_pairs(module_name: str, current_defaults: List[str]) -> List[str]:
    """Resolve default credential pairs from file-based sources for modules."""
    source_uri = _resolve_vendor_uri(module_name)
    if source_uri is None:
        return current_defaults
    return _load_entries(source_uri)


# Raw bundled sets
raw_defaults = _wordlist_uri("defaults.txt")
raw_passwords = _wordlist_uri("passwords.txt")
raw_usernames = _wordlist_uri("usernames.txt")
raw_snmp = _wordlist_uri("snmp.txt")
raw_snmpv3 = _wordlist_uri("snmpv3_defaults.txt")

# Scope-filtered sets (routers/switches/taps)
defaults = _wordlist_uri("router_scope_defaults.txt")
passwords = _wordlist_uri("router_scope_passwords.txt")
usernames = _wordlist_uri("router_scope_usernames.txt")
snmp = _wordlist_uri("router_scope_snmp.txt")
snmpv3 = _wordlist_uri("snmpv3_defaults.txt")
mikrotik_api = _wordlist_uri("mikrotik_api_defaults.txt")
