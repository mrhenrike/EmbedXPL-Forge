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


def _resolve_router_vendor_uri(module_name: str) -> Optional[str]:
    marker = ".modules.creds.routers."
    if marker not in module_name:
        return None

    suffix = module_name.split(marker, 1)[1]
    if "." not in suffix:
        return None

    vendor = suffix.split(".", 1)[0].strip().lower()
    if not vendor:
        return None

    protocol = _infer_protocol(module_name)
    if protocol is None:
        return None

    if vendor == "mikrotik":
        return mikrotik_api

    # Vendor-specific wordlist filenames (optional)
    candidates = (
        f"{vendor}_{protocol}_defaults.txt",
        f"{vendor}_defaults.txt",
    )

    for filename in candidates:
        local_path = Path(__file__).resolve().parent / filename
        if local_path.exists():
            return _wordlist_uri(filename)

    # Fallback for all router vendor protocol modules:
    # always use file-based defaults instead of inline script literals.
    return defaults


def resolve_default_pairs(module_name: str, current_defaults: List[str]) -> List[str]:
    """Resolve default credential pairs from file-based sources for modules."""
    source_uri = _resolve_router_vendor_uri(module_name)
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
