"""IEEE OUI (Organizationally Unique Identifier) lookup module.

Resolves MAC addresses to vendor names using a multi-tier strategy:

  1. **In-memory session cache** — instant, avoids repeated lookups.
  2. **Online API (preferred)** — queries free public services
     (macvendors.com → maclookup.app) for the most current data.
  3. **Local IEEE database** — parses ``data/oui.txt`` (official IEEE
     export, ~39 000 entries) as offline fallback.

The online tier is tried first because it reflects OUI assignments
in near real-time (vendors register new OUIs regularly).  If the
network is unavailable, rate-limited, or returns an error, the
lookup falls through silently to the local file.

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.2.0
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

_ONLINE_APIS: List[Dict[str, str]] = [
    {
        "name": "macvendors.com",
        "url": "https://api.macvendors.com/{}",
        "type": "text",
    },
    {
        "name": "maclookup.app",
        "url": "https://api.maclookup.app/v2/macs/{}",
        "type": "json",
        "field": "company",
    },
]

_ONLINE_TIMEOUT: float = 4.0
_ONLINE_RATE_LIMIT: float = 1.1

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
_OUI_FILE = os.path.join(_DATA_DIR, "oui.txt")

_HEX_RE = re.compile(
    r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$"
)

_VENDOR_ALIASES: Dict[str, str] = {
    "huawei technologies co.,ltd": "huawei",
    "huawei technologies co., ltd": "huawei",
    "huawei device co., ltd.": "huawei",
    "huawei device (dongguan) co., ltd.": "huawei",
    "huawei software technologies co., ltd.": "huawei",
    "tp-link technologies co.,ltd.": "tplink",
    "tp-link technologies co., ltd.": "tplink",
    "tp-link corporation limited": "tplink",
    "tp-link systems inc.": "tplink",
    "d-link corporation": "dlink",
    "d-link international": "dlink",
    "d-link systems, inc.": "dlink",
    "cisco systems, inc": "cisco",
    "cisco systems": "cisco",
    "cisco-linksys, llc": "linksys",
    "linksys": "linksys",
    "belkin international inc.": "belkin",
    "belkin international, inc.": "belkin",
    "netgear": "netgear",
    "netgear inc.,": "netgear",
    "asustek computer inc.": "asus",
    "asus computer inc.": "asus",
    "asustek computer inc.": "asus",
    "mikrotikls sia": "mikrotik",
    "mikrotik": "mikrotik",
    "routerboard.com": "mikrotik",
    "ubiquiti inc": "ubiquiti",
    "ubiquiti networks inc.": "ubiquiti",
    "ubiquiti networks, inc.": "ubiquiti",
    "zte corporation": "zte",
    "zte": "zte",
    "tenda technology co.,ltd.shenzhen": "tenda",
    "tenda technology co., ltd.": "tenda",
    "shenzhen tenda technology co., ltd.": "tenda",
    "fortinet, inc.": "fortinet",
    "fortinet inc.": "fortinet",
    "arris group, inc.": "arris",
    "commscope, inc.": "arris",
    "arris": "arris",
    "trendnet, inc.": "trendnet",
    "trendnet": "trendnet",
    "draytek corp.": "draytek",
    "vigor": "draytek",
    "juniper networks": "juniper",
    "sonicwall": "sonicwall",
    "dell sonicwall": "sonicwall",
    "ruckus networks": "ruckus",
    "ruckus wireless": "ruckus",
    "brocade communications systems llc": "ruckus",
    "sagemcom broadband sas": "sagem",
    "sagem communication": "sagem",
    "fiberhome telecommunication technologies co.,ltd": "fiberhome",
    "intelbras s/a": "intelbras",
    "intelbras s.a": "intelbras",
    "xiaomi communications co ltd": "xiaomi",
    "beijing xiaomi mobile software co., ltd": "xiaomi",
    "totolink": "totolink",
    "wavlink": "wavlink",
    "shenzhen wavlink technology co.,ltd": "wavlink",
}

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_local_cache: Dict[str, str] = {}
_local_cache_loaded: bool = False
_local_cache_mtime: float = 0.0

_session_cache: Dict[str, str] = {}
_session_cache_lock = threading.Lock()

_last_api_call: float = 0.0
_api_call_lock = threading.Lock()

_online_enabled: bool = True
_online_failures: int = 0
_MAX_CONSECUTIVE_FAILURES: int = 5


# ===================================================================
# Public API
# ===================================================================

def lookup(mac: str, *, online: bool = True) -> str:
    """Look up vendor for a MAC address (normalized to EmbedXPL convention).

    Strategy: session cache → online APIs → local oui.txt.

    Args:
        mac: MAC address in any common format
             (``AA:BB:CC:DD:EE:FF``, ``AA-BB-CC-DD-EE-FF``, ``AABBCCDDEEFF``).
        online: Whether to try online APIs. Set ``False`` to force
                offline-only lookup.

    Returns:
        Normalized vendor name (e.g. ``huawei``, ``tplink``), or
        empty string if not found anywhere.
    """
    prefix = _mac_to_prefix(mac)
    if not prefix:
        return ""

    raw = _lookup_raw_cascading(prefix, online=online)
    if not raw:
        return ""
    return normalize_vendor(raw)


def lookup_raw(mac: str, *, online: bool = True) -> str:
    """Look up the raw (non-normalized) vendor name for a MAC address.

    Args:
        mac: MAC address in any common format.
        online: Whether to try online APIs.

    Returns:
        Raw vendor name (e.g. ``HUAWEI TECHNOLOGIES CO.,LTD``),
        or empty string if not found.
    """
    prefix = _mac_to_prefix(mac)
    if not prefix:
        return ""
    return _lookup_raw_cascading(prefix, online=online)


def normalize_vendor(vendor_raw: str) -> str:
    """Normalize a raw vendor string to EmbedXPL folder convention.

    Args:
        vendor_raw: Raw vendor name (e.g. ``HUAWEI TECHNOLOGIES CO.,LTD``).

    Returns:
        Canonical short name (e.g. ``huawei``).
    """
    v_lower = vendor_raw.strip().lower()

    for alias, canonical in _VENDOR_ALIASES.items():
        if alias in v_lower:
            return canonical

    known_brands = [
        "dlink", "tplink", "netgear", "asus", "linksys", "cisco",
        "huawei", "zte", "mikrotik", "ubiquiti", "fortinet",
        "tenda", "arris", "comtrend", "trendnet", "belkin",
        "draytek", "totolink", "wavlink", "xiaomi", "intelbras",
        "juniper", "sonicwall", "fiberhome", "ruckus", "sagem",
    ]
    for brand in known_brands:
        if brand in v_lower:
            return brand

    first_word = v_lower.split()[0] if v_lower else ""
    return re.sub(r"[^a-z0-9]", "", first_word)


def update_oui_file(force: bool = False) -> Tuple[bool, str]:
    """Download the latest IEEE OUI database.

    Args:
        force: Download even if the file already exists and is recent.

    Returns:
        ``(success, message)`` tuple.
    """
    _ensure_data_dir()

    if not force and os.path.exists(_OUI_FILE):
        age_days = (time.time() - os.path.getmtime(_OUI_FILE)) / 86400
        if age_days < 30:
            return (True, "OUI file is up-to-date ({:.0f} days old)".format(age_days))

    try:
        logger.info("Downloading IEEE OUI database from %s", _IEEE_OUI_URL)
        tmp_path = _OUI_FILE + ".tmp"
        urllib.request.urlretrieve(_IEEE_OUI_URL, tmp_path)

        with open(tmp_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        count = content.count("(hex)")
        if count < 1000:
            os.remove(tmp_path)
            return (False, "Downloaded file seems corrupted ({} entries)".format(count))

        if os.path.exists(_OUI_FILE):
            os.replace(tmp_path, _OUI_FILE)
        else:
            os.rename(tmp_path, _OUI_FILE)

        global _local_cache_loaded
        _local_cache_loaded = False

        return (True, "OUI database updated: {} entries".format(count))

    except Exception as exc:
        msg = "Failed to download OUI database: {}".format(exc)
        logger.warning(msg)
        return (False, msg)


def get_stats() -> Dict[str, object]:
    """Return stats about the OUI subsystem."""
    _load_local_cache()
    return {
        "local_entries": len(_local_cache),
        "local_file_exists": os.path.exists(_OUI_FILE),
        "session_cache_size": len(_session_cache),
        "online_enabled": _online_enabled,
        "online_failures": _online_failures,
    }


def clear_session_cache() -> None:
    """Clear the in-memory session cache."""
    global _session_cache, _online_enabled, _online_failures
    with _session_cache_lock:
        _session_cache.clear()
    _online_enabled = True
    _online_failures = 0


# ===================================================================
# Internal: cascading lookup
# ===================================================================

_NEGATIVE_SENTINEL = "\x00__NOT_FOUND__"


def _lookup_raw_cascading(prefix: str, *, online: bool = True) -> str:
    """Try session cache → online APIs → local file.

    Caches both positive and negative results so that MACs not found
    in any source don't trigger repeated slow lookups.
    """
    with _session_cache_lock:
        cached = _session_cache.get(prefix)
        if cached is not None:
            return "" if cached == _NEGATIVE_SENTINEL else cached

    if online and _online_enabled:
        result = _lookup_online(prefix)
        if result:
            with _session_cache_lock:
                _session_cache[prefix] = result
            return result

    result = _lookup_local(prefix)
    with _session_cache_lock:
        _session_cache[prefix] = result if result else _NEGATIVE_SENTINEL
    return result


# ===================================================================
# Internal: online lookup
# ===================================================================

def _lookup_online(prefix: str) -> str:
    """Query public OUI APIs (macvendors.com → maclookup.app).

    Respects rate limiting and disables online lookups after
    consecutive failures to avoid hammering broken services.
    """
    global _last_api_call, _online_enabled, _online_failures

    with _api_call_lock:
        elapsed = time.time() - _last_api_call
        if elapsed < _ONLINE_RATE_LIMIT:
            time.sleep(_ONLINE_RATE_LIMIT - elapsed)

    mac_query = prefix.replace(":", "-")

    for api in _ONLINE_APIS:
        url = api["url"].format(mac_query)
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "EmbedXPL-Forge/0.2.0"},
            )
            with urllib.request.urlopen(req, timeout=_ONLINE_TIMEOUT) as resp:
                with _api_call_lock:
                    _last_api_call = time.time()

                status = resp.getcode()
                if status != 200:
                    continue

                body = resp.read().decode("utf-8", errors="replace").strip()

                if api.get("type") == "json":
                    data = json.loads(body)
                    vendor = data.get(api.get("field", "company"), "")
                else:
                    vendor = body

                if vendor and len(vendor) > 1 and "not found" not in vendor.lower():
                    _online_failures = 0
                    logger.debug(
                        "OUI online [%s]: %s -> %s", api["name"], prefix, vendor
                    )
                    return vendor

        except urllib.error.HTTPError as e:
            if e.code == 404:
                with _api_call_lock:
                    _last_api_call = time.time()
                continue
            if e.code == 429:
                logger.debug("OUI API %s rate-limited", api["name"])
                with _api_call_lock:
                    _last_api_call = time.time()
                time.sleep(2.0)
                continue
            logger.debug("OUI API %s HTTP %d", api["name"], e.code)

        except Exception as exc:
            logger.debug("OUI API %s error: %s", api["name"], exc)

        with _api_call_lock:
            _last_api_call = time.time()

    _online_failures += 1
    if _online_failures >= _MAX_CONSECUTIVE_FAILURES:
        _online_enabled = False
        logger.warning(
            "OUI online disabled after %d consecutive failures — "
            "using local fallback only. Call clear_session_cache() to re-enable.",
            _online_failures,
        )

    return ""


# ===================================================================
# Internal: local file lookup
# ===================================================================

def _lookup_local(prefix: str) -> str:
    """Look up a prefix in the local IEEE oui.txt file."""
    _load_local_cache()
    return _local_cache.get(prefix, "")


def _load_local_cache() -> None:
    """Parse the oui.txt file into the in-memory local cache."""
    global _local_cache, _local_cache_loaded, _local_cache_mtime

    if not os.path.exists(_OUI_FILE):
        logger.warning("OUI file not found at %s -- run update_oui_file()", _OUI_FILE)
        _local_cache_loaded = True
        return

    file_mtime = os.path.getmtime(_OUI_FILE)
    if _local_cache_loaded and file_mtime == _local_cache_mtime:
        return

    new_cache: Dict[str, str] = {}

    try:
        with open(_OUI_FILE, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = _HEX_RE.match(line.strip())
                if m:
                    prefix = m.group(1).upper().replace("-", ":")
                    vendor_raw = m.group(2).strip()
                    new_cache[prefix] = vendor_raw
    except Exception as exc:
        logger.error("Failed to parse OUI file: %s", exc)
        _local_cache_loaded = True
        return

    _local_cache = new_cache
    _local_cache_mtime = file_mtime
    _local_cache_loaded = True
    logger.debug("OUI local cache loaded: %d entries", len(_local_cache))


# ===================================================================
# Internal: helpers
# ===================================================================

def _ensure_data_dir() -> None:
    """Create data directory if it doesn't exist."""
    os.makedirs(_DATA_DIR, exist_ok=True)


def _mac_to_prefix(mac: str) -> str:
    """Extract the 3-byte OUI prefix from a MAC address.

    Args:
        mac: MAC in any format (colon, dash, dot, or raw hex).

    Returns:
        Normalized prefix ``"AA:BB:CC"`` or empty string on failure.
    """
    mac_clean = mac.upper().replace("-", ":").replace(".", ":")
    parts = mac_clean.split(":")

    if len(parts) == 1 and len(mac_clean) >= 6:
        raw = mac_clean.replace(":", "")
        parts = [raw[i:i + 2] for i in range(0, min(len(raw), 12), 2)]

    if len(parts) >= 3:
        return ":".join(parts[:3])
    return ""
