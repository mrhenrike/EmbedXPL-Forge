"""Default credentials compiler.

Parses SecLists Default-Credentials CSVs and Router per-vendor files and
produces two JSON databases:
  - embedxpl/data/default_creds.json      (general devices)
  - embedxpl/data/ics_default_creds.json  (SCADA/ICS/OT devices)

Also writes per-vendor wordlist .txt files into
embedxpl/resources/wordlists/vendors/ for use by cred modules.

Usage:
    python scripts/compile_default_creds.py

Run from the EmbedXPL-Forge root directory.

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 1.0.0
"""

from __future__ import annotations

import csv
import json
import logging
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent

SECLISTS_CREDS = (
    REPO_ROOT.parent.parent
    / "Wordlists"
    / "SecLists"
    / "Passwords"
    / "Default-Credentials"
)

OUT_DIR = REPO_ROOT / "embedxpl" / "data"
WORDLISTS_DIR = REPO_ROOT / "embedxpl" / "resources" / "wordlists" / "vendors"

OUT_GENERAL = OUT_DIR / "default_creds.json"
OUT_ICS = OUT_DIR / "ics_default_creds.json"

# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------
_BLANK = {"<blank>", "(blank)", "<none>", "(none)", "", "<n/a>"}
_NA = {"<n/a>", "n/a", "none", "(none)"}

# Map common vendor name variants → canonical name used as JSON key
VENDOR_ALIASES: dict[str, str] = {
    "2wire, inc.": "2wire",
    "2wire inc": "2wire",
    "3com": "3com",
    "accton technology": "accton",
    "actiontec electronics": "actiontec",
    "actiontec": "actiontec",
    "adtran": "adtran",
    "airties": "airties",
    "alcatel-lucent": "alcatel",
    "alcatel": "alcatel",
    "allied telesyn": "allied_telesyn",
    "allied telesis": "allied_telesyn",
    "allnet": "allnet",
    "alteon": "alteon",
    "ambit": "ambit",
    "american dynamics": "american_dynamics",
    "apc": "apc",
    "apple": "apple",
    "arecont vision": "arecont",
    "arris": "arris",
    "asus": "asus",
    "asustek": "asus",
    "avaya": "avaya",
    "avigilon": "avigilon",
    "axis communications": "axis",
    "axis": "axis",
    "barracuda networks": "barracuda",
    "barracuda": "barracuda",
    "bay networks": "bay_networks",
    "belkin": "belkin",
    "billion": "billion",
    "bintec": "bintec",
    "bintec elmeg": "bintec",
    "blue coat": "blue_coat",
    "blue coat systems": "blue_coat",
    "bosch": "bosch",
    "brickcom": "brickcom",
    "brocade": "brocade",
    "brocade communications": "brocade",
    "brother": "brother",
    "buffalo": "buffalo",
    "cabletron": "cabletron",
    "canon": "canon",
    "check point": "checkpoint",
    "checkpoint": "checkpoint",
    "cisco": "cisco",
    "cisco systems": "cisco",
    "cnet": "cnet",
    "comtrend": "comtrend",
    "d-link": "dlink",
    "d-link systems": "dlink",
    "dahua": "dahua",
    "dahua technology": "dahua",
    "dell": "dell",
    "draytek": "draytek",
    "dvtel": "dvtel",
    "dynacolor": "dynacolor",
    "edimax": "edimax",
    "edimax technology": "edimax",
    "enterasys": "enterasys",
    "enterasys networks": "enterasys",
    "everfocus": "everfocus",
    "extreme networks": "extreme_networks",
    "f5": "f5",
    "f5 networks": "f5",
    "fiberhome": "fiberhome",
    "flir systems": "flir",
    "flir": "flir",
    "fortinet": "fortinet",
    "foscam": "foscam",
    "foundry networks": "foundry",
    "geovision": "geovision",
    "grandstream": "grandstream",
    "grandstream networks": "grandstream",
    "hikvision": "hikvision",
    "hikvision digital technology": "hikvision",
    "honeywell": "honeywell",
    "hp": "hp",
    "hewlett-packard": "hp",
    "huawei": "huawei",
    "ibm": "ibm",
    "inteno": "inteno",
    "iomega": "iomega",
    "iqinvision": "iqinvision",
    "ironport": "ironport",
    "juniper": "juniper",
    "juniper networks": "juniper",
    "jvc": "jvc",
    "kyocera": "kyocera",
    "kyocera mita": "kyocera",
    "lancom": "lancom",
    "lancom systems": "lancom",
    "lantronix": "lantronix",
    "lenovo": "lenovo",
    "lg": "lg",
    "lexmark": "lexmark",
    "linksys": "linksys",
    "logitech": "logitech",
    "lucent": "lucent",
    "march networks": "march_networks",
    "mcafee": "mcafee",
    "mikrotik": "mikrotik",
    "milan": "milan",
    "mitel": "mitel",
    "mobotix": "mobotix",
    "motorola": "motorola",
    "moxa": "moxa",
    "netcomm": "netcomm",
    "netcomm wireless": "netcomm",
    "netgear": "netgear",
    "netopia": "netopia",
    "netscreen": "netscreen",
    "nokia": "nokia",
    "nortel": "nortel",
    "nortel networks": "nortel",
    "oki": "oki",
    "omron": "omron",
    "panasonic": "panasonic",
    "pelco": "pelco",
    "phoenix contact": "phoenix_contact",
    "planet": "planet",
    "planet technology": "planet",
    "polycom": "polycom",
    "proxim": "proxim",
    "qnap": "qnap",
    "qnap systems": "qnap",
    "radware": "radware",
    "ricoh": "ricoh",
    "ricoh company": "ricoh",
    "rockwell automation": "rockwell",
    "rockwell": "rockwell",
    "sagem": "sagem",
    "samsung": "samsung",
    "samsung electronics": "samsung",
    "sanyo": "sanyo",
    "schneider electric": "schneider",
    "apc by schneider electric": "apc",
    "apc": "apc",
    "senao": "senao",
    "seagate": "seagate",
    "sharp": "sharp",
    "siemens": "siemens",
    "siemens ag": "siemens",
    "sitecom": "sitecom",
    "smc": "smc",
    "smc networks": "smc",
    "sonicwall": "sonicwall",
    "sonic wall": "sonicwall",
    "sony": "sony",
    "speco technologies": "speco",
    "speco": "speco",
    "speedstream": "speedstream",
    "synology": "synology",
    "tandberg": "tandberg",
    "cisco tandberg": "tandberg",
    "technicolor": "technicolor",
    "tenda": "tenda",
    "thomson": "thomson",
    "toshiba": "toshiba",
    "tp-link": "tplink",
    "tp link": "tplink",
    "trendnet": "trendnet",
    "ubiquiti": "ubiquiti",
    "ubiquiti networks": "ubiquiti",
    "verifone": "verifone",
    "videoiq": "videoiq",
    "vivotek": "vivotek",
    "vodafone": "vodafone",
    "watchguard": "watchguard",
    "watchguard technologies": "watchguard",
    "western digital": "wd",
    "wodsee": "wodsee",
    "xerox": "xerox",
    "xylan": "xylan",
    "xyplex": "xyplex",
    "zebra": "zebra",
    "zebra technologies": "zebra",
    "zte": "zte",
    "zyxel": "zyxel",
    "zyxel communications": "zyxel",
    "allied": "allied_telesyn",
    "nrg": "ricoh",
    "brother industries": "brother",
    "konica minolta": "konica_minolta",
    "konicaminolta": "konica_minolta",
    "lexmark international": "lexmark",
    "iomega/lenovo": "iomega",
    "lenovo emc": "iomega",
    "buffalo technology": "buffalo",
    "stardot technologies": "stardot",
    "stardot": "stardot",
    "sentry360": "sentry360",
    "march": "march_networks",
    "cbc ganz": "cbc_ganz",
    "ganz": "cbc_ganz",
    "everfocus electronics": "everfocus",
    "arecont": "arecont",
    "iqeye": "iqinvision",
    "sangoma": "sangoma",
    "sangoma technologies": "sangoma",
    "audiocodes": "audiocodes",
    "audio codes": "audiocodes",
    "abb": "abb",
    "abb ltd": "abb",
    "allen-bradley": "rockwell",
    "allen bradley": "rockwell",
    "b&b electronics": "bb_electronics",
    "phoenix contact": "phoenix_contact",
    "honeywell process solutions": "honeywell",
    "moxa technologies": "moxa",
}

# Device type inference from vendor/comments context
DEVICE_TYPE_HINTS: dict[str, str] = {
    "router": "router",
    "switch": "switch",
    "camera": "camera",
    "dvr": "dvr",
    "nvr": "nvr",
    "printer": "printer",
    "nas": "nas",
    "voip": "voip",
    "pbx": "voip",
    "firewall": "firewall",
    "utm": "firewall",
    "vpn": "firewall",
    "access point": "wireless",
    "wireless": "wireless",
    "plc": "ics",
    "scada": "ics",
    "hmi": "ics",
    "modbus": "ics",
    "ups": "ics",
    "controller": "ics",
    "gateway": "gateway",
    "modem": "modem",
    "cpe": "cpe",
    "olt": "olt",
    "onu": "cpe",
    "pon": "cpe",
}

VENDOR_DEVICE_TYPE: dict[str, str] = {
    "hikvision": "camera",
    "dahua": "camera",
    "axis": "camera",
    "bosch": "camera",
    "samsung": "camera",
    "sony": "camera",
    "panasonic": "camera",
    "pelco": "camera",
    "flir": "camera",
    "avigilon": "camera",
    "mobotix": "camera",
    "vivotek": "camera",
    "foscam": "camera",
    "geovision": "camera",
    "march_networks": "camera",
    "american_dynamics": "camera",
    "arecont": "camera",
    "cbc_ganz": "camera",
    "iqinvision": "camera",
    "everfocus": "camera",
    "dynacolor": "camera",
    "dvtel": "camera",
    "acti": "camera",
    "brickcom": "camera",
    "speco": "camera",
    "stardot": "camera",
    "jvc": "camera",
    "videoiq": "camera",
    "sentry360": "camera",
    "wodsee": "camera",
    "hp": "printer",
    "xerox": "printer",
    "ricoh": "printer",
    "brother": "printer",
    "kyocera": "printer",
    "canon": "printer",
    "konica_minolta": "printer",
    "lexmark": "printer",
    "oki": "printer",
    "sharp": "printer",
    "toshiba": "printer",
    "qnap": "nas",
    "synology": "nas",
    "wd": "nas",
    "seagate": "nas",
    "iomega": "nas",
    "polycom": "voip",
    "tandberg": "voip",
    "mitel": "voip",
    "avaya": "voip",
    "grandstream": "voip",
    "sangoma": "voip",
    "audiocodes": "voip",
    "siemens": "switch",
    "extreme_networks": "switch",
    "brocade": "switch",
    "nortel": "switch",
    "cabletron": "switch",
    "enterasys": "switch",
    "alteon": "switch",
    "foundry": "switch",
    "planet": "switch",
    "smc": "switch",
    "accton": "switch",
    "allied_telesyn": "switch",
    "sonicwall": "firewall",
    "watchguard": "firewall",
    "barracuda": "firewall",
    "blue_coat": "firewall",
    "checkpoint": "firewall",
    "fortinet": "firewall",
    "abb": "ics",
    "rockwell": "ics",
    "schneider": "ics",
    "apc": "ics",
    "phoenix_contact": "ics",
    "moxa": "ics",
    "omron": "ics",
    "mikrotik": "router",
    "cisco": "router",
    "juniper": "router",
    "ubiquiti": "wireless",
    "senao": "wireless",
}


def normalise_vendor(raw: str) -> str:
    """Normalise a raw vendor string to a canonical key."""
    key = raw.strip().lower()
    key = re.sub(r"[,\.\(\)\/].*$", "", key).strip()
    return VENDOR_ALIASES.get(key, re.sub(r"\s+", "_", key))


def clean_value(val: str) -> str:
    """Return cleaned credential value; empty string for blank/N/A."""
    v = val.strip()
    if v.lower() in _BLANK:
        return ""
    return v


def infer_device_type(vendor: str, notes: str) -> str:
    """Infer device type from vendor canonical name and notes text."""
    if vendor in VENDOR_DEVICE_TYPE:
        return VENDOR_DEVICE_TYPE[vendor]
    notes_lower = notes.lower()
    for keyword, dtype in DEVICE_TYPE_HINTS.items():
        if keyword in notes_lower:
            return dtype
    return "embedded"


# ---------------------------------------------------------------------------
# Parser: default-passwords.csv
# ---------------------------------------------------------------------------

def parse_main_csv(path: Path) -> dict[str, list[dict[str, Any]]]:
    """Parse SecLists default-passwords.csv into vendor-keyed dict."""
    db: dict[str, list[dict[str, Any]]] = defaultdict(list)

    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            raw_vendor = row.get("Vendor", "").strip()
            if not raw_vendor:
                continue

            username = clean_value(row.get("Username", ""))
            password = clean_value(row.get("Password", ""))
            notes = row.get("Comments", "").strip()

            # Skip obviously non-credential rows
            if username.lower() in _NA and password.lower() in _NA:
                continue

            vendor = normalise_vendor(raw_vendor)
            dtype = infer_device_type(vendor, notes)

            entry: dict[str, Any] = {
                "user": username,
                "pass": password,
                "protocol": "multi",
                "device_type": dtype,
                "notes": notes,
            }
            db[vendor].append(entry)

    return dict(db)


# ---------------------------------------------------------------------------
# Parser: scada-pass.csv
# ---------------------------------------------------------------------------

def parse_scada_csv(path: Path) -> dict[str, list[dict[str, Any]]]:
    """Parse SecLists scada-pass.csv into vendor-keyed dict."""
    db: dict[str, list[dict[str, Any]]] = defaultdict(list)

    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        all_lines = fh.readlines()

    # Skip comment lines and blank/whitespace-only lines (including ",,,,,," rows)
    lines = [
        l for l in all_lines
        if not l.startswith("#") and l.strip().strip(",")
    ]

    reader = csv.DictReader(lines)
    for row in reader:
        raw_vendor = row.get("Vendor", "").strip()
        device = row.get("Device", "").strip()
        raw_cred = row.get("Default password", "").strip()
        port_raw = row.get("Port", "").strip()
        device_type = row.get("Device type", "").strip().lower() or "ics"
        protocol = row.get("Protocol", "").strip().lower() or "multi"
        source = row.get("Source", "").strip()

        if not raw_vendor or not raw_cred:
            continue

        vendor = normalise_vendor(raw_vendor)

        # Raw cred may be "user:pass" or "pass" or "user:pass, user2:pass2"
        pairs = [p.strip() for p in raw_cred.split(",")]
        for pair in pairs:
            if ":" in pair:
                user, pwd = pair.split(":", 1)
            else:
                user, pwd = "", pair

            entry: dict[str, Any] = {
                "user": clean_value(user),
                "pass": clean_value(pwd),
                "protocol": protocol,
                "device": device,
                "device_type": device_type or "ics",
                "port": port_raw,
                "source": source,
            }
            db[vendor].append(entry)

    return dict(db)


# ---------------------------------------------------------------------------
# Parser: Routers/ per-vendor text files
# ---------------------------------------------------------------------------

def parse_router_files(routers_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """Parse SecLists Routers/ paired *_default-users.txt/*_default-passwords.txt."""
    db: dict[str, list[dict[str, Any]]] = defaultdict(list)

    # Collect vendor stems from user files
    stems: set[str] = set()
    for f in routers_dir.glob("*_default-users.txt"):
        stem = f.name.replace("_default-users.txt", "")
        if stem != "0ALL-USERNAMES-AND-PASSWORDS":
            stems.add(stem)

    for stem in sorted(stems):
        users_file = routers_dir / f"{stem}_default-users.txt"
        pass_file = routers_dir / f"{stem}_default-passwords.txt"

        if not users_file.exists() or not pass_file.exists():
            continue

        users = [
            u.strip() for u in users_file.read_text(encoding="utf-8", errors="replace").splitlines()
            if u.strip()
        ]
        passwords = [
            p.strip() for p in pass_file.read_text(encoding="utf-8", errors="replace").splitlines()
            if p.strip()
        ]

        if not users or not passwords:
            continue

        vendor = normalise_vendor(stem.replace("-", " "))
        dtype = infer_device_type(vendor, "router")

        # Build cross-product of users × passwords (capped to reasonable size)
        seen: set[tuple[str, str]] = set()
        for u in users[:20]:
            for p in passwords[:30]:
                if (u, p) not in seen:
                    seen.add((u, p))
                    entry: dict[str, Any] = {
                        "user": u,
                        "pass": p,
                        "protocol": "multi",
                        "device_type": dtype,
                        "notes": f"Router default — {stem}",
                    }
                    db[vendor].append(entry)

    return dict(db)


# ---------------------------------------------------------------------------
# Extra known credentials not in SecLists (well-documented public sources)
# ---------------------------------------------------------------------------

EXTRA_CREDS: dict[str, list[dict[str, Any]]] = {
    "dahua": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "Factory default"},
        {"user": "888888", "pass": "888888", "protocol": "http", "device_type": "camera", "notes": "Numeric admin account"},
        {"user": "default", "pass": "tluafed", "protocol": "http", "device_type": "camera", "notes": "Hidden service account"},
        {"user": "root", "pass": "", "protocol": "telnet", "device_type": "camera", "notes": "Telnet root (no password)"},
        {"user": "admin", "pass": "", "protocol": "rtsp", "device_type": "camera", "notes": "RTSP stream"},
    ],
    "hikvision": [
        {"user": "admin", "pass": "12345", "protocol": "http", "device_type": "camera", "notes": "Pre-2016 factory default"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "Older firmware"},
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "camera", "notes": "OEM blank variant"},
        {"user": "root", "pass": "12345", "protocol": "ssh", "device_type": "camera", "notes": "SSH access"},
    ],
    "axis": [
        {"user": "root", "pass": "pass", "protocol": "http", "device_type": "camera", "notes": "Factory default (pre-2014)"},
        {"user": "root", "pass": "root", "protocol": "http", "device_type": "camera", "notes": "Some models"},
        {"user": "root", "pass": "", "protocol": "http", "device_type": "camera", "notes": "Blank password variant"},
    ],
    "foscam": [
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "camera", "notes": "Factory default — blank password"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "Alternative"},
        {"user": "user", "pass": "user", "protocol": "http", "device_type": "camera", "notes": "User-level account"},
    ],
    "vivotek": [
        {"user": "root", "pass": "", "protocol": "http", "device_type": "camera", "notes": "No password factory default"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "Alternative"},
        {"user": "root", "pass": "", "protocol": "telnet", "device_type": "camera", "notes": "Telnet access"},
    ],
    "pelco": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "Pelco Sarix / VideoXpert"},
        {"user": "root", "pass": "admin", "protocol": "ssh", "device_type": "camera", "notes": "SSH service access"},
        {"user": "viewer", "pass": "viewer", "protocol": "http", "device_type": "camera", "notes": "Read-only account"},
    ],
    "flir": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "FLIR camera default"},
        {"user": "supervisor", "pass": "supervisor", "protocol": "http", "device_type": "camera", "notes": "Nexus VMS"},
        {"user": "service", "pass": "service", "protocol": "ssh", "device_type": "camera", "notes": "Service account"},
    ],
    "bosch": [
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "camera", "notes": "Bosch Configuration Manager default"},
        {"user": "service", "pass": "service", "protocol": "http", "device_type": "camera", "notes": "Service account"},
        {"user": "user", "pass": "user", "protocol": "http", "device_type": "camera", "notes": "Standard user"},
    ],
    "mobotix": [
        {"user": "admin", "pass": "meinsm", "protocol": "http", "device_type": "camera", "notes": "Official Mobotix default"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "Rare alternative"},
    ],
    "sony": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "SNC series IP cameras"},
        {"user": "admin", "pass": "Admin", "protocol": "http", "device_type": "camera", "notes": "Case-sensitive variant"},
    ],
    "march_networks": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "March Networks Command Centre"},
    ],
    "everfocus": [
        {"user": "admin", "pass": "11111111", "protocol": "http", "device_type": "camera", "notes": "EDVR/ECOR series"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "Web interface"},
        {"user": "user", "pass": "11111111", "protocol": "http", "device_type": "camera", "notes": "User-level"},
    ],
    "dynacolor": [
        {"user": "admin", "pass": "1234", "protocol": "http", "device_type": "camera", "notes": "OEM firmware"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "Alternative"},
    ],
    "dvtel": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "Latitude VMS"},
        {"user": "Administrator", "pass": "Administrator", "protocol": "http", "device_type": "camera", "notes": ""},
    ],
    "cbc_ganz": [
        {"user": "admin", "pass": "11111111", "protocol": "http", "device_type": "camera", "notes": "DIGIMASTER DVR"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "General cameras"},
    ],
    "arecont": [
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "camera", "notes": "No default password set"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "Some models"},
    ],
    "iqinvision": [
        {"user": "root", "pass": "system", "protocol": "http", "device_type": "camera", "notes": "IQeye firmware docs"},
        {"user": "root", "pass": "system", "protocol": "telnet", "device_type": "camera", "notes": "Telnet access"},
    ],
    "wodsee": [
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "camera", "notes": "No default password"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "Generic OEM"},
    ],
    "american_dynamics": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "Illustra cameras"},
        {"user": "admin", "pass": "1234", "protocol": "http", "device_type": "camera", "notes": "Alternative"},
    ],
    "speco": [
        {"user": "admin", "pass": "1234", "protocol": "http", "device_type": "camera", "notes": "Speco OEM firmware"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "Alternative"},
    ],
    "panasonic": [
        {"user": "admin", "pass": "12345", "protocol": "http", "device_type": "camera", "notes": "WV-series IP cameras"},
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "camera", "notes": "BL-C series (blank)"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "printer", "notes": "KX series printers"},
    ],
    "stardot": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "StarDot NetCam SC"},
    ],
    "sentry360": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "Mini domes"},
    ],
    "videoiq": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "Avigilon/Bosch acquisition"},
    ],
    "jvc": [
        {"user": "admin", "pass": "jvc", "protocol": "http", "device_type": "camera", "notes": "JVC ProVideo default"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "camera", "notes": "Alternative"},
    ],
    # --- Printers ---
    "hp": [
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "printer", "notes": "HP Embedded Web Server"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "printer", "notes": "Some models"},
        {"user": "", "pass": "", "protocol": "telnet", "device_type": "printer", "notes": "HP JetDirect"},
    ],
    "xerox": [
        {"user": "admin", "pass": "1111", "protocol": "http", "device_type": "printer", "notes": "Xerox CentreWare default"},
        {"user": "11111", "pass": "x-admin", "protocol": "http", "device_type": "printer", "notes": "Legacy WorkCentre"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "printer", "notes": "Alternative"},
    ],
    "ricoh": [
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "printer", "notes": "Aficio series (no password)"},
        {"user": "admin", "pass": "password", "protocol": "http", "device_type": "printer", "notes": "Some models"},
        {"user": "supervisor", "pass": "supervisor", "protocol": "http", "device_type": "printer", "notes": "Supervisor account"},
    ],
    "brother": [
        {"user": "admin", "pass": "access", "protocol": "http", "device_type": "printer", "notes": "Brother EWS default"},
        {"user": "", "pass": "access", "protocol": "http", "device_type": "printer", "notes": "No username variant"},
    ],
    "kyocera": [
        {"user": "Admin", "pass": "Admin", "protocol": "http", "device_type": "printer", "notes": "Kyocera Command Center"},
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "printer", "notes": "Some firmware versions"},
    ],
    "canon": [
        {"user": "7654321", "pass": "7654321", "protocol": "http", "device_type": "printer", "notes": "iR ADVANCE EWS default"},
        {"user": "", "pass": "", "protocol": "http", "device_type": "printer", "notes": "Older imageRUNNER"},
        {"user": "ADMIN", "pass": "canon", "protocol": "http", "device_type": "printer", "notes": "Some models"},
    ],
    "konica_minolta": [
        {"user": "Admin", "pass": "", "protocol": "http", "device_type": "printer", "notes": "bizhub administrator"},
        {"user": "User", "pass": "", "protocol": "http", "device_type": "printer", "notes": "bizhub user level"},
        {"user": "admin", "pass": "12345678", "protocol": "http", "device_type": "printer", "notes": "Some bizhub models"},
    ],
    "lexmark": [
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "printer", "notes": "Lexmark EWS — no password"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "printer", "notes": "Some firmware"},
    ],
    "oki": [
        {"user": "admin", "pass": "aaaaaa", "protocol": "http", "device_type": "printer", "notes": "OKI EWS 6-char default"},
        {"user": "root", "pass": "aaaaaa", "protocol": "http", "device_type": "printer", "notes": "Root account"},
    ],
    "sharp": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "printer", "notes": "Sharp MX series MFP"},
        {"user": "Admin", "pass": "Admin", "protocol": "http", "device_type": "printer", "notes": "Case-sensitive variant"},
    ],
    "toshiba": [
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "printer", "notes": "e-STUDIO TopAccess portal"},
        {"user": "admin00", "pass": "", "protocol": "http", "device_type": "printer", "notes": "Field service account"},
        {"user": "admin", "pass": "123456", "protocol": "http", "device_type": "printer", "notes": "Some models"},
    ],
    # --- NAS / Storage ---
    "qnap": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "nas", "notes": "Factory default — QLocker/DeadBolt targeted"},
        {"user": "admin", "pass": "admin", "protocol": "ssh", "device_type": "nas", "notes": "SSH access"},
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "nas", "notes": "Some firmware"},
    ],
    "synology": [
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "nas", "notes": "DSM default — forces setup"},
        {"user": "admin", "pass": "admin", "protocol": "ssh", "device_type": "nas", "notes": "Older firmware"},
        {"user": "root", "pass": "", "protocol": "ssh", "device_type": "nas", "notes": "Root SSH (disabled by default in newer DSM)"},
    ],
    "wd": [
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "nas", "notes": "WD MyCloud — no password"},
        {"user": "mydlinkBRionyg", "pass": "abc12345cba", "protocol": "http", "device_type": "nas", "notes": "CVE-2018-18472 hardcoded backdoor"},
    ],
    "seagate": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "nas", "notes": "BlackArmor NAS default"},
        {"user": "root", "pass": "", "protocol": "ssh", "device_type": "nas", "notes": "SSH root"},
    ],
    "iomega": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "nas", "notes": "StorCenter EZ Manager"},
        {"user": "guest", "pass": "", "protocol": "http", "device_type": "nas", "notes": "Guest account"},
    ],
    # --- VoIP / Video Conferencing ---
    "polycom": [
        {"user": "Polycom", "pass": "456", "protocol": "http", "device_type": "voip", "notes": "SoundPoint/SoundStation default"},
        {"user": "administrator", "pass": "456", "protocol": "http", "device_type": "voip", "notes": "Admin account"},
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "voip", "notes": "HDX/Group series"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "voip", "notes": "Some models"},
    ],
    "tandberg": [
        {"user": "admin", "pass": "TANDBERG", "protocol": "http", "device_type": "voip", "notes": "Gatekeeper / Border Controller"},
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "voip", "notes": "Codec (no password)"},
        {"user": "root", "pass": "TANDBERG", "protocol": "ssh", "device_type": "voip", "notes": "VCS 5.0 SSH"},
        {"user": "admin", "pass": "TANDBERG", "protocol": "telnet", "device_type": "voip", "notes": "Telnet access"},
    ],
    "mitel": [
        {"user": "maint", "pass": "maint", "protocol": "telnet", "device_type": "voip", "notes": "Mitel MiVoice 3300 maintenance"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "voip", "notes": "6900 series web UI"},
        {"user": "sysadmin", "pass": "sysadmin", "protocol": "http", "device_type": "voip", "notes": "System admin account"},
    ],
    "avaya": [
        {"user": "dadmin", "pass": "dadmin", "protocol": "multi", "device_type": "voip", "notes": "Definity PBX"},
        {"user": "admin", "pass": "barney", "protocol": "http", "device_type": "voip", "notes": "4602 SIP Phone 1.1"},
        {"user": "Craft", "pass": "crftpw", "protocol": "multi", "device_type": "voip", "notes": "Intuity Audix"},
        {"user": "admin", "pass": "admin123", "protocol": "multi", "device_type": "voip", "notes": "IMD"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "voip", "notes": "Scopia"},
    ],
    "sangoma": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "voip", "notes": "FreePBX / Switchvox"},
        {"user": "maint", "pass": "support", "protocol": "ssh", "device_type": "voip", "notes": "Maintenance account"},
    ],
    "audiocodes": [
        {"user": "Admin", "pass": "Admin", "protocol": "http", "device_type": "voip", "notes": "AudioCodes Mediant gateways"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "voip", "notes": "Alternative"},
    ],
    # --- Switches / Network ---
    "extreme_networks": [
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "switch", "notes": "ExtremeOS default — no password"},
        {"user": "user", "pass": "", "protocol": "telnet", "device_type": "switch", "notes": "User-level access"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "switch", "notes": "Some appliances"},
    ],
    "brocade": [
        {"user": "admin", "pass": "password", "protocol": "multi", "device_type": "switch", "notes": "Brocade Fabric OS"},
        {"user": "root", "pass": "fibranne", "protocol": "ssh", "device_type": "switch", "notes": "Root SSH access"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "switch", "notes": "Web interface"},
    ],
    "nortel": [
        {"user": "ro", "pass": "ro", "protocol": "multi", "device_type": "switch", "notes": "Accelar/Passport — read-only"},
        {"user": "rw", "pass": "rw", "protocol": "multi", "device_type": "switch", "notes": "Accelar/Passport — read-write"},
        {"user": "rwa", "pass": "rwa", "protocol": "multi", "device_type": "switch", "notes": "Accelar/Passport — full"},
        {"user": "admin", "pass": "setup", "protocol": "http", "device_type": "switch", "notes": "Contivity/Extranet"},
        {"user": "supervisor", "pass": "visor", "protocol": "multi", "device_type": "switch", "notes": "BCM 3.5-3.7"},
        {"user": "administrator", "pass": "PlsChgMe!", "protocol": "multi", "device_type": "switch", "notes": "BCM"},
    ],
    "cabletron": [
        {"user": "admin", "pass": "", "protocol": "telnet", "device_type": "switch", "notes": "Legacy Cabletron default"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "switch", "notes": "SmartSwitch"},
    ],
    "enterasys": [
        {"user": "admin", "pass": "", "protocol": "telnet", "device_type": "switch", "notes": "Enterasys Networks default"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "switch", "notes": "Web interface"},
    ],
    "alteon": [
        {"user": "admin", "pass": "admin", "protocol": "telnet", "device_type": "switch", "notes": "AD/WebSW series"},
        {"user": "oper", "pass": "oper", "protocol": "telnet", "device_type": "switch", "notes": "Operator account"},
    ],
    "foundry": [
        {"user": "admin", "pass": "", "protocol": "telnet", "device_type": "switch", "notes": "Legacy Foundry/FastIron"},
        {"user": "enable", "pass": "", "protocol": "telnet", "device_type": "switch", "notes": "Enable mode"},
    ],
    "planet": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "switch", "notes": "Planet Technology default"},
        {"user": "admin", "pass": "planet", "protocol": "http", "device_type": "switch", "notes": "Some models"},
    ],
    "smc": [
        {"user": "admin", "pass": "smcadmin", "protocol": "http", "device_type": "switch", "notes": "SMC Networks default"},
        {"user": "admin", "pass": "admin", "protocol": "telnet", "device_type": "switch", "notes": "Telnet access"},
    ],
    "accton": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "switch", "notes": "Accton/EdgeCore default"},
        {"user": "admin", "pass": "", "protocol": "telnet", "device_type": "switch", "notes": "Telnet variant"},
    ],
    "allied_telesyn": [
        {"user": "manager", "pass": "friend", "protocol": "telnet", "device_type": "switch", "notes": "AT-series switches primary"},
        {"user": "manager", "pass": "manager", "protocol": "telnet", "device_type": "switch", "notes": "Some models"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "switch", "notes": "Web UI"},
    ],
    # --- Firewalls ---
    "sonicwall": [
        {"user": "admin", "pass": "password", "protocol": "http", "device_type": "firewall", "notes": "SOHO/TELE/TZ/PRO default"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "firewall", "notes": "Legacy models"},
    ],
    "watchguard": [
        {"user": "admin", "pass": "readwrite", "protocol": "http", "device_type": "firewall", "notes": "Firebox default admin"},
        {"user": "status", "pass": "readonly", "protocol": "http", "device_type": "firewall", "notes": "Read-only account"},
    ],
    "barracuda": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "firewall", "notes": "Barracuda Networks default"},
        {"user": "admin", "pass": "barracuda", "protocol": "http", "device_type": "firewall", "notes": "Alternative"},
    ],
    "blue_coat": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "firewall", "notes": "Blue Coat ProxySG default"},
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "firewall", "notes": "No password variant"},
    ],
    "checkpoint": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "firewall", "notes": "Smart Console"},
        {"user": "cpconfig", "pass": "cpconfig", "protocol": "ssh", "device_type": "firewall", "notes": "CLI configuration"},
        {"user": "monitor", "pass": "monitor", "protocol": "http", "device_type": "firewall", "notes": "Monitor account"},
    ],
    # --- ICS / OT ---
    "abb": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "ics", "notes": "AC500 PLC / RobotStudio"},
        {"user": "service", "pass": "ABB800xA", "protocol": "multi", "device_type": "ics", "notes": "AC 800M controller"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "ics", "notes": "SREA-01 Ethernet adapter"},
    ],
    "rockwell": [
        {"user": "", "pass": "", "protocol": "ethernet/ip", "device_type": "ics", "notes": "ControlLogix/MicroLogix — no auth by default"},
        {"user": "Administrator", "pass": "", "protocol": "windows", "device_type": "ics", "notes": "FactoryTalk View"},
    ],
    "apc": [
        {"user": "apc", "pass": "apc", "protocol": "http", "device_type": "ics", "notes": "APC Smart-UPS — universal default"},
        {"user": "device", "pass": "apc", "protocol": "http", "device_type": "ics", "notes": "Device-level account"},
        {"user": "apc", "pass": "apc", "protocol": "ssh", "device_type": "ics", "notes": "SSH management"},
    ],
    "phoenix_contact": [
        {"user": "admin", "pass": "private", "protocol": "http", "device_type": "ics", "notes": "FL SWITCH managed series"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "ics", "notes": "PLCnext / ILC series"},
        {"user": "root", "pass": "root", "protocol": "http", "device_type": "ics", "notes": "Some older models"},
    ],
    "moxa": [
        {"user": "admin", "pass": "moxa", "protocol": "http", "device_type": "ics", "notes": "NPort serial-to-Ethernet"},
        {"user": "admin", "pass": "moxa", "protocol": "telnet", "device_type": "ics", "notes": "Telnet management"},
        {"user": "admin", "pass": "root", "protocol": "ssh", "device_type": "ics", "notes": "AWK wireless APs"},
    ],
    "omron": [
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "ics", "notes": "NJ/NX PLCs — no password"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "ics", "notes": "CX-One variant"},
    ],
    # --- Additional routers not in SecLists ---
    "tenda": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "router", "notes": "Factory default"},
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "router", "notes": "Blank password variant"},
    ],
    "draytek": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "router", "notes": "Vigor series default"},
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "router", "notes": "No password variant"},
    ],
    "sitecom": [
        {"user": "sitecom", "pass": "sitecom", "protocol": "http", "device_type": "router", "notes": "WL series default"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "router", "notes": "Alternative"},
    ],
    "inteno": [
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "router", "notes": "Inteno router default"},
        {"user": "user", "pass": "user", "protocol": "http", "device_type": "router", "notes": "User account"},
    ],
    "arris": [
        {"user": "admin", "pass": "password", "protocol": "http", "device_type": "modem", "notes": "Cable modem / CPE default"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "modem", "notes": "Alternative"},
        {"user": "technician", "pass": "technician", "protocol": "http", "device_type": "modem", "notes": "ISP tech account"},
    ],
    "ubiquiti": [
        {"user": "ubnt", "pass": "ubnt", "protocol": "http", "device_type": "wireless", "notes": "Universal AirOS/UniFi/EdgeRouter default"},
        {"user": "admin", "pass": "admin", "protocol": "http", "device_type": "wireless", "notes": "Some AirOS versions"},
        {"user": "ubnt", "pass": "ubnt", "protocol": "ssh", "device_type": "wireless", "notes": "SSH access"},
    ],
    "fortinet": [
        {"user": "admin", "pass": "", "protocol": "http", "device_type": "firewall", "notes": "FortiGate factory default — no password"},
        {"user": "admin", "pass": "", "protocol": "ssh", "device_type": "firewall", "notes": "FortiGate SSH"},
        {"user": "maintainer", "pass": "bcpb+SERIAL", "protocol": "console", "device_type": "firewall", "notes": "Console recovery (physical access only)"},
    ],
    "zyxel": [
        {"user": "admin", "pass": "1234", "protocol": "http", "device_type": "router", "notes": "Prestige series default"},
        {"user": "", "pass": "1234", "protocol": "telnet", "device_type": "router", "notes": "Telnet — no username"},
        {"user": "zyfwp", "pass": "PrOw!aN_fXp", "protocol": "ftp", "device_type": "router", "notes": "CVE-2020-29583 hardcoded backdoor"},
    ],
    # SNMP universal community strings
    "snmp_universal": [
        {"user": "public", "pass": "public", "protocol": "snmp", "device_type": "embedded", "notes": "SNMP read community string — universal"},
        {"user": "private", "pass": "private", "protocol": "snmp", "device_type": "embedded", "notes": "SNMP read-write community string"},
        {"user": "community", "pass": "community", "protocol": "snmp", "device_type": "embedded", "notes": "SNMP read string"},
        {"user": "manager", "pass": "manager", "protocol": "snmp", "device_type": "embedded", "notes": "SNMP r/w (HP/Compaq)"},
        {"user": "admin", "pass": "admin", "protocol": "snmp", "device_type": "embedded", "notes": "SNMP r/w (various)"},
        {"user": "ILMI", "pass": "ILMI", "protocol": "snmp", "device_type": "embedded", "notes": "ATM ILMI community string"},
        {"user": "secret", "pass": "secret", "protocol": "snmp", "device_type": "embedded", "notes": "Cisco IOS secret community string"},
    ],
}


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def dedup_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove exact (user, pass, protocol) duplicates, keep first occurrence."""
    seen: set[tuple[str, str, str]] = set()
    result: list[dict[str, Any]] = []
    for e in entries:
        key = (e.get("user", ""), e.get("pass", ""), e.get("protocol", ""))
        if key not in seen:
            seen.add(key)
            result.append(e)
    return result


# ---------------------------------------------------------------------------
# Wordlist file writer
# ---------------------------------------------------------------------------

def write_vendor_wordlist(vendor: str, entries: list[dict[str, Any]], out_dir: Path) -> None:
    """Write user:pass wordlist for a vendor to out_dir/{vendor}_defaults.txt."""
    lines: list[str] = []
    for e in entries:
        u = e.get("user", "")
        p = e.get("pass", "")
        if u or p:
            lines.append(f"{u}:{p}")

    if not lines:
        return

    # Deduplicate preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            deduped.append(line)

    out_path = out_dir / f"{vendor}_defaults.txt"
    out_path.write_text("\n".join(deduped) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Run the credential compiler."""
    logger.info("Starting EmbedXPL default credentials compiler...")

    # Verify SecLists path
    if not SECLISTS_CREDS.exists():
        logger.error("SecLists Default-Credentials directory not found: %s", SECLISTS_CREDS)
        logger.error("Ensure SecLists submodule is initialised at submodules/Wordlists/SecLists")
        sys.exit(1)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)

    # --- Parse sources ---
    logger.info("Parsing default-passwords.csv...")
    main_csv = SECLISTS_CREDS / "default-passwords.csv"
    db_main = parse_main_csv(main_csv) if main_csv.exists() else {}
    logger.info("  → %d vendors from main CSV", len(db_main))

    logger.info("Parsing scada-pass.csv...")
    scada_csv = SECLISTS_CREDS / "scada-pass.csv"
    db_ics = parse_scada_csv(scada_csv) if scada_csv.exists() else {}
    logger.info("  → %d ICS vendors from SCADA CSV", len(db_ics))

    logger.info("Parsing Routers/ per-vendor files...")
    routers_dir = SECLISTS_CREDS / "Routers"
    db_routers = parse_router_files(routers_dir) if routers_dir.exists() else {}
    logger.info("  → %d router vendors", len(db_routers))

    # --- Merge into unified general DB ---
    combined: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for vendor, entries in db_routers.items():
        combined[vendor].extend(entries)

    for vendor, entries in db_main.items():
        combined[vendor].extend(entries)

    for vendor, entries in EXTRA_CREDS.items():
        combined[vendor].extend(entries)

    # Deduplicate per vendor
    final_db: dict[str, list[dict[str, Any]]] = {}
    for vendor, entries in sorted(combined.items()):
        deduped = dedup_entries(entries)
        if deduped:
            final_db[vendor] = deduped

    # --- Finalise ICS DB ---
    ics_final: dict[str, list[dict[str, Any]]] = {}
    for vendor, entries in sorted(db_ics.items()):
        # Also merge ICS entries from main combined DB
        main_ics = [
            e for e in combined.get(vendor, [])
            if e.get("device_type") in ("ics", "scada", "plc")
        ]
        all_entries = dedup_entries(entries + main_ics)
        if all_entries:
            ics_final[vendor] = all_entries

    # Also add EXTRA_CREDS ICS vendors not yet in ics_final
    for vendor in ("abb", "rockwell", "apc", "phoenix_contact", "moxa", "omron", "siemens", "schneider"):
        extras = EXTRA_CREDS.get(vendor, [])
        if extras and vendor not in ics_final:
            ics_final[vendor] = dedup_entries(extras)
        elif extras:
            ics_final[vendor] = dedup_entries(ics_final[vendor] + extras)

    # --- Write JSON databases ---
    logger.info("Writing %s (%d vendors)...", OUT_GENERAL.name, len(final_db))
    OUT_GENERAL.write_text(
        json.dumps(final_db, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    logger.info("Writing %s (%d ICS vendors)...", OUT_ICS.name, len(ics_final))
    OUT_ICS.write_text(
        json.dumps(ics_final, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # --- Write per-vendor wordlist .txt files ---
    logger.info("Writing per-vendor wordlist files to %s...", WORDLISTS_DIR)
    count_wl = 0
    for vendor, entries in final_db.items():
        write_vendor_wordlist(vendor, entries, WORDLISTS_DIR)
        count_wl += 1
    logger.info("  → %d wordlist files written", count_wl)

    # --- Summary ---
    total_entries = sum(len(v) for v in final_db.values())
    ics_entries = sum(len(v) for v in ics_final.values())
    logger.info("Done.")
    logger.info("  General DB : %d vendors, %d credential entries", len(final_db), total_entries)
    logger.info("  ICS DB     : %d vendors, %d credential entries", len(ics_final), ics_entries)
    logger.info("  Wordlists  : %d files in %s", count_wl, WORDLISTS_DIR)


if __name__ == "__main__":
    main()
