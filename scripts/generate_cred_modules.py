"""Bulk generator for EmbedXPL-Forge default credential modules.

Creates vendor-specific cred module directories and Python stub files for all
new device categories: cameras, switches, firewalls, printers, NAS, VoIP, ICS,
and additional routers.

Run from EmbedXPL-Forge root:
    python scripts/generate_cred_modules.py

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 1.0.0
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
CREDS_BASE = REPO_ROOT / "embedxpl" / "modules" / "creds"
WORDLISTS_DIR = REPO_ROOT / "embedxpl" / "resources" / "wordlists" / "vendors"
DATA_DIR = REPO_ROOT / "embedxpl" / "data"

# ---------------------------------------------------------------------------
# Module templates
# ---------------------------------------------------------------------------

SSH_TEMPLATE = '''\
# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ssh_default import Exploit as SSHDefault


class Exploit(SSHDefault):
    """{display_name} — Default SSH Credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {{
        "name": "{display_name} Default SSH Creds",
        "description": (
            "Module performs dictionary attack with default credentials against "
            "{display_name} SSH service. "
            "If valid credentials are found, they are displayed to the user."
        ),
        "authors": (
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "devices": (
            "{display_name}",
        ),
    }}

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(22, "Target SSH port")

    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("{default_cred}", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")
'''

TELNET_TEMPLATE = '''\
# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.telnet_default import Exploit as TelnetDefault


class Exploit(TelnetDefault):
    """{display_name} — Default Telnet Credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {{
        "name": "{display_name} Default Telnet Creds",
        "description": (
            "Module performs dictionary attack with default credentials against "
            "{display_name} Telnet service. "
            "If valid credentials are found, they are displayed to the user."
        ),
        "authors": (
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "devices": (
            "{display_name}",
        ),
    }}

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target Telnet port")

    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("{default_cred}", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")
'''

FTP_TEMPLATE = '''\
# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ftp_default import Exploit as FTPDefault


class Exploit(FTPDefault):
    """{display_name} — Default FTP Credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {{
        "name": "{display_name} Default FTP Creds",
        "description": (
            "Module performs dictionary attack with default credentials against "
            "{display_name} FTP service. "
            "If valid credentials are found, they are displayed to the user."
        ),
        "authors": (
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "devices": (
            "{display_name}",
        ),
    }}

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(21, "Target FTP port")

    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("{default_cred}", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")
'''

HTTP_AUTH_TEMPLATE = '''\
# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.http_basic_digest_default import Exploit as HTTPBasicDigestDefault


class Exploit(HTTPBasicDigestDefault):
    """{display_name} — Default Web Interface Credentials (HTTP Basic/Digest Auth).

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {{
        "name": "{display_name} Default Web Interface Creds - HTTP Auth",
        "description": (
            "Module performs dictionary attack against {display_name} Web Interface "
            "protected by HTTP Basic/Digest authentication. "
            "If valid credentials are found, they are displayed to the user."
        ),
        "authors": (
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "devices": (
            "{display_name}",
        ),
    }}

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort({http_port}, "Target HTTP port")
    path = OptString("/", "Target path")

    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("{default_cred}", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")
'''

SNMP_TEMPLATE = '''\
# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.snmp_bruteforce import Exploit as SNMPBruteforce


class Exploit(SNMPBruteforce):
    """{display_name} — Default SNMP Community Strings.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {{
        "name": "{display_name} Default SNMP Community Strings",
        "description": (
            "Module performs dictionary attack against {display_name} SNMP service "
            "using known default community strings. "
            "If valid community strings are found, they are displayed to the user."
        ),
        "authors": (
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "devices": (
            "{display_name}",
        ),
    }}

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(161, "Target SNMP port")

    threads = OptInteger(4, "Number of threads")
    defaults = OptWordlist("public,private,community,manager,admin,secret,ILMI", "Community strings to try")
    stop_on_success = OptBool(False, "Stop on first valid community string")
    verbosity = OptBool(True, "Display attempts")
'''

INIT_PY = '''\
# Author: André Henrique (LinkedIn/X: @mrhenrike)
'''


# ---------------------------------------------------------------------------
# Vendor definitions
# ---------------------------------------------------------------------------

def get_primary_cred(vendor_key: str) -> str:
    """Return the most common default credential for a vendor as inline string."""
    wordlist_path = WORDLISTS_DIR / f"{vendor_key}_defaults.txt"
    if wordlist_path.exists():
        lines = [l.strip() for l in wordlist_path.read_text().splitlines() if l.strip()]
        if lines:
            # Return first N as inline comma-separated for OptWordlist
            top = lines[:5]
            return ",".join(top)
    return "admin:admin"


# Format: (category_dir, vendor_key, display_name, http_port, modules_to_create)
# modules_to_create: list of 'ssh','telnet','ftp','http_auth','snmp'
VENDORS_TO_CREATE: list[tuple[str, str, str, int, list[str]]] = [
    # -----------------------------------------------------------------------
    # CAMERAS — missing 15 vendors
    # -----------------------------------------------------------------------
    ("cameras", "dahua", "Dahua Camera/DVR/NVR", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("cameras", "foscam", "Foscam IP Camera", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("cameras", "vivotek", "Vivotek IP Camera", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("cameras", "pelco", "Pelco IP Camera/DVR", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("cameras", "flir", "FLIR Camera/Thermal", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("cameras", "bosch", "Bosch IP Camera", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("cameras", "march_networks", "March Networks Recorder", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("cameras", "panasonic", "Panasonic IP Camera", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("cameras", "sony", "Sony SNC IP Camera", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("cameras", "dynacolor", "DynaColor DVR/NVR", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("cameras", "dvtel", "DVTel IP Camera/VMS", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("cameras", "everfocus", "EverFocus DVR/NVR", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("cameras", "cbc_ganz", "CBC Ganz DIGIMASTER DVR", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("cameras", "wodsee", "Wodsee IP Camera", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("cameras", "arecont", "Arecont Vision MegaVideo", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("cameras", "mobotix", "Mobotix IP Camera", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    # -----------------------------------------------------------------------
    # SWITCHES — new category
    # -----------------------------------------------------------------------
    ("switches", "cisco_catalyst", "Cisco Catalyst Switch", 80, ["ssh", "telnet", "snmp", "http_auth"]),
    ("switches", "hp_procurve", "HP ProCurve Switch", 80, ["ssh", "telnet", "snmp", "http_auth"]),
    ("switches", "extreme_networks", "Extreme Networks Switch", 80, ["ssh", "telnet", "snmp", "http_auth"]),
    ("switches", "brocade", "Brocade Switch/SAN", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("switches", "nortel", "Nortel Accelar/Passport Switch", 80, ["ssh", "telnet", "snmp", "http_auth"]),
    ("switches", "cabletron", "Cabletron/Enterasys Switch", 80, ["ssh", "telnet", "snmp"]),
    ("switches", "enterasys", "Enterasys Switch", 80, ["ssh", "telnet", "snmp", "http_auth"]),
    ("switches", "alteon", "Alteon/Radware Switch", 80, ["ssh", "telnet", "http_auth"]),
    ("switches", "foundry", "Foundry Networks/FastIron", 80, ["ssh", "telnet", "snmp"]),
    ("switches", "planet", "Planet Technology Switch", 80, ["ssh", "telnet", "http_auth"]),
    ("switches", "smc", "SMC Networks Switch", 80, ["ssh", "telnet", "http_auth"]),
    ("switches", "accton", "Accton/EdgeCore Switch", 80, ["ssh", "telnet", "http_auth"]),
    ("switches", "allied_telesyn", "Allied Telesyn/Telesis Switch", 80, ["ssh", "telnet", "http_auth"]),
    # -----------------------------------------------------------------------
    # FIREWALLS — new category
    # -----------------------------------------------------------------------
    ("firewalls", "sonicwall", "SonicWall Firewall/UTM", 443, ["ssh", "http_auth"]),
    ("firewalls", "watchguard", "WatchGuard Firebox", 443, ["ssh", "http_auth"]),
    ("firewalls", "barracuda", "Barracuda Networks Firewall", 443, ["ssh", "http_auth"]),
    ("firewalls", "blue_coat", "Blue Coat ProxySG", 8082, ["ssh", "http_auth"]),
    ("firewalls", "checkpoint", "Check Point Gateway", 443, ["ssh", "http_auth"]),
    ("firewalls", "cisco_asa", "Cisco ASA Firewall", 443, ["ssh", "telnet", "http_auth"]),
    # -----------------------------------------------------------------------
    # PRINTERS — new category
    # -----------------------------------------------------------------------
    ("printers", "hp", "HP LaserJet/OfficeJet Printer", 80, ["ftp", "http_auth"]),
    ("printers", "xerox", "Xerox WorkCentre/ColorQube", 80, ["ftp", "http_auth"]),
    ("printers", "ricoh", "Ricoh Aficio/MP Printer", 80, ["ftp", "http_auth"]),
    ("printers", "brother", "Brother HL/MFC Printer", 80, ["ftp", "http_auth"]),
    ("printers", "kyocera", "Kyocera FS/ECOSYS Printer", 80, ["ftp", "http_auth"]),
    ("printers", "canon", "Canon imageRUNNER/LBP Printer", 80, ["ftp", "http_auth"]),
    ("printers", "konica_minolta", "Konica Minolta bizhub Printer", 80, ["ftp", "http_auth"]),
    ("printers", "lexmark", "Lexmark Printer", 80, ["ftp", "http_auth"]),
    ("printers", "oki", "OKI MC/ES/C Printer", 80, ["ftp", "http_auth"]),
    ("printers", "sharp", "Sharp MX Series MFP", 80, ["ftp", "http_auth"]),
    ("printers", "toshiba", "Toshiba e-STUDIO Printer", 80, ["ftp", "http_auth"]),
    ("printers", "samsung", "Samsung ML/CLX/SCX Printer", 80, ["ftp", "http_auth"]),
    ("printers", "panasonic", "Panasonic KX Printer", 80, ["ftp", "http_auth"]),
    # -----------------------------------------------------------------------
    # NAS / Storage — new category
    # -----------------------------------------------------------------------
    ("nas", "qnap", "QNAP NAS", 80, ["ssh", "ftp", "http_auth"]),
    ("nas", "synology", "Synology DiskStation NAS", 5000, ["ssh", "ftp", "http_auth"]),
    ("nas", "wd", "Western Digital My Cloud NAS", 80, ["ssh", "ftp", "http_auth"]),
    ("nas", "seagate", "Seagate BlackArmor NAS", 80, ["ssh", "ftp", "http_auth"]),
    ("nas", "iomega", "Iomega/LenovoEMC StorCenter NAS", 80, ["ssh", "ftp", "http_auth"]),
    ("nas", "buffalo", "Buffalo LinkStation/TeraStation NAS", 80, ["ssh", "ftp", "http_auth"]),
    ("nas", "netgear", "Netgear ReadyNAS", 80, ["ssh", "ftp", "http_auth"]),
    # -----------------------------------------------------------------------
    # VoIP / Video Conferencing — new category
    # -----------------------------------------------------------------------
    ("voip", "polycom", "Polycom SoundPoint/ViewStation", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("voip", "tandberg", "TANDBERG/Cisco TelePresence", 80, ["ssh", "telnet", "http_auth"]),
    ("voip", "mitel", "Mitel MiVoice PBX", 80, ["ssh", "telnet", "http_auth"]),
    ("voip", "avaya", "Avaya Definity/Aura PBX", 80, ["ssh", "telnet", "http_auth"]),
    ("voip", "cisco_voip", "Cisco CUCM/VoIP Gateway", 80, ["ssh", "telnet", "http_auth"]),
    ("voip", "grandstream", "Grandstream IP Phone/GXV Camera", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("voip", "sangoma", "Sangoma/FreePBX Gateway", 80, ["ssh", "http_auth"]),
    ("voip", "audiocodes", "AudioCodes Mediant Gateway", 80, ["ssh", "http_auth"]),
    # -----------------------------------------------------------------------
    # ICS / OT — new category
    # -----------------------------------------------------------------------
    ("ics", "siemens", "Siemens PLC/SCADA/Switch", 80, ["ssh", "telnet", "http_auth"]),
    ("ics", "schneider", "Schneider Electric/APC", 80, ["ssh", "telnet", "http_auth"]),
    ("ics", "abb", "ABB PLC/Robot Controller", 80, ["ssh", "http_auth"]),
    ("ics", "rockwell", "Rockwell/Allen-Bradley PLC", 80, ["ssh", "http_auth"]),
    ("ics", "honeywell_ot", "Honeywell Experion/HC900 OT", 80, ["ssh", "http_auth"]),
    ("ics", "phoenix_contact", "Phoenix Contact FL SWITCH/PLCnext", 80, ["ssh", "telnet", "http_auth"]),
    ("ics", "moxa", "Moxa NPort/EDS Serial/Switch", 80, ["ssh", "telnet", "http_auth"]),
    ("ics", "omron", "OMRON NJ/NX PLC", 80, ["ssh", "http_auth"]),
    # -----------------------------------------------------------------------
    # ISP CPEs — additional
    # -----------------------------------------------------------------------
    ("ispcpes", "sagemcom", "Sagemcom CPE/Gateway", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("ispcpes", "arris", "Arris Cable Modem/CPE", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("ispcpes", "netcomm", "NetComm Wireless CPE", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("ispcpes", "actiontec", "Actiontec Router/CPE", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    # -----------------------------------------------------------------------
    # Routers — additional vendors
    # -----------------------------------------------------------------------
    ("routers", "tenda", "Tenda Router", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("routers", "draytek", "DrayTek Vigor Router", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("routers", "sitecom", "Sitecom WL Router", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("routers", "inteno", "Inteno Router", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("routers", "lancom", "LANCOM Router/Switch", 80, ["ssh", "telnet", "http_auth"]),
    ("routers", "netcomm_router", "NetComm Router", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("routers", "buffalo_router", "Buffalo AirStation Router", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("routers", "edimax", "Edimax Router/Switch", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("routers", "trendnet", "TRENDnet Router/Switch", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("routers", "motorola", "Motorola Router/CPE", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("routers", "aztech", "Aztech Router", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("routers", "allnet", "ALLNET Router/Switch", 80, ["ssh", "telnet", "http_auth"]),
    ("routers", "vodafone", "Vodafone ISP Router", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("routers", "adtran", "ADTRAN Router/Switch", 80, ["ssh", "telnet", "snmp", "http_auth"]),
    ("routers", "dlink_adsl", "D-Link ADSL/DSL Modem", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("routers", "fiberhome", "FiberHome OLT/CPE", 80, ["ssh", "telnet", "http_auth"]),
    ("routers", "alcatel", "Alcatel-Lucent Router/DSL", 80, ["ssh", "telnet", "http_auth"]),
    ("routers", "senao", "Senao/EnGenius AP/Router", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("routers", "planet_router", "Planet Technology Router/AP", 80, ["ssh", "telnet", "ftp", "http_auth"]),
    ("routers", "proxim", "Proxim Wireless AP/Bridge", 80, ["ssh", "telnet", "http_auth"]),
    ("routers", "bhu", "BHU Router/CPE", 80, ["ssh", "telnet", "ftp", "http_auth"]),
]

# Map vendor_key → wordlist key (when they differ)
VENDOR_KEY_MAP: dict[str, str] = {
    "cisco_catalyst": "cisco",
    "hp_procurve": "hp",
    "cisco_asa": "cisco",
    "cisco_voip": "cisco",
    "buffalo_router": "buffalo",
    "netcomm_router": "netcomm",
    "honeywell_ot": "honeywell",
    "dlink_adsl": "dlink",
    "planet_router": "planet",
}


def get_primary_cred_for(vendor_key: str) -> str:
    """Return top default credential(s) for vendor_key."""
    lookup_key = VENDOR_KEY_MAP.get(vendor_key, vendor_key)
    wordlist_path = WORDLISTS_DIR / f"{lookup_key}_defaults.txt"
    if wordlist_path.exists():
        lines = [l.strip() for l in wordlist_path.read_text(encoding="utf-8").splitlines() if l.strip()]
        if lines:
            return ",".join(lines[:5])
    # Hardcoded fallbacks for known vendors
    fallbacks = {
        "dahua": "admin:admin,888888:888888",
        "hikvision": "admin:12345,admin:admin",
        "axis": "root:pass,root:root",
        "foscam": "admin:,admin:admin",
        "vivotek": "root:,admin:admin",
        "pelco": "admin:admin,viewer:viewer",
        "flir": "admin:admin,supervisor:supervisor",
        "bosch": "admin:,service:service",
        "mobotix": "admin:meinsm",
        "sony": "admin:admin",
        "march_networks": "admin:admin",
        "everfocus": "admin:11111111,admin:admin",
        "dynacolor": "admin:1234,admin:admin",
        "dvtel": "admin:admin,Administrator:Administrator",
        "cbc_ganz": "admin:11111111,admin:admin",
        "wodsee": "admin:,admin:admin",
        "arecont": "admin:,admin:admin",
        "panasonic": "admin:12345,admin:",
        "stardot": "admin:admin",
        "sentry360": "admin:admin",
        "videoiq": "admin:admin",
        "jvc": "admin:jvc,admin:admin",
        "sonicwall": "admin:password,admin:admin",
        "watchguard": "admin:readwrite,status:readonly",
        "barracuda": "admin:admin,admin:barracuda",
        "blue_coat": "admin:admin,admin:",
        "checkpoint": "admin:admin,cpconfig:cpconfig",
        "cisco_asa": "admin:admin,cisco:cisco",
        "cisco_catalyst": "admin:admin,cisco:cisco,enable:cisco",
        "hp_procurve": "manager:,admin:admin",
        "extreme_networks": "admin:,user:",
        "brocade": "admin:password,root:fibranne",
        "nortel": "ro:ro,rw:rw,rwa:rwa",
        "cabletron": "admin:,admin:admin",
        "enterasys": "admin:,admin:admin",
        "alteon": "admin:admin,oper:oper",
        "foundry": "admin:,enable:",
        "planet": "admin:admin,admin:planet",
        "smc": "admin:smcadmin,admin:admin",
        "accton": "admin:admin,admin:",
        "allied_telesyn": "manager:friend,manager:manager",
        "hp": "admin:,admin:admin",
        "xerox": "admin:1111,11111:x-admin",
        "ricoh": "admin:,admin:password",
        "brother": "admin:access,:access",
        "kyocera": "Admin:Admin,admin:",
        "canon": "7654321:7654321,ADMIN:canon",
        "konica_minolta": "Admin:,User:",
        "lexmark": "admin:,admin:admin",
        "oki": "admin:aaaaaa,root:aaaaaa",
        "sharp": "admin:admin,Admin:Admin",
        "toshiba": "admin:,admin00:,admin:123456",
        "samsung": "admin:admin,admin:sec00000",
        "qnap": "admin:admin,admin:",
        "synology": "admin:,admin:admin",
        "wd": "admin:,mydlinkBRionyg:abc12345cba",
        "seagate": "admin:admin,root:",
        "iomega": "admin:admin,guest:",
        "buffalo": "admin:password,root:",
        "netgear": "admin:password,admin:netgear1",
        "polycom": "Polycom:456,administrator:456,admin:",
        "tandberg": "admin:TANDBERG,admin:,root:TANDBERG",
        "mitel": "maint:maint,admin:admin",
        "avaya": "dadmin:dadmin,admin:barney,Craft:crftpw",
        "cisco_voip": "admin:admin,cisco:cisco,EAdmin:",
        "grandstream": "admin:admin,Administrator:admin",
        "sangoma": "admin:admin,maint:support",
        "audiocodes": "Admin:Admin,admin:admin",
        "siemens": "admin:admin,basisk:basisk,:admin,:123456",
        "schneider": "USER:USER,apc:apc,device:apc",
        "abb": "admin:admin,service:ABB800xA",
        "rockwell": "Administrator:,admin:admin",
        "honeywell_ot": "admin:admin,user:",
        "phoenix_contact": "admin:private,admin:admin",
        "moxa": "admin:moxa,admin:root",
        "omron": "admin:,admin:admin",
        "sagemcom": "admin:admin,admin:sagemcom",
        "arris": "admin:password,admin:admin,technician:technician",
        "netcomm": "admin:admin,admin:password",
        "actiontec": "admin:admin,admin:",
        "tenda": "admin:admin,admin:",
        "draytek": "admin:admin,admin:",
        "sitecom": "sitecom:sitecom,admin:admin",
        "inteno": "admin:admin,user:user",
        "lancom": "admin:,admin:admin",
        "buffalo_router": "root:,admin:password",
        "edimax": "admin:1234,admin:admin",
        "trendnet": "admin:admin,admin:",
        "motorola": "admin:motorola,admin:admin",
        "aztech": "admin:admin,admin:",
        "allnet": "admin:admin",
        "vodafone": "admin:admin,admin:vodafone",
        "adtran": "admin:admin,admin:",
        "dlink_adsl": "admin:,admin:admin",
        "fiberhome": "admin:admin,admin:fiberhome",
        "alcatel": "admin:admin,isadmin:isamadmin",
        "senao": "admin:admin",
        "planet_router": "admin:admin,admin:planet",
        "proxim": "admin:admin,public:",
        "bhu": "admin:admin,telecomadmin:admintelecom",
        "netcomm_router": "admin:admin,admin:password",
    }
    return fallbacks.get(vendor_key, "admin:admin")


def write_module(path: Path, content: str) -> None:
    """Write module file, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(content, encoding="utf-8")


def create_vendor_modules(
    category: str,
    vendor_key: str,
    display_name: str,
    http_port: int,
    modules: list[str],
) -> int:
    """Create all module files for a single vendor. Returns count created."""
    vendor_dir = CREDS_BASE / category / vendor_key
    vendor_dir.mkdir(parents=True, exist_ok=True)

    # Always create __init__.py
    init_path = vendor_dir / "__init__.py"
    write_module(init_path, INIT_PY)

    default_cred = get_primary_cred_for(vendor_key)
    created = 0

    for mod in modules:
        if mod == "ssh":
            p = vendor_dir / "ssh_default_creds.py"
            content = SSH_TEMPLATE.format(display_name=display_name, default_cred=default_cred)
        elif mod == "telnet":
            p = vendor_dir / "telnet_default_creds.py"
            content = TELNET_TEMPLATE.format(display_name=display_name, default_cred=default_cred)
        elif mod == "ftp":
            p = vendor_dir / "ftp_default_creds.py"
            content = FTP_TEMPLATE.format(display_name=display_name, default_cred=default_cred)
        elif mod == "http_auth":
            p = vendor_dir / "webinterface_http_auth_default_creds.py"
            content = HTTP_AUTH_TEMPLATE.format(
                display_name=display_name,
                default_cred=default_cred,
                http_port=http_port,
            )
        elif mod == "snmp":
            p = vendor_dir / "snmp_default_creds.py"
            content = SNMP_TEMPLATE.format(display_name=display_name)
        else:
            continue

        if not p.exists():
            p.write_text(content, encoding="utf-8")
            created += 1

    return created


def ensure_category_init(category: str) -> None:
    """Ensure category __init__.py exists."""
    cat_dir = CREDS_BASE / category
    cat_dir.mkdir(parents=True, exist_ok=True)
    init_path = cat_dir / "__init__.py"
    if not init_path.exists():
        init_path.write_text(INIT_PY, encoding="utf-8")


def main() -> None:
    """Generate all vendor credential modules."""
    logger.info("Starting EmbedXPL cred module generator...")

    total_created = 0
    categories: set[str] = set()

    for category, vendor_key, display_name, http_port, modules in VENDORS_TO_CREATE:
        categories.add(category)
        ensure_category_init(category)
        n = create_vendor_modules(category, vendor_key, display_name, http_port, modules)
        if n > 0:
            logger.info("  [%s/%s] Created %d module(s)", category, vendor_key, n)
        total_created += n

    logger.info("Done. Created %d module files across %d categories.", total_created, len(categories))


if __name__ == "__main__":
    main()
