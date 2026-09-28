"""Bulk generator for missing SecLists router vendor cred modules.

Author: André Henrique (LinkedIn/X: @mrhenrike)
"""
from __future__ import annotations
from pathlib import Path

CREDS_BASE = Path(__file__).resolve().parent.parent / "embedxpl" / "modules" / "creds"
WORDLISTS_DIR = Path(__file__).resolve().parent.parent / "embedxpl" / "resources" / "wordlists" / "vendors"

SSH_T = """# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ssh_default import Exploit as SSHDefault


class Exploit(SSHDefault):
    __info__ = {{
        "name": "{dn} Default SSH Creds",
        "description": "Dictionary attack with default credentials against {dn} SSH service.",
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": ("{dn}",),
    }}
    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(22, "Target SSH port")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("{dc}", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid attempt")
    verbosity = OptBool(True, "Display attempts")
"""
TELNET_T = """# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.telnet_default import Exploit as TelnetDefault


class Exploit(TelnetDefault):
    __info__ = {{
        "name": "{dn} Default Telnet Creds",
        "description": "Dictionary attack with default credentials against {dn} Telnet service.",
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": ("{dn}",),
    }}
    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target Telnet port")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("{dc}", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid attempt")
    verbosity = OptBool(True, "Display attempts")
"""
FTP_T = """# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ftp_default import Exploit as FTPDefault


class Exploit(FTPDefault):
    __info__ = {{
        "name": "{dn} Default FTP Creds",
        "description": "Dictionary attack with default credentials against {dn} FTP service.",
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": ("{dn}",),
    }}
    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(21, "Target FTP port")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("{dc}", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid attempt")
    verbosity = OptBool(True, "Display attempts")
"""
HTTP_T = """# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.http_basic_digest_default import Exploit as HTTPBasicDigestDefault


class Exploit(HTTPBasicDigestDefault):
    __info__ = {{
        "name": "{dn} Default Web Interface Creds",
        "description": "Dictionary attack against {dn} Web Interface (HTTP Basic/Digest Auth).",
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": ("{dn}",),
    }}
    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(80, "Target HTTP port")
    path = OptString("/", "Target path")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("{dc}", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid attempt")
    verbosity = OptBool(True, "Display attempts")
"""
INIT = "# Author: André Henrique (LinkedIn/X: @mrhenrike)\n"

MISSING_VENDORS = [
    "100fio_networks", "1net1", "3bb", "a_link", "acorp", "actiontec", "adb",
    "addon", "airlink_101", "airlive", "airnet", "airrouter", "airties",
    "alcatel_lucent", "allied_data", "alvarion", "ambit", "amped_wireless",
    "aolynk", "arcadyan", "arris", "artnet", "askey", "atlantis_land",
    "awb_networks", "axesstel", "bandluxe", "baudtec", "baytec",
    "bec_technologies", "beetel", "belgacom", "bell", "benq", "binatone",
    "blitzz", "bt", "buffalo", "calix", "canyon", "cbn", "cd_r_king",
    "cisco_linksys", "cnet", "conceptronic", "conexant", "creative", "crypto",
    "d_link", "dasan", "davolink", "dell", "dick_smith_elec", "digicom",
    "digisol", "digitus", "dovado", "dslink", "dynalink", "dynamode", "dynex",
    "e_tech", "eci", "efficient_siemens", "eltex", "eminent", "encore",
    "engenius", "ericsson", "etec", "eusso", "fiber_home", "franklin_wireless",
    "fritz_box", "gateway", "geek_adsl", "genexis", "gigabyte", "great_speed",
    "green_packet", "hama", "hamlet", "hawking", "hitron_technologies", "hot",
    "humax", "iball", "ice_net", "icotera", "inca", "inexq", "intelbras",
    "intellinet", "intracom", "inventel", "iskratel", "jaht",
    "jensen_scandinavia", "justec", "kaiomy", "kaon_media", "kasda",
    "kingtype", "kozumi", "kraun", "lectron", "legrand", "level_one", "lg",
    "loopcomm", "luxul", "marconi", "medialink", "microcom", "micronet",
    "mitrastar", "mobily", "msi", "mymax", "net_lynx", "netcomm",
    "netcoretek", "netgate", "netis", "netopia", "noganet", "nokia", "nucom",
    "olitec", "open_networks", "ovislink", "pace_plc", "paradigm", "paradyne",
    "pci", "pentagram", "pikatel", "ping_communication", "pirelli", "planet",
    "planex", "pluscom", "prolink", "pronets", "pti", "q_tec", "quicktel",
    "readynet", "repotec", "riger", "rosewill", "safecom", "sagem",
    "sagemcom", "samsung", "scientific_atlanta", "sercomm", "siemens",
    "sierra_wireless", "sky", "smartrg", "smc", "soho", "solwise", "sonicwall",
    "sparkcom", "spectrum", "speedcom", "starbridge", "surecom", "sweex",
    "tactio", "tecom", "telewell", "telindus", "telkom", "telsey", "telstra",
    "teltonika", "telus", "teracom", "thomson_alcatel", "tilgin", "topcom",
    "tornado", "tot", "totolink", "tp_link", "trendchip", "trust", "ubee",
    "utstarcom", "v_link", "verizon", "visionnet", "vonage", "vtech",
    "web_excel", "westell", "western_digital", "x_micro", "xavi", "zhone",
    "zioncom", "zonet", "zoom",
]


def get_cred(vk: str) -> str:
    """Return top default cred(s) for vendor key."""
    for key in (vk, vk.replace("_", "-")):
        wl = WORDLISTS_DIR / f"{key}_defaults.txt"
        if wl.exists():
            lines = [l.strip() for l in wl.read_text(encoding="utf-8").splitlines() if l.strip()]
            if lines:
                return ",".join(lines[:5])
    return "admin:admin"


def main() -> None:
    total = 0
    for vk in MISSING_VENDORS:
        dn = vk.replace("_", " ").title().replace("  ", " ") + " Router"
        dc = get_cred(vk)
        vdir = CREDS_BASE / "routers" / vk
        vdir.mkdir(parents=True, exist_ok=True)
        (vdir / "__init__.py").write_text(INIT, encoding="utf-8")
        for fname, tmpl in [
            ("ssh_default_creds.py", SSH_T),
            ("telnet_default_creds.py", TELNET_T),
            ("ftp_default_creds.py", FTP_T),
            ("webinterface_http_auth_default_creds.py", HTTP_T),
        ]:
            p = vdir / fname
            if not p.exists():
                p.write_text(tmpl.format(dn=dn, dc=dc), encoding="utf-8")
                total += 1
    print(f"Created {total} module files for {len(MISSING_VENDORS)} router vendors")


if __name__ == "__main__":
    main()
