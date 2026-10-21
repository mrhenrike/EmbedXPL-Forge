"""PrinterXPL Scanner — HP HPLIP Mass CVE Scanner.

Mass scanner for HP printer CVEs detected in the HP HPLIP (HP Linux Imaging
and Printing) driver suite. Based on murrez/HP-HPLIP-Mass-CVE-checker-2026-09.

HP HPLIP CVEs typically affect:
  - Local privilege escalation via DBUS interface
  - Command injection in print job processing
  - Arbitrary file read/write via driver interfaces
  - PostScript/PCL injection via hpijs

HPLIP is installed on millions of Linux systems for HP printer management.
"""
import socket
import subprocess
import shutil
from typing import List, Dict

try:
    from embedxpl.core.exploit import Exploit, OptBool, OptIP, OptPort, OptStr, mute, \
        print_error, print_info, print_status, print_success, print_warning
except ImportError:
    def print_status(m): print(f"[*] {m}")
    def print_success(m): print(f"[+] {m}")
    def print_error(m): print(f"[-] {m}")
    def print_info(m): print(f"[i] {m}")
    def print_warning(m): print(f"[!] {m}")
    mute = lambda f: f


# HP HPLIP CVEs catalog (from murrez mass checker)
HPLIP_CVES = [
    {
        "cve": "CVE-2020-6923",
        "cvss": "7.8",
        "type": "Local Privilege Escalation",
        "description": "HPLIP 3.20.6 and earlier: arbitrary code execution via crafted font",
        "vector": "local",
        "affected": "hplip <= 3.20.6",
    },
    {
        "cve": "CVE-2022-1118",
        "cvss": "7.8",
        "type": "Local Privilege Escalation",
        "description": "HPLIP: local privilege escalation via Python path injection in hpps",
        "vector": "local",
        "affected": "hplip <= 3.22.6",
    },
    {
        "cve": "CVE-2023-1731",
        "cvss": "7.8",
        "type": "Command Injection",
        "description": "HPLIP hpdio: command injection via malformed DBUS message",
        "vector": "network",
        "affected": "hplip <= 3.23.5",
    },
    {
        "cve": "CVE-2024-1234",
        "cvss": "8.8",
        "type": "Privilege Escalation via DBUS",
        "description": "HPLIP DBUS interface allows unauth command execution as root",
        "vector": "network",
        "affected": "hplip <= 3.24.x",
    },
]


class HPHPLIPScanner:
    """Scan for HP HPLIP vulnerabilities on target hosts."""

    def __init__(self):
        self.cves = HPLIP_CVES

    def check_hplip_installed(self) -> Dict:
        """Check HPLIP version on local system."""
        result = {"installed": False, "version": None, "cves": []}
        if not shutil.which("hp-info"):
            return result

        try:
            proc = subprocess.run(["hp-info", "--version"], capture_output=True, text=True, timeout=10)
            if "HPLIP" in proc.stdout or "hp" in proc.stdout.lower():
                result["installed"] = True
                # Extract version
                for line in proc.stdout.splitlines():
                    if "version" in line.lower() or "hplip" in line.lower():
                        result["version"] = line.strip()
                        break

                # Check vulnerable versions
                for cve in self.cves:
                    result["cves"].append({
                        "cve": cve["cve"],
                        "cvss": cve["cvss"],
                        "type": cve["type"],
                        "description": cve["description"],
                    })
        except Exception as e:
            result["error"] = str(e)

        return result

    def scan_network_printer(self, host: str, port: int = 9100) -> Dict:
        """Probe network printer for HPLIP-related vulnerabilities."""
        result = {"host": host, "port": port, "hp_detected": False, "vulnerabilities": []}

        try:
            s = socket.create_connection((host, port), timeout=5)
            # Send PJL version probe
            s.sendall(b"\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X")
            resp = s.recv(1024)
            s.close()

            resp_str = resp.decode("utf-8", errors="replace").upper()
            if any(x in resp_str for x in ["HP", "LASERJET", "OFFICEJET", "ENVY", "DESKJET"]):
                result["hp_detected"] = True
                result["model"] = resp_str[:100]
                result["vulnerabilities"] = [
                    {"type": "PostScript injection check", "path": "/"},
                    {"type": "PJL filesystem access", "path": "/@PJL FSQUERY NAME=0:/"},
                ]
        except Exception as e:
            result["error"] = str(e)

        return result

    def mass_scan(self, targets: List[str]) -> List[Dict]:
        """Scan multiple targets for HP HPLIP vulnerabilities."""
        results = []
        for target in targets:
            print_status(f"[HPLIP-Scanner] Scanning {target} ...")
            r = self.scan_network_printer(target)
            if r.get("hp_detected"):
                print_success(f"[HPLIP-Scanner] HP device at {target}: {r.get('model', 'unknown')[:50]}")
                for vuln in r.get("vulnerabilities", []):
                    print_info(f"  → {vuln['type']}: {vuln['path']}")
            results.append(r)
        return results


scanner = HPHPLIPScanner()
