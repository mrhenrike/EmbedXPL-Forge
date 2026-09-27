"""MITRE ATT&CK for ICS TTP Matrix Mapper.

Maps ICS security assessment findings to MITRE ATT&CK for ICS tactics
and techniques (v19, 103 techniques across 12 tactics).

Original research / PoC credits
--------------------------------
Source  : MITRE ATT&CK for ICS (https://attack.mitre.org/matrices/ics/)
          IndustrialXPL-Forge assessment framework concept
Author  : Andre Henrique (@mrhenrike) | Uniao Geek

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

from embedxpl.core.exploit import *


_ICS_TACTICS = {
    "TA0108": "Initial Access — Gain first foothold in ICS network",
    "TA0104": "Execution — Run attacker code on ICS systems",
    "TA0110": "Persistence — Maintain access to ICS systems",
    "TA0111": "Privilege Escalation — Gain higher-level permissions",
    "TA0103": "Evasion — Avoid detection by ICS security controls",
    "TA0102": "Discovery — Map ICS network and assets",
    "TA0109": "Lateral Movement — Move between ICS systems",
    "TA0100": "Collection — Gather ICS data for exfiltration/analysis",
    "TA0101": "Command and Control — Communicate with compromised ICS systems",
    "TA0107": "Inhibit Response Function — Prevent ICS safety/protective responses",
    "TA0106": "Impair Process Control — Interfere with industrial process",
    "TA0105": "Impact — Disrupt/damage physical industrial process",
}

_HIGH_IMPACT_TECHNIQUES = {
    "T0831": "Manipulation of Control — Modify PLC/RTU control programs",
    "T0836": "Modify Parameter — Change process setpoints",
    "T0843": "Program Download — Push malicious logic to PLC",
    "T0855": "Unauthorized Command Message — Send rogue Modbus/S7/DNP3 commands",
    "T0878": "Alarm Suppression — Disable/manipulate safety alarms",
    "T0883": "Internet Accessible Device — Exploit internet-exposed ICS",
    "T0814": "Denial of Control — Prevent operator commands from reaching PLC",
}


class Exploit(Exploit):
    """MITRE ATT&CK for ICS TTP Matrix Mapper."""

    __info__ = {
        "name": "MITRE ATT&CK ICS TTP Matrix (v19)",
        "description": (
            "Maps ICS attack scenarios to MITRE ATT&CK for ICS tactics and techniques "
            "(v19, 103 techniques, 12 tactics). Highlights high-impact techniques. "
            "Use to correlate red-team findings with ATT&CK coverage."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://attack.mitre.org/matrices/ics/",
            "https://collaborate.mitre.org/attackics",
        ),
        "devices": ("OT/ICS environments",),
    }

    technique_id = OptString("", "Lookup a specific TTP (e.g. T0831)")
    show_tactics = OptBool(True, "Display ICS tactic overview")

    @mute
    def check(self) -> bool:
        return True

    def run(self) -> None:
        tid = str(self.technique_id).upper().strip()
        show_tactics = bool(self.show_tactics)

        if tid:
            # Lookup specific technique
            found = _HIGH_IMPACT_TECHNIQUES.get(tid)
            if found:
                print_success(f"{tid}: {found}")
            else:
                print_info(f"{tid}: not in local high-impact index — check attack.mitre.org/matrices/ics/")
            return

        if show_tactics:
            print_status("MITRE ATT&CK for ICS — v19 Tactics (12)")
            for tactic_id, desc in _ICS_TACTICS.items():
                print_info(f"  {tactic_id}: {desc}")

        print_status("\nHigh-impact techniques for OT pentest findings:")
        for tech_id, desc in _HIGH_IMPACT_TECHNIQUES.items():
            print_success(f"  {tech_id}: {desc}")

        print_info(
            "\nUsage: set technique_id=T0831 to look up a specific technique. "
            "Full 103-technique coverage at: https://attack.mitre.org/matrices/ics/"
        )
