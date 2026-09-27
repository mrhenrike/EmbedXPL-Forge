"""IEC 62443 Security Level Assessment Stub.

Evaluates an OT/ICS environment against IEC 62443 security levels (SL-1 to SL-4)
across seven foundational requirements (7FRs): identification/auth control,
use control, system integrity, data confidentiality, restricted data flow,
timely response, and resource availability.

Original research / PoC credits
--------------------------------
Source  : IEC 62443 standard assessment methodology
          IndustrialXPL-Forge assessment framework concept
Author  : Andre Henrique (@mrhenrike) | Uniao Geek

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

from embedxpl.core.exploit import *


_SECURITY_LEVELS = {
    0: "No security requirements",
    1: "Protection against casual or unintentional violation",
    2: "Protection against intentional violation with simple means",
    3: "Protection against intentional violation with sophisticated means",
    4: "Protection against state-sponsored attacks",
}

_7FR_CATEGORIES = {
    "FR1_IAC": "Identification and Authentication Control",
    "FR2_UC": "Use Control",
    "FR3_SI": "System Integrity",
    "FR4_DC": "Data Confidentiality",
    "FR5_RDF": "Restricted Data Flow",
    "FR6_TRE": "Timely Response to Events",
    "FR7_RA": "Resource Availability",
}

_SL_REQUIREMENTS: dict = {
    1: {
        "FR1_IAC": "Basic authentication required for all access",
        "FR2_UC": "Limit software installation to authorized users",
        "FR3_SI": "Software integrity verification at startup",
        "FR4_DC": "Protect data in transit with basic encryption",
        "FR5_RDF": "Network segmentation between IT and OT",
        "FR6_TRE": "Log security events; review quarterly",
        "FR7_RA": "Redundancy for critical components",
    },
    2: {
        "FR1_IAC": "MFA for remote access; password complexity enforced",
        "FR2_UC": "Role-based access control; least privilege",
        "FR3_SI": "Code signing; configuration change management",
        "FR4_DC": "Encrypt all remote sessions (TLS 1.2+)",
        "FR5_RDF": "Firewall rules; DMZ between zones",
        "FR6_TRE": "SIEM integration; 24h response SLA",
        "FR7_RA": "Hot standby; tested RTO/RPO",
    },
}


class Exploit(Exploit):
    """IEC 62443 Security Level Assessment Stub."""

    __info__ = {
        "name": "IEC 62443 Security Level Assessment",
        "description": (
            "Assessment stub that checks an OT/ICS site against IEC 62443 "
            "security level requirements (SL1–SL4) across 7 foundational requirements. "
            "Produces a gap analysis report. Interactive checklist mode."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://www.iec.ch/iec62443",
            "https://www.isaglobal.org/isa99/",
        ),
        "devices": ("OT/ICS environments (PLCs, SCADA, DCS, HMI)",),
    }

    target_sl = OptInteger(2, "Target security level to assess against (1-4)")
    interactive = OptBool(False, "Interactive checklist mode")

    @mute
    def check(self) -> bool:
        return True

    def run(self) -> None:
        target_sl = min(max(int(self.target_sl), 1), 4)
        interactive = bool(self.interactive)

        print_status(f"IEC 62443 Security Level {target_sl} Assessment")
        print_info(f"Target SL: {target_sl} — {_SECURITY_LEVELS[target_sl]}")
        print_info("=" * 60)

        requirements = _SL_REQUIREMENTS.get(target_sl, _SL_REQUIREMENTS[2])
        gaps = []

        for fr_id, fr_name in _7FR_CATEGORIES.items():
            req = requirements.get(fr_id, f"See IEC 62443-3-3 SL{target_sl} for {fr_id}")
            if interactive:
                resp = input(f"  [{fr_id}] {fr_name}\n  Requirement: {req}\n  Met? [y/n]: ").strip().lower()
                met = resp == "y"
            else:
                met = None  # Non-interactive: report requirements only

            if met is False:
                gaps.append((fr_id, fr_name, req))
                print_info(f"  OPEN GAP: [{fr_id}] {fr_name}")
            elif met is True:
                print_success(f"  MET: [{fr_id}] {fr_name}")
            else:
                print_info(f"  [{fr_id}] {fr_name}: {req}")

        if interactive and gaps:
            print_warning(f"\n{len(gaps)} gaps identified for SL{target_sl}:")
            for fr_id, fr_name, req in gaps:
                print_info(f"  - {fr_id} ({fr_name}): {req}")
        elif not interactive:
            print_info(
                f"\nRun with interactive=True for guided checklist. "
                f"Full assessment requires site survey per IEC 62443-2-1 / 3-3."
            )
