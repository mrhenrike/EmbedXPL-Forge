"""NIST SP 800-82 Rev 3 OT/ICS Security Gap Analysis Stub.

Evaluates an OT/ICS environment against NIST SP 800-82 Revision 3
'Guide to Operational Technology (OT) Security' control families.

Original research / PoC credits
--------------------------------
Source  : NIST SP 800-82r3 (public standard)
          IndustrialXPL-Forge assessment framework concept
Author  : Andre Henrique (@mrhenrike) | Uniao Geek

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

from embedxpl.core.exploit import *


_SP800_82_CONTROL_FAMILIES = {
    "AC": "Access Control — Limit access to OT systems to authorized users",
    "AU": "Audit and Accountability — Collect and protect OT system audit logs",
    "CM": "Configuration Management — Baseline and change-manage OT configs",
    "IA": "Identification and Authentication — Authenticate OT users/devices",
    "IR": "Incident Response — OT-specific incident response capability",
    "MA": "Maintenance — Secure maintenance on OT systems",
    "MP": "Media Protection — Protect OT removable media",
    "PE": "Physical and Environmental Protection — Physical OT access controls",
    "PL": "Planning — OT security planning and policies",
    "PS": "Personnel Security — OT personnel screening and training",
    "RA": "Risk Assessment — Identify and assess OT security risks",
    "CA": "Assessment, Authorization, Monitoring — OT security assessments",
    "SC": "System and Communications Protection — OT network segmentation",
    "SI": "System and Information Integrity — Patch management / malware defense",
    "SA": "System and Services Acquisition — OT security in procurement",
}

_HIGH_PRIORITY = ("AC", "IA", "SC", "SI", "IR", "CM")


class Exploit(Exploit):
    """NIST SP 800-82 Rev 3 OT Security Gap Analysis Stub."""

    __info__ = {
        "name": "NIST SP 800-82 Rev 3 OT/ICS Gap Analysis",
        "description": (
            "Assessment stub that maps an OT/ICS environment against NIST SP 800-82 "
            "Revision 3 security control families. Prioritizes high-impact controls "
            "for OT environments. Produces a gap report."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final",
        ),
        "devices": ("OT/ICS environments",),
    }

    profile = OptString("moderate", "Assessment profile: low | moderate | high")
    show_all = OptBool(True, "Show all control families")

    @mute
    def check(self) -> bool:
        return True

    def run(self) -> None:
        profile = str(self.profile).lower()
        show_all = bool(self.show_all)

        print_status(f"NIST SP 800-82 Rev 3 Gap Analysis — Profile: {profile.upper()}")
        print_info("Control families sorted by priority for OT environments:")
        print_info("=" * 65)

        for family, desc in _SP800_82_CONTROL_FAMILIES.items():
            if not show_all and family not in _HIGH_PRIORITY:
                continue
            priority = "[HIGH]" if family in _HIGH_PRIORITY else "[STD ]"
            print_info(f"  {priority} {family}: {desc}")

        print_info("\nKey OT-specific considerations per SP 800-82 Rev 3:")
        print_info("  1. Network segregation (SC): IT/OT boundary, DMZ, unidirectional gateways")
        print_info("  2. Patch management (SI): test in staging before OT deployment")
        print_info("  3. Incident response (IR): OT-tailored playbooks, forensic preservation")
        print_info("  4. Secure remote access (AC/IA): encrypted, MFA, session recording")
        print_info("  5. Asset inventory (CM): comprehensive OT asset management")
        print_info("\nFor full gap assessment: conduct site survey per SP 800-82r3 Appendix B.")
