"""RKES Rollback-Replay Attack — Alps Alpine R53R0 / Suzuki Swift 2024 (CVE-2026-49319).

The Alps Alpine R53R0 Remote Keyless Entry System fails to invalidate captured
rolling codes after use.  An attacker within 433 MHz RF range who records two
consecutive key-fob transmissions can later replay the same pair to unlock the
vehicle (RollJam variant).

CVSS: 6.5 Medium | AV:A/AC:L/PR:N/UI:N
HW_REQ: HackRF One / CC1101 / Flipper Zero (Sub-GHz 433 MHz)

Original research / PoC credits
--------------------------------
CVE     : CVE-2026-49319
CVSS    : 6.5 (Medium)
Source  : WirelessXPL-Forge wirelessxpl/modules/generic/subghz/
          rkes_rollback_replay_cve_2026_49319.py
          RollJam technique: Samy Kamkar (DEF CON 23)
          ProtoPirate: https://github.com/G4MEOVER18/ProtoPirate

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

from embedxpl.core.exploit import *


_CVE = "CVE-2026-49319"


class Exploit(Exploit):
    """RKES Rollback-Replay Attack (CVE-2026-49319)."""

    __info__ = {
        "name": "RKES Rollback-Replay (CVE-2026-49319) — Alps Alpine R53R0",
        "description": (
            "Alps Alpine R53R0 RKES (2024 Suzuki Swift) fails to invalidate used "
            "rolling codes. RollJam attack: jam+capture Code A, capture Code B, "
            "replay Code A to unlock; Code B still valid for next use. "
            "CVSS 6.5 (Medium). Requires 433 MHz RF hardware."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
            # RollJam technique: Samy Kamkar (DEF CON 23)
        ),
        "references": (
            "https://www.cve.org/CVERecord?id=CVE-2026-49319",
            "https://github.com/G4MEOVER18/RollJam",
            "https://github.com/G4MEOVER18/ProtoPirate",
            "https://samy.pl/rolljam/",
        ),
        "devices": ("2024 Suzuki Swift (Alps Alpine R53R0)", "Other Alps R53R0-based RKES"),
    }

    hw_tool = OptString("flipper_zero", "RF hardware: flipper_zero | hackrf | cc1101")
    freq_mhz = OptString("433.92", "Target frequency in MHz")
    dry_run = OptBool(True, "Dry run — describe attack only")

    @mute
    def check(self) -> bool:
        return True

    def run(self) -> None:
        hw = str(self.hw_tool)
        freq = str(self.freq_mhz)
        dry_run = bool(self.dry_run)

        print_status(f"RKES Rollback-Replay probe — {_CVE}")
        print_info(f"Target frequency: {freq} MHz | Hardware: {hw}")

        if dry_run:
            print_info(
                f"DRY-RUN: RollJam attack against Alps R53R0 RKES. "
                f"Phase 1: jam {freq} MHz + capture Code A (key does not lock car). "
                f"Phase 2: continue jam + capture Code B. "
                f"Phase 3: release jam, replay Code A → car unlocks. "
                f"Code B retained for future access. "
                f"Requires: {hw} capable of jam+rx on {freq} MHz."
            )
        else:
            print_warning(
                f"Live mode for {_CVE}. Use WirelessXPL-Forge rkes_rollback_replay module "
                "with full HackRF/Flipper Zero jam+capture orchestration."
            )
