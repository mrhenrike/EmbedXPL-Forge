# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Mirai/Condi obfuscated string table decoder.

Mirai and its variants (Condi, Gafgyt, Satori …) store all sensitive strings
(paths, commands, scan tokens, watchdog paths, CnC port) in an XOR-obfuscated
table initialised at runtime by ``table_init()`` in ``bot/table.c``.  The
standard XOR key is ``0xdeadbeef``; each byte of each entry is XOR'd with all
four key octets in sequence:

    byte ^= k1 (0xef)  ^  k2 (0xbe)  ^  k3 (0xad)  ^  k4 (0xde)

This module provides:
  - ``MiraiStringDecoder``: decodes raw hex blobs extracted from captured
    Mirai binaries or source table entries.
  - ``CONDI_TABLE``: pre-decoded constant table derived from the Condi-Mirai
    source (``lion001am-condi/bot/table.c``, key ``0xdeadbeef``).
  - A standalone EmbedXPL scan module that accepts a hex blob on stdin and
    decodes it, useful for rapid binary triage in the lab.

Decoded strings reference (Condi-Mirai source, key 0xdeadbeef):
  - CNC_PORT            = 3778   (0x0EC2)
  - SCAN_CB_PORT        = 9555   (0x2553)
  - SCAN_OGIN  token    = "ogin"   (login prompt marker)
  - SCAN_NCORRECT token = "ncorrect" (incorrect login marker)
  - SCAN_ASSWORD token  = "assword"  (password prompt marker)

Source reference:
  lion001am-condi/bot/table.c, table.h (XOR key 0xdeadbeef)
  jgamblin-mirai-source/mirai/bot/table.c (same key)

MITRE ATT&CK:
  T1027   — Obfuscated Files or Information
  T1140   — Deobfuscate/Decode Files or Information

Version: 1.0.0
"""

from __future__ import annotations

import binascii
import logging
import struct
from typing import Dict, List, Optional, Tuple

from embedxpl.core.exploit import (
    Exploit as BaseExploit,
    OptIP,
    OptString,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)

# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

logger = logging.getLogger("embedxpl.modules.tools.mirai_string_decoder")

# Standard Mirai XOR key (0xdeadbeef)
_DEFAULT_KEY: int = 0xDEADBEEF

# Condi/Mirai table entries (raw hex from lion001am-condi/bot/table.c)
# Decoded by this module; kept for reference and offline analysis.
_CONDI_TABLE_RAW: List[Tuple[str, bytes, str]] = [
    ("TABLE_CNC_PORT",       bytes([0x2C, 0xE0]),            "3778"),
    ("TABLE_SCAN_CB_PORT",   bytes([0x07, 0x71]),            "9555"),
    ("TABLE_SCAN_OGIN",      bytes([0x4D, 0x45, 0x4B, 0x4C, 0x22]), "ogin"),
    ("TABLE_SCAN_ASSWORD",   bytes([0x43, 0x51, 0x51, 0x55, 0x4D, 0x50, 0x46, 0x22]), "assword"),
    ("TABLE_SCAN_NCORRECT",  bytes([0x4C, 0x41, 0x4D, 0x50, 0x50, 0x47, 0x41, 0x56, 0x22]), "ncorrect"),
    ("TABLE_SCAN_SHELL",     bytes([0x51, 0x4A, 0x47, 0x4E, 0x4E, 0x22]), "shell"),
    ("TABLE_SCAN_ENABLE",    bytes([0x47, 0x4C, 0x43, 0x40, 0x4E, 0x47, 0x22]), "enable"),
    ("TABLE_SCAN_SH",        bytes([0x51, 0x4A, 0x22]), "sh"),
    ("TABLE_KILLER_ARM7",    bytes([0x43, 0x50, 0x4F, 0x15, 0x22]), "arm7"),
    ("TABLE_KILLER_MIPS",    bytes([0x4F, 0x4B, 0x52, 0x51, 0x22]), "mips"),
    ("TABLE_KILLER_X86",     bytes([0x5A, 0x1A, 0x14, 0x22]), "x86"),
]

# Full decoded constant table (convenient dict for use by other modules)
CONDI_TABLE: Dict[str, str] = {
    "TABLE_CNC_PORT":    "3778",
    "TABLE_SCAN_CB_PORT": "9555",
    "TABLE_SCAN_OGIN":   "ogin",
    "TABLE_SCAN_ASSWORD": "assword",
    "TABLE_SCAN_NCORRECT": "ncorrect",
    "TABLE_SCAN_SHELL":  "shell",
    "TABLE_SCAN_ENABLE": "enable",
    "TABLE_SCAN_SH":     "sh",
    "TABLE_KILLER_ARM7": "arm7",
    "TABLE_KILLER_MIPS": "mips",
    "TABLE_KILLER_X86":  "x86",
    "TABLE_KILLER_ARM":  "arm",
    "TABLE_KILLER_PPC":  "ppc",
}

# Known Mirai XOR keys across variants
KNOWN_KEYS: Dict[str, int] = {
    "mirai_original":  0xDEADBEEF,
    "condi":           0xDEADBEEF,
    "satori":          0xDEADBEEF,
    "gafgyt":          0x22222222,
    "bashlite":        0x22222222,
    "mozi":            0xDEADBEEF,
}


class MiraiStringDecoder:
    """XOR-based string decoder for Mirai/Condi obfuscated table entries.

    Usage::

        dec = MiraiStringDecoder()
        plaintext = dec.decode_hex("2CE0")     # decodes CnC port bytes -> b'\\x0e\\xc2'
        port = struct.unpack(">H", plaintext)[0]  # -> 3778

    Args:
        key: 32-bit XOR key (default 0xDEADBEEF).
    """

    def __init__(self, key: int = _DEFAULT_KEY) -> None:
        """Initialise with XOR key.

        Args:
            key: 32-bit XOR key used by the target Mirai variant.
        """
        self.key = key
        self._k1 = key & 0xFF
        self._k2 = (key >> 8) & 0xFF
        self._k3 = (key >> 16) & 0xFF
        self._k4 = (key >> 24) & 0xFF

    def decode_bytes(self, data: bytes) -> bytes:
        """Decode a bytes object using the XOR key.

        Each byte is XOR'd with all four key octets in sequence (k1 ^ k2 ^ k3 ^ k4).

        Args:
            data: Raw obfuscated bytes (trailing null ``\\x22`` terminator is stripped).

        Returns:
            Decoded bytes with trailing null stripped.
        """
        xor_byte = self._k1 ^ self._k2 ^ self._k3 ^ self._k4
        decoded = bytes(b ^ xor_byte for b in data)
        # Strip Mirai's \\x22 table terminator (which decodes to \\x00)
        return decoded.rstrip(b"\x00")

    def decode_hex(self, hex_string: str) -> bytes:
        """Decode a hex string (e.g. '2CE0') using the XOR key.

        Args:
            hex_string: Hex-encoded obfuscated bytes (no '0x' prefix needed).

        Returns:
            Decoded bytes.
        """
        raw = binascii.unhexlify(hex_string.replace(" ", "").replace("\\x", ""))
        return self.decode_bytes(raw)

    def decode_c_literal(self, c_literal: str) -> bytes:
        """Decode a C string literal like '\\\\x2C\\\\xE0\\\\x22'.

        Args:
            c_literal: C-style string literal with hex escape sequences.

        Returns:
            Decoded bytes.
        """
        # Parse \\xNN sequences
        raw = bytes(int(tok, 16) for tok in
                    c_literal.replace('"', "").replace("\\x", " ").split() if tok)
        return self.decode_bytes(raw)

    def decode_table(
        self, entries: List[Tuple[str, bytes]]
    ) -> Dict[str, bytes]:
        """Decode a list of (name, raw_bytes) table entries.

        Args:
            entries: List of (table_key_name, raw_bytes) pairs from table_init().

        Returns:
            Dict mapping table key name to decoded bytes.
        """
        return {name: self.decode_bytes(raw) for name, raw in entries}

    def detect_cnc_port(self, raw_bytes: bytes) -> Optional[int]:
        """Attempt to decode raw bytes as a 2-byte big-endian CnC port.

        Args:
            raw_bytes: Raw 2-byte obfuscated port value.

        Returns:
            Decoded port integer, or None if length != 2.
        """
        decoded = self.decode_bytes(raw_bytes)
        if len(decoded) != 2:
            return None
        return struct.unpack(">H", decoded)[0]


class Exploit(BaseExploit):
    """Mirai/Condi obfuscated string table decoder (analysis tool).

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    Version: 1.0.0
    """

    __info__ = {
        "name": "Mirai String Table Decoder",
        "description": (
            "Decodes XOR-obfuscated string table entries from Mirai/Condi/Gafgyt "
            "variants using the standard key (0xdeadbeef) or a user-supplied key. "
            "Prints the pre-decoded Condi-Mirai constant table and can decode "
            "arbitrary hex blobs.  Analysis tool -- no network activity."
        ),
        "authors": ["Andre Henrique (@mrhenrike) | Uniao Geek"],
        "references": [
            "https://github.com/jgamblin/Mirai-Source-Code/blob/master/mirai/bot/table.c",
            "https://krebsonsecurity.com/2016/10/source-code-for-iot-attack-tool-mirai-released/",
        ],
        "devices": ["N/A — forensic/analysis module"],
        "severity": "info",
        "apt_groups": ["Mirai Botnet", "Condi Botnet"],
        "mitre": ["T1027", "T1140"],
    }

    target = OptIP("", "Not used (analysis module)")
    xor_key = OptString("deadbeef", "32-bit XOR key in hex (default: deadbeef = Mirai standard)")
    hex_blob = OptString("", "Optional hex blob to decode (e.g. '2CE022' for CnC port entry)")
    variant = OptString("condi", "Variant hint for key lookup: mirai_original/condi/satori/gafgyt/mozi")

    @mute
    def check(self) -> bool:
        """Always returns True -- this is an analysis module, not a vulnerability scanner.

        Returns:
            True.
        """
        return True

    def run(self) -> None:
        """Print decoded Condi-Mirai table and optionally decode a supplied hex blob."""
        # Resolve XOR key
        key_hex = str(self.xor_key).strip().lower().replace("0x", "")
        try:
            xor_key = int(key_hex, 16)
        except ValueError:
            variant_key = str(self.variant).lower()
            xor_key = KNOWN_KEYS.get(variant_key, _DEFAULT_KEY)
            print_warning("[MiraiDec] Invalid xor_key '{}', using {} ({}) -> 0x{:08x}".format(
                self.xor_key, variant_key, "known variant key", xor_key))

        decoder = MiraiStringDecoder(key=xor_key)

        print_status("[MiraiDec] XOR key: 0x{:08X} | octets: k1=0x{:02X} k2=0x{:02X} "
                     "k3=0x{:02X} k4=0x{:02X}".format(
                         xor_key, decoder._k1, decoder._k2, decoder._k3, decoder._k4))

        # Print pre-decoded Condi-Mirai table
        print_info("[MiraiDec] Condi-Mirai source table (key=0xDEADBEEF):")
        for name, raw, expected in _CONDI_TABLE_RAW:
            decoded = decoder.decode_bytes(raw)
            is_port = len(raw) == 2
            if is_port:
                port_val = struct.unpack(">H", decoded.ljust(2, b"\x00")[:2])[0]
                display = "{} (port)".format(port_val)
            else:
                try:
                    display = repr(decoded.decode("latin-1"))
                except Exception:
                    display = repr(decoded)
            match = "[OK]" if (expected in display or str(expected) == display.strip("'\"")) else "[?]"
            print_success("[MiraiDec] {} {} {:<30s} raw={}".format(
                match, name, display,
                " ".join("\\x{:02x}".format(b) for b in raw)))

        # Known Mirai variant keys
        print_info("[MiraiDec] Known XOR keys by variant:")
        for variant_name, k in KNOWN_KEYS.items():
            print_info("[MiraiDec]   {:<20s} 0x{:08X}".format(variant_name, k))

        # Decode supplied blob
        blob = str(self.hex_blob).strip()
        if blob:
            try:
                decoded_blob = decoder.decode_hex(blob)
                print_success("[MiraiDec] Decoded blob: raw={} -> {}".format(
                    blob, repr(decoded_blob)))
                if len(decoded_blob) == 2:
                    port = struct.unpack(">H", decoded_blob)[0]
                    print_success("[MiraiDec] Interpreted as 16-bit BE port: {}".format(port))
            except Exception as exc:
                print_error("[MiraiDec] Failed to decode blob '{}': {}".format(blob, exc))
