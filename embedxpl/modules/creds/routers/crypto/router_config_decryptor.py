"""
embedxpl/modules/creds/routers/crypto/router_config_decryptor.py

Unified Multi-Vendor Router Configuration Decryptor.

Aggregates vendor-specific config decryption and credential extraction into
a single entry point. Wraps: Cisco Type 7, Juniper $9$, D-Link DES/AES,
ZTE AES/XOR, Huawei AES-256 (via huawei_password_derive), MikroTik .backup.

Usage:
    from embedxpl.modules.creds.routers.crypto.router_config_decryptor import (
        auto_detect_and_decrypt,
        extract_all_credentials,
    )

    plaintext, vendor = auto_detect_and_decrypt(raw_bytes)
    creds = extract_all_credentials(plaintext.decode())

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""
from __future__ import annotations

import re
from typing import Optional

from embedxpl.modules.creds.routers.crypto.cisco_type7_decode import (
    decode_config_passwords as cisco_decode_config,
    decode_type7,
)
from embedxpl.modules.creds.routers.crypto.dlink_config_decrypt import (
    auto_decrypt as dlink_auto_decrypt,
    extract_credentials as dlink_extract_creds,
)
from embedxpl.modules.creds.routers.crypto.juniper_type9_decode import (
    decode_config_passwords as juniper_decode_config,
    decode_type9,
)
from embedxpl.modules.creds.routers.crypto.zte_config_decrypt import (
    auto_decrypt as zte_auto_decrypt,
    extract_credentials as zte_extract_creds,
)

__version__ = "1.0.0"


def detect_vendor(data: bytes) -> Optional[str]:
    """Detect the router vendor from config file content or magic bytes.

    Args:
        data: raw config file bytes.

    Returns:
        Vendor name string or None.
    """
    text = data[:4096].decode("utf-8", errors="replace").lower()

    if any(k in text for k in ("ios", "cisco", "router ospf", "router bgp", "interface gigabit")):
        return "cisco"
    if any(k in text for k in ("junos", "juniper", "$9$", "set system")):
        return "juniper"
    if any(k in text for k in ("d-link", "dlink", "dir-")):
        return "dlink"
    if any(k in text for k in ("zte", "zxhn", "zxdsl", "gpon")):
        return "zte"
    if any(k in text for k in ("huawei", "vrp", "sysname")):
        return "huawei"
    if any(k in text for k in ("routeros", "mikrotik", "/ip address")):
        return "mikrotik"

    # Check magic bytes
    if data[:4] == b"DCFG":
        return "dlink"
    if data[:4] == b"\x88\xAC\xA1\xB1":
        return "mikrotik"

    return None


def auto_detect_and_decrypt(data: bytes) -> Optional[tuple[bytes, str]]:
    """Auto-detect vendor and decrypt a router config file.

    Tries all supported vendors if detection fails.

    Returns:
        Tuple of (decrypted_bytes, vendor_string) or None.
    """
    vendor = detect_vendor(data)

    if vendor == "dlink":
        result = dlink_auto_decrypt(data)
        if result:
            return result[0], "dlink"

    if vendor == "zte":
        result = zte_auto_decrypt(data)
        if result:
            return result[0], "zte"

    # For text-based configs (Cisco, Juniper), return as-is
    # (individual password decoders handle inline encoded values)
    if vendor in ("cisco", "juniper", "huawei", "mikrotik"):
        return data, vendor

    # Unknown vendor: try all binary decryptors
    for decrypt_fn, vname in [
        (dlink_auto_decrypt, "dlink"),
        (zte_auto_decrypt, "zte"),
    ]:
        result = decrypt_fn(data)
        if result:
            return result[0], vname

    # If it looks like text, return it
    try:
        data.decode("utf-8")
        return data, "unknown"
    except UnicodeDecodeError:
        pass

    return None


def extract_all_credentials(config_text: str) -> list[dict[str, str]]:
    """Extract credentials from a config using all vendor decoders.

    Combines Cisco Type 7, Juniper $9$, D-Link XML, and ZTE XML extraction.

    Returns:
        Deduplicated list of credential dicts.
    """
    all_creds: list[dict[str, str]] = []
    seen: set[str] = set()

    # Cisco Type 7
    for entry in cisco_decode_config(config_text):
        key = f"cisco:{entry['encoded']}"
        if key not in seen:
            seen.add(key)
            entry["vendor"] = "cisco"
            all_creds.append(entry)

    # Juniper $9$
    for entry in juniper_decode_config(config_text):
        key = f"juniper:{entry['encoded']}"
        if key not in seen:
            seen.add(key)
            entry["vendor"] = "juniper"
            all_creds.append(entry)

    # D-Link XML
    for entry in dlink_extract_creds(config_text):
        key = f"dlink:{entry['type']}:{entry['value']}"
        if key not in seen:
            seen.add(key)
            entry["vendor"] = "dlink"
            all_creds.append(entry)

    # ZTE XML
    for entry in zte_extract_creds(config_text):
        key = f"zte:{entry['type']}:{entry['value']}"
        if key not in seen:
            seen.add(key)
            entry["vendor"] = "zte"
            all_creds.append(entry)

    # Generic password patterns (catch-all)
    generic_patterns = [
        (r"password\s*[=:]\s*(\S+)", "generic_password"),
        (r"secret\s*[=:]\s*(\S+)", "generic_secret"),
        (r"community\s+(\S+)", "snmp_community"),
    ]
    for pat, cred_type in generic_patterns:
        for match in re.finditer(pat, config_text, re.IGNORECASE):
            val = match.group(1).strip('"\'')
            key = f"generic:{cred_type}:{val}"
            if key not in seen and len(val) > 2:
                seen.add(key)
                all_creds.append({
                    "vendor": "generic",
                    "type": cred_type,
                    "value": val,
                    "context": match.group(0)[:120],
                })

    return all_creds


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <config_file>")
        sys.exit(1)

    filepath = sys.argv[1]
    with open(filepath, "rb") as f:
        raw = f.read()

    result = auto_detect_and_decrypt(raw)
    if result is None:
        print("[!] Could not decrypt or detect format.")
        sys.exit(1)

    decrypted, vendor = result
    print(f"[+] Vendor: {vendor}")
    print(f"[+] Size: {len(decrypted)} bytes")

    text = decrypted.decode("utf-8", errors="replace")
    creds = extract_all_credentials(text)
    if creds:
        print(f"\n[+] Found {len(creds)} credential(s):")
        for c in creds:
            v = c.get("vendor", "?")
            t = c.get("type", "?")
            val = c.get("decoded", c.get("value", "?"))
            print(f"    [{v}/{t}] {val}")
    else:
        print("\n[-] No credentials found.")
