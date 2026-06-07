"""ICS Device Default Credential Database for EmbedXPL-Forge.

Comprehensive database of known default credentials for ICS/OT devices,
compiled from public sources including the ISF icssploit wordlists, ICS-CERT
advisories, and vendor documentation.

Provides both a structured Python database and helper functions for
credential lookups by vendor, product, or protocol.

Source wordlists: submodules/OT/isf/icssploit/wordlists/ (defaults.txt,
usernames.txt, passwords.txt).

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class IcsCredential:
    """A default credential entry for an ICS/OT device."""

    vendor: str
    product: str
    username: str
    password: str
    protocol: str
    port: int
    notes: str = ""
    cve_reference: str = ""


# fmt: off
ICS_DEFAULT_CREDENTIALS: tuple[IcsCredential, ...] = (
    # Schneider Electric
    IcsCredential("Schneider Electric", "Modicon M340",          "USER",       "USER",       "http",   80,  "Default web HMI credentials"),
    IcsCredential("Schneider Electric", "Modicon M340",          "USER",       "USER",       "ftp",    21,  "Default FTP credentials"),
    IcsCredential("Schneider Electric", "Modicon M340",          "ntpupdate",  "ntpupdate",  "http",   80,  "NTP update service account"),
    IcsCredential("Schneider Electric", "Modicon Quantum",       "USER",       "USER",       "http",   80,  "Default web HMI credentials"),
    IcsCredential("Schneider Electric", "Modicon TSX",           "USER",       "USER",       "http",   80,  "Default web HMI credentials"),
    IcsCredential("Schneider Electric", "Magelis HMI",           "USER",       "USER",       "http",   80,  "Default web interface", "CVE-2024-29104"),
    IcsCredential("Schneider Electric", "APC UPS",               "apc",        "apc",        "http",   80,  "Default web management"),
    IcsCredential("Schneider Electric", "APC UPS",               "admin",      "",           "http",   80,  "Blank password default"),
    IcsCredential("Schneider Electric", "Conext ComBox",         "admin",      "admin",      "http",   80,  "Default HTTP management", "CVE-2017-6019"),
    IcsCredential("Schneider Electric", "Conext ComBox",         "admin",      "password",   "http",   80,  "Alternate default", "CVE-2017-6019"),
    IcsCredential("Schneider Electric", "EcoStruxure",           "admin",      "admin",      "http",   80,  "Default web console", "CVE-2021-22763"),
    IcsCredential("Schneider Electric", "IONSCADA",              "Administrator", "password", "http",  80,  "Default admin account"),

    # Siemens
    IcsCredential("Siemens", "S7-300/400",                       "admin",      "admin",      "http",   80,  "Default Simatic manager"),
    IcsCredential("Siemens", "S7-1200/1500",                     "admin",      "admin",      "http",   80,  "Default TIA portal web server"),
    IcsCredential("Siemens", "S7-1500",                          "admin",      "admin",      "https",  443, "TLS-enabled default", "CVE-2024-38876"),
    IcsCredential("Siemens", "SINEMA Remote Connect",            "admin",      "admin",      "https",  443, "Default management interface"),
    IcsCredential("Siemens", "SCALANCE X-200",                   "admin",      "admin",      "http",   80,  "Industrial Ethernet switch default"),
    IcsCredential("Siemens", "SCALANCE S-600",                   "admin",      "admin",      "http",   80,  "Industrial security module default"),
    IcsCredential("Siemens", "WinCC",                            "admin",      "admin",      "http",   80,  "SCADA web client default"),
    IcsCredential("Siemens", "WinCC OA",                         "root",       "root",       "tcp",    4999, "Default manager port"),

    # Rockwell Automation / Allen-Bradley
    IcsCredential("Rockwell Automation", "ControlLogix 1756",    "admin",      "1234",       "http",   80,  "Default web module"),
    IcsCredential("Rockwell Automation", "ControlLogix 1756",    "admin",      "admin",      "http",   80,  "Alternate default", "CVE-2023-46280"),
    IcsCredential("Rockwell Automation", "MicroLogix 1100",      "admin",      "1234",       "http",   80,  "Default web server"),
    IcsCredential("Rockwell Automation", "Studio 5000",          "Administrator", "1234",    "http",   80,  "Default project admin"),
    IcsCredential("Rockwell Automation", "FactoryTalk",          "admin",      "admin",      "http",   8080, "Default FactoryTalk admin"),

    # ABB
    IcsCredential("ABB", "AC500 PLC",                            "admin",      "admin",      "http",   80,  "Default web server"),
    IcsCredential("ABB", "ASPECT BMS",                           "admin",      "admin",      "http",   80,  "Default BMS interface", "CVE-2023-28489"),
    IcsCredential("ABB", "Symphony Plus",                        "admin",      "admin",      "http",   80,  "Default DCS web interface"),
    IcsCredential("ABB", "800xA DCS",                            "Administrator", "Abb@1234", "http",  80,  "Default engineering station"),
    IcsCredential("ABB", "IRB Robot Controller",                 "admin",      "admin",      "telnet", 23,  "Default telnet management"),

    # GE / GE Digital
    IcsCredential("GE Digital", "iFIX SCADA",                    "admin",      "admin",      "http",   80,  "Default iFIX web client"),
    IcsCredential("GE Digital", "Proficy Historian",             "Administrator", "password", "http",  80,  "Default historian admin"),
    IcsCredential("GE Digital", "D20 RTU",                       "admin",      "admin",      "http",   80,  "Default RTU web interface", "CVE-2024-41203"),
    IcsCredential("GE Digital", "PAC Systems RX3i",              "admin",      "admin",      "http",   80,  "Default PLC web server"),
    IcsCredential("GE Digital", "MDS ORBIT",                     "admin",      "admin",      "http",   80,  "Default radio modem management"),

    # Honeywell
    IcsCredential("Honeywell", "Experion PKS",                   "admin",      "admin",      "http",   80,  "Default DCS interface"),
    IcsCredential("Honeywell", "UniSim Operations",               "admin",      "admin",      "http",   80,  "Default simulator access"),
    IcsCredential("Honeywell", "HC900 Process Controller",       "admin",      "admin",      "http",   80,  "Default web server"),
    IcsCredential("Honeywell", "RTU2020",                        "admin",      "admin",      "http",   80,  "Default RTU management"),

    # Moxa
    IcsCredential("Moxa", "EDR-G9010",                           "admin",      "moxa",       "http",   80,  "Default industrial router", "CVE-2023-27357"),
    IcsCredential("Moxa", "EDR-G9010",                           "admin",      "moxa",       "telnet", 23,  "Default telnet access"),
    IcsCredential("Moxa", "NPort 5000",                          "admin",      "moxa",       "http",   80,  "Default serial-to-Ethernet server"),
    IcsCredential("Moxa", "MXview",                              "admin",      "moxa",       "http",   80,  "Default network management"),
    IcsCredential("Moxa", "EDS Switch",                          "admin",      "moxa",       "http",   80,  "Default managed switch"),

    # OMRON
    IcsCredential("OMRON", "CJ2 PLC",                            "admin",      "1234",       "http",   80,  "Default PLC web server"),
    IcsCredential("OMRON", "NJ/NX Controller",                   "admin",      "admin",      "http",   80,  "Default web interface"),
    IcsCredential("OMRON", "SYSMAC Studio",                      "admin",      "admin",      "http",   80,  "Default engineering environment"),
    IcsCredential("OMRON", "HMI NS Series",                      "admin",      "1234",       "http",   80,  "Default HMI access"),

    # Phoenix Contact
    IcsCredential("Phoenix Contact", "FL SWITCH",                "admin",      "private",    "http",   80,  "Default managed switch"),
    IcsCredential("Phoenix Contact", "AXC F 2152",               "admin",      "admin",      "http",   80,  "Default PLC web server"),
    IcsCredential("Phoenix Contact", "TC ROUTER",                "admin",      "private",    "http",   80,  "Default industrial router"),

    # OSIsoft (AVEVA)
    IcsCredential("OSIsoft", "PI Server",                        "PIWorld",    "",           "tcp",    5450, "Anonymous PI read account", "CVE-2024-35587"),
    IcsCredential("OSIsoft", "PI Web API",                       "admin",      "admin",      "https",  443,  "Default PI Web API admin"),
    IcsCredential("AVEVA", "PI Server",                          "PIWorld",    "",           "tcp",    5450, "Anonymous PI read account"),
    IcsCredential("AVEVA", "System Platform",                    "Administrator", "wwAdmin", "http",   80,  "Default ArchestrA admin"),

    # Emerson
    IcsCredential("Emerson", "DeltaV DCS",                       "Administrator", "deltav",  "http",   80,  "Default DeltaV admin"),
    IcsCredential("Emerson", "ROC800 RTU",                       "admin",      "admin",      "http",   80,  "Default RTU web interface"),
    IcsCredential("Emerson", "Ovation DCS",                      "admin",      "admin",      "http",   80,  "Default DCS interface"),

    # Yokogawa
    IcsCredential("Yokogawa", "CENTUM VP",                       "admin",      "admin",      "http",   80,  "Default DCS web server"),
    IcsCredential("Yokogawa", "ProSafe-RS",                      "admin",      "admin",      "http",   80,  "Default safety system"),

    # Inductive Automation
    IcsCredential("Inductive Automation", "Ignition SCADA",      "admin",      "password",   "http",   8088, "Default Ignition gateway"),
    IcsCredential("Inductive Automation", "Ignition SCADA",      "admin",      "password",   "https",  8043, "Default Ignition TLS gateway"),

    # Generic ICS defaults (from ISF wordlists)
    IcsCredential("Generic", "ICS Device",                       "admin",      "admin",      "http",   80,  "Widely used default"),
    IcsCredential("Generic", "ICS Device",                       "admin",      "1234",       "http",   80,  "Numeric default"),
    IcsCredential("Generic", "ICS Device",                       "admin",      "password",   "http",   80,  "Common default"),
    IcsCredential("Generic", "ICS Device",                       "admin",      "12345",      "http",   80,  "Numeric sequence default"),
    IcsCredential("Generic", "ICS Device",                       "admin",      "",           "http",   80,  "Blank password default"),
    IcsCredential("Generic", "ICS Device",                       "root",       "root",       "ssh",    22,  "Root SSH default"),
    IcsCredential("Generic", "ICS Device",                       "root",       "admin",      "ssh",    22,  "Root-admin SSH default"),
    IcsCredential("Generic", "ICS Device",                       "root",       "1234",       "telnet", 23,  "Root telnet default"),
    IcsCredential("Generic", "ICS Device",                       "operator",   "operator",   "http",   80,  "Operator role default"),
    IcsCredential("Generic", "ICS Device",                       "engineer",   "engineer",   "http",   80,  "Engineering role default"),
    IcsCredential("Generic", "ICS Device",                       "guest",      "guest",      "http",   80,  "Guest account default"),
    IcsCredential("Generic", "ICS Device",                       "service",    "service",    "http",   80,  "Service account default"),
    IcsCredential("Generic", "ICS Device",                       "supervisor", "supervisor", "http",   80,  "Supervisor account default"),
    IcsCredential("Generic", "Modbus RTU/TCP",                   "admin",      "admin",      "modbus", 502, "Modbus gateway default"),
    IcsCredential("Generic", "DNP3 Gateway",                     "admin",      "admin",      "dnp3",   20000, "DNP3 gateway default"),
    IcsCredential("Generic", "OPC DA/UA Server",                 "admin",      "admin",      "opcua",  4840, "OPC UA server default"),
    IcsCredential("Generic", "BACnet Controller",                "admin",      "admin",      "bacnet", 47808, "BACnet IP controller default"),
)
# fmt: on


def lookup_by_vendor(vendor: str) -> list[IcsCredential]:
    """Return all credential entries matching the given vendor name (case-insensitive).

    Args:
        vendor: Vendor name substring to search for.

    Returns:
        List of matching :class:`IcsCredential` entries.
    """
    vendor_lower = vendor.lower()
    return [c for c in ICS_DEFAULT_CREDENTIALS if vendor_lower in c.vendor.lower()]


def lookup_by_product(product: str) -> list[IcsCredential]:
    """Return all credential entries matching the given product name (case-insensitive).

    Args:
        product: Product name substring to search for.

    Returns:
        List of matching :class:`IcsCredential` entries.
    """
    product_lower = product.lower()
    return [c for c in ICS_DEFAULT_CREDENTIALS if product_lower in c.product.lower()]


def lookup_by_protocol(protocol: str, port: Optional[int] = None) -> list[IcsCredential]:
    """Return credential entries for a given protocol, optionally filtered by port.

    Args:
        protocol: Protocol string (e.g. ``"http"``, ``"ssh"``, ``"telnet"``).
        port: Optional port number to further filter results.

    Returns:
        List of matching :class:`IcsCredential` entries.
    """
    proto_lower = protocol.lower()
    results = [c for c in ICS_DEFAULT_CREDENTIALS if c.protocol == proto_lower]
    if port is not None:
        results = [c for c in results if c.port == port]
    return results


def to_wordlist(credentials: Optional[list[IcsCredential]] = None) -> list[str]:
    """Convert credential entries to ``username:password`` wordlist lines.

    Args:
        credentials: Subset of credentials to convert.  If None, uses the
            full :data:`ICS_DEFAULT_CREDENTIALS` database.

    Returns:
        Deduplicated list of ``"username:password"`` strings.
    """
    source = credentials if credentials is not None else list(ICS_DEFAULT_CREDENTIALS)
    seen: set[str] = set()
    lines: list[str] = []
    for cred in source:
        entry = "{}:{}".format(cred.username, cred.password)
        if entry not in seen:
            seen.add(entry)
            lines.append(entry)
    return lines


def cve_affected_credentials() -> list[IcsCredential]:
    """Return only credential entries that are associated with a known CVE.

    Returns:
        List of :class:`IcsCredential` entries with a non-empty
        ``cve_reference`` field.
    """
    return [c for c in ICS_DEFAULT_CREDENTIALS if c.cve_reference]
