"""ICS/IoT OSINT dorks collection for ZoomEye, Fofa, Shodan, Censys.

Curated search queries for discovering industrial control systems,
IoT devices, and embedded systems via passive intelligence platforms.
Focused on Brazil-specific deployments as documented in Daryus IoT
course research (2026).

Usage:
    from embedxpl.modules.osint.ics_iot_dorks import ICSIOTDorks
    dorks = ICSIOTDorks()
    print(dorks.shodan("printers_br"))
    print(dorks.zoomeye("dahua_dvr_br"))

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from embedxpl.core.exploit import *


@dataclass
class DorkResult:
    """A search dork and its context.

    Attributes:
        platform: Platform this dork targets (shodan/zoomeye/fofa/censys).
        category: Device/service category.
        dork: The actual search query string.
        description: What this finds.
        country: Target country filter (None = global).
        estimated_results: Rough estimate of result count.
        legal_note: Important legal/ethical note.
    """

    platform: str
    category: str
    dork: str
    description: str
    country: Optional[str] = None
    estimated_results: str = "varies"
    legal_note: str = "Authorized passive intelligence only. Do not interact with discovered systems without permission."


# Curated dork database
_DORKS: List[DorkResult] = [
    # ============ SHODAN BRAZIL-SPECIFIC ============
    DorkResult(
        platform="shodan",
        category="printers_jetdirect_br",
        dork='port:9100 product:"HP" country:"BR"',
        description="HP printers with JetDirect exposed in Brazil (course lab topic)",
        country="BR",
        estimated_results="~5,000-15,000",
    ),
    DorkResult(
        platform="shodan",
        category="modbus_plc_br",
        dork='port:502 country:"BR"',
        description="Modbus/TCP devices exposed in Brazil - PLCs, RTUs, gateways",
        country="BR",
        estimated_results="~2,000-8,000",
    ),
    DorkResult(
        platform="shodan",
        category="fuxa_scada_br",
        dork='http.title:"FUXA" country:"BR"',
        description="FUXA SCADA HMI interfaces exposed in Brazil (CVE-2026-25895/25939)",
        country="BR",
        estimated_results="~100-500",
    ),
    DorkResult(
        platform="shodan",
        category="wattrouter_solar",
        dork='intitle:"WATTrouter" "SYSTEM WEB INTERFACE"',
        description="WATTrouter solar panel controllers with unauthenticated web interface",
        country=None,
        estimated_results="~200-800",
    ),
    DorkResult(
        platform="shodan",
        category="proxmox_ve",
        dork='product:"Proxmox Virtual Environment" port:8006',
        description="Proxmox VE admin panels exposed (port 8006, root@pam target)",
        country=None,
        estimated_results="~50,000+",
    ),
    DorkResult(
        platform="shodan",
        category="scada_index_br",
        dork='intitle:"index of SCADA" country:"BR"',
        description="SCADA file listings exposed in Brazil",
        country="BR",
        estimated_results="~50-200",
    ),
    DorkResult(
        platform="shodan",
        category="openvpn_config",
        dork='intitle:"index of" .ovpn',
        description="Exposed OpenVPN configuration files",
        country=None,
        estimated_results="~500-2,000",
    ),
    DorkResult(
        platform="shodan",
        category="hikvision_camera_br",
        dork='product:"Hikvision" country:"BR"',
        description="Hikvision cameras in Brazil",
        country="BR",
        estimated_results="~100,000+",
    ),
    DorkResult(
        platform="shodan",
        category="mqtt_broker_public",
        dork='port:1883 "mosquitto"',
        description="Public MQTT brokers (Mosquitto) without auth",
        country=None,
        estimated_results="~30,000+",
    ),
    DorkResult(
        platform="shodan",
        category="compactlogix_plc",
        dork='product:"Allen-Bradley" port:44818 country:"BR"',
        description="Rockwell/Allen-Bradley CompactLogix PLCs in Brazil",
        country="BR",
        estimated_results="~200-1,000",
    ),
    # ============ ZOOMEYE ============
    DorkResult(
        platform="zoomeye",
        category="dahua_dvr_br",
        dork='(app="Dahua DVR" || device="Dahua") && (port="37777" || port="554") && country="BR"',
        description="Dahua DVR/cameras in Brazil with RTSP and management ports",
        country="BR",
        estimated_results="~10,000-50,000",
    ),
    DorkResult(
        platform="zoomeye",
        category="hikvision_ipcam_br",
        dork='Server: Hipcam RealServer has_screenshot:true country:"BR"',
        description="Hikvision IP cameras in Brazil with screenshots",
        country="BR",
        estimated_results="~5,000-20,000",
    ),
    DorkResult(
        platform="zoomeye",
        category="siemens_s7",
        dork='app="Siemens-S7-300-PLC" || app="Siemens-S7-1200-PLC"',
        description="Siemens S7 PLCs exposed (S7comm port 102)",
        country=None,
        estimated_results="~5,000-15,000",
    ),
    DorkResult(
        platform="zoomeye",
        category="fuxa_scada",
        dork='title:"FUXA"',
        description="FUXA SCADA interfaces (CVE-2026-25895/25939)",
        country=None,
        estimated_results="~500-2,000",
    ),
    # ============ FOFA ============
    DorkResult(
        platform="fofa",
        category="modbus_gateway_br",
        dork='port="502" && country="BR"',
        description="Modbus/TCP exposed in Brazil via FOFA",
        country="BR",
        estimated_results="~1,000-5,000",
    ),
    DorkResult(
        platform="fofa",
        category="jetdirect_9100_br",
        dork='port="9100" && country="BR"',
        description="JetDirect printers port 9100 in Brazil via FOFA",
        country="BR",
        estimated_results="~5,000-20,000",
    ),
    DorkResult(
        platform="fofa",
        category="dnp3_br",
        dork='port="20000" && country="BR"',
        description="DNP3 protocol devices in Brazil (port 20000)",
        country="BR",
        estimated_results="~100-500",
    ),
]


class ICSIOTDorks:
    """ICS/IoT OSINT dorks collection and query helper.

    Provides curated search queries for ZoomEye, Fofa, Shodan, and Censys
    targeting ICS, IoT, and embedded systems. Focused on Brazil deployments
    as documented in course research.

    Usage:
        dorks = ICSIOTDorks()
        for d in dorks.by_platform("shodan"):
            print(f"{d.category}: {d.dork}")
    """

    __info__ = {
        "name": "ICS/IoT OSINT Dorks",
        "category": "osint",
        "description": (
            "Curated OSINT search dorks for Shodan/ZoomEye/Fofa/Censys targeting "
            "ICS, IoT, and embedded systems. Includes Brazil-specific queries for "
            "PLCs (Modbus/S7), cameras (Hikvision/Dahua), SCADA (FUXA), printers "
            "(JetDirect), solar controllers (WATTrouter), and more."
        ),
        "legal_note": (
            "PASSIVE INTELLIGENCE ONLY. Use only information already indexed by the "
            "platform. Do not interact with discovered systems without explicit written "
            "authorization from the system owner."
        ),
    }

    def __init__(self) -> None:
        self._dorks = _DORKS

    def all(self) -> List[DorkResult]:
        """Return all dorks.

        Returns:
            All DorkResult instances.
        """
        return self._dorks

    def by_platform(self, platform: str) -> List[DorkResult]:
        """Return dorks for a specific platform.

        Args:
            platform: Platform name (shodan, zoomeye, fofa, censys).

        Returns:
            Filtered list of DorkResult.
        """
        return [d for d in self._dorks if d.platform.lower() == platform.lower()]

    def by_category(self, category: str) -> List[DorkResult]:
        """Return dorks matching a category substring.

        Args:
            category: Category substring to match.

        Returns:
            Matching DorkResult instances.
        """
        return [d for d in self._dorks if category.lower() in d.category.lower()]

    def brazil_only(self) -> List[DorkResult]:
        """Return only Brazil-specific dorks.

        Returns:
            DorkResult instances targeting Brazil.
        """
        return [d for d in self._dorks if d.country == "BR"]

    def shodan(self, category: str = "") -> str:
        """Get Shodan dork for a category.

        Args:
            category: Category filter (empty = list all).

        Returns:
            Dork string or formatted list.
        """
        results = self.by_platform("shodan")
        if category:
            results = [d for d in results if category.lower() in d.category.lower()]
        if len(results) == 1:
            return results[0].dork
        return "\n".join(f"{d.category}: {d.dork}" for d in results)

    def zoomeye(self, category: str = "") -> str:
        """Get ZoomEye dork for a category.

        Args:
            category: Category filter.

        Returns:
            Dork string or formatted list.
        """
        results = self.by_platform("zoomeye")
        if category:
            results = [d for d in results if category.lower() in d.category.lower()]
        if len(results) == 1:
            return results[0].dork
        return "\n".join(f"{d.category}: {d.dork}" for d in results)

    def summary_table(self) -> List[tuple]:
        """Return summary as list of tuples for print_table.

        Returns:
            List of (Platform, Category, Country, Description) tuples.
        """
        return [
            (d.platform, d.category, d.country or "global", d.description)
            for d in self._dorks
        ]
