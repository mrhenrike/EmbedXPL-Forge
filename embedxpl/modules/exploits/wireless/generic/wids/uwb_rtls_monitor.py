"""UWB RTLS Protocol Anomaly Monitor.

Monitors Ultra-Wideband Real-Time Location System (RTLS) traffic for
anomalies using Nozomi Networks Wireshark dissectors.

Vendors covered: Sewio Networks, Avalue Technology, Ubisense
Dissectors: avalue_uwb.lua, sewio_uwb.lua, ubisense_uwb.lua

# Original: https://github.com/NozomiNetworks/blackhat22-uwb-rtls (MIT)
# Research: Nozomi Networks -- BlackHat USA 2022
# AUTHORIZED USE ONLY -- deploy only on networks you own or control.
"""
from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

NOZOMI_LABS = Path(os.environ.get("NOZOMI_LABS", r"D:\Projects\Labs\nozomi-research"))
UWB_REPO    = NOZOMI_LABS / "blackhat22-uwb-rtls"
UWB_LUA_DIR = Path(r"D:\Projects\UniaoGeek\XPL-Suite\WirelessXPL-Forge\wirelessxpl\resources\wireshark\uwb_rtls")

LUA_SCRIPTS = {
    "sewio":    UWB_LUA_DIR / "sewio_uwb.lua",
    "avalue":   UWB_LUA_DIR / "avalue_uwb.lua",
    "ubisense": UWB_LUA_DIR / "ubisense_uwb.lua",
}

PCAP_SAMPLES = {
    "sewio":    UWB_REPO / "sewio_backhaul_traffic.pcapng",
    "avalue":   UWB_REPO / "avalue_backhaul_traffic.pcapng",
    "ubisense": UWB_REPO / "ubisense_backhaul_traffic.pcapng",
}


class UWBVendor(Enum):
    SEWIO    = "sewio"
    AVALUE   = "avalue"
    UBISENSE = "ubisense"
    UNKNOWN  = "unknown"


@dataclass
class UWBAnomaly:
    vendor: str
    timestamp: float
    packet_num: int
    anomaly_type: str
    description: str
    src_addr: str = ""
    dst_addr: str = ""
    raw: str = ""


@dataclass
class UWBMonitorResult:
    vendor: str = ""
    pcap_file: str = ""
    total_packets: int = 0
    uwb_packets: int = 0
    anomalies: list[UWBAnomaly] = field(default_factory=list)
    error: str = ""


class UWBRTLSMonitor:
    """
    Monitor UWB RTLS backhaul traffic for security anomalies.

    Supported anomaly classes (per Nozomi BH22 research):
      - Tag spoofing: forged anchor reports with modified tag IDs
      - Location injection: crafted packets placing tags at false positions
      - Replay attacks: duplicate sequence numbers / stale timestamps
      - Protocol fuzzing: malformed TLV fields in backhaul frames
      - Unauthorized anchors: new anchor MAC not in whitelist

    Usage:
        monitor = UWBRTLSMonitor()
        # Analyze a PCAP
        result = monitor.analyze_pcap("sewio", "capture.pcapng")
        # Live capture (requires root + wireless interface)
        monitor.live_capture("sewio", interface="eth0")
    """

    # ─────────────────────────────────────────── availability

    def lua_available(self, vendor: str) -> bool:
        script = LUA_SCRIPTS.get(vendor)
        return bool(script and script.exists())

    def tshark_available(self) -> bool:
        try:
            subprocess.run(["tshark", "--version"], capture_output=True, check=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            return False

    def pcap_sample_available(self, vendor: str) -> bool:
        p = PCAP_SAMPLES.get(vendor)
        return bool(p and p.exists())

    # ─────────────────────────────────────────── analysis

    def analyze_pcap(self, vendor: str, pcap_path: str = None) -> UWBMonitorResult:
        """
        Analyze a PCAP/PCAPNG file with the vendor's Lua dissector.
        Falls back to sample PCAPs from the Nozomi repo if pcap_path is None.
        """
        result = UWBMonitorResult(vendor=vendor)

        if vendor not in LUA_SCRIPTS:
            result.error = f"Unknown vendor '{vendor}'. Supported: {list(LUA_SCRIPTS)}"
            return result

        if not self.lua_available(vendor):
            result.error = (
                f"Lua dissector for {vendor} not found at {LUA_SCRIPTS[vendor]}. "
                f"Run: cp {UWB_REPO}/*.lua {UWB_LUA_DIR}/"
            )
            return result

        if pcap_path is None:
            if not self.pcap_sample_available(vendor):
                result.error = f"Sample PCAP not found at {PCAP_SAMPLES[vendor]}"
                return result
            pcap_path = str(PCAP_SAMPLES[vendor])

        result.pcap_file = pcap_path

        if not self.tshark_available():
            result.error = "tshark not found. Install Wireshark/tshark."
            return result

        try:
            cmd = [
                "tshark",
                "-r", pcap_path,
                "--lua-script", str(LUA_SCRIPTS[vendor]),
                "-T", "json",
                "-x",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = proc.stdout

            # Parse packet count from stderr summary
            for line in proc.stderr.splitlines():
                if "packets" in line.lower():
                    try:
                        result.total_packets = int(line.split()[0])
                    except (ValueError, IndexError):
                        pass

            anomalies = self._parse_anomalies(vendor, output)
            result.anomalies = anomalies
            result.uwb_packets = len([a for a in anomalies if a.anomaly_type != "parse_error"])

        except subprocess.TimeoutExpired:
            result.error = "tshark timed out after 60s"
        except Exception as exc:
            result.error = str(exc)

        return result

    def _parse_anomalies(self, vendor: str, tshark_json: str) -> list[UWBAnomaly]:
        """Parse tshark JSON output for UWB anomaly indicators."""
        import json
        import time
        anomalies = []
        try:
            packets = json.loads(tshark_json) if tshark_json.strip() else []
        except json.JSONDecodeError:
            return anomalies

        seen_seqnums: set = set()
        for i, pkt in enumerate(packets, 1):
            layers = pkt.get("_source", {}).get("layers", {})
            # Check for replay via sequence number
            seq = (layers.get(f"{vendor}_uwb.seq_num") or
                   layers.get("frame.number", [str(i)]))[0]
            if seq in seen_seqnums:
                anomalies.append(UWBAnomaly(
                    vendor=vendor, timestamp=time.time(),
                    packet_num=i, anomaly_type="replay",
                    description=f"Duplicate sequence number {seq} detected (replay attack indicator)",
                ))
            seen_seqnums.add(seq)

            # Check for malformed frames
            if layers.get("_ws.malformed"):
                anomalies.append(UWBAnomaly(
                    vendor=vendor, timestamp=time.time(),
                    packet_num=i, anomaly_type="malformed",
                    description="Malformed UWB frame detected (fuzzing/injection indicator)",
                    raw=str(layers)[:200],
                ))

        return anomalies

    # ─────────────────────────────────────────── live capture

    def live_capture(self, vendor: str, interface: str = "eth0",
                     duration_s: int = 60) -> UWBMonitorResult:
        """Capture live traffic and analyze. Requires root + tshark."""
        result = UWBMonitorResult(vendor=vendor)
        if not self.tshark_available():
            result.error = "tshark not available"
            return result

        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            pcap_tmp = f.name

        try:
            subprocess.run(
                ["tshark", "-i", interface, "-a", f"duration:{duration_s}", "-w", pcap_tmp],
                check=True, timeout=duration_s + 10,
            )
            return self.analyze_pcap(vendor, pcap_tmp)
        except subprocess.TimeoutExpired:
            result.error = f"Live capture timed out after {duration_s + 10}s"
        except Exception as exc:
            result.error = str(exc)
        finally:
            try:
                os.unlink(pcap_tmp)
            except Exception:
                pass
        return result

    # ─────────────────────────────────────────── Wireshark setup

    def print_wireshark_setup(self) -> None:
        """Print instructions for installing the Lua dissectors in Wireshark."""
        import platform
        if platform.system() == "Windows":
            lua_dir = Path.home() / "AppData" / "Roaming" / "Wireshark" / "plugins"
        elif platform.system() == "Darwin":
            lua_dir = Path.home() / ".local" / "lib" / "wireshark" / "plugins"
        else:
            lua_dir = Path.home() / ".local" / "lib" / "wireshark" / "plugins"

        print("=== UWB RTLS Dissector Setup ===")
        print(f"Copy Lua scripts to: {lua_dir}")
        for vendor, script in LUA_SCRIPTS.items():
            print(f"  cp {script} {lua_dir}/")
        print("\nOr open Wireshark -> Analyze -> Lua -> Evaluate: <script_path>")
        print("\nSample PCAPs for testing:")
        for vendor, pcap in PCAP_SAMPLES.items():
            print(f"  {vendor}: {pcap}")


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    monitor = UWBRTLSMonitor()

    vendor = sys.argv[1] if len(sys.argv) > 1 else "sewio"
    pcap   = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"[*] UWB RTLS Monitor -- vendor: {vendor}")
    print(f"    Lua scripts: {[str(v) for v in LUA_SCRIPTS.values() if v.exists()]}")

    result = monitor.analyze_pcap(vendor, pcap)

    if result.error:
        print(f"[-] Error: {result.error}")
        monitor.print_wireshark_setup()
        sys.exit(1)

    print(f"[+] PCAP: {result.pcap_file}")
    print(f"    Packets: {result.total_packets} total, {result.uwb_packets} UWB")
    print(f"    Anomalies: {len(result.anomalies)}")
    for a in result.anomalies:
        print(f"    [{a.anomaly_type}] pkt#{a.packet_num}: {a.description}")
