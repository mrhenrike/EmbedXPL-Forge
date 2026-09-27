# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Profinet DCP (Discovery and Basic Configuration) Scanner.

Profinet DCP uses Ethernet Layer 2 multicast frames (EtherType 0x8892)
for device discovery. Since raw Layer 2 sockets (AF_PACKET) are only
available on Linux, this module implements two strategies:

  1. Linux — raw AF_PACKET socket to send a Profinet DCP Identify All Request
     to the PROFINET multicast address (01:0e:cf:00:00:00, EtherType 0x8892)
     and listens for DCP Identify responses.

  2. Fallback — tries to reach the device via TCP/102 (ISO-on-TCP/TPKT),
     which some Profinet devices also expose alongside DCP, and reports
     basic TCP reachability as a Profinet indicator.

The DCP Identify Request causes any Profinet device to respond with:
  - NameOfStation (device name)
  - DeviceVendorValue (device type/manufacturer)
  - IP address, netmask, gateway

Note: Full DCP discovery requires L2 access (same broadcast domain).
      No authentication is required — DCP is an open discovery protocol.

Protocol: Profinet DCP (PNIO)
EtherType: 0x8892, Multicast: 01:0e:cf:00:00:00

References:
  - IEC 61158-6-10 (Profinet protocol specification)
  - MITRE ATT&CK ICS: T0846 (Remote System Discovery)

Version: 1.0.0
"""

import socket
import struct
import sys
import time
from typing import List, Optional

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_PROFINET_ETHERTYPE = 0x8892
_PN_MULTICAST_1 = "01:0e:cf:00:00:00"
_PN_MULTICAST_2 = "28:63:36:5a:18:f1"
_PNIO_FRAMEID_IDENTIFY = 0xFEFE  # DCP Identify All Request

# DCP Identify All Request (no specific station)
# ProfinetIO FrameID (2) + DCP Header (10) + DCP Block (4)
_DCP_IDENT_REQUEST = struct.pack(
    ">HBBHHHH",
    _PNIO_FRAMEID_IDENTIFY,  # FrameID
    5,       # ServiceID: Identify
    0,       # ServiceType: Request
    1,       # XID
    0,       # ResponseDelay
    4,       # DCPDataLength (4 bytes of blocks)
    0xFFFF,  # Option/SubOption: All (0xFF/0xFF)
) + struct.pack(">H", 0)  # BlockLength=0


def _mac_to_bytes(mac: str) -> bytes:
    """Convert 'aa:bb:cc:dd:ee:ff' to bytes."""
    return bytes(int(x, 16) for x in mac.split(":"))


def _build_eth_frame(src_mac: bytes, dst_mac: bytes, ethertype: int, payload: bytes) -> bytes:
    """Build a raw Ethernet II frame."""
    return dst_mac + src_mac + struct.pack(">H", ethertype) + payload


def _get_local_mac(iface: str) -> Optional[bytes]:
    """Get MAC address of a local interface (Linux only)."""
    try:
        import fcntl
        SIOCGIFHWADDR = 0x8927
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, b"\x00" * 8 + iface.ljust(16).encode())
        return info[18:24]
    except Exception:
        return None


def _parse_dcp_response(data: bytes, src_mac: str) -> Optional[dict]:
    """Parse a received Ethernet frame for Profinet DCP Identify response."""
    if len(data) < 28:
        return None
    try:
        # Ethernet header: 6+6+2 = 14 bytes
        frameid = struct.unpack_from(">H", data, 14)[0]
        if frameid != 0xFEFE and frameid != 0xFF00:
            # DCP Identify responses may use 0xFF01..0xFF3F range
            if frameid < 0xFF01 or frameid > 0xFF3F:
                return None

        result = {"mac_address": src_mac}
        # DCP Header: ServiceID(1)+ServiceType(1)+XID(4)+ResponseDelay(2)+DCPDataLength(2) = 10 bytes
        dcp_offset = 16  # after frameid (2 bytes at offset 14) + offset 16
        dcp_len = struct.unpack_from(">H", data, dcp_offset + 8)[0]
        block_offset = dcp_offset + 10

        end = block_offset + dcp_len
        while block_offset < end and block_offset < len(data):
            option = data[block_offset]
            suboption = data[block_offset + 1]
            block_len = struct.unpack_from(">H", data, block_offset + 2)[0]
            block_data = data[block_offset + 4: block_offset + 4 + block_len]
            block_offset += 4 + block_len
            if block_len % 2 != 0:
                block_offset += 1  # padding

            if option == 0x02 and suboption == 0x01:  # IP — IPAddress
                if len(block_data) >= 12:
                    ip = socket.inet_ntoa(block_data[0:4])
                    mask = socket.inet_ntoa(block_data[4:8])
                    gw = socket.inet_ntoa(block_data[8:12])
                    result["ip_address"] = ip
                    result["netmask"] = mask
                    result["gateway"] = gw
            elif option == 0x02 and suboption == 0x02:  # IP — MAC
                pass
            elif option == 0x01 and suboption == 0x01:  # Manufacturer specific - DeviceVendor
                result["device_vendor"] = block_data.rstrip(b"\x00").decode("ascii", errors="replace")
            elif option == 0x01 and suboption == 0x02:  # Manufacturer specific - NameOfStation
                result["name_of_station"] = block_data.rstrip(b"\x00").decode("ascii", errors="replace")
            elif option == 0x02 and suboption == 0x05:  # IP — NameOfStation
                result["name_of_station"] = block_data.rstrip(b"\x00").decode("ascii", errors="replace")

        return result if len(result) > 1 else None
    except Exception:
        return None


def _scan_l2(iface: str, timeout: int) -> List[dict]:
    """Send Profinet DCP Identify on L2 and collect responses (Linux only)."""
    results = []
    try:
        local_mac = _get_local_mac(iface)
        if not local_mac:
            return results
        dst_mac = _mac_to_bytes(_PN_MULTICAST_1)
        frame = _build_eth_frame(local_mac, dst_mac, _PROFINET_ETHERTYPE, _DCP_IDENT_REQUEST)

        # AF_PACKET: Linux raw socket
        ETH_P_ALL = 0x0003
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sock.bind((iface, 0))
        sock.settimeout(timeout)
        sock.send(frame)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                pkt, addr = sock.recvfrom(1500)
                if len(pkt) < 16:
                    continue
                ethertype = struct.unpack_from(">H", pkt, 12)[0]
                if ethertype == _PROFINET_ETHERTYPE:
                    src_mac_bytes = pkt[6:12]
                    src_mac = ":".join(f"{b:02x}" for b in src_mac_bytes)
                    info = _parse_dcp_response(pkt, src_mac)
                    if info and info not in results:
                        results.append(info)
            except socket.timeout:
                break
        sock.close()
    except Exception:
        pass
    return results


def _check_tcp_port(host: str, port: int, timeout: int) -> bool:
    """Fallback: check if TCP port is open (non-L2 environments)."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except Exception:
        return False


class Exploit(BaseExploit):
    """Profinet DCP Scanner — Layer 2 device discovery.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Profinet DCP (Discovery and Basic Configuration) Scanner",
        "description": (
            "Sends a Profinet DCP Identify All Request over raw Layer 2 Ethernet "
            "(EtherType 0x8892) to multicast 01:0e:cf:00:00:00. Identifies Profinet "
            "devices: Siemens S7 PLCs, SCALANCE switches, I/O modules. Requires AF_PACKET "
            "(Linux root). Falls back to TCP/102 reachability check on non-Linux platforms. "
            "Ported from ISF icssploit profinet_dcp_scan.py using raw sockets (no Scapy)."
        ),
        "authors": (
            "wenzhe zhu <jtrkid[at]gmail.com> (ISF icssploit)",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge port",
        ),
        "references": (
            "https://www.profibus.com/technology/profinet/",
            "https://attack.mitre.org/techniques/T0846/",
        ),
        "devices": (
            "Siemens S7-1200 / S7-1500 / S7-300 / S7-400",
            "Siemens SCALANCE X/XC/XR managed switches",
            "Siemens ET 200SP / ET 200M I/O modules",
            "Phoenix Contact industrial controllers",
            "Wago PLC series (Profinet-capable)",
        ),
    }

    target = OptIP("", "Target IPv4 address (fallback TCP check) or empty for L2 broadcast")
    port = OptPort(102, "Fallback TCP port for ISO-on-TCP reachability check")
    iface = OptString("eth0", "Network interface for L2 Profinet DCP scan (Linux only)")
    timeout = OptInteger(5, "Listen timeout in seconds")

    def run(self) -> None:
        """Discover Profinet devices via DCP L2 broadcast or TCP fallback."""
        if sys.platform.startswith("linux"):
            print_status(f"[Profinet DCP] Sending DCP Identify on {self.iface}...")
            results = _scan_l2(self.iface, self.timeout)
            if results:
                for dev in results:
                    print_success(f"[Profinet DCP] Device found:")
                    for key, val in dev.items():
                        print_success(f"  {key}: {val}")
            else:
                print_error(f"[Profinet DCP] No Profinet devices found on {self.iface}")
                print_info("[Profinet DCP] Ensure you are in the same L2 broadcast domain as the devices")
        else:
            print_status(f"[Profinet DCP] Non-Linux platform — falling back to TCP/{self.port} reachability on {self.target}")
            if _check_tcp_port(self.target, self.port, self.timeout):
                print_success(f"[Profinet DCP] TCP/{self.port} open on {self.target} — potential Profinet/S7 device")
                print_info("[Profinet DCP] Use Linux with AF_PACKET for full DCP discovery")
            else:
                print_error(f"[Profinet DCP] No response from {self.target}:{self.port}")

    @mute
    def check(self) -> bool:
        """Check TCP/102 reachability as a Profinet indicator."""
        return _check_tcp_port(self.target, self.port, 3)
