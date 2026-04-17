# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""VxWorks RTOS Scanner — WdbRPC v2 (UDP/17185) device detection.

Wind River VxWorks is the world's most widely deployed RTOS, found in
PLCs, industrial controllers, avionics, medical devices, and network
equipment. In VxWorks 6.x and earlier, the WDB (Wind DeBug) agent
runs on UDP/17185 by default when built with WDB_COMM_NETWORK.

The WDB agent provides an unauthenticated debugging interface that
exposes target information and can provide remote memory read/write access.

This scanner sends a minimal WdbRPC version 2 ping/getInfo request and
parses the response to identify:
  - VxWorks version, CPU type and model
  - Target type, memory size
  - Operating system build date

WDB on UDP/17185 has no authentication — any device responding is
potentially exploitable for full memory access and code execution.

Protocol: WdbRPC v2 (Wind DeBug RPC) over UDP/17185
References:
  - CVE-2010-2967: VxWorks WDB authentication bypass
  - ISS X-Force VxWorks WDB advisory (2010)
  - MITRE ATT&CK ICS: T0846 (Remote System Discovery)

Version: 1.0.0
"""

import socket
import struct
import time
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_WDB_PORT = 17185

# WdbRPC v2 Ping request (RPC Call, program 0x55555555, version 1, procedure 1)
# XID=0x1, message_type=0 (CALL), rpc_version=2, program=0x55555555 (WDB),
# version=1, procedure=1 (WdbTargetPing), credential/verifier=AUTH_NULL
_WDB_PING_REQ = struct.pack(
    "!IIIIIIIII",
    1,             # XID
    0,             # message_type: CALL
    2,             # rpc_version
    0x55555555,    # program: WDB
    1,             # program_version
    1,             # procedure: WdbTargetPing (1)
    0,             # credential flavor: AUTH_NULL
    0,             # credential length
    0,             # verifier flavor: AUTH_NULL
) + struct.pack("!I", 0)  # verifier length + WDB header sequence

# WdbRPC v2 GetInfo request (procedure 5 — WdbInfoGet)
_WDB_INFO_REQ = struct.pack(
    "!IIIIIIIII",
    2,             # XID
    0,             # CALL
    2,             # rpc_version
    0x55555555,    # program: WDB
    1,             # version
    5,             # procedure: WdbInfoGet
    0, 0, 0,
) + struct.pack("!I", 0)

_CPU_TYPES = {
    20: "MIPS", 25: "MIPS", 26: "MIPS",
    42: "PowerPC 405", 55: "PowerPC 860", 59: "PowerPC 603",
    60: "PowerPC 604", 67: "PowerPC 750", 90: "x86/Pentium",
    94: "x86/Pentium 4", 201: "ARM", 202: "ARM Cortex-A", 212: "ARM926EJ-S",
}


def _wdb_probe(host: str, port: int, timeout: int) -> Optional[dict]:
    """Send WdbRPC ping and GetInfo to detect VxWorks WDB agent."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Ping first
        sock.sendto(_WDB_PING_REQ, (host, port))
        try:
            ping_resp, _ = sock.recvfrom(256)
        except socket.timeout:
            sock.close()
            return None

        if len(ping_resp) < 8:
            sock.close()
            return None

        # Check for RPC REPLY
        reply_type = struct.unpack_from("!I", ping_resp, 4)[0]
        if reply_type != 1:  # 1 = REPLY
            sock.close()
            return None

        result: dict = {"host": host, "port": port, "wdb_present": True}

        # GetInfo
        sock.sendto(_WDB_INFO_REQ, (host, port))
        try:
            info_resp, _ = sock.recvfrom(512)
        except socket.timeout:
            sock.close()
            return result

        sock.close()

        if len(info_resp) < 32:
            return result

        # WdbInfo response: after RPC reply header (~28 bytes) comes WDB info struct
        # Approximate parse: look for printable strings (version, cpu model)
        data = info_resp[28:]

        # Try to extract VxWorks version string and CPU info
        strings = []
        current = []
        for b in data:
            if 0x20 <= b <= 0x7E:
                current.append(chr(b))
            else:
                if len(current) >= 3:
                    strings.append("".join(current))
                current = []
        if current and len(current) >= 3:
            strings.append("".join(current))

        vx_versions = [s for s in strings if "VxWorks" in s or s.startswith("5.") or s.startswith("6.")]
        cpu_strings = [s for s in strings if any(c in s for c in ["PPC", "MIPS", "ARM", "x86", "Intel"])]

        if vx_versions:
            result["vxworks_version"] = vx_versions[0]
        if cpu_strings:
            result["cpu"] = cpu_strings[0]
        if strings:
            result["info_strings"] = strings[:6]

        # Extract memory size if RPC integers are parseable
        try:
            if len(data) >= 16:
                mem_size = struct.unpack_from("!I", data, 12)[0]
                if 0x100000 <= mem_size <= 0x100000000:
                    result["memory_size"] = _sizeof_fmt(mem_size)
        except Exception:
            pass

        return result
    except Exception:
        return None


def _sizeof_fmt(num: int) -> str:
    """Format bytes to human-readable size."""
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(num) < 1024.0:
            return f"{num:.1f}{unit}"
        num //= 1024
    return f"{num:.1f}TB"


class Exploit(BaseExploit):
    """VxWorks RTOS WDB Agent Scanner — UDP/17185 device detection.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "VxWorks WDB Agent Scanner (UDP/17185)",
        "description": (
            "Sends WdbRPC v2 Ping and GetInfo requests to UDP/17185 to detect "
            "Wind River VxWorks devices with the WDB debug agent enabled. "
            "WDB has no authentication — a responding device is directly exploitable. "
            "Ported from ISF icssploit vxworks_6_scan.py using raw sockets (no Scapy)."
        ),
        "authors": (
            "wenzhe zhu <jtrkid[at]gmail.com> (ISF icssploit)",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge port",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2010-2967",
            "https://www.windriver.com/products/vxworks",
            "https://attack.mitre.org/techniques/T0846/",
        ),
        "devices": (
            "Wind River VxWorks 5.x (all variants)",
            "Wind River VxWorks 6.x (all variants with WDB enabled)",
            "Siemens SIPROTEC relays",
            "GE MDS industrial radios",
            "Cisco IOS-XR (some versions use VxWorks internally)",
            "Rockwell Allen-Bradley ControlLogix (older firmware)",
        ),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(_WDB_PORT, "WdbRPC port (default 17185/UDP)")
    timeout = OptInteger(5, "Socket timeout in seconds")

    def run(self) -> None:
        """Probe target for VxWorks WDB agent on UDP/17185."""
        print_status(f"[VxWorks] Probing {self.target}:{self.port}/UDP for WDB agent...")
        result = _wdb_probe(self.target, self.port, self.timeout)
        if result:
            print_success(f"[VxWorks] WDB agent detected on {self.target}:{self.port}/UDP — device is UNPROTECTED")
            for key, val in result.items():
                if isinstance(val, list):
                    print_success(f"  {key}: {', '.join(val)}")
                elif key != "wdb_present":
                    print_success(f"  {key}: {val}")
            print_info("[VxWorks] Use vxworks_rpc_dos.py to crash or further exploit this target")
        else:
            print_error(f"[VxWorks] No WDB agent response from {self.target}:{self.port}")

    @mute
    def check(self) -> bool:
        """Return True if WDB agent responds."""
        return _wdb_probe(self.target, self.port, 3) is not None
