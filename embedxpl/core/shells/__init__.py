"""Shell transport engines for EmbedXPL-Forge.

Provides pluggable shell transports (TCP, UDP, ICMP, DNS, MQTT, HTTP,
Meterpreter, IWP) that share a common ShellEngine interface.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from embedxpl.core.shells.shell_engine import (
    ShellEngine,
    ShellError,
    ShellConnectionError,
    ShellIOError,
    ShellMode,
    ShellStatus,
    ShellTimeoutError,
)
from embedxpl.core.shells.raw_tcp_shell import RawTCPShell
from embedxpl.core.shells.raw_udp_shell import RawUDPShell
from embedxpl.core.shells.icmp_covert_shell import ICMPCovertShell
from embedxpl.core.shells.dns_tunnel_shell import DNSTunnelShell
from embedxpl.core.shells.mqtt_shell import MQTTShell
from embedxpl.core.shells.http_poll_shell import HTTPPollShell
from embedxpl.core.shells.meterpreter_bridge import MeterpreterBridge
from embedxpl.core.shells.internal_shell import InternalShell

__all__ = [
    "ShellEngine",
    "ShellError",
    "ShellConnectionError",
    "ShellIOError",
    "ShellMode",
    "ShellStatus",
    "ShellTimeoutError",
    "RawTCPShell",
    "RawUDPShell",
    "ICMPCovertShell",
    "DNSTunnelShell",
    "MQTTShell",
    "HTTPPollShell",
    "MeterpreterBridge",
    "InternalShell",
]
