"""EmbedXPL-Forge shell shim -- re-exports from xpl-core canonical package.

All shell infrastructure now lives in xpl_core.shells. This module
re-exports the public API so that existing ``from embedxpl.core.shells
import ...`` statements continue to work unchanged.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from xpl_core.shells import (
    # Stager
    SHELL_TYPES,
    DNSTunnelShell,
    HTTPPollShell,
    ICMPCovertShell,
    InternalShell,
    MeterpreterBridge,
    MQTTShell,
    # Concrete engines
    RawTCPShell,
    RawUDPShell,
    # Listener
    ReverseListener,
    # Session manager (new)
    SessionManager,
    SessionState,
    ShellConnectionError,
    # Engine ABC + types
    ShellEngine,
    ShellError,
    # Handler
    ShellHandler,
    ShellIOError,
    ShellMode,
    ShellSession,
    ShellStagingMixin,
    ShellStatus,
    ShellTimeoutError,
    generate_msf_rc,
    generate_payload,
    pty_interact,
    reverse_shell_payload,
    simple_interact,
    start_listener,
    tty_upgrade_commands,
)

__all__ = [
    "SHELL_TYPES",
    "DNSTunnelShell",
    "HTTPPollShell",
    "ICMPCovertShell",
    "InternalShell",
    "MQTTShell",
    "MeterpreterBridge",
    "RawTCPShell",
    "RawUDPShell",
    "ReverseListener",
    "SessionManager",
    "SessionState",
    "ShellConnectionError",
    "ShellEngine",
    "ShellError",
    "ShellHandler",
    "ShellIOError",
    "ShellMode",
    "ShellSession",
    "ShellStagingMixin",
    "ShellStatus",
    "ShellTimeoutError",
    "generate_msf_rc",
    "generate_payload",
    "pty_interact",
    "reverse_shell_payload",
    "simple_interact",
    "start_listener",
    "tty_upgrade_commands",
]
