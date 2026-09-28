"""ISF (icssploit) compatibility shim.

Provides base classes and helpers that ISF/icssploit modules expect,
mapped to EmbedXPL equivalents.
"""

from embedxpl.core.exploit.exploit import Exploit as _Exploit
from embedxpl.core.http.http_client import HTTPClient
from embedxpl.core.tcp.tcp_client import TCPClient
from embedxpl.core.udp.udp_client import UDPClient


class ISFModule(_Exploit):
    """Base class for ISF/icssploit modules in EmbedXPL."""

    def __init__(self):
        super().__init__()


# ISF protocol mixin classes
class ISFTCPClient(ISFModule, TCPClient): pass
class ISFHTTPClient(ISFModule, HTTPClient): pass
class ISFUDPClient(ISFModule, UDPClient): pass


# ISF-specific exceptions
class ISFExploitError(Exception): pass
class ISFCommunicationError(ISFExploitError): pass


def print_success(msg): from embedxpl.core.exploit.printer import print_success as _p; _p(msg)
def print_error(msg): from embedxpl.core.exploit.printer import print_error as _p; _p(msg)
def print_status(msg): from embedxpl.core.exploit.printer import print_status as _p; _p(msg)


__all__ = [
    'ISFModule', 'ISFTCPClient', 'ISFHTTPClient', 'ISFUDPClient',
    'HTTPClient', 'TCPClient', 'UDPClient',
    'print_success', 'print_error', 'print_status',
]
