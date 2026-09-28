"""HatSploit compatibility shim.

Provides base classes and helpers that HatSploit modules expect,
mapped to EmbedXPL equivalents so absorbed HatSploit modules work.

Usage in absorbed HatSploit modules:
    # ABSORBED: from hatsploit.lib.core.module.basic import *
    # Instead, add to top of module:
    from embedxpl.core.compat.hatsploit_shim import *
"""

from embedxpl.core.exploit.exploit import Exploit as _Exploit
from embedxpl.core.http.http_client import HTTPClient
from embedxpl.core.tcp.tcp_client import TCPClient
from embedxpl.core.udp.udp_client import UDPClient
from embedxpl.core.ssh.ssh_client import SSHClient
from embedxpl.core.telnet.telnet_client import TelnetClient


class HatSploitModule(_Exploit):
    """Base class for HatSploit exploit modules in EmbedXPL."""
    details = {}     # HatSploit uses 'details' instead of '__info__'
    options = {}
    target = None

    def __init__(self):
        super().__init__()
        # Map HatSploit 'details' to EmbedXPL '__info__'
        if hasattr(self, 'details') and not hasattr(self, '__info__'):
            self.__info__ = self.details

    def execute(self, *args, **kwargs):
        """HatSploit uses execute() — alias to run()."""
        return self.run(*args, **kwargs)

    def run(self):
        raise NotImplementedError("Implement run() or execute()")


# HatSploit protocol aliases
class TCP(HatSploitModule, TCPClient):
    pass

class HTTP(HatSploitModule, HTTPClient):
    pass

class SSH(HatSploitModule, SSHClient):
    pass

class Telnet(HatSploitModule, TelnetClient):
    pass


# Shim for 'exploits' module that HatSploit expects
class _ExploitsShim:
    Exploit = HatSploitModule
    TCP = TCP
    HTTP = HTTP
    SSH = SSH
    Telnet = Telnet

exploits = _ExploitsShim()


# Common HatSploit helpers
def output_success(msg): from embedxpl.core.exploit.printer import print_success; print_success(msg)
def output_error(msg): from embedxpl.core.exploit.printer import print_error; print_error(msg)
def output_information(msg): from embedxpl.core.exploit.printer import print_info; print_info(msg)
def output_warning(msg): from embedxpl.core.exploit.printer import print_warning; print_warning(msg)

# Export all
__all__ = [
    'HatSploitModule', 'TCP', 'HTTP', 'SSH', 'Telnet', 'exploits',
    'HTTPClient', 'TCPClient', 'UDPClient', 'SSHClient', 'TelnetClient',
    'output_success', 'output_error', 'output_information', 'output_warning',
]
