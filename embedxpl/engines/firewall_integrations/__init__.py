"""Optional bridges to external frameworks (e.g. Metasploit).

Optional Metasploit bridge only; vendored Exploit-DB tree is not shipped in FirewallXPL-Forge (lighter perimeter lab clone).

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from firewallxpl.core.integrations.msf_cli import find_msfconsole, run_msf_batch_commands

__all__ = (
    "find_msfconsole",
    "run_msf_batch_commands",
)
