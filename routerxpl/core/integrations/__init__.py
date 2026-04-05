"""Optional bridges to external frameworks (e.g. Metasploit).

Exploit-DB offline search lives in ``generic/external/exploitdb_embedded_lookup``
(embedded tree); this package does not wrap the ``searchsploit`` CLI.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from routerxpl.core.integrations.msf_cli import find_msfconsole, run_msf_batch_commands

__all__ = (
    "find_msfconsole",
    "run_msf_batch_commands",
)
