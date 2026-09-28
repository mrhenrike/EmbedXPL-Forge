"""Delegate execution to Rapid7 Metasploit ``msfconsole`` (local install).

Uses the framework's own Ruby modules *verbatim* — no EmbedXPL port of MSF
code. Keep original authors and ``LICENSE`` from your Metasploit checkout.
Requires authorized testing targets only.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

from embedxpl.core.exploit import *
from embedxpl.core.integrations.msf_cli import find_msfconsole, run_msf_batch_commands


class Exploit(Exploit):
    """Run a Metasploit module path via installed ``msfconsole``."""

    __info__ = {
        "name": "Metasploit Console Bridge",
        "description": "Invokes local msfconsole with 'use <module>; setg RHOSTS; …; check|run'. "
        "MSF modules and license remain under Rapid7/BSD at your install path — this module only "
        "orchestrates the CLI. Not legal advice: comply with all licenses and target authorization.",
        "authors": (
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://github.com/rapid7/metasploit-framework",
            "https://www.metasploit.com/",
        ),
        "devices": (
            "Any (depends on chosen Metasploit module)",
        ),
    }

    target = OptIP("", "Target IP (mapped to setg RHOSTS)")
    msf_module = OptString(
        "",
        "Metasploit module path as in REPL, e.g. exploit/linux/http/foo or auxiliary/scanner/ssh/ssh_version",
    )
    msf_action = OptString(
        "check",
        "Final action: check | run | exploit (or custom msf command)",
    )
    msf_extra = OptString(
        "",
        "Extra msfconsole lines, one per line (e.g. set RPORT 443\\nset SSL true)",
    )
    msfconsole_path = OptString(
        "",
        "Path to msfconsole binary (empty = RXF_METASPLOIT_CONSOLE env or PATH)",
    )
    timeout_s = OptInteger(300, "Subprocess timeout in seconds")
    verbosity = OptBool(True, "Print msfconsole stdout/stderr")

    def run(self) -> None:
        """Execute Metasploit batch via msfconsole."""
        if not str(self.msf_module).strip():
            print_error("Set msf_module to a valid Metasploit path (use …; show options).", verbose=True)
            return
        bin_path = find_msfconsole(str(self.msfconsole_path))
        if not bin_path:
            print_error(
                "msfconsole not found. Install Metasploit or set msfconsole_path / RXF_METASPLOIT_CONSOLE.",
                verbose=True,
            )
            return

        print_status("Using msfconsole: {}".format(bin_path), verbose=self.verbosity)
        print_status("Module: {} | action: {}".format(self.msf_module, self.msf_action), verbose=self.verbosity)

        code, out, err = run_msf_batch_commands(
            bin_path,
            str(self.msf_module),
            str(self.target),
            str(self.msf_action),
            str(self.msf_extra),
            int(self.timeout_s),
        )

        if out and self.verbosity:
            print_status("--- msfconsole stdout ---\n{}".format(out))
        if err and self.verbosity:
            print_error("--- msfconsole stderr ---\n{}".format(err))

        if code == 0:
            print_success("msfconsole finished with exit code 0", verbose=self.verbosity)
        else:
            print_error("msfconsole exit code {}".format(code))
