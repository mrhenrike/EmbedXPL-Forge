"""Read Metasploit ``*.rb`` module metadata without executing Ruby.

Parses common `'Name' =>`, `'Author' =>`, `'References' =>` patterns for
documentation / cataloging. The file on disk is unchanged (ipsi litteris).

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import os

from embedxpl.core.exploit import *
from embedxpl.core.integrations.msf_cli import read_metasploit_rb_metadata


class Exploit(Exploit):
    """Display metadata extracted from a Metasploit module file."""

    __info__ = {
        "name": "Metasploit Ruby Module Metadata (read-only)",
        "description": "Loads a .rb path from your Metasploit tree and prints Name/Author/References heuristics. "
        "Does not run Ruby or MSF; original file is not modified. Credit remains with module authors and Rapid7 license.",
        "authors": (
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://github.com/rapid7/metasploit-framework",
        ),
        "devices": (
            "Documentation",
        ),
    }

    rb_path = OptString(
        "",
        "Absolute path to module .rb (e.g. under .../metasploit-framework/modules/)",
    )
    msf_root = OptString(
        "",
        "If rb_relative is set, join with this root directory",
    )
    rb_relative = OptString(
        "",
        "Relative path under msf_root (e.g. exploit/linux/http/foo.rb)",
    )

    def run(self) -> None:
        """Parse and print metadata."""
        path = str(self.rb_path).strip()
        root = str(self.msf_root).strip()
        rel = str(self.rb_relative).strip()
        if rel and root:
            path = os.path.normpath(os.path.join(root, rel.replace("/", os.sep)))
        if not path or not os.path.isfile(path):
            print_error("Set rb_path or msf_root + rb_relative to a valid .rb file.", verbose=True)
            return

        meta = read_metasploit_rb_metadata(path)
        print_success("File: {}".format(path))
        print_status("Name: {}".format(meta.get("name") or "(not detected)"))
        print_status("Authors: {}".format(", ".join(meta.get("authors") or []) or "(not detected)"))
        desc = (meta.get("description") or "").strip()
        if desc:
            print_status("Description snippet: {}…".format(desc[:400]))
        refs = meta.get("references") or []
        if refs:
            print_status("References:")
            for r in refs:
                print_status("  - {}".format(r))
