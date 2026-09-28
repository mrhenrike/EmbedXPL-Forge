"""Invoke MikrotikAPI-BF as an external process (your code / PyPI install).

Does not embed mikrotikapi-bf sources — delegates to ``mikrotikapi-bf`` on PATH
or to a checkout of ``mikrotikapi-bf.py``. Up MIT license / credits stay with that project.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from typing import List

from embedxpl.core.exploit import *


class Exploit(Exploit):
    """Run MikrotikAPI-BF CLI against ``target``."""

    __info__ = {
        "name": "MikrotikAPI-BF Bridge",
        "description": "Runs MikrotikAPI-BF (https://github.com/mrhenrike/MikrotikAPI-BF) via subprocess. "
        "Set script_path to your repo's mikrotikapi-bf.py or leave empty to use PATH (mikrotikapi-bf).",
        "authors": (
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://github.com/mrhenrike/MikrotikAPI-BF",
            "https://pypi.org/project/mikrotikapi-bf/",
        ),
        "devices": (
            "MikroTik RouterOS",
        ),
    }

    target = OptIP("", "Target IP (passed as -t)")
    script_path = OptString(
        "",
        "Path to mikrotikapi-bf.py checkout (empty = use mikrotikapi-bf from PATH)",
    )
    python_executable = OptString(
        "",
        "Python to run script_path (empty = current interpreter)",
    )
    passthrough = OptString(
        "",
        "Extra CLI args (quoted as needed), e.g. -d wordlist.txt --fingerprint",
    )
    timeout_s = OptInteger(600, "Subprocess timeout seconds")
    verbosity = OptBool(True, "Print stdout/stderr")

    def _split_args(self, raw: str) -> List[str]:
        """Split passthrough for Windows/POSIX."""
        raw = (raw or "").strip()
        if not raw:
            return []
        return shlex.split(raw, posix=os.name != "nt")

    def run(self) -> None:
        """Spawn MikrotikAPI-BF."""
        script = str(self.script_path).strip()
        extra = self._split_args(str(self.passthrough))
        if script:
            py = str(self.python_executable).strip() or sys.executable
            if not os.path.isfile(script):
                print_error("script_path is not a file: {}".format(script), verbose=True)
                return
            cmd = [py, script, "-t", str(self.target)] + extra
        else:
            exe = shutil.which("mikrotikapi-bf") or shutil.which("mikrotik-bf")
            if not exe:
                print_error(
                    "mikrotikapi-bf not on PATH; set script_path to mikrotikapi-bf.py or pip install mikrotikapi-bf.",
                    verbose=True,
                )
                return
            cmd = [exe, "-t", str(self.target)] + extra

        print_status("Command: {}".format(" ".join(cmd[:8]) + (" …" if len(cmd) > 8 else "")), verbose=self.verbosity)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(1, int(self.timeout_s)),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            print_error("MikrotikAPI-BF timeout: {}".format(exc), verbose=True)
            return
        except OSError as exc:
            print_error(str(exc), verbose=True)
            return

        if proc.stdout and self.verbosity:
            print_status(proc.stdout)
        if proc.stderr and self.verbosity:
            print_error(proc.stderr)
        if proc.returncode == 0:
            print_success("MikrotikAPI-BF exited 0", verbose=self.verbosity)
        else:
            print_error("MikrotikAPI-BF exit code {}".format(proc.returncode))
