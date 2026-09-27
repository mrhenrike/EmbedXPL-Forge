"""Helpers to invoke Metasploit ``msfconsole`` without vendoring Rapid7 code.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


def find_msfconsole(explicit_path: str) -> Optional[str]:
    """Resolve ``msfconsole`` binary from explicit path, env, or PATH."""
    if explicit_path and explicit_path.strip():
        if os.path.isfile(explicit_path) and os.access(explicit_path, os.X_OK):
            return explicit_path
        w = shutil.which(explicit_path)
        if w:
            return w
    env = (os.environ.get("RXF_METASPLOIT_CONSOLE") or "").strip()
    if env and os.path.isfile(env) and os.access(env, os.X_OK):
        return env
    return shutil.which("msfconsole")


def build_command_sequence(
    module_ref: str,
    rhosts: str,
    action: str,
    extra_lines: List[str],
) -> str:
    """Build a single ``-x`` string for msfconsole (semicolon-separated)."""
    parts = [
        "use {}".format(module_ref.strip()),
        "setg RHOSTS {}".format(rhosts.strip()),
    ]
    for line in extra_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts.append(line)
    act = action.strip().lower()
    if act in ("check", "run", "exploit"):
        parts.append(act)
    else:
        parts.append(act)
    parts.append("exit")
    return "; ".join(parts)


def run_msf_batch_commands(
    msfconsole: str,
    module_ref: str,
    rhosts: str,
    action: str,
    extra_set_lines: str,
    timeout_s: int,
) -> Tuple[int, str, str]:
    """Run msfconsole non-interactively. Returns (returncode, stdout, stderr)."""
    extras: List[str] = []
    for raw in (extra_set_lines or "").splitlines():
        raw = raw.strip()
        if raw:
            extras.append(raw)

    arg_x = build_command_sequence(module_ref, rhosts, action, extras)
    cmd = [msfconsole, "-q", "-x", arg_x]
    logger.info("msfconsole batch: %s", arg_x[:500])
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(1, int(timeout_s)),
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return -9, "", "timeout: {}".format(exc)
    except OSError as exc:
        return -1, "", str(exc)


def read_metasploit_rb_metadata(rb_path: str) -> dict:
    """Best-effort parse of Name/Author/Description from a Metasploit .rb module.

    Does not execute Ruby; reads file as text. Preserves original file untouched.

    Args:
        rb_path: Absolute path to ``*.rb`` under a Metasploit install.

    Returns:
        Dict with keys name, authors, description, references (lists/str).
    """
    out: dict = {"name": "", "authors": [], "description": "", "references": [], "path": rb_path}
    if not os.path.isfile(rb_path):
        return out
    with open(rb_path, "r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    name_m = re.search(r"['\"]Name['\"]\s*=>\s*['\"]([^'\"]+)['\"]", text)
    if name_m:
        out["name"] = name_m.group(1)
    desc_m = re.search(r"['\"]Description['\"]\s*=>\s*%?\{?\s*(.+?)\n", text, re.DOTALL)
    if desc_m:
        out["description"] = desc_m.group(1).strip()[:2000]
    auth_m = re.search(r"['\"]Author['\"]\s*=>\s*\[(.*?)\]", text, re.DOTALL)
    if auth_m:
        chunk = auth_m.group(1)
        for q in re.findall(r"['\"]([^'\"]+)['\"]", chunk):
            out["authors"].append(q)
    ref_m = re.search(r"['\"]References['\"]\s*=>\s*\[(.*?)\]\s*,", text, re.DOTALL)
    if ref_m:
        for url in re.findall(r"https?://[^\s\]'\"]+", ref_m.group(1)):
            out["references"].append(url)
    return out
