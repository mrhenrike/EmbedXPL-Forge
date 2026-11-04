"""Cross-platform compatibility smoke check for EmbedXPL-Forge.

Author: André Henrique (@mrhenrike) | União Geek  -  https://github.com/Uniao-Geek
"""
from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from typing import Dict, List

LOGGER = logging.getLogger("compat_smoke")


@dataclass
class CheckResult:
    """Stores the compatibility check output."""
    python_version: str = ""
    python_ok: bool = False
    platform: str = ""
    distribution: str = ""
    is_termux: bool = False
    imports: Dict[str, bool] = field(default_factory=dict)
    cli_ok: bool = False
    cli_output: List[str] = field(default_factory=list)


def check_python(result: CheckResult) -> None:
    result.python_version = platform.python_version()
    result.python_ok = sys.version_info >= (3, 8)
    result.platform = sys.platform
    result.distribution = platform.platform()
    result.is_termux = "com.termux" in os.environ.get("PREFIX", "")


def check_imports(result: CheckResult) -> None:
    core_imports = [
        "embedxpl",
        "embedxpl.interpreter",
        "embedxpl.core",
        "embedxpl.tools.venv_bootstrap",
        "embedxpl.tools.xpl_cli",
    ]
    for mod in core_imports:
        try:
            __import__(mod)
            result.imports[mod] = True
        except Exception as exc:
            result.imports[mod] = False
            LOGGER.warning("Import failed: %s — %s", mod, exc)


def check_cli(result: CheckResult) -> None:
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "embedxpl", "--version"],
            capture_output=True, text=True, timeout=15,
        )
        result.cli_ok = proc.returncode == 0
        result.cli_output = (proc.stdout + proc.stderr).strip().splitlines()
    except Exception as exc:
        result.cli_ok = False
        result.cli_output = [str(exc)]


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    result = CheckResult()
    check_python(result)
    check_imports(result)
    check_cli(result)

    data = asdict(result)
    print(json.dumps(data, indent=2))

    failures = [k for k, v in result.imports.items() if not v]
    if not result.python_ok:
        print(f"[FAIL] Python {result.python_version} < 3.8", file=sys.stderr)
        return 1
    if failures:
        print(f"[FAIL] Failed imports: {failures}", file=sys.stderr)
        return 1
    print("[OK] Compatibility smoke check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
