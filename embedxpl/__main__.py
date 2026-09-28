"""Entry point for `python -m embedxpl` and `exf` / `embedxpl` console scripts.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

import logging.handlers
import platform
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tools.venv_bootstrap import ensure_runtime

ensure_runtime(_ROOT / "exf.py")


def main() -> None:
    """Bootstrap EmbedXPL-Forge interactive shell or non-interactive mode."""
    if sys.version_info.major < 3:
        print("EmbedXPL supports only Python 3. Rerun in a Python 3 environment.")
        raise SystemExit(1)
    if sys.version_info < (3, 8):
        print(
            "EmbedXPL requires Python 3.8+ (detected: {}).".format(
                platform.python_version()
            )
        )
        raise SystemExit(1)

    log_handler = logging.handlers.RotatingFileHandler(
        filename="embedxpl.log", maxBytes=500_000, encoding="utf-8"
    )
    log_formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s       %(message)s"
    )
    log_handler.setFormatter(log_formatter)
    logging.root.addHandler(log_handler)

    try:
        from embedxpl.interpreter import EmbedXPLInterpreter
    except ModuleNotFoundError as err:
        print("EmbedXPL bootstrap error — missing dependency: {}".format(err))
        print("Run: ./setup_venv.sh   or   .\\setup_venv.ps1")
        print("Or:  ./run.sh")
        print("Optional diagnostics: python tools/env_doctor.py")
        raise SystemExit(1)

    exf = EmbedXPLInterpreter()
    if len(sys.argv[1:]):
        exf.nonInteractive(sys.argv)
    else:
        exf.start()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        pass
