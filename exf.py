#!/usr/bin/env python3

import platform
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tools.venv_bootstrap import ensure_runtime

ensure_runtime(__file__)

import logging.handlers

if sys.version_info.major < 3:
    print("EmbedXPL supports only Python3. Rerun application in Python3 environment.")
    exit(1)
if sys.version_info < (3, 8):
    print("EmbedXPL requires Python 3.8+ (detected: {}).".format(platform.python_version()))
    exit(1)

log_handler = logging.handlers.RotatingFileHandler(filename="embedxpl.log", maxBytes=500000)
log_formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s       %(message)s")
log_handler.setFormatter(log_formatter)
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)
LOGGER.addHandler(log_handler)


def embedxpl(argv):
    try:
        from embedxpl.interpreter import EmbedXPLInterpreter
    except ModuleNotFoundError as err:
        print("EmbedXPL bootstrap error: missing Python dependency: {}".format(err))
        print("Run: ./setup_venv.sh   (Linux/macOS)  or  .\\setup_venv.ps1   (Windows)")
        print("Or:  ./run.sh")
        print("Optional diagnostics: python tools/env_doctor.py")
        raise SystemExit(1)

    exf = EmbedXPLInterpreter()
    if len(argv[1:]):
        exf.nonInteractive(argv)
    else:
        exf.start()

if __name__ == "__main__":
    try:
        embedxpl(sys.argv)
    except (KeyboardInterrupt, SystemExit):
        pass
