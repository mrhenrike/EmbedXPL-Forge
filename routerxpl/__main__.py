"""Entry point for `python -m routerxpl` and `rxf` / `routerxpl` console scripts.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

import logging.handlers
import platform
import sys


def main() -> None:
    """Bootstrap RouterXPL-Forge interactive shell or non-interactive mode."""
    if sys.version_info.major < 3:
        print("RouterXPL supports only Python 3. Rerun in a Python 3 environment.")
        raise SystemExit(1)
    if sys.version_info < (3, 8):
        print(
            "RouterXPL requires Python 3.8+ (detected: {}).".format(
                platform.python_version()
            )
        )
        raise SystemExit(1)

    log_handler = logging.handlers.RotatingFileHandler(
        filename="routerxpl.log", maxBytes=500_000
    )
    log_formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s       %(message)s"
    )
    log_handler.setFormatter(log_formatter)
    logging.root.addHandler(log_handler)

    try:
        from routerxpl.interpreter import RouterXPLInterpreter
    except ModuleNotFoundError as err:
        print("RouterXPL bootstrap error — missing dependency: {}".format(err))
        print("Run: python -m pip install routerxpl[ml]")
        print("Optional diagnostics: python tools/env_doctor.py")
        raise SystemExit(1)

    rxf = RouterXPLInterpreter()
    if len(sys.argv[1:]):
        rxf.nonInteractive(sys.argv)
    else:
        rxf.start()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        pass
