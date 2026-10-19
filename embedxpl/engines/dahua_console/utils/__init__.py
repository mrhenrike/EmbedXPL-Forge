"""
Package initialiser.
Imports both module-level objects and sub-modules so consumers can use either:
    from IngramPro.utils import color          # ColorPalette instance
    from IngramPro.utils import common         # module
    from IngramPro.utils import timer          # module
"""
# --- importable objects (instances / callables defined inside each module) ---
# --- sub-modules (consumers use common.singleton, timer.get_time_stamp, etc.) ---
from . import (
    common,
    log,  # also accessible as module (log.config_logger)
    net,
    timer,
)
from .alive_check import alive_check  # liveness check function
from .argparse import get_parse  # argument parser function
from .color import color  # ColorPalette instance
from .fingerprint import fingerprint  # fingerprint function
from .log import config_logger  # logging setup function
from .logo import logo  # logo list
from .port_scan import port_scan  # port scan function
from .status_bar import status_bar  # status bar function
