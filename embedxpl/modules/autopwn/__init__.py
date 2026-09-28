"""EmbedXPL AutoPwn — Automated exploitation by segment.

Usage:
    from embedxpl.modules.autopwn import RouterAutoPwn, PrinterAutoPwn, FirewallAutoPwn

    # Router AutoPwn
    ap = RouterAutoPwn(target="192.168.1.1")
    report = ap.run()

    # Printer AutoPwn
    ap = PrinterAutoPwn(target="10.0.0.50")
    report = ap.run(check_only=True)

    # Segment AutoPwn (generic)
    from embedxpl.modules.autopwn.segment import SegmentAutoPwn
    ap = SegmentAutoPwn(segment="router", targets=["192.168.1.0/24"])
    report = ap.run()

# authorized use only
"""
from .router import RouterAutoPwn
from .printer import PrinterAutoPwn
from .firewall import FirewallAutoPwn
from .camera import CameraAutoPwn
from .ics import ICSAutoPwn
from .segment import SegmentAutoPwn

__all__ = [
    "RouterAutoPwn",
    "PrinterAutoPwn",
    "FirewallAutoPwn",
    "CameraAutoPwn",
    "ICSAutoPwn",
    "SegmentAutoPwn",
]
