"""EmbedXPL AutoPwn — Printer segment."""
from .segment import SegmentAutoPwn

class PrinterAutoPwn(SegmentAutoPwn):
    """AutoPwn all printer modules against target(s)."""
    def __init__(self, targets, **kwargs):
        super().__init__(segment="printer", targets=targets, **kwargs)
