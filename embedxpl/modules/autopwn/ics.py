"""EmbedXPL AutoPwn — Ics segment."""
from .segment import SegmentAutoPwn

class IcsAutoPwn(SegmentAutoPwn):
    """AutoPwn all ics modules against target(s)."""
    def __init__(self, targets, **kwargs):
        super().__init__(segment="ics", targets=targets, **kwargs)
