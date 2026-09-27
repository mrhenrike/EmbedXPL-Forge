"""EmbedXPL AutoPwn — Router segment."""
from .segment import SegmentAutoPwn

class RouterAutoPwn(SegmentAutoPwn):
    """AutoPwn all router modules against target(s)."""
    def __init__(self, targets, **kwargs):
        super().__init__(segment="router", targets=targets, **kwargs)
