"""EmbedXPL AutoPwn  -  ICS/OT segment."""
from .segment import SegmentAutoPwn

class ICSAutoPwn(SegmentAutoPwn):
    """AutoPwn all ICS/OT modules against target(s)."""
    def __init__(self, targets, **kwargs):
        super().__init__(segment="ics", targets=targets, **kwargs)
