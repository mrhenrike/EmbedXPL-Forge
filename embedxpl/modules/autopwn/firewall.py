"""EmbedXPL AutoPwn — Firewall segment."""
from .segment import SegmentAutoPwn

class FirewallAutoPwn(SegmentAutoPwn):
    """AutoPwn all firewall modules against target(s)."""
    def __init__(self, targets, **kwargs):
        super().__init__(segment="firewall", targets=targets, **kwargs)
