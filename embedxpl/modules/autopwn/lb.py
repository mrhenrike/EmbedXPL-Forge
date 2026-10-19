"""firewallxpl AutoPwn — lb segment. # authorized use only"""
from .base import SegmentAutoPwn
class LbAutoPwn(SegmentAutoPwn):
    def __init__(self, targets, **kw): super().__init__("lb", targets, **kw)
