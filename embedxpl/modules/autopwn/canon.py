"""printerxpl AutoPwn — canon segment. # authorized use only"""
from .base import SegmentAutoPwn
class CanonAutoPwn(SegmentAutoPwn):
    def __init__(self, targets, **kw): super().__init__("canon", targets, **kw)
