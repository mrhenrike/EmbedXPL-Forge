"""printerxpl AutoPwn — hp segment. # authorized use only"""
from .base import SegmentAutoPwn
class HpAutoPwn(SegmentAutoPwn):
    def __init__(self, targets, **kw): super().__init__("hp", targets, **kw)
