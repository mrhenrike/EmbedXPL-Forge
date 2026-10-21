"""printerxpl AutoPwn — brother segment. # authorized use only"""
from .base import SegmentAutoPwn
class BrotherAutoPwn(SegmentAutoPwn):
    def __init__(self, targets, **kw): super().__init__("brother", targets, **kw)
