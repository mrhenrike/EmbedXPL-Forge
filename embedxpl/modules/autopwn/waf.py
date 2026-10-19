"""firewallxpl AutoPwn — waf segment. # authorized use only"""
from .base import SegmentAutoPwn
class WafAutoPwn(SegmentAutoPwn):
    def __init__(self, targets, **kw): super().__init__("waf", targets, **kw)
