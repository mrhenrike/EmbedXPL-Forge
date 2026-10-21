"""embedxpl AutoPwn — firewall segment. # authorized use only"""
from .base import SegmentAutoPwn
class FirewallAutoPwn(SegmentAutoPwn):
    def __init__(self, targets, **kw): super().__init__("firewall", targets, **kw)
