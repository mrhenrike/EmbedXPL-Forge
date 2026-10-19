"""firewallxpl AutoPwn — vpn segment. # authorized use only"""
from .base import SegmentAutoPwn
class VpnAutoPwn(SegmentAutoPwn):
    def __init__(self, targets, **kw): super().__init__("vpn", targets, **kw)
