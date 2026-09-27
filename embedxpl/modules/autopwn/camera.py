"""EmbedXPL AutoPwn — Camera segment."""
from .segment import SegmentAutoPwn

class CameraAutoPwn(SegmentAutoPwn):
    """AutoPwn all camera modules against target(s)."""
    def __init__(self, targets, **kwargs):
        super().__init__(segment="camera", targets=targets, **kwargs)
