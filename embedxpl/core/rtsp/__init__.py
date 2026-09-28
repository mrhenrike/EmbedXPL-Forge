# Author: André Henrique (LinkedIn/X: @mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""EmbedXPL-Forge — RTSP Camera Engine.

Complete RTSP protocol implementation ported and extended from
`cameradar <https://github.com/ullaakut/cameradar>`_ (MIT, Ullaakut).

Provides:
  - :class:`~embedxpl.core.rtsp.client.RTSPClient` — low-level RTSP socket client
  - :class:`~embedxpl.core.rtsp.attacker.RTSPAttacker` — route + credential brute-force
  - :class:`~embedxpl.core.rtsp.scanner.RTSPScanner` — network discovery (nmap/masscan/direct)
  - :class:`~embedxpl.core.rtsp.models.RTSPStream` — stream data model

Author: André Henrique (@mrhenrike) | União Geek
Version: 1.0.0
"""

from embedxpl.core.rtsp.models import RTSPStream, AuthType
from embedxpl.core.rtsp.client import RTSPClient
from embedxpl.core.rtsp.attacker import RTSPAttacker
from embedxpl.core.rtsp.scanner import RTSPScanner

__all__ = ["RTSPStream", "AuthType", "RTSPClient", "RTSPAttacker", "RTSPScanner"]
