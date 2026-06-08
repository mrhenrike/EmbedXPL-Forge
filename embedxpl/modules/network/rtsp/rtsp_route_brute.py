"""RTSP stream route discovery via bruteforce of common paths.

Attempts common RTSP stream paths against a target to identify
accessible streams without credentials.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from __future__ import annotations
from embedxpl.modules.network.rtsp.rtsp_client import RTSPClient

COMMON_RTSP_PATHS: list[str] = [
    "/",
    "/live",
    "/live.sdp",
    "/live/ch00_0",
    "/live/ch01_0",
    "/stream",
    "/stream1",
    "/stream2",
    "/video",
    "/video1",
    "/video2",
    "/h264",
    "/h264/ch1/main/av_stream",
    "/h264Preview_01_main",
    "/h264Preview_01_sub",
    "/cam/realmonitor",
    "/cam/realmonitor?channel=1&subtype=0",
    "/axis-media/media.amp",
    "/mpeg4/media.amp",
    "/onvif-media/media.amp",
    "/onvif/profile1/media.smp",
    "/onvif/profile2/media.smp",
    "/1",
    "/11",
    "/12",
    "/1/stream",
    "/ch01.264",
    "/ch01.264?ptype=tcp",
    "/ch0/stream",
    "/ch1/stream",
    "/videoMain",
    "/videoSub",
    "/cam",
    "/cam0_0",
    "/cam1_0",
    "/rtsp_tunnel",
    "/unicast",
    "/av0_0",
    "/av0_1",
    "/Streaming/Channels/1",
    "/Streaming/Channels/2",
    "/Streaming/Channels/101",
    "/Streaming/Channels/102",
    "/PSIA/Streaming/channels/1",
    "/PSIA/Streaming/channels/2",
    "/channel1",
    "/channel2",
    "/MediaInput/h264",
    "/media/video1",
    "/preview",
    "/0/video1",
    "/0/video2",
    "/1/video1",
    "/2/video1",
    "/3/video1",
    "/live/av0",
    "/live/av1",
    "/live/video0",
    "/live/video1",
    "/nphMpeg4/nil-320x240",
    "/nphMpeg4/nil-640x480",
    "/wfov",
    "/nvr",
    "/image",
    "/img/video.sav",
    "/GetData.cgi",
    "/GetData.cgi?ch=1",
]


def discover_routes(
    host: str,
    port: int = 554,
    paths: list[str] | None = None,
    timeout: float = 3.0,
) -> list[str]:
    """Discover accessible RTSP stream paths on a target.

    Sends DESCRIBE requests to each path and returns those that
    respond with a 200 OK (stream available) or 401 (stream exists
    but authentication required).

    Args:
        host: Target RTSP server hostname or IP.
        port: RTSP port number (default 554).
        paths: List of paths to probe. Defaults to COMMON_RTSP_PATHS.
        timeout: Per-request socket timeout in seconds.

    Returns:
        List of accessible RTSP path strings.
    """
    probe_paths = paths if paths is not None else COMMON_RTSP_PATHS
    found: list[str] = []

    for path in probe_paths:
        try:
            client = RTSPClient(host, port, timeout=timeout)
            client.connect()
            resp = client.describe(path)
            client.disconnect()

            if resp.status_code in (200, 401):
                found.append(path)
        except Exception:
            pass

    return found
