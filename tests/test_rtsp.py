"""Tests for embedxpl.core.rtsp (client + models).

All tests are offline; socket calls are mocked.
"""

from __future__ import annotations

import base64

import pytest

from embedxpl.core.rtsp.models import AuthType, RTSPStream
from embedxpl.core.rtsp.client import (
    RTSP_FORBIDDEN,
    RTSP_NOT_FOUND,
    RTSP_OK,
    RTSP_UNAUTHORIZED,
    _build_describe_request,
    _build_options_request,
    _detect_auth_type_from_header,
    _parse_digest_challenge,
    _parse_rtsp_response,
)


# -------------------------------------------------------
# RTSPStream model
# -------------------------------------------------------


class TestRTSPStream:
    def test_defaults(self):
        s = RTSPStream(address="10.0.0.1")
        assert s.port == 554
        assert s.auth_type == AuthType.UNKNOWN
        assert s.available is False

    def test_route_empty(self):
        s = RTSPStream(address="10.0.0.1")
        assert s.route() == ""

    def test_route_first(self):
        s = RTSPStream(address="10.0.0.1", routes=["/live", "/stream"])
        assert s.route() == "/live"

    def test_url_no_creds(self):
        s = RTSPStream(address="10.0.0.1", port=554, routes=["/live"])
        assert s.url_no_creds() == "rtsp://10.0.0.1:554/live"

    def test_url_with_creds(self):
        s = RTSPStream(
            address="10.0.0.1", port=554, routes=["/live"],
            username="admin", password="p@ss",
        )
        url = s.url()
        assert "admin" in url
        assert "p%40ss" in url
        assert url.startswith("rtsp://")

    def test_url_rtsps_scheme(self):
        s = RTSPStream(address="10.0.0.1", port=443, scheme="rtsps", routes=["/cam"])
        assert s.url().startswith("rtsps://")

    def test_to_m3u_entry(self):
        s = RTSPStream(address="10.0.0.1", port=554, device="Hikvision", routes=["/h264"])
        m3u = s.to_m3u_entry()
        assert "#EXTINF:" in m3u
        assert "Hikvision" in m3u
        assert "rtsp://10.0.0.1:554/h264" in m3u

    def test_summary_not_accessible(self):
        s = RTSPStream(address="10.0.0.1")
        assert "NOT_ACCESSIBLE" in s.summary()

    def test_summary_accessible(self):
        s = RTSPStream(address="10.0.0.1", available=True)
        assert "ACCESSIBLE" in s.summary()

    def test_summary_route_found(self):
        s = RTSPStream(address="10.0.0.1", route_found=True)
        assert "ROUTE_FOUND" in s.summary()


# -------------------------------------------------------
# AuthType enum
# -------------------------------------------------------


class TestAuthType:
    def test_values(self):
        assert AuthType.NONE == 1
        assert AuthType.BASIC == 2
        assert AuthType.DIGEST == 3

    def test_name(self):
        assert AuthType.DIGEST.name == "DIGEST"


# -------------------------------------------------------
# RTSP request builders
# -------------------------------------------------------


class TestBuildOptionsRequest:
    def test_basic_format(self):
        req = _build_options_request("10.0.0.1", 554)
        assert req.startswith("OPTIONS rtsp://10.0.0.1:554/ RTSP/1.0\r\n")
        assert "CSeq: 1" in req
        assert req.endswith("\r\n\r\n")

    def test_custom_port(self):
        req = _build_options_request("192.168.1.100", 8554)
        assert "rtsp://192.168.1.100:8554/" in req


class TestBuildDescribeRequest:
    def test_no_auth(self):
        req = _build_describe_request("10.0.0.1", 554, "/live")
        assert "DESCRIBE rtsp://10.0.0.1:554/live RTSP/1.0" in req
        assert "Authorization" not in req
        assert "Accept: application/sdp" in req

    def test_basic_auth(self):
        req = _build_describe_request(
            "10.0.0.1", 554, "/live",
            username="admin", password="test",
            auth_type=AuthType.BASIC,
        )
        expected_creds = base64.b64encode(b"admin:test").decode()
        assert f"Authorization: Basic {expected_creds}" in req

    def test_digest_auth(self):
        req = _build_describe_request(
            "10.0.0.1", 554, "/cam",
            username="admin", password="test",
            auth_type=AuthType.DIGEST,
            digest_realm="RTSP Server",
            digest_nonce="abc123",
        )
        assert 'Authorization: Digest' in req
        assert 'username="admin"' in req
        assert 'realm="RTSP Server"' in req
        assert 'nonce="abc123"' in req

    def test_rtsps_scheme(self):
        req = _build_describe_request("10.0.0.1", 443, "/live", scheme="rtsps")
        assert "rtsps://10.0.0.1:443/live" in req


# -------------------------------------------------------
# RTSP response parser
# -------------------------------------------------------


class TestParseRtspResponse:
    def test_200_ok(self):
        raw = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: TestCam\r\n\r\nv=0\r\n"
        code, headers, body = _parse_rtsp_response(raw)
        assert code == 200
        assert headers["server"] == "TestCam"
        assert "v=0" in body

    def test_401_unauthorized(self):
        raw = (
            b"RTSP/1.0 401 Unauthorized\r\n"
            b'WWW-Authenticate: Digest realm="cam", nonce="xyz"\r\n'
            b"\r\n"
        )
        code, headers, body = _parse_rtsp_response(raw)
        assert code == 401
        assert "www-authenticate" in headers
        assert body == ""

    def test_empty_input(self):
        code, headers, body = _parse_rtsp_response(b"")
        assert code == 0

    def test_malformed_no_status(self):
        code, headers, body = _parse_rtsp_response(b"garbage\r\n\r\n")
        assert code == 0


# -------------------------------------------------------
# Auth helpers
# -------------------------------------------------------


class TestDetectAuthType:
    @pytest.mark.parametrize(("header", "expected"), [
        ("", AuthType.NONE),
        ("Basic realm='cam'", AuthType.BASIC),
        ('Digest realm="cam", nonce="abc"', AuthType.DIGEST),
        ("SomeUnknownScheme", AuthType.UNKNOWN),
    ])
    def test_detect(self, header, expected):
        assert _detect_auth_type_from_header(header) == expected


class TestParseDigestChallenge:
    def test_full_parse(self):
        header = 'Digest realm="IPCamera", nonce="1a2b3c4d"'
        realm, nonce = _parse_digest_challenge(header)
        assert realm == "IPCamera"
        assert nonce == "1a2b3c4d"

    def test_empty_header(self):
        realm, nonce = _parse_digest_challenge("")
        assert realm == ""
        assert nonce == ""

    def test_missing_nonce(self):
        header = 'Digest realm="test"'
        realm, nonce = _parse_digest_challenge(header)
        assert realm == "test"
        assert nonce == ""


# -------------------------------------------------------
# Constants
# -------------------------------------------------------


class TestRTSPConstants:
    def test_status_codes(self):
        assert RTSP_OK == 200
        assert RTSP_UNAUTHORIZED == 401
        assert RTSP_FORBIDDEN == 403
        assert RTSP_NOT_FOUND == 404


# -------------------------------------------------------
# RTSPClient (socket-level, mocked)
# -------------------------------------------------------

from unittest.mock import MagicMock, patch
from embedxpl.core.rtsp.client import RTSPClient, RTSPOverHTTPTunnel


class TestRTSPClientInit:
    def test_defaults(self):
        c = RTSPClient("10.0.0.1")
        assert c.host == "10.0.0.1"
        assert c.port == 554
        assert c.timeout == 5.0
        assert c.use_tls is False
        assert c.tunnel_http is False
        assert c._cseq == 0

    def test_tls_mode(self):
        c = RTSPClient("10.0.0.1", port=443, use_tls=True)
        assert c.use_tls is True

    def test_tunnel_mode(self):
        c = RTSPClient("10.0.0.1", tunnel_http=True)
        assert c.tunnel_http is True
        assert c._http_tunnel is not None


class TestRTSPClientFromScheme:
    def test_rtsp(self):
        c = RTSPClient.from_scheme("10.0.0.1", 554, "rtsp")
        assert c.use_tls is False
        assert c.tunnel_http is False

    def test_rtsps(self):
        c = RTSPClient.from_scheme("10.0.0.1", 443, "rtsps")
        assert c.use_tls is True
        assert c.tunnel_http is False

    def test_http_tunnel(self):
        c = RTSPClient.from_scheme("10.0.0.1", 80, "http")
        assert c.tunnel_http is True
        assert c.use_tls is False

    def test_https_tunnel(self):
        c = RTSPClient.from_scheme("10.0.0.1", 443, "https")
        assert c.tunnel_http is True
        assert c.use_tls is True

    def test_unknown_scheme(self):
        c = RTSPClient.from_scheme("10.0.0.1", 554, "foobar")
        assert c.use_tls is False
        assert c.tunnel_http is False


class TestRTSPClientOptions:
    @patch.object(RTSPClient, "_send_recv")
    def test_options_200(self, mock_send):
        mock_send.return_value = b"RTSP/1.0 200 OK\r\nServer: TestCam\r\n\r\n"
        c = RTSPClient("10.0.0.1")
        code, headers, body = c.options()
        assert code == 200
        assert headers["server"] == "TestCam"
        assert c._cseq == 1

    @patch.object(RTSPClient, "_send_recv")
    def test_options_empty_response(self, mock_send):
        mock_send.return_value = b""
        c = RTSPClient("10.0.0.1")
        code, _, _ = c.options()
        assert code == 0


class TestRTSPClientDescribe:
    @patch.object(RTSPClient, "_send_recv")
    def test_describe_200(self, mock_send):
        mock_send.return_value = b"RTSP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nv=0\r\n"
        c = RTSPClient("10.0.0.1")
        code, headers, body = c.describe(route="/live")
        assert code == 200
        assert "v=0" in body

    @patch.object(RTSPClient, "_send_recv")
    def test_describe_401(self, mock_send):
        mock_send.return_value = (
            b"RTSP/1.0 401 Unauthorized\r\n"
            b'WWW-Authenticate: Digest realm="cam", nonce="xyz"\r\n'
            b"\r\n"
        )
        c = RTSPClient("10.0.0.1")
        code, headers, _ = c.describe(route="/live")
        assert code == 401


class TestRTSPClientProbeAuthType:
    @patch.object(RTSPClient, "_send_recv")
    def test_probe_no_auth(self, mock_send):
        mock_send.return_value = b"RTSP/1.0 200 OK\r\n\r\n"
        c = RTSPClient("10.0.0.1")
        auth_type, realm, nonce = c.probe_auth_type("/live")
        assert auth_type == AuthType.NONE

    @patch.object(RTSPClient, "_send_recv")
    def test_probe_digest(self, mock_send):
        mock_send.return_value = (
            b"RTSP/1.0 401 Unauthorized\r\n"
            b'WWW-Authenticate: Digest realm="IPCam", nonce="abc"\r\n'
            b"\r\n"
        )
        c = RTSPClient("10.0.0.1")
        auth_type, realm, nonce = c.probe_auth_type("/live")
        assert auth_type == AuthType.DIGEST
        assert realm == "IPCam"
        assert nonce == "abc"

    @patch.object(RTSPClient, "_send_recv")
    def test_probe_basic(self, mock_send):
        mock_send.return_value = (
            b"RTSP/1.0 401 Unauthorized\r\n"
            b"WWW-Authenticate: Basic realm=\"cam\"\r\n"
            b"\r\n"
        )
        c = RTSPClient("10.0.0.1")
        auth_type, _, _ = c.probe_auth_type()
        assert auth_type == AuthType.BASIC

    @patch.object(RTSPClient, "_send_recv")
    def test_probe_unknown_status(self, mock_send):
        mock_send.return_value = b"RTSP/1.0 503 Service Unavailable\r\n\r\n"
        c = RTSPClient("10.0.0.1")
        auth_type, _, _ = c.probe_auth_type()
        assert auth_type == AuthType.UNKNOWN


class TestRTSPClientTestRoute:
    @patch.object(RTSPClient, "_send_recv")
    def test_route_200(self, mock_send):
        mock_send.return_value = b"RTSP/1.0 200 OK\r\n\r\n"
        assert RTSPClient("10.0.0.1").test_route("/live") is True

    @patch.object(RTSPClient, "_send_recv")
    def test_route_401(self, mock_send):
        mock_send.return_value = b"RTSP/1.0 401 Unauthorized\r\n\r\n"
        assert RTSPClient("10.0.0.1").test_route("/live") is True

    @patch.object(RTSPClient, "_send_recv")
    def test_route_404(self, mock_send):
        mock_send.return_value = b"RTSP/1.0 404 Not Found\r\n\r\n"
        assert RTSPClient("10.0.0.1").test_route("/missing") is False


class TestRTSPClientTestCredentials:
    @patch.object(RTSPClient, "_send_recv")
    def test_creds_ok(self, mock_send):
        mock_send.return_value = b"RTSP/1.0 200 OK\r\n\r\n"
        c = RTSPClient("10.0.0.1")
        assert c.test_credentials("/live", "admin", "pass", AuthType.BASIC) is True

    @patch.object(RTSPClient, "_send_recv")
    def test_creds_401(self, mock_send):
        mock_send.return_value = b"RTSP/1.0 401 Unauthorized\r\n\r\n"
        c = RTSPClient("10.0.0.1")
        assert c.test_credentials("/live", "admin", "bad", AuthType.BASIC) is False

    @patch.object(RTSPClient, "_send_recv")
    def test_creds_404_accepted(self, mock_send):
        mock_send.return_value = b"RTSP/1.0 404 Not Found\r\n\r\n"
        c = RTSPClient("10.0.0.1")
        assert c.test_credentials("/x", "admin", "pass", AuthType.BASIC) is True


class TestRTSPClientBanner:
    @patch.object(RTSPClient, "_send_recv")
    def test_banner_returned(self, mock_send):
        mock_send.return_value = b"RTSP/1.0 200 OK\r\nServer: Hikvision\r\n\r\n"
        assert RTSPClient("10.0.0.1").banner() == "Hikvision"

    @patch.object(RTSPClient, "_send_recv", side_effect=Exception("timeout"))
    def test_banner_error(self, mock_send):
        assert RTSPClient("10.0.0.1").banner() == ""


class TestRTSPClientIsRtsp:
    @patch.object(RTSPClient, "_send_recv")
    def test_is_rtsp_200(self, mock_send):
        mock_send.return_value = b"RTSP/1.0 200 OK\r\n\r\n"
        assert RTSPClient("10.0.0.1").is_rtsp() is True

    @patch.object(RTSPClient, "_send_recv")
    def test_is_rtsp_401(self, mock_send):
        mock_send.return_value = b"RTSP/1.0 401 Unauthorized\r\n\r\n"
        assert RTSPClient("10.0.0.1").is_rtsp() is True

    @patch.object(RTSPClient, "_send_recv", side_effect=Exception("err"))
    def test_not_rtsp(self, mock_send):
        assert RTSPClient("10.0.0.1").is_rtsp() is False


# -------------------------------------------------------
# RTSPOverHTTPTunnel
# -------------------------------------------------------


class TestRTSPOverHTTPTunnel:
    def test_init(self):
        t = RTSPOverHTTPTunnel("10.0.0.1", 80)
        assert t.host == "10.0.0.1"
        assert t.port == 80
        assert t.use_tls is False
        assert len(t._session_cookie) > 0

    def test_init_tls(self):
        t = RTSPOverHTTPTunnel("10.0.0.1", 443, use_tls=True)
        assert t.use_tls is True

    @patch("socket.create_connection", side_effect=Exception("refused"))
    def test_send_via_http_error(self, mock_conn):
        t = RTSPOverHTTPTunnel("10.0.0.1", 80)
        result = t.send_rtsp_via_http("OPTIONS rtsp://10.0.0.1/ RTSP/1.0\r\n\r\n")
        assert result is None

    @patch("socket.create_connection", side_effect=Exception("refused"))
    def test_establish_get_channel_error(self, mock_conn):
        t = RTSPOverHTTPTunnel("10.0.0.1", 80)
        result = t.establish_get_channel()
        assert result is None
