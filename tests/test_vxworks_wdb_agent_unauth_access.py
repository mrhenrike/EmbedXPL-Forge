"""Tests for VxWorks WDB Agent unauthenticated access module.

Covers: packet construction, response parsing, string extraction,
and exploit class option validation — all without network I/O.
"""

import socket
import struct
from unittest.mock import MagicMock, patch

from embedxpl.modules.exploits.embedded_os.vxworks.vxworks_wdb_agent_unauth_access import (
    _VXWORKS_CPU_MAP,
    Exploit,
    _extract_strings,
    _probe_wdb,
    _rpc_call,
)

# ---------------------------------------------------------------------------
# _extract_strings
# ---------------------------------------------------------------------------

class TestExtractStrings:
    def test_simple_ascii(self):
        data = b"hello world\x00"
        assert "hello world" in _extract_strings(data, min_len=4)

    def test_min_len_filtering(self):
        data = b"abc\x00long_string\x00"
        result = _extract_strings(data, min_len=4)
        assert "abc" not in result
        assert "long_string" in result

    def test_multiple_strings(self):
        data = b"VxWorks5.5.1\x00\x00\x00Freescale MPC8568E\x00"
        result = _extract_strings(data, min_len=4)
        assert "VxWorks5.5.1" in result
        assert "Freescale MPC8568E" in result

    def test_empty_data(self):
        assert _extract_strings(b"", min_len=4) == []

    def test_non_printable_only(self):
        data = bytes(range(256))
        # Only 0x20-0x7e are printable; long run doesn't exist
        result = _extract_strings(data, min_len=20)
        # 0x20..0x7e is 95 chars, so there should be one long string
        assert len(result) >= 1

    def test_bootline_extraction(self):
        data = b"\x00\x00CMG_2:F:/DAT_FILE/SLOT_3.dat\x00"
        result = _extract_strings(data, min_len=4)
        assert any("CMG_2" in s for s in result)


# ---------------------------------------------------------------------------
# _rpc_call (mocked socket)
# ---------------------------------------------------------------------------

class TestRpcCall:
    def _make_reply(self, xid=0x12345678, accept_stat=0, body=b""):
        """Build a minimal valid RPC REPLY frame."""
        return struct.pack(">IIIIII",
                           xid,       # XID
                           1,         # REPLY
                           0,         # MSG_ACCEPTED
                           0,         # verf flavor
                           0,         # verf length
                           accept_stat) + body

    def test_null_procedure_success(self):
        reply = self._make_reply(body=b"\x00" * 4)
        sock = MagicMock()
        sock.recvfrom.return_value = (reply, ("1.2.3.4", 17185))
        result = _rpc_call(sock, "1.2.3.4", 17185, proc=0)
        assert result == b"\x00" * 4

    def test_reply_too_short_returns_none(self):
        sock = MagicMock()
        sock.recvfrom.return_value = (b"\x00" * 10, ("1.2.3.4", 17185))
        result = _rpc_call(sock, "1.2.3.4", 17185, proc=0)
        assert result is None

    def test_timeout_returns_none(self):
        sock = MagicMock()
        sock.recvfrom.side_effect = socket.timeout
        result = _rpc_call(sock, "1.2.3.4", 17185, proc=0)
        assert result is None

    def test_non_zero_accept_stat_returns_none(self):
        reply = self._make_reply(accept_stat=4)  # PROC_UNAVAIL
        sock = MagicMock()
        sock.recvfrom.return_value = (reply, ("1.2.3.4", 17185))
        result = _rpc_call(sock, "1.2.3.4", 17185, proc=0)
        assert result is None


# ---------------------------------------------------------------------------
# _probe_wdb (mocked)
# ---------------------------------------------------------------------------

class TestProbeWdb:
    def _make_null_reply(self):
        return struct.pack(">III",
                           0xDEAD0001,  # XID
                           1,           # REPLY
                           0)           # MSG_ACCEPTED

    def test_active_agent_returns_true(self):
        with patch("socket.socket") as MockSocket:
            s = MagicMock()
            s.recvfrom.return_value = (self._make_null_reply(), ("1.2.3.4", 17185))
            MockSocket.return_value.__enter__ = MagicMock(return_value=s)
            MockSocket.return_value = s
            result = _probe_wdb("1.2.3.4", 17185, timeout=2.0)
        assert result is True

    def test_no_response_returns_false(self):
        with patch("socket.socket") as MockSocket:
            s = MagicMock()
            s.recvfrom.side_effect = socket.timeout
            MockSocket.return_value = s
            result = _probe_wdb("1.2.3.4", 17185, timeout=0.1)
        assert result is False


# ---------------------------------------------------------------------------
# CPU map coverage
# ---------------------------------------------------------------------------

class TestCpuMap:
    def test_powerpc_e500_in_map(self):
        assert 0x0000000a in _VXWORKS_CPU_MAP
        assert "MPC85" in _VXWORKS_CPU_MAP[0x0000000a]

    def test_mips_in_map(self):
        assert 0x00000005 in _VXWORKS_CPU_MAP


# ---------------------------------------------------------------------------
# Exploit class options
# ---------------------------------------------------------------------------

class TestExploitOptions:
    def test_default_port(self):
        e = Exploit()
        assert e.port == 17185

    def test_default_target_empty(self):
        e = Exploit()
        assert e.target == ""

    def test_default_scan_mem_false(self):
        e = Exploit()
        assert e.scan_mem is False

    def test_info_has_required_keys(self):
        info = Exploit.__info__
        assert "name" in info
        assert "description" in info
        assert "attack_class" in info
        assert info["attack_class"] == "remote_code_execution"

    def test_cwe_missing_auth(self):
        assert Exploit.__info__["cwe"] == "CWE-306"

    def test_check_returns_false_on_no_response(self):
        e = Exploit()
        e.target = "127.0.0.1"
        e.port = 19999  # nothing listening
        e.timeout = 1
        with patch("embedxpl.modules.exploits.embedded_os.vxworks.vxworks_wdb_agent_unauth_access._probe_wdb",
                   return_value=False):
            result = e.check()
        assert result is False
