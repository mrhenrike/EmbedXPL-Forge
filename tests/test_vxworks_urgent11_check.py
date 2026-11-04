"""Tests for VxWorks URGENT/11 check module.

Covers: CVE list completeness, regex patterns, WDB probe logic,
and exploit class option validation — all without network I/O.
"""

import socket
import struct
from unittest.mock import MagicMock, patch

from embedxpl.modules.exploits.embedded_os.vxworks_urgent11_check import (
    _URGENT11_CVES,
    _VXWORKS_ANY_PATTERN,
    _VXWORKS_PATTERN,
    Exploit,
)

# ---------------------------------------------------------------------------
# CVE list completeness
# ---------------------------------------------------------------------------

class TestUrgent11CveList:
    def test_has_eleven_cves(self):
        assert len(_URGENT11_CVES) == 11

    def test_has_six_rce(self):
        rce = [c for c in _URGENT11_CVES if c[1] == "RCE"]
        assert len(rce) == 6

    def test_cve_2019_12255_present(self):
        ids = [c[0] for c in _URGENT11_CVES]
        assert "CVE-2019-12255" in ids

    def test_cve_2019_12265_present(self):
        ids = [c[0] for c in _URGENT11_CVES]
        assert "CVE-2019-12265" in ids

    def test_each_entry_has_three_fields(self):
        for entry in _URGENT11_CVES:
            assert len(entry) == 3


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

class TestVersionPatterns:
    def test_urgent11_pattern_matches_65(self):
        m = _VXWORKS_PATTERN.search("VxWorks 6.5")
        assert m is not None
        assert m.group(1) == "6.5"

    def test_urgent11_pattern_matches_69(self):
        m = _VXWORKS_PATTERN.search("VxWorks 6.9.4")
        assert m is not None

    def test_urgent11_pattern_no_match_55(self):
        assert _VXWORKS_PATTERN.search("VxWorks 5.5.1") is None

    def test_urgent11_pattern_no_match_7(self):
        assert _VXWORKS_PATTERN.search("VxWorks 7.0") is None

    def test_any_pattern_matches_55(self):
        m = _VXWORKS_ANY_PATTERN.search("VxWorks 5.5.1")
        assert m is not None
        assert m.group(1) == "5.5.1"

    def test_any_pattern_matches_65(self):
        m = _VXWORKS_ANY_PATTERN.search("VxWorks 6.5")
        assert m is not None

    def test_any_pattern_case_insensitive(self):
        assert _VXWORKS_ANY_PATTERN.search("VXWORKS 5.5") is not None


# ---------------------------------------------------------------------------
# Exploit class options and metadata
# ---------------------------------------------------------------------------

class TestExploitOptions:
    def test_default_ftp_port(self):
        e = Exploit()
        assert e.ftp_port == 21

    def test_default_wdb_port(self):
        e = Exploit()
        assert e.wdb_port == 17185

    def test_default_simulate_true(self):
        e = Exploit()
        assert e.simulate is True

    def test_default_check_wdb_true(self):
        e = Exploit()
        assert e.check_wdb is True

    def test_info_name_mentions_urgent11(self):
        info = vars(Exploit).get("_Exploit__info__", {})
        assert "URGENT/11" in info.get("name", "")

    def test_info_has_authors(self):
        info = vars(Exploit).get("_Exploit__info__", {})
        assert len(info.get("authors", ())) >= 1


# ---------------------------------------------------------------------------
# _probe_wdb (mocked)
# ---------------------------------------------------------------------------

class TestProbeWdb:
    def _make_reply(self, xid=0xDEAD0001, msg_type=1, reply_stat=0):
        return struct.pack(">III", xid, msg_type, reply_stat)

    def test_wdb_probe_active(self):
        """Active WDB agent returns True."""
        e = Exploit()
        e.target = "1.2.3.4"
        e.wdb_port = 17185
        e.timeout = 2.0
        with patch("socket.socket") as MockSocket:
            s = MagicMock()
            s.recvfrom.return_value = (self._make_reply(), ("1.2.3.4", 17185))
            MockSocket.return_value = s
            result = e._probe_wdb()
        assert result is True

    def test_wdb_probe_timeout(self):
        """Timeout returns False."""
        e = Exploit()
        e.target = "1.2.3.4"
        e.wdb_port = 17185
        e.timeout = 1.0
        with patch("socket.socket") as MockSocket:
            s = MagicMock()
            s.recvfrom.side_effect = socket.timeout
            MockSocket.return_value = s
            result = e._probe_wdb()
        assert result is False

    def test_wdb_probe_bad_reply(self):
        """Non-REPLY message type returns False."""
        e = Exploit()
        e.target = "1.2.3.4"
        e.wdb_port = 17185
        e.timeout = 1.0
        with patch("socket.socket") as MockSocket:
            s = MagicMock()
            # msg_type=0 (CALL, not REPLY)
            s.recvfrom.return_value = (self._make_reply(msg_type=0), ("1.2.3.4", 17185))
            MockSocket.return_value = s
            result = e._probe_wdb()
        assert result is False


# ---------------------------------------------------------------------------
# check() in simulate mode
# ---------------------------------------------------------------------------

class TestCheckSimulate:
    def test_check_returns_true_in_simulate(self):
        e = Exploit()
        e.simulate = "true"  # OptBool accepts "true"/"false" strings
        assert e.check() is True

    def test_check_returns_false_on_connection_error(self):
        e = Exploit()
        e.simulate = "false"
        e.target = "127.0.0.1"
        e.ftp_port = 19999  # nothing listening
        e.timeout = 1.0
        result = e.check()
        assert result is False
