"""Tests for embedxpl.core.telnet.telnet_client (TelnetCli)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from embedxpl.core.telnet.telnet_client import TELNET_TIMEOUT, TelnetCli


class TestTelnetCliInit:
    def test_defaults(self):
        cli = TelnetCli("192.168.1.1", 23)
        assert cli.telnet_target == "192.168.1.1"
        assert cli.telnet_port == 23
        assert cli.peer == "192.168.1.1:23"
        assert cli.verbosity is False
        assert cli.telnet_client is None

    def test_verbosity_true(self):
        cli = TelnetCli("10.0.0.1", 23, verbosity=True)
        assert cli.verbosity is True


class TestTelnetCliConnect:
    @patch("embedxpl.core.telnet.telnet_client.telnetlib")
    def test_connect_success(self, mock_tl):
        cli = TelnetCli("10.0.0.1", 23)
        result = cli.connect()
        assert result is True
        mock_tl.Telnet.assert_called_once_with("10.0.0.1", 23, timeout=TELNET_TIMEOUT)
        assert cli.telnet_client is mock_tl.Telnet.return_value

    @patch("embedxpl.core.telnet.telnet_client.telnetlib")
    def test_connect_failure(self, mock_tl):
        mock_tl.Telnet.side_effect = ConnectionRefusedError("refused")
        cli = TelnetCli("10.0.0.1", 23)
        result = cli.connect()
        assert result is False


class TestTelnetCliLogin:
    @patch("embedxpl.core.telnet.telnet_client.telnetlib")
    def test_login_success_shell_prompt(self, mock_tl):
        cli = TelnetCli("10.0.0.1", 23)
        mock_conn = MagicMock()
        mock_tl.Telnet.return_value = mock_conn
        mock_conn.expect.side_effect = [
            (0, None, b"Login: "),
            (0, None, b"Password: "),
            (-1, None, b"admin@router# "),
        ]
        result = cli.login("admin", "admin")
        assert result is True

    @patch("embedxpl.core.telnet.telnet_client.telnetlib")
    def test_login_failure_incorrect(self, mock_tl):
        cli = TelnetCli("10.0.0.1", 23)
        mock_conn = MagicMock()
        mock_tl.Telnet.return_value = mock_conn
        mock_conn.expect.side_effect = [
            (0, None, b"Login: "),
            (0, None, b"Password: "),
            (0, None, b"Incorrect"),
        ]
        result = cli.login("admin", "wrong")
        assert result is False

    @patch("embedxpl.core.telnet.telnet_client.telnetlib")
    def test_login_big_banner_success(self, mock_tl):
        cli = TelnetCli("10.0.0.1", 23)
        mock_conn = MagicMock()
        mock_tl.Telnet.return_value = mock_conn
        big_banner = b"A" * 600
        mock_conn.expect.side_effect = [
            (0, None, b"Login: "),
            (0, None, b"Password: "),
            (-1, None, big_banner),
        ]
        result = cli.login("admin", "admin")
        assert result is True

    @patch("embedxpl.core.telnet.telnet_client.telnetlib")
    def test_login_connect_failure(self, mock_tl):
        mock_tl.Telnet.side_effect = ConnectionRefusedError("down")
        cli = TelnetCli("10.0.0.1", 23)
        result = cli.login("admin", "admin", retries=1)
        assert result is False


class TestTelnetCliTestConnect:
    @patch("embedxpl.core.telnet.telnet_client.telnetlib")
    def test_test_connect_success(self, mock_tl):
        mock_conn = MagicMock()
        mock_tl.Telnet.return_value = mock_conn
        mock_conn.expect.return_value = (0, None, b"Login: ")
        cli = TelnetCli("10.0.0.1", 23)
        assert cli.test_connect() is True
        mock_conn.close.assert_called_once()

    @patch("embedxpl.core.telnet.telnet_client.telnetlib")
    def test_test_connect_failure(self, mock_tl):
        mock_tl.Telnet.side_effect = OSError("timeout")
        cli = TelnetCli("10.0.0.1", 23)
        assert cli.test_connect() is False


class TestTelnetCliReadWrite:
    def test_read_until_success(self):
        cli = TelnetCli("10.0.0.1", 23)
        cli.telnet_client = MagicMock()
        cli.telnet_client.read_until.return_value = b"prompt# "
        result = cli.read_until(b"# ")
        assert result == b"prompt# "
        cli.telnet_client.read_until.assert_called_once_with(b"# ", 5)

    def test_read_until_failure(self):
        cli = TelnetCli("10.0.0.1", 23)
        cli.telnet_client = MagicMock()
        cli.telnet_client.read_until.side_effect = OSError("err")
        assert cli.read_until(b"# ") is None

    def test_write_success(self):
        cli = TelnetCli("10.0.0.1", 23)
        cli.telnet_client = MagicMock()
        cli.telnet_client.write.return_value = None
        assert cli.write(b"show version\r\n") is True

    def test_write_failure(self):
        cli = TelnetCli("10.0.0.1", 23)
        cli.telnet_client = MagicMock()
        cli.telnet_client.write.side_effect = OSError("broken pipe")
        assert cli.write(b"data") is False


class TestTelnetCliClose:
    def test_close_success(self):
        cli = TelnetCli("10.0.0.1", 23)
        cli.telnet_client = MagicMock()
        cli.telnet_client.close.return_value = None
        assert cli.close() is True

    def test_close_failure(self):
        cli = TelnetCli("10.0.0.1", 23)
        cli.telnet_client = MagicMock()
        cli.telnet_client.close.side_effect = OSError("err")
        assert cli.close() is False


class TestTelnetCliInteractive:
    def test_interactive_delegates(self):
        cli = TelnetCli("10.0.0.1", 23)
        cli.telnet_client = MagicMock()
        cli.interactive()
        cli.telnet_client.interact.assert_called_once()
