"""Tests for embedxpl.core.ftp.ftp_client (FTPCli)."""

from __future__ import annotations

import ftplib
from unittest.mock import MagicMock, patch

from embedxpl.core.ftp.ftp_client import FTP_TIMEOUT, FTPCli


class TestFTPCliInit:
    def test_plain_creates_ftp(self):
        cli = FTPCli("192.168.1.1", 21)
        assert isinstance(cli.ftp_client, ftplib.FTP)
        assert cli.ftp_target == "192.168.1.1"
        assert cli.ftp_port == 21
        assert cli.peer == "192.168.1.1:21"
        assert cli.verbosity is False

    def test_ssl_creates_ftp_tls(self):
        cli = FTPCli("10.0.0.1", 990, ssl=True)
        assert isinstance(cli.ftp_client, ftplib.FTP_TLS)

    def test_verbosity_true(self):
        cli = FTPCli("10.0.0.1", 21, verbosity=True)
        assert cli.verbosity is True


class TestFTPCliConnect:
    def test_connect_success(self):
        cli = FTPCli("10.0.0.1", 21)
        cli.ftp_client.connect = MagicMock(return_value="220 Welcome")
        result = cli.connect()
        assert result is True
        cli.ftp_client.connect.assert_called_once_with("10.0.0.1", 21, timeout=FTP_TIMEOUT)

    def test_connect_failure_single_retry(self):
        cli = FTPCli("10.0.0.1", 21)
        cli.ftp_client.connect = MagicMock(side_effect=OSError("refused"))
        cli.ftp_client.close = MagicMock()
        result = cli.connect(retries=1)
        assert result is False
        cli.ftp_client.close.assert_called()

    def test_connect_retries_multiple(self):
        cli = FTPCli("10.0.0.1", 21)
        cli.ftp_client.connect = MagicMock(side_effect=[OSError("err"), "220 OK"])
        cli.ftp_client.close = MagicMock()
        result = cli.connect(retries=2)
        assert result is True
        assert cli.ftp_client.connect.call_count == 2


class TestFTPCliLogin:
    def test_login_success(self):
        cli = FTPCli("10.0.0.1", 21)
        cli.ftp_client.login = MagicMock(return_value="230 Logged in")
        result = cli.login("admin", "admin")
        assert result is True
        cli.ftp_client.login.assert_called_once_with("admin", "admin")

    def test_login_failure(self):
        cli = FTPCli("10.0.0.1", 21)
        cli.ftp_client.login = MagicMock(side_effect=ftplib.error_perm("530 Login incorrect"))
        cli.ftp_client.close = MagicMock()
        result = cli.login("admin", "wrong")
        assert result is False
        cli.ftp_client.close.assert_called()


class TestFTPCliTestConnect:
    def test_test_connect_success(self):
        cli = FTPCli("10.0.0.1", 21)
        cli.ftp_client.connect = MagicMock(return_value="220")
        cli.ftp_client.close = MagicMock()
        assert cli.test_connect() is True
        cli.ftp_client.close.assert_called()

    def test_test_connect_failure(self):
        cli = FTPCli("10.0.0.1", 21)
        cli.ftp_client.connect = MagicMock(side_effect=OSError("down"))
        cli.ftp_client.close = MagicMock()
        assert cli.test_connect() is False


class TestFTPCliGetContent:
    def test_get_content_success(self):
        cli = FTPCli("10.0.0.1", 21)

        def fake_retrbinary(cmd, callback):
            callback(b"file content here")

        cli.ftp_client.retrbinary = MagicMock(side_effect=fake_retrbinary)
        result = cli.get_content("/etc/passwd")
        assert result == b"file content here"
        cli.ftp_client.retrbinary.assert_called_once()
        assert "RETR /etc/passwd" in cli.ftp_client.retrbinary.call_args[0][0]

    def test_get_content_failure_returns_none(self):
        cli = FTPCli("10.0.0.1", 21)
        cli.ftp_client.retrbinary = MagicMock(side_effect=ftplib.error_perm("550 Not found"))
        result = cli.get_content("/nonexistent")
        assert result is None


class TestFTPCliClose:
    def test_close_success(self):
        cli = FTPCli("10.0.0.1", 21)
        cli.ftp_client.close = MagicMock(return_value=None)
        assert cli.close() is True

    def test_close_failure(self):
        cli = FTPCli("10.0.0.1", 21)
        cli.ftp_client.close = MagicMock(side_effect=OSError("err"))
        assert cli.close() is False
