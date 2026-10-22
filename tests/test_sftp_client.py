"""Tests for embedxpl.core.sftp.sftp_client (offline, mocked network)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import paramiko
import pytest

from embedxpl.core.sftp.sftp_client import SFTP_TIMEOUT, SFTPCli, SFTPClient


# -------------------------------------------------------
# SFTPCli construction
# -------------------------------------------------------


class TestSFTPCliInit:
    def test_defaults(self):
        cli = SFTPCli("10.0.0.1", 22)
        assert cli.sftp_target == "10.0.0.1"
        assert cli.sftp_port == 22
        assert cli.verbosity is False
        assert cli.peer == "10.0.0.1:22"
        assert cli.transport is None
        assert cli.sftp_client is None

    def test_verbose(self):
        cli = SFTPCli("192.168.1.1", 2222, verbosity=True)
        assert cli.verbosity is True


# -------------------------------------------------------
# SFTPCli.connect
# -------------------------------------------------------


class TestSFTPCliConnect:
    @patch("embedxpl.core.sftp.sftp_client.paramiko.Transport")
    def test_connect_success(self, mock_transport_cls):
        mock_transport = MagicMock()
        mock_transport_cls.return_value = mock_transport

        cli = SFTPCli("10.0.0.1", 22)
        assert cli.connect() is True
        mock_transport.start_client.assert_called_once()
        assert cli.transport is mock_transport

    @patch("embedxpl.core.sftp.sftp_client.paramiko.Transport", side_effect=Exception("refused"))
    def test_connect_failure(self, mock_transport_cls):
        cli = SFTPCli("10.0.0.1", 22)
        assert cli.connect() is False

    @patch("embedxpl.core.sftp.sftp_client.paramiko.Transport", side_effect=Exception("refused"))
    def test_connect_retries(self, mock_transport_cls):
        cli = SFTPCli("10.0.0.1", 22)
        assert cli.connect(retries=3) is False
        assert mock_transport_cls.call_count == 3


# -------------------------------------------------------
# SFTPCli.login
# -------------------------------------------------------


class TestSFTPCliLogin:
    @patch("embedxpl.core.sftp.sftp_client.paramiko.SFTPClient.from_transport")
    @patch("embedxpl.core.sftp.sftp_client.paramiko.Transport")
    def test_login_success(self, mock_transport_cls, mock_sftp_from):
        mock_transport = MagicMock()
        mock_transport_cls.return_value = mock_transport
        mock_sftp_from.return_value = MagicMock()

        cli = SFTPCli("10.0.0.1", 22)
        assert cli.login("admin", "password") is True
        mock_transport.auth_password.assert_called_once()

    @patch("embedxpl.core.sftp.sftp_client.paramiko.Transport")
    def test_login_auth_failure(self, mock_transport_cls):
        mock_transport = MagicMock()
        mock_transport.auth_password.side_effect = paramiko.AuthenticationException("bad")
        mock_transport_cls.return_value = mock_transport

        cli = SFTPCli("10.0.0.1", 22)
        assert cli.login("admin", "wrong") is False

    @patch("embedxpl.core.sftp.sftp_client.paramiko.Transport", side_effect=Exception("no conn"))
    def test_login_connect_failure(self, mock_transport_cls):
        cli = SFTPCli("10.0.0.1", 22)
        assert cli.login("admin", "pass") is False


# -------------------------------------------------------
# SFTPCli.test_connect
# -------------------------------------------------------


class TestSFTPCliTestConnect:
    @patch("embedxpl.core.sftp.sftp_client.paramiko.Transport")
    def test_connect_ok(self, mock_transport_cls):
        mock_transport = MagicMock()
        mock_transport_cls.return_value = mock_transport

        cli = SFTPCli("10.0.0.1", 22)
        assert cli.test_connect() is True

    @patch("embedxpl.core.sftp.sftp_client.paramiko.Transport", side_effect=Exception("err"))
    def test_connect_fail(self, mock_transport_cls):
        cli = SFTPCli("10.0.0.1", 22)
        assert cli.test_connect() is False


# -------------------------------------------------------
# SFTPCli.close
# -------------------------------------------------------


class TestSFTPCliClose:
    def test_close_no_connections(self):
        cli = SFTPCli("10.0.0.1", 22)
        assert cli.close() is True
        assert cli.transport is None
        assert cli.sftp_client is None

    def test_close_with_transport(self):
        cli = SFTPCli("10.0.0.1", 22)
        cli.transport = MagicMock()
        cli.sftp_client = MagicMock()
        assert cli.close() is True
        assert cli.transport is None
        assert cli.sftp_client is None

    def test_close_error(self):
        cli = SFTPCli("10.0.0.1", 22)
        mock_transport = MagicMock()
        mock_transport.close.side_effect = Exception("fail")
        cli.transport = mock_transport
        assert cli.close() is False


# -------------------------------------------------------
# SFTPClient (Exploit wrapper)
# -------------------------------------------------------


class TestSFTPClientExploit:
    def test_class_exists(self):
        assert hasattr(SFTPClient, "target_protocol")

    def test_sftp_create_method(self):
        assert hasattr(SFTPClient, "sftp_create")


# -------------------------------------------------------
# Constants
# -------------------------------------------------------


class TestConstants:
    def test_timeout(self):
        assert SFTP_TIMEOUT == 8.0
