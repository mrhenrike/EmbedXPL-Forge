"""Tests for embedxpl.core.ssh.ssh_client (offline, mocked network)."""
from __future__ import annotations

import io
from unittest.mock import MagicMock, PropertyMock, call, patch

import paramiko
import pytest

from embedxpl.core.ssh.ssh_client import SSH_TIMEOUT, SSHCli, SSHClient


# -------------------------------------------------------
# SSHCli construction
# -------------------------------------------------------


class TestSSHCliInit:
    def test_defaults(self):
        cli = SSHCli("10.0.0.1", 22)
        assert cli.ssh_target == "10.0.0.1"
        assert cli.ssh_port == 22
        assert cli.verbosity is False
        assert cli.peer == "10.0.0.1:22"

    def test_verbose(self):
        cli = SSHCli("192.168.1.1", 2222, verbosity=True)
        assert cli.verbosity is True
        assert cli.peer == "192.168.1.1:2222"

    def test_ssh_client_is_paramiko(self):
        cli = SSHCli("10.0.0.1", 22)
        assert isinstance(cli.ssh_client, paramiko.SSHClient)


# -------------------------------------------------------
# _load_private_key
# -------------------------------------------------------


class TestLoadPrivateKey:
    def test_rsa_key(self):
        rsa_pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIBogIBAAJBANjXbZKKZknBJYIgkiZ6hXlM88sCfk/dN0thdFAsmrFW1Pfwu7q0\n"
            "-----END RSA PRIVATE KEY-----"
        )
        with patch.object(paramiko.RSAKey, "from_private_key") as mock_rsa:
            mock_rsa.return_value = MagicMock()
            result = SSHCli._load_private_key(rsa_pem)
            assert mock_rsa.called

    def test_ecdsa_key(self):
        ec_pem = (
            "-----BEGIN EC PRIVATE KEY-----\n"
            "MHQCAQEEIFake\n"
            "-----END EC PRIVATE KEY-----"
        )
        with patch.object(paramiko.ECDSAKey, "from_private_key") as mock_ec:
            mock_ec.return_value = MagicMock()
            result = SSHCli._load_private_key(ec_pem)
            assert mock_ec.called

    def test_openssh_key_tries_loaders(self):
        openssh_pem = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEA\n"
            "-----END OPENSSH PRIVATE KEY-----"
        )
        with patch.object(paramiko.RSAKey, "from_private_key", side_effect=Exception):
            with patch.object(paramiko.ECDSAKey, "from_private_key", side_effect=Exception):
                result = SSHCli._load_private_key(openssh_pem)
                assert result is None

    def test_dsa_key(self):
        dsa_pem = (
            "-----BEGIN DSA PRIVATE KEY-----\n"
            "MIIBuwIBAAJBAMFake\n"
            "-----END DSA PRIVATE KEY-----"
        )
        if hasattr(paramiko, "DSSKey"):
            with patch.object(paramiko.DSSKey, "from_private_key") as mock_dss:
                mock_dss.return_value = MagicMock()
                result = SSHCli._load_private_key(dsa_pem)
                assert mock_dss.called

    def test_unknown_key_type(self):
        result = SSHCli._load_private_key("not a real key format")
        assert result is None


# -------------------------------------------------------
# SSHCli.login
# -------------------------------------------------------


class TestSSHCliLogin:
    @patch.object(paramiko.SSHClient, "connect")
    @patch.object(paramiko.SSHClient, "close")
    def test_login_success(self, mock_close, mock_connect):
        cli = SSHCli("10.0.0.1", 22)
        assert cli.login("admin", "password") is True

    @patch.object(paramiko.SSHClient, "connect", side_effect=paramiko.AuthenticationException("bad creds"))
    @patch.object(paramiko.SSHClient, "close")
    def test_login_auth_failure(self, mock_close, mock_connect):
        cli = SSHCli("10.0.0.1", 22)
        assert cli.login("admin", "wrong") is False

    @patch.object(paramiko.SSHClient, "connect", side_effect=Exception("connection refused"))
    @patch.object(paramiko.SSHClient, "close")
    def test_login_connection_error_retries(self, mock_close, mock_connect):
        cli = SSHCli("10.0.0.1", 22)
        assert cli.login("admin", "pass", retries=2) is False
        assert mock_connect.call_count == 2


# -------------------------------------------------------
# SSHCli.login_pkey
# -------------------------------------------------------


class TestSSHCliLoginPkey:
    @patch.object(paramiko.SSHClient, "connect")
    @patch.object(paramiko.SSHClient, "close")
    def test_login_pkey_success(self, mock_close, mock_connect):
        rsa_pem = "-----BEGIN RSA PRIVATE KEY-----\nFake\n-----END RSA PRIVATE KEY-----"
        with patch.object(paramiko.RSAKey, "from_private_key", return_value=MagicMock()):
            cli = SSHCli("10.0.0.1", 22)
            assert cli.login_pkey("admin", rsa_pem) is True

    def test_login_pkey_invalid_key(self):
        cli = SSHCli("10.0.0.1", 22)
        assert cli.login_pkey("admin", "not-a-key") is False

    @patch.object(paramiko.SSHClient, "connect", side_effect=paramiko.AuthenticationException)
    @patch.object(paramiko.SSHClient, "close")
    def test_login_pkey_auth_failure(self, mock_close, mock_connect):
        rsa_pem = "-----BEGIN RSA PRIVATE KEY-----\nFake\n-----END RSA PRIVATE KEY-----"
        with patch.object(paramiko.RSAKey, "from_private_key", return_value=MagicMock()):
            cli = SSHCli("10.0.0.1", 22)
            assert cli.login_pkey("admin", rsa_pem) is False


# -------------------------------------------------------
# SSHCli.test_connect
# -------------------------------------------------------


class TestSSHCliTestConnect:
    @patch.object(paramiko.SSHClient, "connect", side_effect=paramiko.AuthenticationException)
    @patch.object(paramiko.SSHClient, "close")
    def test_connect_success_on_auth_error(self, mock_close, mock_connect):
        cli = SSHCli("10.0.0.1", 22)
        assert cli.test_connect() is True

    @patch.object(paramiko.SSHClient, "connect", side_effect=Exception("timeout"))
    @patch.object(paramiko.SSHClient, "close")
    def test_connect_failure(self, mock_close, mock_connect):
        cli = SSHCli("10.0.0.1", 22)
        assert cli.test_connect() is False


# -------------------------------------------------------
# SSHCli.execute
# -------------------------------------------------------


class TestSSHCliExecute:
    @patch.object(paramiko.SSHClient, "exec_command")
    def test_execute_returns_stdout(self, mock_exec):
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"uid=0(root)"
        mock_exec.return_value = (MagicMock(), mock_stdout, MagicMock())

        cli = SSHCli("10.0.0.1", 22)
        result = cli.execute("id")
        assert result == b"uid=0(root)"

    @patch.object(paramiko.SSHClient, "exec_command", side_effect=Exception("not connected"))
    def test_execute_error(self, mock_exec):
        cli = SSHCli("10.0.0.1", 22)
        result = cli.execute("id")
        assert result is None


# -------------------------------------------------------
# SSHCli.get_file / get_content / send_file / send_content
# -------------------------------------------------------


class TestSSHCliFileOps:
    @patch.object(paramiko.SSHClient, "open_sftp")
    def test_get_file_success(self, mock_sftp):
        mock_sftp_client = MagicMock()
        mock_sftp.return_value = mock_sftp_client

        cli = SSHCli("10.0.0.1", 22)
        assert cli.get_file("/etc/passwd", "/tmp/passwd") is True
        mock_sftp_client.get.assert_called_once_with("/etc/passwd", "/tmp/passwd")

    @patch.object(paramiko.SSHClient, "open_sftp", side_effect=Exception("no sftp"))
    def test_get_file_failure(self, mock_sftp):
        cli = SSHCli("10.0.0.1", 22)
        assert cli.get_file("/etc/passwd", "/tmp/passwd") is False

    @patch.object(paramiko.SSHClient, "open_sftp")
    def test_get_content_success(self, mock_sftp):
        mock_sftp_client = MagicMock()

        def mock_getfo(remote, fp):
            fp.write(b"file content here")

        mock_sftp_client.getfo = mock_getfo
        mock_sftp.return_value = mock_sftp_client

        cli = SSHCli("10.0.0.1", 22)
        result = cli.get_content("/etc/hostname")
        assert result == b"file content here"

    @patch.object(paramiko.SSHClient, "open_sftp", side_effect=Exception("err"))
    def test_get_content_failure(self, mock_sftp):
        cli = SSHCli("10.0.0.1", 22)
        assert cli.get_content("/etc/hostname") is None

    @patch.object(paramiko.SSHClient, "open_sftp")
    def test_send_file_success(self, mock_sftp):
        mock_sftp_client = MagicMock()
        mock_sftp.return_value = mock_sftp_client

        cli = SSHCli("10.0.0.1", 22)
        assert cli.send_file("/local/payload", "/remote/payload") is True
        mock_sftp_client.put.assert_called_once()

    @patch.object(paramiko.SSHClient, "open_sftp", side_effect=Exception("err"))
    def test_send_file_failure(self, mock_sftp):
        cli = SSHCli("10.0.0.1", 22)
        assert cli.send_file("/local/payload", "/remote/payload") is False

    @patch.object(paramiko.SSHClient, "open_sftp")
    def test_send_content_success(self, mock_sftp):
        mock_sftp_client = MagicMock()
        mock_sftp.return_value = mock_sftp_client

        cli = SSHCli("10.0.0.1", 22)
        assert cli.send_content(b"data", "/remote/file") is True
        mock_sftp_client.putfo.assert_called_once()

    @patch.object(paramiko.SSHClient, "open_sftp", side_effect=Exception("err"))
    def test_send_content_failure(self, mock_sftp):
        cli = SSHCli("10.0.0.1", 22)
        assert cli.send_content(b"data", "/remote/file") is False


# -------------------------------------------------------
# SSHCli.close
# -------------------------------------------------------


class TestSSHCliClose:
    @patch.object(paramiko.SSHClient, "close")
    def test_close_success(self, mock_close):
        cli = SSHCli("10.0.0.1", 22)
        assert cli.close() is True

    @patch.object(paramiko.SSHClient, "close", side_effect=Exception("already closed"))
    def test_close_failure(self, mock_close):
        cli = SSHCli("10.0.0.1", 22)
        assert cli.close() is False


# -------------------------------------------------------
# SSHClient (Exploit wrapper)
# -------------------------------------------------------


class TestSSHClientExploit:
    def test_class_exists(self):
        assert hasattr(SSHClient, "target_protocol")

    def test_ssh_create_method(self):
        assert hasattr(SSHClient, "ssh_create")


# -------------------------------------------------------
# Constants
# -------------------------------------------------------


class TestConstants:
    def test_timeout(self):
        assert SSH_TIMEOUT == 8.0
