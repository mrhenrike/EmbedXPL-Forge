"""Tests for embedxpl.core.tcp.tcp_client (TCPCli)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from embedxpl.core.tcp.tcp_client import TCP_SOCKET_TIMEOUT, TCPCli


class TestTCPCliInit:
    def test_ipv4_creates_socket(self):
        with patch("embedxpl.core.tcp.tcp_client.socket") as mock_sock:
            mock_sock.AF_INET = 2
            mock_sock.SOCK_STREAM = 1
            inst = mock_sock.socket.return_value
            cli = TCPCli("192.168.1.1", 80)
            mock_sock.socket.assert_called_once_with(2, 1)
            inst.settimeout.assert_called_once_with(TCP_SOCKET_TIMEOUT)
            assert cli.tcp_target == "192.168.1.1"
            assert cli.tcp_port == 80
            assert cli.peer == "192.168.1.1:80"

    def test_ipv6_creates_socket(self):
        with patch("embedxpl.core.tcp.tcp_client.socket") as mock_sock, \
             patch("embedxpl.core.tcp.tcp_client.is_ipv4", return_value=False), \
             patch("embedxpl.core.tcp.tcp_client.is_ipv6", return_value=True):
            mock_sock.AF_INET6 = 10
            mock_sock.SOCK_STREAM = 1
            inst = mock_sock.socket.return_value
            cli = TCPCli("::1", 443)
            mock_sock.socket.assert_called_once_with(10, 1)
            inst.settimeout.assert_called_once_with(TCP_SOCKET_TIMEOUT)
            assert cli.tcp_target == "::1"

    def test_verbosity_default_false(self):
        with patch("embedxpl.core.tcp.tcp_client.socket"):
            cli = TCPCli("10.0.0.1", 22)
            assert cli.verbosity is False

    def test_verbosity_explicit_true(self):
        with patch("embedxpl.core.tcp.tcp_client.socket"):
            cli = TCPCli("10.0.0.1", 22, verbosity=True)
            assert cli.verbosity is True


class TestTCPCliConnect:
    def test_connect_success(self):
        with patch("embedxpl.core.tcp.tcp_client.socket"):
            cli = TCPCli("10.0.0.1", 80)
            cli.tcp_client.connect = MagicMock(return_value=None)
            result = cli.connect()
            assert result is True
            cli.tcp_client.connect.assert_called_once_with(("10.0.0.1", 80))

    def test_connect_failure(self):
        with patch("embedxpl.core.tcp.tcp_client.socket"):
            cli = TCPCli("10.0.0.1", 80)
            cli.tcp_client.connect = MagicMock(side_effect=ConnectionRefusedError("refused"))
            result = cli.connect()
            assert result is False


class TestTCPCliSendRecv:
    def test_send_success(self):
        with patch("embedxpl.core.tcp.tcp_client.socket"):
            cli = TCPCli("10.0.0.1", 80)
            cli.tcp_client.send = MagicMock(return_value=5)
            result = cli.send(b"hello")
            assert result is True

    def test_send_failure(self):
        with patch("embedxpl.core.tcp.tcp_client.socket"):
            cli = TCPCli("10.0.0.1", 80)
            cli.tcp_client.send = MagicMock(side_effect=OSError("broken pipe"))
            result = cli.send(b"data")
            assert result is False

    def test_recv_success(self):
        with patch("embedxpl.core.tcp.tcp_client.socket"):
            cli = TCPCli("10.0.0.1", 80)
            cli.tcp_client.recv = MagicMock(return_value=b"response")
            result = cli.recv(1024)
            assert result == b"response"

    def test_recv_failure_returns_none(self):
        with patch("embedxpl.core.tcp.tcp_client.socket"):
            cli = TCPCli("10.0.0.1", 80)
            cli.tcp_client.recv = MagicMock(side_effect=OSError("timeout"))
            result = cli.recv(1024)
            assert result is None

    def test_recv_all_collects_chunks(self):
        with patch("embedxpl.core.tcp.tcp_client.socket"):
            cli = TCPCli("10.0.0.1", 80)
            cli.tcp_client.recv = MagicMock(side_effect=[b"ab", b"cd", b""])
            result = cli.recv_all(10)
            assert result == b"abcd"

    def test_recv_all_failure_returns_none(self):
        with patch("embedxpl.core.tcp.tcp_client.socket"):
            cli = TCPCli("10.0.0.1", 80)
            cli.tcp_client.recv = MagicMock(side_effect=OSError("reset"))
            result = cli.recv_all(100)
            assert result is None


class TestTCPCliClose:
    def test_close_success(self):
        with patch("embedxpl.core.tcp.tcp_client.socket"):
            cli = TCPCli("10.0.0.1", 80)
            cli.tcp_client.close = MagicMock(return_value=None)
            assert cli.close() is True

    def test_close_failure(self):
        with patch("embedxpl.core.tcp.tcp_client.socket"):
            cli = TCPCli("10.0.0.1", 80)
            cli.tcp_client.close = MagicMock(side_effect=OSError("err"))
            assert cli.close() is False
