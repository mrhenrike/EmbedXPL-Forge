"""Tests for embedxpl.core.udp.udp_client (UDPCli)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from embedxpl.core.udp.udp_client import UDP_SOCKET_TIMEOUT, UDPCli


class TestUDPCliInit:
    def test_ipv4_creates_dgram_socket(self):
        with patch("embedxpl.core.udp.udp_client.socket") as mock_sock:
            mock_sock.AF_INET = 2
            mock_sock.SOCK_DGRAM = 2
            inst = mock_sock.socket.return_value
            cli = UDPCli("192.168.1.1", 161)
            mock_sock.socket.assert_called_once_with(2, 2)
            inst.settimeout.assert_called_once_with(UDP_SOCKET_TIMEOUT)
            assert cli.udp_target == "192.168.1.1"
            assert cli.udp_port == 161
            assert cli.peer == "192.168.1.1:161"

    def test_ipv6_creates_dgram_socket(self):
        with patch("embedxpl.core.udp.udp_client.socket") as mock_sock, \
             patch("embedxpl.core.udp.udp_client.is_ipv4", return_value=False), \
             patch("embedxpl.core.udp.udp_client.is_ipv6", return_value=True):
            mock_sock.AF_INET6 = 10
            mock_sock.SOCK_DGRAM = 2
            inst = mock_sock.socket.return_value
            cli = UDPCli("::1", 5353)
            mock_sock.socket.assert_called_once_with(10, 2)
            inst.settimeout.assert_called_once_with(UDP_SOCKET_TIMEOUT)
            assert cli.udp_target == "::1"

    def test_invalid_address_skips_socket(self):
        with patch("embedxpl.core.udp.udp_client.socket") as mock_sock, \
             patch("embedxpl.core.udp.udp_client.print_error"):
            cli = UDPCli("not-an-ip", 123)
            mock_sock.socket.assert_not_called()
            assert cli.udp_target == "not-an-ip"

    def test_verbosity_default_false(self):
        with patch("embedxpl.core.udp.udp_client.socket"):
            cli = UDPCli("10.0.0.1", 53)
            assert cli.verbosity is False

    def test_verbosity_explicit_true(self):
        with patch("embedxpl.core.udp.udp_client.socket"):
            cli = UDPCli("10.0.0.1", 53, verbosity=True)
            assert cli.verbosity is True


class TestUDPCliSend:
    def test_send_success(self):
        with patch("embedxpl.core.udp.udp_client.socket"):
            cli = UDPCli("10.0.0.1", 161)
            cli.udp_client.sendto = MagicMock(return_value=5)
            result = cli.send(b"hello")
            assert result is True
            cli.udp_client.sendto.assert_called_once_with(b"hello", ("10.0.0.1", 161))

    def test_send_failure(self):
        with patch("embedxpl.core.udp.udp_client.socket"):
            cli = UDPCli("10.0.0.1", 161)
            cli.udp_client.sendto = MagicMock(side_effect=OSError("network unreachable"))
            result = cli.send(b"data")
            assert result is False


class TestUDPCliRecv:
    def test_recv_success(self):
        with patch("embedxpl.core.udp.udp_client.socket"):
            cli = UDPCli("10.0.0.1", 161)
            cli.udp_client.recv = MagicMock(return_value=b"response")
            result = cli.recv(1024)
            assert result == b"response"

    def test_recv_failure_returns_none(self):
        with patch("embedxpl.core.udp.udp_client.socket"):
            cli = UDPCli("10.0.0.1", 161)
            cli.udp_client.recv = MagicMock(side_effect=OSError("timeout"))
            result = cli.recv(1024)
            assert result is None


class TestUDPCliClose:
    def test_close_success(self):
        with patch("embedxpl.core.udp.udp_client.socket"):
            cli = UDPCli("10.0.0.1", 161)
            cli.udp_client.close = MagicMock(return_value=None)
            assert cli.close() is True

    def test_close_failure(self):
        with patch("embedxpl.core.udp.udp_client.socket"):
            cli = UDPCli("10.0.0.1", 161)
            cli.udp_client.close = MagicMock(side_effect=OSError("err"))
            assert cli.close() is False
