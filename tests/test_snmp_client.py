"""Tests for embedxpl.core.snmp.snmp_client (offline, mocked network)."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

try:
    from embedxpl.core.snmp.snmp_client import SNMP_IMPORT_ERROR, SNMP_TIMEOUT, SNMPCli, SNMPClient
except (ImportError, ModuleNotFoundError, RuntimeError):
    pytest.skip("pysnmp not available", allow_module_level=True)

if SNMP_IMPORT_ERROR is not None:
    pytest.skip("pysnmp backend unavailable: {}".format(SNMP_IMPORT_ERROR), allow_module_level=True)

# -------------------------------------------------------
# SNMPCli construction
# -------------------------------------------------------


class TestSNMPCliInit:
    def test_defaults(self):
        cli = SNMPCli("10.0.0.1", 161)
        assert cli.snmp_target == "10.0.0.1"
        assert cli.snmp_port == 161
        assert cli.verbosity is False
        assert cli.peer == "10.0.0.1:161"

    def test_verbose(self):
        cli = SNMPCli("192.168.1.1", 162, verbosity=True)
        assert cli.verbosity is True
        assert cli.peer == "192.168.1.1:162"


# -------------------------------------------------------
# SNMPCli.get (SNMPv1/v2c via asyncio.run)
# -------------------------------------------------------


class TestSNMPCliGet:
    @patch.object(SNMPCli, "get_cmd", new_callable=AsyncMock)
    def test_get_success(self, mock_get_cmd):
        mock_get_cmd.return_value = [("1.3.6.1.2.1.1.1.0", b"Linux router")]
        cli = SNMPCli("10.0.0.1", 161)
        result = cli.get("public", "1.3.6.1.2.1.1.1.0")
        assert result is not None
        mock_get_cmd.assert_awaited_once()

    @patch.object(SNMPCli, "get_cmd", new_callable=AsyncMock)
    def test_get_returns_none_on_error(self, mock_get_cmd):
        mock_get_cmd.return_value = None
        cli = SNMPCli("10.0.0.1", 161)
        result = cli.get("public", "1.3.6.1.2.1.1.1.0")
        assert result is None

    @patch.object(SNMPCli, "get_cmd", new_callable=AsyncMock)
    def test_get_passes_version(self, mock_get_cmd):
        mock_get_cmd.return_value = b"ok"
        cli = SNMPCli("10.0.0.1", 161)
        cli.get("public", "1.3.6.1.2.1.1.1.0", version=0)
        args = mock_get_cmd.call_args
        assert args[0][2] == 0

    @patch.object(SNMPCli, "get_cmd", new_callable=AsyncMock)
    def test_get_passes_retries(self, mock_get_cmd):
        mock_get_cmd.return_value = b"ok"
        cli = SNMPCli("10.0.0.1", 161)
        cli.get("public", "1.3.6.1.2.1.1.1.0", retries=3)
        args = mock_get_cmd.call_args
        assert args[0][3] == 3


# -------------------------------------------------------
# SNMPCli.get_v3
# -------------------------------------------------------


class TestSNMPCliGetV3:
    @patch.object(SNMPCli, "get_cmd_v3", new_callable=AsyncMock)
    def test_get_v3_success(self, mock_v3):
        mock_v3.return_value = [("oid", "v3 data")]
        cli = SNMPCli("10.0.0.1", 161)
        result = cli.get_v3(
            username="admin",
            auth_key="authpass123",
            priv_key="privpass123",
            oid="1.3.6.1.2.1.1.1.0",
        )
        assert result is not None
        mock_v3.assert_awaited_once()

    @patch.object(SNMPCli, "get_cmd_v3", new_callable=AsyncMock)
    def test_get_v3_returns_none(self, mock_v3):
        mock_v3.return_value = None
        cli = SNMPCli("10.0.0.1", 161)
        result = cli.get_v3(
            username="admin",
            oid="1.3.6.1.2.1.1.1.0",
        )
        assert result is None

    @patch.object(SNMPCli, "get_cmd_v3", new_callable=AsyncMock)
    def test_get_v3_passes_security_level(self, mock_v3):
        mock_v3.return_value = None
        cli = SNMPCli("10.0.0.1", 161)
        cli.get_v3(
            username="admin",
            oid="1.3.6.1.2.1.1.1.0",
            security_level="noAuthNoPriv",
        )
        kwargs = mock_v3.call_args[1]
        assert kwargs["security_level"] == "noAuthNoPriv"


# -------------------------------------------------------
# SNMPCli._resolve_auth_protocol / _resolve_priv_protocol
# -------------------------------------------------------


class TestResolveProtocols:
    def test_resolve_auth_md5(self):
        result = SNMPCli._resolve_auth_protocol("md5")
        assert result is not None

    def test_resolve_auth_sha(self):
        result = SNMPCli._resolve_auth_protocol("sha")
        assert result is not None

    def test_resolve_auth_none_returns_no_auth(self):
        result = SNMPCli._resolve_auth_protocol("none")
        assert result is not None

    def test_resolve_auth_unknown_returns_none(self):
        result = SNMPCli._resolve_auth_protocol("unknown_algo")
        assert result is None

    def test_resolve_priv_des(self):
        result = SNMPCli._resolve_priv_protocol("des")
        assert result is not None

    def test_resolve_priv_aes(self):
        result = SNMPCli._resolve_priv_protocol("aes")
        assert result is not None

    def test_resolve_priv_none_returns_no_priv(self):
        result = SNMPCli._resolve_priv_protocol("none")
        assert result is not None

    def test_resolve_priv_unknown_returns_none(self):
        result = SNMPCli._resolve_priv_protocol("unknown_algo")
        assert result is None


# -------------------------------------------------------
# SNMPClient (Exploit wrapper)
# -------------------------------------------------------


class TestSNMPClientExploit:
    def test_target_protocol(self):
        assert hasattr(SNMPClient, "target_protocol")

    def test_snmp_create_method(self):
        assert hasattr(SNMPClient, "snmp_create")

    def test_timeout_constant(self):
        assert SNMP_TIMEOUT == 15.0
