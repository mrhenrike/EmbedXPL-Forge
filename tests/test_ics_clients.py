"""Tests for embedxpl.core.ics protocol clients (Modbus, S7, CIP, WDB2)."""
from __future__ import annotations

import struct
from unittest.mock import MagicMock, patch

import pytest

from embedxpl.core.ics.modbus_client import ModbusClient
from embedxpl.core.ics.s7_client import S7Client
from embedxpl.core.ics.cip_client import CIPClient
from embedxpl.core.ics.wdb2_client import Wdb2Client as WDB2Client


class TestModbusClient:
    def test_init(self):
        c = ModbusClient("10.0.0.1", port=502, unit_id=1)
        assert c._ip == "10.0.0.1"
        assert c._port == 502
        assert c._unit_id == 1

    def test_default_port(self):
        c = ModbusClient("10.0.0.1")
        assert c._port == 502

    def test_disconnect_no_socket(self):
        c = ModbusClient("10.0.0.1")
        c.disconnect()

    def test_next_tid_increments(self):
        c = ModbusClient("10.0.0.1")
        t1 = c._next_tid()
        t2 = c._next_tid()
        assert t2 == t1 + 1

    def test_build_adu_structure(self):
        c = ModbusClient("10.0.0.1", unit_id=1)
        c._tid = 0
        pdu = b"\x01\x00\x00\x00\x0a"
        adu = c._build_adu(pdu)
        assert isinstance(adu, bytes)
        assert len(adu) == 7 + len(pdu)
        tid = struct.unpack(">H", adu[0:2])[0]
        assert tid == 1
        proto = struct.unpack(">H", adu[2:4])[0]
        assert proto == 0
        length = struct.unpack(">H", adu[4:6])[0]
        assert length == len(pdu) + 1

    def test_context_manager(self):
        c = ModbusClient("10.0.0.1")
        with patch.object(c, "connect", return_value=True):
            with patch.object(c, "disconnect"):
                with c as client:
                    assert client is c

    def test_connect_failure(self):
        c = ModbusClient("192.0.2.1", timeout=0.1)
        result = c.connect()
        assert result is False

    def test_read_coils_no_connection(self):
        c = ModbusClient("10.0.0.1")
        result = c.read_coils(0, 10)
        assert result is None

    def test_write_single_coil_no_connection(self):
        c = ModbusClient("10.0.0.1")
        result = c.write_single_coil(0, True)
        assert result is False


class TestS7Client:
    def test_init(self):
        c = S7Client("10.0.0.1")
        assert c._ip == "10.0.0.1"

    def test_default_port(self):
        c = S7Client("10.0.0.1")
        assert c._port == 102

    def test_disconnect_no_socket(self):
        c = S7Client("10.0.0.1")
        c.disconnect()


class TestCIPClient:
    def test_init(self):
        c = CIPClient("10.0.0.1")
        assert c._ip == "10.0.0.1"

    def test_default_port(self):
        c = CIPClient("10.0.0.1")
        assert c._port == 44818

    def test_disconnect_no_socket(self):
        c = CIPClient("10.0.0.1")
        c.disconnect()


class TestWDB2Client:
    def test_init(self):
        c = WDB2Client("10.0.0.1")
        assert c._ip == "10.0.0.1"

    def test_disconnect_no_socket(self):
        c = WDB2Client("10.0.0.1")
        c.disconnect()
