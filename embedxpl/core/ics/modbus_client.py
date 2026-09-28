"""
EmbedXPL-Forge — Modbus/TCP Client
Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

Python 3 raw-socket implementation of the Modbus/TCP protocol.
Ported and modernised from ISF ModbusClient (original: WenZhe Zhu / ICSsploit).

Supports Function Codes: FC1 FC2 FC3 FC4 FC5 FC6 FC15 FC16 FC20 FC21 FC22 FC23
"""

import socket
import struct
import logging
from typing import Optional, List


class ModbusClient:
    """Reusable Modbus/TCP client for EmbedXPL ICS exploit modules.

    Args:
        ip: Target IP address.
        port: Modbus TCP port (default 502).
        unit_id: Modbus Unit/Slave ID (default 1).
        timeout: Socket timeout in seconds (default 2.0).
    """

    def __init__(self, ip: str, port: int = 502, unit_id: int = 1, timeout: float = 2.0) -> None:
        self._ip = ip
        self._port = port
        self._unit_id = unit_id
        self._timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._tid = 0
        self._logger = logging.getLogger(self.__class__.__name__)

    # ------------------------------------------------------------------ #
    # Connection management
    # ------------------------------------------------------------------ #

    def connect(self) -> bool:
        """Open TCP connection to target Modbus device.

        Returns:
            True if connected successfully, False otherwise.
        """
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self._timeout)
            self._sock.connect((self._ip, self._port))
            return True
        except OSError as exc:
            self._logger.error("Connect failed: %s", exc)
            self._sock = None
            return False

    def disconnect(self) -> None:
        """Close the TCP connection."""
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def __enter__(self) -> "ModbusClient":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.disconnect()

    # ------------------------------------------------------------------ #
    # Low-level packet helpers
    # ------------------------------------------------------------------ #

    def _next_tid(self) -> int:
        self._tid = (self._tid + 1) & 0xFFFF
        return self._tid

    def _build_adu(self, pdu: bytes) -> bytes:
        """Wrap PDU in Modbus Application Data Unit (MBAP header).

        Returns:
            MBAP-prefixed ADU bytes.
        """
        tid = self._next_tid()
        length = len(pdu) + 1  # +1 for unit_id
        return struct.pack(">HHHB", tid, 0, length, self._unit_id) + pdu

    def _send_recv(self, pdu: bytes) -> Optional[bytes]:
        """Send PDU, return raw response PDU (stripped of MBAP).

        Returns:
            Response PDU bytes or None on error.
        """
        if not self._sock:
            self._logger.error("Not connected")
            return None
        try:
            self._sock.sendall(self._build_adu(pdu))
            header = self._sock.recv(7)
            if len(header) < 7:
                return None
            _tid, _proto, length, _uid = struct.unpack(">HHHB", header)
            payload = b""
            remaining = length - 1
            while remaining > 0:
                chunk = self._sock.recv(remaining)
                if not chunk:
                    break
                payload += chunk
                remaining -= len(chunk)
            if payload and (payload[0] & 0x80):
                exc_code = payload[1] if len(payload) > 1 else 0
                self._logger.warning("Modbus exception response fc=0x%02x code=0x%02x",
                                     payload[0] & 0x7F, exc_code)
                return None
            return payload
        except OSError as exc:
            self._logger.error("I/O error: %s", exc)
            return None

    # ------------------------------------------------------------------ #
    # Read coils / discrete / registers
    # ------------------------------------------------------------------ #

    def read_coils(self, address: int, count: int) -> Optional[List[int]]:
        """FC1 — Read Coil Status.

        Args:
            address: Starting coil address.
            count: Number of coils to read.

        Returns:
            List of coil values (0 or 1) or None on error.
        """
        pdu = struct.pack(">BHH", 0x01, address, count)
        rsp = self._send_recv(pdu)
        if rsp is None or len(rsp) < 2:
            return None
        byte_count = rsp[1]
        bits = []
        for byte in rsp[2:2 + byte_count]:
            for bit in range(8):
                bits.append((byte >> bit) & 1)
        return bits[:count]

    def read_discrete_inputs(self, address: int, count: int) -> Optional[List[int]]:
        """FC2 — Read Discrete Inputs.

        Args:
            address: Starting input address.
            count: Number of discrete inputs to read.

        Returns:
            List of input values (0 or 1) or None on error.
        """
        pdu = struct.pack(">BHH", 0x02, address, count)
        rsp = self._send_recv(pdu)
        if rsp is None or len(rsp) < 2:
            return None
        byte_count = rsp[1]
        bits = []
        for byte in rsp[2:2 + byte_count]:
            for bit in range(8):
                bits.append((byte >> bit) & 1)
        return bits[:count]

    def read_holding_registers(self, address: int, count: int) -> Optional[List[int]]:
        """FC3 — Read Holding Registers.

        Args:
            address: Starting register address.
            count: Number of registers to read.

        Returns:
            List of register values or None on error.
        """
        pdu = struct.pack(">BHH", 0x03, address, count)
        rsp = self._send_recv(pdu)
        if rsp is None or len(rsp) < 2:
            return None
        byte_count = rsp[1]
        registers = []
        for i in range(2, 2 + byte_count, 2):
            registers.append(struct.unpack(">H", rsp[i:i + 2])[0])
        return registers

    def read_input_registers(self, address: int, count: int) -> Optional[List[int]]:
        """FC4 — Read Input Registers.

        Args:
            address: Starting register address.
            count: Number of input registers to read.

        Returns:
            List of register values or None on error.
        """
        pdu = struct.pack(">BHH", 0x04, address, count)
        rsp = self._send_recv(pdu)
        if rsp is None or len(rsp) < 2:
            return None
        byte_count = rsp[1]
        registers = []
        for i in range(2, 2 + byte_count, 2):
            registers.append(struct.unpack(">H", rsp[i:i + 2])[0])
        return registers

    # ------------------------------------------------------------------ #
    # Write operations
    # ------------------------------------------------------------------ #

    def write_single_coil(self, address: int, value: bool) -> bool:
        """FC5 — Write Single Coil.

        Args:
            address: Coil address.
            value: True = ON (0xFF00), False = OFF (0x0000).

        Returns:
            True if the coil was written, False otherwise.
        """
        coil_val = 0xFF00 if value else 0x0000
        pdu = struct.pack(">BHH", 0x05, address, coil_val)
        return self._send_recv(pdu) is not None

    def write_single_register(self, address: int, value: int) -> bool:
        """FC6 — Write Single Register.

        Args:
            address: Register address.
            value: 16-bit register value (0x0000–0xFFFF).

        Returns:
            True if the register was written, False otherwise.
        """
        pdu = struct.pack(">BHH", 0x06, address, value & 0xFFFF)
        return self._send_recv(pdu) is not None

    def write_multiple_coils(self, address: int, values: List[int]) -> bool:
        """FC15 — Write Multiple Coils.

        Args:
            address: Starting coil address.
            values: List of coil values (0 or 1).

        Returns:
            True if coils were written, False otherwise.
        """
        count = len(values)
        byte_count = (count + 7) // 8
        coil_bytes = bytearray(byte_count)
        for i, v in enumerate(values):
            if v:
                coil_bytes[i // 8] |= (1 << (i % 8))
        pdu = struct.pack(">BHHB", 0x0F, address, count, byte_count) + bytes(coil_bytes)
        return self._send_recv(pdu) is not None

    def write_multiple_registers(self, address: int, values: List[int]) -> bool:
        """FC16 — Write Multiple Registers.

        Args:
            address: Starting register address.
            values: List of 16-bit register values.

        Returns:
            True if registers were written, False otherwise.
        """
        count = len(values)
        byte_count = count * 2
        reg_bytes = b"".join(struct.pack(">H", v & 0xFFFF) for v in values)
        pdu = struct.pack(">BHHB", 0x10, address, count, byte_count) + reg_bytes
        return self._send_recv(pdu) is not None

    # ------------------------------------------------------------------ #
    # Device identification
    # ------------------------------------------------------------------ #

    def read_device_identification(self) -> Optional[dict]:
        """FC43/0x0E — Read Device Identification (MEI).

        Returns:
            Dict with 'vendor', 'product_code', 'version' or None on error.
        """
        pdu = bytes([0x2B, 0x0E, 0x01, 0x00])
        rsp = self._send_recv(pdu)
        if rsp is None or len(rsp) < 8:
            return None
        result: dict = {}
        try:
            num_objects = rsp[7]
            offset = 8
            for _ in range(num_objects):
                if offset + 2 > len(rsp):
                    break
                obj_id = rsp[offset]
                obj_len = rsp[offset + 1]
                obj_val = rsp[offset + 2:offset + 2 + obj_len].decode("ascii", errors="replace")
                if obj_id == 0x00:
                    result["vendor"] = obj_val
                elif obj_id == 0x01:
                    result["product_code"] = obj_val
                elif obj_id == 0x02:
                    result["version"] = obj_val
                offset += 2 + obj_len
        except Exception:
            pass
        return result or None
