# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Tunnel Manager - Multi-protocol tunneling for exploit delivery.

Provides TunnelManager for creating and destroying network tunnels
across six transport types: tcp_forward, udp_forward, icmp_tunnel,
dns_tunnel, http_tunnel, ssh_local.

Version: 1.0.0
"""

import os
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


_PROJECT_TMP = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", ".tmp"
)

TUNNEL_TYPES = (
    "tcp_forward",
    "udp_forward",
    "icmp_tunnel",
    "dns_tunnel",
    "http_tunnel",
    "ssh_local",
)


@dataclass
class TunnelConfig:
    """Configuration for a network tunnel.

    Attributes:
        tunnel_type: One of the supported tunnel types.
        local_port: Local listening port.
        remote_host: Target remote host.
        remote_port: Target remote port.
        bind_addr: Local bind address (default 127.0.0.1).
        dns_domain: Domain for DNS tunneling.
        http_proxy: HTTP proxy URL for HTTP tunneling.
        ssh_key: Path to SSH private key for ssh_local.
        ssh_user: SSH username for ssh_local.
    """

    tunnel_type: str = "tcp_forward"
    local_port: int = 0
    remote_host: str = ""
    remote_port: int = 0
    bind_addr: str = "127.0.0.1"
    dns_domain: str = ""
    http_proxy: str = ""
    ssh_key: str = ""
    ssh_user: str = "root"

    def validate(self) -> None:
        """Validate tunnel configuration.

        Raises:
            ValueError: If tunnel_type or required fields are invalid.
        """
        if self.tunnel_type not in TUNNEL_TYPES:
            raise ValueError(
                "Unsupported tunnel type '{}'. Valid: {}".format(
                    self.tunnel_type, ", ".join(TUNNEL_TYPES)
                )
            )
        if not self.remote_host:
            raise ValueError("remote_host is required")
        if self.remote_port < 1 or self.remote_port > 65535:
            raise ValueError("remote_port must be 1-65535")
        if self.tunnel_type == "dns_tunnel" and not self.dns_domain:
            raise ValueError("dns_domain is required for dns_tunnel")
        if self.tunnel_type == "ssh_local" and not self.ssh_user:
            raise ValueError("ssh_user is required for ssh_local")


@dataclass
class TunnelHandle:
    """Active tunnel handle with management metadata.

    Attributes:
        tunnel_id: Unique identifier for the tunnel.
        config: TunnelConfig used to create the tunnel.
        local_port: Actual local port (may differ from config if auto-assigned).
        pid: Process ID if tunnel runs as a subprocess.
        thread: Thread reference if tunnel runs in-process.
        active: Whether the tunnel is currently active.
        created_at: Unix timestamp of creation.
    """

    tunnel_id: str = ""
    config: Optional[TunnelConfig] = None
    local_port: int = 0
    pid: int = 0
    thread: Optional[threading.Thread] = None
    active: bool = False
    created_at: float = 0.0
    _process: Optional[subprocess.Popen] = field(default=None, repr=False)
    _stop_event: Optional[threading.Event] = field(default=None, repr=False)


class TunnelManager:
    """Manage network tunnels for exploit delivery.

    Supports six tunnel types:
      - tcp_forward: TCP port forwarding via socket relay.
      - udp_forward: UDP port forwarding via socket relay.
      - icmp_tunnel: ICMP-based tunnel (requires external tooling).
      - dns_tunnel: DNS-based tunnel (requires external tooling).
      - http_tunnel: HTTP CONNECT-based tunnel.
      - ssh_local: SSH local port forwarding.

    Args:
        max_tunnels: Maximum number of concurrent tunnels.
    """

    def __init__(self, max_tunnels: int = 16):
        self._max_tunnels = max_tunnels
        self._tunnels = {}
        self._lock = threading.Lock()
        self._counter = 0

    def _next_id(self) -> str:
        """Generate unique tunnel ID."""
        with self._lock:
            self._counter += 1
            return "tun-{:04d}".format(self._counter)

    def _find_free_port(self, bind_addr: str = "127.0.0.1") -> int:
        """Find a free TCP port on the specified interface."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((bind_addr, 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    def create(self, config: TunnelConfig) -> TunnelHandle:
        """Create and start a new tunnel.

        Args:
            config: TunnelConfig specifying tunnel parameters.

        Returns:
            TunnelHandle for the active tunnel.

        Raises:
            ValueError: If config is invalid.
            RuntimeError: If max tunnels reached or creation fails.
        """
        config.validate()

        with self._lock:
            if len(self._tunnels) >= self._max_tunnels:
                raise RuntimeError(
                    "Maximum tunnel count reached ({})".format(self._max_tunnels)
                )

        if config.local_port == 0:
            config.local_port = self._find_free_port(config.bind_addr)

        tunnel_id = self._next_id()
        handle = TunnelHandle(
            tunnel_id=tunnel_id,
            config=config,
            local_port=config.local_port,
            created_at=time.time(),
        )

        if config.tunnel_type == "tcp_forward":
            self._start_tcp_forward(handle)
        elif config.tunnel_type == "udp_forward":
            self._start_udp_forward(handle)
        elif config.tunnel_type == "ssh_local":
            self._start_ssh_local(handle)
        elif config.tunnel_type == "http_tunnel":
            self._start_http_tunnel(handle)
        elif config.tunnel_type in ("icmp_tunnel", "dns_tunnel"):
            self._start_external_tunnel(handle)
        else:
            raise RuntimeError("Tunnel type not implemented: {}".format(config.tunnel_type))

        handle.active = True
        with self._lock:
            self._tunnels[tunnel_id] = handle
        return handle

    def _tcp_relay(self, client_sock: socket.socket,
                   remote_host: str, remote_port: int,
                   stop_event: threading.Event) -> None:
        """Relay data between client and remote TCP sockets."""
        try:
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.settimeout(10)
            remote_sock.connect((remote_host, remote_port))
        except (socket.error, OSError):
            client_sock.close()
            return

        def forward(src, dst):
            try:
                while not stop_event.is_set():
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            except (socket.error, OSError):
                pass
            finally:
                try:
                    src.close()
                except OSError:
                    pass
                try:
                    dst.close()
                except OSError:
                    pass

        t1 = threading.Thread(target=forward, args=(client_sock, remote_sock), daemon=True)
        t2 = threading.Thread(target=forward, args=(remote_sock, client_sock), daemon=True)
        t1.start()
        t2.start()

    def _start_tcp_forward(self, handle: TunnelHandle) -> None:
        """Start TCP port forwarding tunnel."""
        cfg = handle.config
        stop_event = threading.Event()
        handle._stop_event = stop_event

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((cfg.bind_addr, cfg.local_port))
        server_sock.listen(5)
        server_sock.settimeout(1.0)

        def accept_loop():
            while not stop_event.is_set():
                try:
                    client, _ = server_sock.accept()
                    threading.Thread(
                        target=self._tcp_relay,
                        args=(client, cfg.remote_host, cfg.remote_port, stop_event),
                        daemon=True,
                    ).start()
                except socket.timeout:
                    continue
                except (socket.error, OSError):
                    break
            server_sock.close()

        thread = threading.Thread(target=accept_loop, daemon=True)
        thread.start()
        handle.thread = thread

    def _start_udp_forward(self, handle: TunnelHandle) -> None:
        """Start UDP port forwarding tunnel."""
        cfg = handle.config
        stop_event = threading.Event()
        handle._stop_event = stop_event

        def udp_relay():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((cfg.bind_addr, cfg.local_port))
            sock.settimeout(1.0)
            clients = {}
            while not stop_event.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                    remote = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    remote.settimeout(5)
                    remote.sendto(data, (cfg.remote_host, cfg.remote_port))
                    try:
                        resp, _ = remote.recvfrom(65535)
                        sock.sendto(resp, addr)
                    except socket.timeout:
                        pass
                    remote.close()
                except socket.timeout:
                    continue
                except (socket.error, OSError):
                    break
            sock.close()

        thread = threading.Thread(target=udp_relay, daemon=True)
        thread.start()
        handle.thread = thread

    def _start_ssh_local(self, handle: TunnelHandle) -> None:
        """Start SSH local port forwarding via ssh subprocess."""
        cfg = handle.config
        cmd = [
            "ssh", "-N", "-L",
            "{}:{}:{}:{}".format(cfg.bind_addr, cfg.local_port,
                                 cfg.remote_host, cfg.remote_port),
            "{}@{}".format(cfg.ssh_user, cfg.remote_host),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
        ]
        if cfg.ssh_key:
            cmd.extend(["-i", cfg.ssh_key])

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
            )
            handle._process = proc
            handle.pid = proc.pid
        except (FileNotFoundError, OSError) as exc:
            raise RuntimeError("Failed to start SSH tunnel: {}".format(exc))

    def _start_http_tunnel(self, handle: TunnelHandle) -> None:
        """Start HTTP CONNECT-based tunnel."""
        cfg = handle.config
        stop_event = threading.Event()
        handle._stop_event = stop_event

        def http_connect_relay(client_sock):
            try:
                connect_req = "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n".format(
                    cfg.remote_host, cfg.remote_port,
                    cfg.remote_host, cfg.remote_port,
                )
                proxy_host, _, proxy_port = (cfg.http_proxy or "").partition(":")
                proxy_port = int(proxy_port) if proxy_port else 8080
                proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                proxy_sock.settimeout(10)
                proxy_sock.connect((proxy_host, proxy_port))
                proxy_sock.sendall(connect_req.encode())
                resp = proxy_sock.recv(4096)
                if b"200" not in resp:
                    proxy_sock.close()
                    client_sock.close()
                    return
                self._tcp_relay(client_sock, cfg.remote_host, cfg.remote_port, stop_event)
            except (socket.error, OSError, ValueError):
                try:
                    client_sock.close()
                except OSError:
                    pass

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((cfg.bind_addr, cfg.local_port))
        server_sock.listen(5)
        server_sock.settimeout(1.0)

        def accept_loop():
            while not stop_event.is_set():
                try:
                    client, _ = server_sock.accept()
                    threading.Thread(
                        target=http_connect_relay, args=(client,), daemon=True,
                    ).start()
                except socket.timeout:
                    continue
                except (socket.error, OSError):
                    break
            server_sock.close()

        thread = threading.Thread(target=accept_loop, daemon=True)
        thread.start()
        handle.thread = thread

    def _start_external_tunnel(self, handle: TunnelHandle) -> None:
        """Placeholder for ICMP/DNS tunnels requiring external tools."""
        raise RuntimeError(
            "Tunnel type '{}' requires external tooling. "
            "Use a dedicated tool (e.g., iodine for DNS, ptunnel for ICMP) "
            "and configure the local port manually.".format(handle.config.tunnel_type)
        )

    def destroy(self, tunnel_id: str) -> bool:
        """Destroy an active tunnel.

        Args:
            tunnel_id: Identifier of the tunnel to destroy.

        Returns:
            True if tunnel was destroyed, False if not found.
        """
        with self._lock:
            handle = self._tunnels.pop(tunnel_id, None)
        if not handle:
            return False

        handle.active = False
        if handle._stop_event:
            handle._stop_event.set()
        if handle._process:
            try:
                handle._process.terminate()
                handle._process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    handle._process.kill()
                except OSError:
                    pass
        return True

    def destroy_all(self) -> int:
        """Destroy all active tunnels.

        Returns:
            Number of tunnels destroyed.
        """
        with self._lock:
            ids = list(self._tunnels.keys())
        count = 0
        for tid in ids:
            if self.destroy(tid):
                count += 1
        return count

    def list_tunnels(self) -> list:
        """List all active tunnel handles."""
        with self._lock:
            return list(self._tunnels.values())

    def get(self, tunnel_id: str) -> Optional[TunnelHandle]:
        """Get a tunnel handle by ID."""
        with self._lock:
            return self._tunnels.get(tunnel_id)
