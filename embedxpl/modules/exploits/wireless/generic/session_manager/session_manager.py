"""Session Manager - persistent WiFi pentest session management.

Saves and restores pentest sessions including discovered networks,
executed attacks, captured handshakes, and recovered credentials.
Backed by SQLite with JSON export per session.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain records
# ---------------------------------------------------------------------------

@dataclass
class AttackRecord:
    """A recorded attack attempt within a session."""
    attack_type: str
    target_ssid: str
    target_bssid: str
    outcome: str
    timestamp: str = ""
    tool: Optional[str] = None
    notes: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class SessionInfo:
    """Lightweight session summary returned by list_sessions()."""
    session_id: str
    name: str
    created_at: str
    updated_at: str
    network_count: int
    attack_count: int
    capture_count: int
    credential_count: int
    notes: Optional[str] = None


# ---------------------------------------------------------------------------
# Session Manager
# ---------------------------------------------------------------------------

class SessionManager:
    """SQLite-backed WiFi pentest session manager.

    Supports saving and restoring session state, including discovered networks,
    executed attacks, file captures, and recovered credentials. Multiple
    sessions coexist in the same database.

    Attributes:
        __info__: Module metadata.

    Args:
        db_path: Path to the SQLite database file. Created on first use.
        simulate: When True, all write operations are skipped (dry-run mode).
    """

    __info__ = {
        "name": "Session Manager",
        "category": "session_manager",
        "type": "utility",
        "description": (
            "SQLite-backed WiFi pentest session manager. "
            "Tracks networks, attacks, handshake captures, and recovered credentials "
            "across multiple sessions with JSON export."
        ),
        "hw_req": ["None - software only"],
        "authors": ["Andre Henrique (@mrhenrike) | Uniao Geek"],
    }

    def __init__(
        self,
        db_path: Optional[str | Path] = None,
        simulate: bool = True,
    ) -> None:
        self.simulate = simulate

        if db_path is None:
            default_dir = Path.cwd() / ".wxf_sessions"
            if not simulate:
                default_dir.mkdir(parents=True, exist_ok=True)
            self._db_path = default_dir / "sessions.db"
        else:
            self._db_path = Path(db_path).resolve()
            if not simulate:
                self._db_path.parent.mkdir(parents=True, exist_ok=True)

        self._active_session_id: Optional[str] = None

        if not simulate:
            self._init_db()
        else:
            logger.info("[SessionManager] simulate=True - no data will be persisted")

    # ------------------------------------------------------------------
    # DB setup
    # ------------------------------------------------------------------

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        if self.simulate:
            raise RuntimeError("SessionManager is in simulate mode")
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id  TEXT PRIMARY KEY,
                    name        TEXT NOT NULL UNIQUE,
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL,
                    notes       TEXT
                );
                CREATE TABLE IF NOT EXISTS networks (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  TEXT NOT NULL,
                    ssid        TEXT NOT NULL,
                    bssid       TEXT NOT NULL,
                    security    TEXT,
                    channel     INTEGER,
                    rssi        INTEGER,
                    vendor      TEXT,
                    latitude    REAL,
                    longitude   REAL,
                    timestamp   TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                );
                CREATE TABLE IF NOT EXISTS attacks (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    target_ssid TEXT,
                    target_bssid TEXT,
                    outcome     TEXT,
                    tool        TEXT,
                    notes       TEXT,
                    timestamp   TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                );
                CREATE TABLE IF NOT EXISTS captures (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  TEXT NOT NULL,
                    ssid        TEXT NOT NULL,
                    bssid       TEXT NOT NULL,
                    filepath    TEXT NOT NULL,
                    capture_type TEXT DEFAULT 'hc22000',
                    timestamp   TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                );
                CREATE TABLE IF NOT EXISTS credentials (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  TEXT NOT NULL,
                    ssid        TEXT NOT NULL,
                    password    TEXT NOT NULL,
                    bssid       TEXT,
                    method      TEXT DEFAULT 'handshake',
                    timestamp   TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                );
            """)

    # ------------------------------------------------------------------
    # Session CRUD
    # ------------------------------------------------------------------

    def save_session(self, name: str, notes: Optional[str] = None) -> str:
        """Create or touch a named session and make it active.

        Args:
            name: Human-readable session name (must be unique).
            notes: Optional engagement notes.

        Returns:
            The session_id for the created/updated session.
        """
        if self.simulate:
            sid = str(uuid.uuid4())[:8]
            self._active_session_id = sid
            logger.info("[SessionManager] simulate save_session name=%s sid=%s", name, sid)
            return sid

        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT session_id FROM sessions WHERE name = ?", (name,)
            ).fetchone()
            if existing:
                sid = existing["session_id"]
                conn.execute(
                    "UPDATE sessions SET updated_at = ?, notes = COALESCE(?, notes) WHERE session_id = ?",
                    (now, notes, sid),
                )
            else:
                sid = str(uuid.uuid4())
                conn.execute(
                    "INSERT INTO sessions (session_id, name, created_at, updated_at, notes) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (sid, name, now, now, notes),
                )

        self._active_session_id = sid
        logger.info("[SessionManager] Session active: name=%s sid=%s", name, sid)
        return sid

    def load_session(self, name: str) -> Optional[str]:
        """Load an existing session by name and make it active.

        Args:
            name: Session name to load.

        Returns:
            The session_id, or None if not found.
        """
        if self.simulate:
            logger.info("[SessionManager] simulate load_session name=%s", name)
            return None

        with self._conn() as conn:
            row = conn.execute(
                "SELECT session_id FROM sessions WHERE name = ?", (name,)
            ).fetchone()
            if not row:
                logger.warning("[SessionManager] Session not found: %s", name)
                return None
            self._active_session_id = row["session_id"]
            logger.info("[SessionManager] Loaded session: %s", name)
            return self._active_session_id

    def list_sessions(self) -> list[SessionInfo]:
        """List all sessions with summary counts.

        Returns:
            List of SessionInfo objects ordered by creation time (newest first).
        """
        if self.simulate:
            return []

        with self._conn() as conn:
            rows = conn.execute("""
                SELECT s.session_id, s.name, s.created_at, s.updated_at, s.notes,
                    (SELECT COUNT(*) FROM networks n WHERE n.session_id = s.session_id) AS net_c,
                    (SELECT COUNT(*) FROM attacks  a WHERE a.session_id = s.session_id) AS atk_c,
                    (SELECT COUNT(*) FROM captures c WHERE c.session_id = s.session_id) AS cap_c,
                    (SELECT COUNT(*) FROM credentials cr WHERE cr.session_id = s.session_id) AS cred_c
                FROM sessions s
                ORDER BY s.created_at DESC
            """).fetchall()

        return [
            SessionInfo(
                session_id=r["session_id"],
                name=r["name"],
                created_at=r["created_at"],
                updated_at=r["updated_at"],
                network_count=r["net_c"],
                attack_count=r["atk_c"],
                capture_count=r["cap_c"],
                credential_count=r["cred_c"],
                notes=r["notes"],
            )
            for r in rows
        ]

    def delete_session(self, name: str) -> bool:
        """Delete a session and all its associated records.

        Args:
            name: Session name to delete.

        Returns:
            True if deleted, False if not found.
        """
        if self.simulate:
            logger.info("[SessionManager] simulate delete_session name=%s", name)
            return True

        with self._conn() as conn:
            row = conn.execute(
                "SELECT session_id FROM sessions WHERE name = ?", (name,)
            ).fetchone()
            if not row:
                return False
            sid = row["session_id"]
            for table in ("networks", "attacks", "captures", "credentials"):
                conn.execute(f"DELETE FROM {table} WHERE session_id = ?", (sid,))
            conn.execute("DELETE FROM sessions WHERE session_id = ?", (sid,))

        if self._active_session_id == sid:
            self._active_session_id = None
        logger.info("[SessionManager] Session deleted: %s", name)
        return True

    # ------------------------------------------------------------------
    # Record writers
    # ------------------------------------------------------------------

    def _require_session(self) -> str:
        if not self._active_session_id:
            raise RuntimeError(
                "No active session. Call save_session() or load_session() first."
            )
        return self._active_session_id

    def add_network(
        self,
        ssid: str,
        bssid: str,
        security: str = "",
        channel: int = 0,
        rssi: int = -100,
        vendor: Optional[str] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
    ) -> None:
        """Add a discovered network to the active session.

        Args:
            ssid: Network SSID.
            bssid: AP MAC address.
            security: Security type (e.g. 'WPA2').
            channel: WiFi channel.
            rssi: Signal strength in dBm.
            vendor: OUI vendor name.
            latitude: GPS latitude.
            longitude: GPS longitude.
        """
        if self.simulate:
            logger.debug("[SessionManager] simulate add_network ssid=%s", ssid)
            return
        sid = self._require_session()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO networks
                   (session_id, ssid, bssid, security, channel, rssi,
                    vendor, latitude, longitude, timestamp)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (sid, ssid, bssid, security, channel, rssi,
                 vendor, latitude, longitude, datetime.now(timezone.utc).isoformat()),
            )
            conn.execute(
                "UPDATE sessions SET updated_at = ? WHERE session_id = ?",
                (datetime.now(timezone.utc).isoformat(), sid),
            )

    def add_attack(
        self,
        attack_type: str,
        target_ssid: str,
        target_bssid: str,
        outcome: str,
        tool: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> None:
        """Record an executed attack in the active session.

        Args:
            attack_type: Attack name (e.g. 'DEAUTH', 'EVIL_TWIN', 'HANDSHAKE').
            target_ssid: Target network SSID.
            target_bssid: Target AP MAC address.
            outcome: Result (e.g. 'handshake_captured', 'failed', 'success').
            tool: Tool or module used.
            notes: Optional additional context.
        """
        if self.simulate:
            logger.debug("[SessionManager] simulate add_attack type=%s", attack_type)
            return
        sid = self._require_session()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO attacks
                   (session_id, attack_type, target_ssid, target_bssid,
                    outcome, tool, notes, timestamp)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (sid, attack_type, target_ssid, target_bssid,
                 outcome, tool, notes, datetime.now(timezone.utc).isoformat()),
            )
            conn.execute(
                "UPDATE sessions SET updated_at = ? WHERE session_id = ?",
                (datetime.now(timezone.utc).isoformat(), sid),
            )

    def add_capture(
        self,
        ssid: str,
        bssid: str,
        filepath: str,
        capture_type: str = "hc22000",
    ) -> None:
        """Record a capture file in the active session.

        Args:
            ssid: Target SSID.
            bssid: Target BSSID.
            filepath: Path to the capture file.
            capture_type: Format identifier ('hc22000', 'pcap', 'pmkid').
        """
        if self.simulate:
            logger.debug("[SessionManager] simulate add_capture ssid=%s", ssid)
            return
        sid = self._require_session()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO captures
                   (session_id, ssid, bssid, filepath, capture_type, timestamp)
                   VALUES (?,?,?,?,?,?)""",
                (sid, ssid, bssid, filepath, capture_type,
                 datetime.now(timezone.utc).isoformat()),
            )
            conn.execute(
                "UPDATE sessions SET updated_at = ? WHERE session_id = ?",
                (datetime.now(timezone.utc).isoformat(), sid),
            )

    def add_credential(
        self,
        ssid: str,
        password: str,
        bssid: Optional[str] = None,
        method: str = "handshake",
    ) -> None:
        """Record a recovered credential in the active session.

        Args:
            ssid: Network SSID.
            password: Recovered passphrase.
            bssid: AP MAC address.
            method: Recovery method ('handshake', 'pmkid', 'wps', 'evil_twin').
        """
        if self.simulate:
            logger.debug("[SessionManager] simulate add_credential ssid=%s", ssid)
            return
        sid = self._require_session()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO credentials
                   (session_id, ssid, password, bssid, method, timestamp)
                   VALUES (?,?,?,?,?,?)""",
                (sid, ssid, password, bssid, method,
                 datetime.now(timezone.utc).isoformat()),
            )
            conn.execute(
                "UPDATE sessions SET updated_at = ? WHERE session_id = ?",
                (datetime.now(timezone.utc).isoformat(), sid),
            )

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_session(self, name: str, path: str | Path) -> str:
        """Export a session to a JSON file.

        Args:
            name: Session name to export.
            path: Output JSON file path.

        Returns:
            Absolute path to the written file.
        """
        out = Path(path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        if self.simulate:
            logger.info("[SessionManager] simulate export_session name=%s", name)
            return str(out)

        with self._conn() as conn:
            s = conn.execute(
                "SELECT * FROM sessions WHERE name = ?", (name,)
            ).fetchone()
            if not s:
                raise KeyError(f"Session '{name}' not found")
            sid = s["session_id"]

            networks = [dict(r) for r in conn.execute(
                "SELECT * FROM networks WHERE session_id = ?", (sid,)
            ).fetchall()]
            attacks = [dict(r) for r in conn.execute(
                "SELECT * FROM attacks WHERE session_id = ?", (sid,)
            ).fetchall()]
            captures = [dict(r) for r in conn.execute(
                "SELECT * FROM captures WHERE session_id = ?", (sid,)
            ).fetchall()]
            credentials = [dict(r) for r in conn.execute(
                "SELECT ssid, bssid, method, timestamp FROM credentials WHERE session_id = ?",
                (sid,)
            ).fetchall()]

        export_data = {
            "session_id": sid,
            "name": name,
            "created_at": s["created_at"],
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "notes": s["notes"],
            "networks": networks,
            "attacks": attacks,
            "captures": captures,
            "credentials": credentials,
        }

        with open(str(out), "w", encoding="utf-8") as fh:
            json.dump(export_data, fh, indent=2, default=str)

        logger.info("[SessionManager] Session '%s' exported to %s", name, out)
        return str(out)

    # ------------------------------------------------------------------
    # Context protocol
    # ------------------------------------------------------------------

    def __enter__(self) -> "SessionManager":
        return self

    def __exit__(self, *_: Any) -> None:
        pass

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def active_session_id(self) -> Optional[str]:
        """Currently active session ID, or None if no session is loaded."""
        return self._active_session_id
