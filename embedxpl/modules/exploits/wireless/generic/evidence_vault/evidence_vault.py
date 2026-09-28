"""Evidence Vault - hash-chained tamper-evident audit ledger for WiFi pentest.

Stores WiFi pentest artifacts in a forensically defensible chain compatible
with ISO/IEC 27037 chain-of-custody requirements.

Each record includes a SHA-256 Merkle-style chain: any modification to a past
record breaks the chain, which verify_chain() detects.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import csv
import hashlib
import html
import json
import logging
import os
import sqlite3
import tarfile
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional

logger = logging.getLogger(__name__)

_GENESIS = "0" * 64


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_of(obj: dict[str, Any]) -> str:
    """Return deterministic SHA-256 hex digest of a JSON-serialisable dict."""
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Domain objects
# ---------------------------------------------------------------------------

@dataclass
class CaptureRecord:
    """A captured handshake or PCAP file."""
    ssid: str
    bssid: str
    filepath: str
    capture_type: str = "hc22000"
    channel: Optional[int] = None
    rssi: Optional[int] = None
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = _now_iso()


@dataclass
class CredentialRecord:
    """A recovered WiFi credential."""
    ssid: str
    password: str
    bssid: Optional[str] = None
    method: str = "handshake"
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = _now_iso()


@dataclass
class NetworkRecord:
    """A discovered WiFi network."""
    ssid: str
    bssid: str
    security: str
    channel: int
    rssi: int
    vendor: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = _now_iso()


# ---------------------------------------------------------------------------
# Evidence Vault
# ---------------------------------------------------------------------------

class EvidenceVault:
    """Hash-chained, SQLite-backed evidence store for WiFi pentest engagements.

    Each appended record includes a sha256 digest of itself and a prev_hash
    pointer to the prior record, forming a tamper-evident chain.

    Args:
        vault_dir: Directory where the vault database and artifacts are stored.
            Resolved relative to the caller's CWD if not absolute.
        operator: Operator identifier (name or anonymized ID - never a password).

    Attributes:
        __info__: Module metadata.
    """

    __info__ = {
        "name": "Evidence Vault",
        "category": "evidence_vault",
        "type": "forensics",
        "description": (
            "Hash-chained tamper-evident audit ledger for WiFi pentest. "
            "ISO/IEC 27037 chain-of-custody compatible. "
            "Records scans, handshakes, credentials with SHA-256 Merkle chain."
        ),
        "hw_req": ["None - software only"],
        "standards": ["ISO/IEC 27037", "NIST SP 800-86"],
        "authors": ["Andre Henrique (@mrhenrike) | Uniao Geek"],
    }

    def __init__(
        self,
        vault_dir: str | Path,
        operator: str = "operator",
        session_id: Optional[str] = None,
        simulate: bool = True,
    ) -> None:
        self.vault_dir = Path(vault_dir).resolve()
        self.operator = operator
        self.session_id = session_id or str(uuid.uuid4())[:8]
        self.simulate = simulate

        if not self.simulate:
            self.vault_dir.mkdir(parents=True, exist_ok=True)
            self._artifacts_dir = self.vault_dir / "artifacts"
            self._artifacts_dir.mkdir(exist_ok=True)
            self._db_path = self.vault_dir / f"vault_{self.session_id}.db"
            self._init_db()
        else:
            self._db_path = None
            self._artifacts_dir = None
            logger.info("[EvidenceVault] simulate=True - nothing will be written to disk")

        self._last_hash = self._tail_hash()

    # ------------------------------------------------------------------
    # DB bootstrap
    # ------------------------------------------------------------------

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        """Context-managed SQLite connection."""
        if self._db_path is None:
            raise RuntimeError("Vault is in simulate mode - no database available")
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
                CREATE TABLE IF NOT EXISTS ledger (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts          TEXT NOT NULL,
                    session     TEXT NOT NULL,
                    operator    TEXT NOT NULL,
                    kind        TEXT NOT NULL,
                    prev_hash   TEXT NOT NULL,
                    payload     TEXT NOT NULL,
                    artifact_sha256 TEXT,
                    artifact_size   INTEGER,
                    sha256      TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS captures (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ssid        TEXT NOT NULL,
                    bssid       TEXT NOT NULL,
                    filepath    TEXT NOT NULL,
                    capture_type TEXT DEFAULT 'hc22000',
                    channel     INTEGER,
                    rssi        INTEGER,
                    timestamp   TEXT NOT NULL,
                    ledger_sha256 TEXT
                );
                CREATE TABLE IF NOT EXISTS credentials (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ssid        TEXT NOT NULL,
                    password    TEXT NOT NULL,
                    bssid       TEXT,
                    method      TEXT DEFAULT 'handshake',
                    timestamp   TEXT NOT NULL,
                    ledger_sha256 TEXT
                );
                CREATE TABLE IF NOT EXISTS networks (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ssid        TEXT NOT NULL,
                    bssid       TEXT NOT NULL,
                    security    TEXT NOT NULL,
                    channel     INTEGER NOT NULL,
                    rssi        INTEGER NOT NULL,
                    vendor      TEXT,
                    latitude    REAL,
                    longitude   REAL,
                    timestamp   TEXT NOT NULL,
                    ledger_sha256 TEXT
                );
            """)

    # ------------------------------------------------------------------
    # Chain helpers
    # ------------------------------------------------------------------

    def _tail_hash(self) -> str:
        if self.simulate or self._db_path is None or not self._db_path.exists():
            return _GENESIS
        try:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT sha256 FROM ledger ORDER BY id DESC LIMIT 1"
                ).fetchone()
                return row["sha256"] if row else _GENESIS
        except Exception:
            return _GENESIS

    def _append_ledger(self, kind: str, payload: dict[str, Any],
                       artifact: Optional[bytes] = None) -> dict[str, Any]:
        """Build a chain record. Persists if not in simulate mode."""
        record: dict[str, Any] = {
            "ts": _now_iso(),
            "session": self.session_id,
            "operator": self.operator,
            "kind": kind,
            "prev_hash": self._last_hash,
            "payload": payload,
        }

        if artifact is not None:
            art_hash = hashlib.sha256(artifact).hexdigest()
            record["artifact_sha256"] = art_hash
            record["artifact_size"] = len(artifact)
            if not self.simulate and self._artifacts_dir is not None:
                art_path = self._artifacts_dir / f"artifact_{art_hash}.bin"
                if not art_path.exists():
                    art_path.write_bytes(artifact)

        record["sha256"] = _sha256_of(record)
        self._last_hash = record["sha256"]

        if not self.simulate:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ledger
                       (ts, session, operator, kind, prev_hash, payload,
                        artifact_sha256, artifact_size, sha256)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        record["ts"],
                        record["session"],
                        record["operator"],
                        record["kind"],
                        record["prev_hash"],
                        json.dumps(record["payload"], default=str),
                        record.get("artifact_sha256"),
                        record.get("artifact_size"),
                        record["sha256"],
                    ),
                )
        else:
            logger.debug("[EvidenceVault] simulate ledger append: kind=%s", kind)

        return record

    # ------------------------------------------------------------------
    # Public add methods
    # ------------------------------------------------------------------

    def add_capture(
        self,
        ssid: str,
        bssid: str,
        filepath: str,
        capture_type: str = "hc22000",
        channel: Optional[int] = None,
        rssi: Optional[int] = None,
        artifact: Optional[bytes] = None,
    ) -> dict[str, Any]:
        """Record a captured handshake or PCAP file.

        Args:
            ssid: Target network SSID.
            bssid: Target AP MAC address.
            filepath: Path to the capture file.
            capture_type: Format identifier, e.g. 'hc22000', 'pcap'.
            channel: WiFi channel number.
            rssi: Signal strength in dBm.
            artifact: Raw file bytes to store as evidence artifact.

        Returns:
            The ledger record dict.
        """
        rec = CaptureRecord(
            ssid=ssid, bssid=bssid, filepath=filepath,
            capture_type=capture_type, channel=channel, rssi=rssi,
        )
        record = self._append_ledger("CAPTURE", asdict(rec), artifact)

        if not self.simulate:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO captures
                       (ssid, bssid, filepath, capture_type, channel, rssi,
                        timestamp, ledger_sha256)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (ssid, bssid, filepath, capture_type, channel, rssi,
                     rec.timestamp, record["sha256"]),
                )
        return record

    def add_credential(
        self,
        ssid: str,
        password: str,
        bssid: Optional[str] = None,
        method: str = "handshake",
    ) -> dict[str, Any]:
        """Record a recovered credential.

        Args:
            ssid: Network SSID.
            password: Recovered passphrase.
            bssid: Optional AP MAC address.
            method: Recovery method ('handshake', 'wps', 'pmkid', 'evil_twin').

        Returns:
            The ledger record dict.
        """
        rec = CredentialRecord(ssid=ssid, password=password, bssid=bssid, method=method)
        record = self._append_ledger("CREDENTIAL", asdict(rec))

        if not self.simulate:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO credentials
                       (ssid, password, bssid, method, timestamp, ledger_sha256)
                       VALUES (?,?,?,?,?,?)""",
                    (ssid, password, bssid, method, rec.timestamp, record["sha256"]),
                )
        return record

    def add_network(
        self,
        ssid: str,
        bssid: str,
        security: str,
        channel: int,
        rssi: int,
        vendor: Optional[str] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
    ) -> dict[str, Any]:
        """Record a discovered WiFi network.

        Args:
            ssid: Network SSID.
            bssid: AP MAC address.
            security: Security type (e.g. 'WPA2', 'Open').
            channel: WiFi channel.
            rssi: Signal strength in dBm.
            vendor: OUI-resolved vendor name.
            latitude: GPS latitude if available.
            longitude: GPS longitude if available.

        Returns:
            The ledger record dict.
        """
        rec = NetworkRecord(
            ssid=ssid, bssid=bssid, security=security,
            channel=channel, rssi=rssi, vendor=vendor,
            latitude=latitude, longitude=longitude,
        )
        record = self._append_ledger("NETWORK", asdict(rec))

        if not self.simulate:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO networks
                       (ssid, bssid, security, channel, rssi, vendor,
                        latitude, longitude, timestamp, ledger_sha256)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (ssid, bssid, security, channel, rssi, vendor,
                     latitude, longitude, rec.timestamp, record["sha256"]),
                )
        return record

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_chain(self) -> dict[str, Any]:
        """Walk the ledger and verify every hash linkage.

        Returns:
            Dict with keys: ok (bool), count (int), errors (list[str]), head (str).
        """
        if self.simulate:
            return {"ok": True, "count": 0, "errors": [], "head": _GENESIS, "simulated": True}

        errors: list[str] = []
        try:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM ledger ORDER BY id ASC"
                ).fetchall()
        except Exception as exc:
            return {"ok": False, "count": 0, "errors": [str(exc)], "head": _GENESIS}

        prev = _GENESIS
        for i, row in enumerate(rows):
            r = dict(row)
            r["payload"] = json.loads(r["payload"])
            stated = r.pop("id")  # not part of the hash
            sha_stated = r.pop("sha256")

            if r.get("prev_hash") != prev:
                errors.append(
                    f"#{i} prev_hash mismatch: expected {prev[:12]}, "
                    f"got {r.get('prev_hash', '')[:12]}"
                )

            recomputed = _sha256_of(r)
            if sha_stated != recomputed:
                errors.append(
                    f"#{i} sha256 mismatch: stated {sha_stated[:12]}, "
                    f"recomputed {recomputed[:12]}"
                )

            prev = sha_stated

        return {
            "ok": not errors,
            "count": len(rows),
            "errors": errors,
            "head": prev,
        }

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_report(self, format: str = "html") -> str:
        """Generate a pentest findings report.

        Args:
            format: Output format - 'html' or 'json'.

        Returns:
            Report content as a string.
        """
        if format not in ("html", "json"):
            raise ValueError("format must be 'html' or 'json'")

        data = self._collect_export_data()

        if format == "json":
            return json.dumps(data, indent=2, default=str)
        return self._render_html(data)

    def _collect_export_data(self) -> dict[str, Any]:
        if self.simulate:
            return {
                "session": self.session_id,
                "operator": self.operator,
                "generated": _now_iso(),
                "simulated": True,
                "captures": [],
                "credentials": [],
                "networks": [],
                "chain_ok": True,
            }

        with self._conn() as conn:
            captures = [dict(r) for r in conn.execute(
                "SELECT ssid, bssid, filepath, capture_type, channel, rssi, timestamp "
                "FROM captures ORDER BY timestamp"
            ).fetchall()]
            credentials = [dict(r) for r in conn.execute(
                "SELECT ssid, password, bssid, method, timestamp "
                "FROM credentials ORDER BY timestamp"
            ).fetchall()]
            networks = [dict(r) for r in conn.execute(
                "SELECT ssid, bssid, security, channel, rssi, vendor, "
                "latitude, longitude, timestamp FROM networks ORDER BY rssi DESC"
            ).fetchall()]

        chain_result = self.verify_chain()
        return {
            "session": self.session_id,
            "operator": self.operator,
            "generated": _now_iso(),
            "captures": captures,
            "credentials": credentials,
            "networks": networks,
            "chain_ok": chain_result["ok"],
            "chain_errors": chain_result.get("errors", []),
        }

    def _render_html(self, data: dict[str, Any]) -> str:
        def _esc(v: Any) -> str:
            return html.escape(str(v) if v is not None else "")

        def _rows(records: list[dict], keys: list[str]) -> str:
            if not records:
                return "<tr><td colspan='100' style='text-align:center'>No records</td></tr>"
            lines = []
            for rec in records:
                cells = "".join(f"<td>{_esc(rec.get(k, ''))}</td>" for k in keys)
                lines.append(f"<tr>{cells}</tr>")
            return "".join(lines)

        chain_badge = (
            "<span style='color:#27ae60'>VALID</span>"
            if data.get("chain_ok")
            else "<span style='color:#e74c3c'>BROKEN</span>"
        )

        net_keys = ["ssid", "bssid", "security", "channel", "rssi", "vendor", "timestamp"]
        cap_keys = ["ssid", "bssid", "capture_type", "channel", "rssi", "filepath", "timestamp"]
        cred_keys = ["ssid", "bssid", "method", "timestamp"]

        cred_rows = []
        for rec in data.get("credentials", []):
            pw_masked = "*" * len(rec.get("password", ""))
            cells = (
                f"<td>{_esc(rec.get('ssid',''))}</td>"
                f"<td>{_esc(rec.get('bssid',''))}</td>"
                f"<td>{_esc(rec.get('method',''))}</td>"
                f"<td><code>{pw_masked}</code></td>"
                f"<td>{_esc(rec.get('timestamp',''))}</td>"
            )
            cred_rows.append(f"<tr>{cells}</tr>")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Evidence Vault - Session {_esc(data['session'])}</title>
<style>
  body {{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}}
  h1 {{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:8px}}
  h2 {{color:#8b949e;margin-top:28px}}
  table {{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}}
  th {{background:#161b22;color:#58a6ff;padding:8px;text-align:left;border:1px solid #30363d}}
  td {{padding:6px 8px;border:1px solid #21262d;word-break:break-all}}
  tr:nth-child(even) {{background:#161b22}}
  .badge {{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px}}
  .meta {{color:#8b949e;font-size:12px;margin-top:4px}}
</style>
</head>
<body>
<h1>Evidence Vault - Pentest Report</h1>
<p class="meta">Session: {_esc(data['session'])} | Operator: {_esc(data['operator'])}</p>
<p class="meta">Generated: {_esc(data['generated'])} | Chain integrity: {chain_badge}</p>

<h2>Discovered Networks ({len(data.get('networks', []))})</h2>
<table>
<tr>{''.join(f'<th>{k.upper()}</th>' for k in net_keys)}</tr>
{_rows(data.get('networks', []), net_keys)}
</table>

<h2>Captures ({len(data.get('captures', []))})</h2>
<table>
<tr>{''.join(f'<th>{k.upper()}</th>' for k in cap_keys)}</tr>
{_rows(data.get('captures', []), cap_keys)}
</table>

<h2>Credentials ({len(data.get('credentials', []))})</h2>
<table>
<tr><th>SSID</th><th>BSSID</th><th>METHOD</th><th>PASSWORD</th><th>TIMESTAMP</th></tr>
{''.join(cred_rows) if cred_rows else "<tr><td colspan='5' style='text-align:center'>No credentials recovered</td></tr>"}
</table>
</body>
</html>"""

    def export_bundle(self, out_path: str | Path) -> dict[str, Any]:
        """Bundle ledger DB and artifacts into a tar.gz archive.

        Args:
            out_path: Destination path for the .tar.gz archive.

        Returns:
            Dict with path, bytes, and head_hash keys.
        """
        if self.simulate:
            logger.info("[EvidenceVault] simulate=True - skipping bundle export")
            return {"path": None, "bytes": 0, "head_hash": _GENESIS, "simulated": True}

        out = Path(out_path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        with tarfile.open(str(out), "w:gz") as tar:
            if self._db_path and self._db_path.exists():
                tar.add(str(self._db_path), arcname=self._db_path.name)
            if self._artifacts_dir and self._artifacts_dir.exists():
                for art in self._artifacts_dir.glob("artifact_*.bin"):
                    tar.add(str(art), arcname=art.name)

        return {
            "path": str(out),
            "bytes": out.stat().st_size,
            "head_hash": self._last_hash,
        }

    def export_csv(self, out_path: str | Path, table: str = "networks") -> str:
        """Export a table to CSV.

        Args:
            out_path: Output CSV file path.
            table: One of 'networks', 'captures', 'credentials'.

        Returns:
            Absolute path to the written file.
        """
        allowed = {"networks", "captures", "credentials"}
        if table not in allowed:
            raise ValueError(f"table must be one of {sorted(allowed)}")

        out = Path(out_path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        if self.simulate:
            logger.info("[EvidenceVault] simulate=True - skipping CSV export")
            return str(out)

        with self._conn() as conn:
            rows = [dict(r) for r in conn.execute(f"SELECT * FROM {table}").fetchall()]

        if rows:
            with open(str(out), "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)

        return str(out)

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @property
    def head_hash(self) -> str:
        """Current chain head hash."""
        return self._last_hash

    def summary(self) -> dict[str, Any]:
        """Return a lightweight summary of vault contents."""
        if self.simulate:
            return {"session": self.session_id, "simulated": True}
        with self._conn() as conn:
            return {
                "session": self.session_id,
                "operator": self.operator,
                "networks": conn.execute("SELECT COUNT(*) FROM networks").fetchone()[0],
                "captures": conn.execute("SELECT COUNT(*) FROM captures").fetchone()[0],
                "credentials": conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0],
                "ledger_entries": conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0],
                "head_hash": self._last_hash,
            }
