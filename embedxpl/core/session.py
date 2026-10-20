"""Session persistence for EmbedXPL-Forge.

Tracks scan history per host (keyed by IP+MAC) so subsequent runs
can resume where they left off — similar to John the Ripper's session
restore.  All data is stored as JSON in ``~/.exf_sessions/``.

Storage layout::

    ~/.exf_sessions/
        <host_id>.json      # one file per unique host
        _index.json          # lightweight index: host_id -> summary

Each session file contains:
- Host identity (IP, MAC, vendor, model)
- Discovery results (ports, banners, fingerprint)
- Module execution history (which ran, results, timestamps)
- Findings summary (vulns confirmed, errors, etc.)
- Wireless info and recommendations
- Timestamps (first_seen, last_scanned)

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""


import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_SESSIONS_DIR = Path(os.path.expanduser("~/.exf_sessions"))
_INDEX_FILE = _SESSIONS_DIR / "_index.json"


def _ensure_dir() -> None:
    """Create the sessions directory if it doesn't exist."""
    _SESSIONS_DIR.mkdir(parents=True, exist_ok=True)


def host_id(ip: str, mac: str = "") -> str:
    """Generate a deterministic host identifier from IP+MAC.

    Uses a short SHA-256 prefix so filenames stay manageable.
    If MAC is empty, falls back to IP-only hashing (less unique
    but still usable).
    """
    key = f"{ip.strip().lower()}|{mac.strip().upper()}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass
class ModuleResult:
    """Outcome of a single module execution."""

    module_path: str
    vulnerable: bool | None = None
    error: str | None = None
    elapsed_s: float = 0.0
    port: int = 0
    protocol: str = ""
    timestamp: float = 0.0
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "module_path": self.module_path,
            "vulnerable": self.vulnerable,
            "error": self.error,
            "elapsed_s": round(self.elapsed_s, 3),
            "port": self.port,
            "protocol": self.protocol,
            "timestamp": self.timestamp,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ModuleResult":
        """Deserialize from dict."""
        return cls(
            module_path=d.get("module_path", ""),
            vulnerable=d.get("vulnerable"),
            error=d.get("error"),
            elapsed_s=d.get("elapsed_s", 0.0),
            port=d.get("port", 0),
            protocol=d.get("protocol", ""),
            timestamp=d.get("timestamp", 0.0),
            details=d.get("details", ""),
        )


@dataclass
class HostSession:
    """Full session state for a single host."""

    host_id: str
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    model: str = ""
    open_ports: list[int] = field(default_factory=list)
    banners: dict[str, str] = field(default_factory=dict)
    fingerprint_confidence: float = 0.0
    matched_modules: list[str] = field(default_factory=list)
    has_wireless: bool = False
    wireless_ssids: list[str] = field(default_factory=list)
    wireless_recommendation: str = ""

    module_results: list[ModuleResult] = field(default_factory=list)
    vulns_found: list[str] = field(default_factory=list)
    total_scans: int = 0

    first_seen: float = 0.0
    last_scanned: float = 0.0
    notes: list[str] = field(default_factory=list)

    def modules_tested(self) -> list[str]:
        """Return list of module paths that have been executed."""
        return list({r.module_path for r in self.module_results})

    def modules_pending(self) -> list[str]:
        """Return matched modules not yet tested."""
        tested = set(self.modules_tested())
        return [m for m in self.matched_modules if m not in tested]

    def modules_vulnerable(self) -> list[str]:
        """Return modules that confirmed vulnerability."""
        return list({
            r.module_path for r in self.module_results
            if r.vulnerable is True
        })

    def modules_safe(self) -> list[str]:
        """Return modules that confirmed NOT vulnerable."""
        return list({
            r.module_path for r in self.module_results
            if r.vulnerable is False
        })

    def modules_errored(self) -> list[str]:
        """Return modules that errored during execution."""
        return list({
            r.module_path for r in self.module_results
            if r.error
        })

    def add_result(self, result: ModuleResult) -> None:
        """Record a module execution result."""
        if not result.timestamp:
            result.timestamp = time.time()
        self.module_results.append(result)
        if result.vulnerable is True:
            if result.module_path not in self.vulns_found:
                self.vulns_found.append(result.module_path)

    def merge_discovery(
        self,
        ip: str,
        mac: str = "",
        hostname: str = "",
        vendor: str = "",
        model: str = "",
        open_ports: list[int] | None = None,
        banners: dict[str, str] | None = None,
        fingerprint_confidence: float = 0.0,
        matched_modules: list[str] | None = None,
        has_wireless: bool = False,
        wireless_ssids: list[str] | None = None,
        wireless_recommendation: str = "",
    ) -> None:
        """Update session with fresh discovery data (merge, don't overwrite history)."""
        self.ip = ip
        if mac:
            self.mac = mac
        if hostname:
            self.hostname = hostname
        if vendor:
            self.vendor = vendor
        if model:
            self.model = model
        if open_ports:
            merged_ports = list(set(self.open_ports) | set(open_ports))
            merged_ports.sort()
            self.open_ports = merged_ports
        if banners:
            self.banners.update({str(k): v for k, v in banners.items()})
        if fingerprint_confidence > self.fingerprint_confidence:
            self.fingerprint_confidence = fingerprint_confidence
        if matched_modules:
            merged_mods = list(dict.fromkeys(self.matched_modules + matched_modules))
            self.matched_modules = merged_mods
        if has_wireless:
            self.has_wireless = True
        if wireless_ssids:
            for ssid in wireless_ssids:
                if ssid not in self.wireless_ssids:
                    self.wireless_ssids.append(ssid)
        if wireless_recommendation:
            self.wireless_recommendation = wireless_recommendation

        self.total_scans += 1
        self.last_scanned = time.time()

    def summary_line(self) -> str:
        """One-line summary for index/listing."""
        tested = len(self.modules_tested())
        pending = len(self.modules_pending())
        vulns = len(self.vulns_found)
        return (
            "{ip} ({mac}) [{vendor} {model}] — "
            "scans:{scans} tested:{tested} pending:{pending} vulns:{vulns}"
        ).format(
            ip=self.ip,
            mac=self.mac or "no-mac",
            vendor=self.vendor or "?",
            model=self.model or "?",
            scans=self.total_scans,
            tested=tested,
            pending=pending,
            vulns=vulns,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dict."""
        return {
            "host_id": self.host_id,
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "model": self.model,
            "open_ports": self.open_ports,
            "banners": self.banners,
            "fingerprint_confidence": self.fingerprint_confidence,
            "matched_modules": self.matched_modules,
            "has_wireless": self.has_wireless,
            "wireless_ssids": self.wireless_ssids,
            "wireless_recommendation": self.wireless_recommendation,
            "module_results": [r.to_dict() for r in self.module_results],
            "vulns_found": self.vulns_found,
            "total_scans": self.total_scans,
            "first_seen": self.first_seen,
            "last_scanned": self.last_scanned,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "HostSession":
        """Deserialize from dict."""
        session = cls(
            host_id=d.get("host_id", ""),
            ip=d.get("ip", ""),
            mac=d.get("mac", ""),
            hostname=d.get("hostname", ""),
            vendor=d.get("vendor", ""),
            model=d.get("model", ""),
            open_ports=d.get("open_ports", []),
            banners=d.get("banners", {}),
            fingerprint_confidence=d.get("fingerprint_confidence", 0.0),
            matched_modules=d.get("matched_modules", []),
            has_wireless=d.get("has_wireless", False),
            wireless_ssids=d.get("wireless_ssids", []),
            wireless_recommendation=d.get("wireless_recommendation", ""),
            vulns_found=d.get("vulns_found", []),
            total_scans=d.get("total_scans", 0),
            first_seen=d.get("first_seen", 0.0),
            last_scanned=d.get("last_scanned", 0.0),
            notes=d.get("notes", []),
        )
        for mr in d.get("module_results", []):
            session.module_results.append(ModuleResult.from_dict(mr))
        return session


class SessionManager:
    """Manages persistent scan sessions per host.

    Provides load/save/list/delete/purge operations and maintains
    a lightweight index file for fast lookups.
    """

    def __init__(self, sessions_dir: Path | None = None):
        self._dir = sessions_dir or _SESSIONS_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._index_file = self._dir / "_index.json"
        self._index: dict[str, dict[str, Any]] = self._load_index()

    def _load_index(self) -> dict[str, dict[str, Any]]:
        """Load the index file."""
        if self._index_file.exists():
            try:
                with open(self._index_file, encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    return data
            except Exception as exc:
                logger.debug("Session index load failed: %s", exc)
        return {}

    def _save_index(self) -> None:
        """Persist the index file."""
        try:
            with open(self._index_file, "w", encoding="utf-8") as fh:
                json.dump(self._index, fh, indent=2, ensure_ascii=False)
        except Exception as exc:
            logger.debug("Session index save failed: %s", exc)

    def _session_path(self, hid: str) -> Path:
        """Return the file path for a host session."""
        return self._dir / f"{hid}.json"

    def exists(self, ip: str, mac: str = "") -> bool:
        """Check if a session exists for the given host."""
        hid = host_id(ip, mac)
        return hid in self._index or self._session_path(hid).exists()

    def find(self, ip: str, mac: str = "") -> str | None:
        """Find session ID for a host. Returns host_id or None.

        Tries exact IP+MAC match first, then falls back to IP-only
        if no MAC is provided.
        """
        hid = host_id(ip, mac)
        if hid in self._index or self._session_path(hid).exists():
            return hid

        if not mac:
            for entry_id, meta in self._index.items():
                if meta.get("ip") == ip:
                    return entry_id
        return None

    def load(self, ip: str, mac: str = "") -> HostSession | None:
        """Load an existing session for the host, or return None."""
        hid = self.find(ip, mac)
        if hid is None:
            return None
        path = self._session_path(hid)
        if not path.exists():
            return None
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            return HostSession.from_dict(data)
        except Exception as exc:
            logger.warning("Failed to load session %s: %s", hid, exc)
            return None

    def save(self, session: HostSession) -> None:
        """Persist a session to disk and update the index."""
        path = self._session_path(session.host_id)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(session.to_dict(), fh, indent=2, ensure_ascii=False)
        except Exception as exc:
            logger.warning("Failed to save session %s: %s", session.host_id, exc)
            return

        self._index[session.host_id] = {
            "ip": session.ip,
            "mac": session.mac,
            "vendor": session.vendor,
            "model": session.model,
            "total_scans": session.total_scans,
            "vulns": len(session.vulns_found),
            "tested": len(session.modules_tested()),
            "pending": len(session.modules_pending()),
            "last_scanned": session.last_scanned,
            "first_seen": session.first_seen,
        }
        self._save_index()
        logger.debug("Session saved: %s (%s)", session.host_id, session.ip)

    def create(self, ip: str, mac: str = "") -> HostSession:
        """Create a new empty session for a host."""
        hid = host_id(ip, mac)
        session = HostSession(
            host_id=hid,
            ip=ip,
            mac=mac,
            first_seen=time.time(),
            last_scanned=time.time(),
        )
        return session

    def get_or_create(self, ip: str, mac: str = "") -> tuple[HostSession, bool]:
        """Load existing session or create new one.

        Returns:
            Tuple of (session, is_existing).
        """
        existing = self.load(ip, mac)
        if existing:
            return existing, True
        return self.create(ip, mac), False

    def list_sessions(self) -> list[dict[str, Any]]:
        """Return index entries for all saved sessions."""
        result = []
        for hid, meta in sorted(
            self._index.items(),
            key=lambda x: x[1].get("last_scanned", 0),
            reverse=True,
        ):
            entry = dict(meta)
            entry["host_id"] = hid
            result.append(entry)
        return result

    def delete(self, ip: str, mac: str = "") -> bool:
        """Delete session for a specific host."""
        hid = self.find(ip, mac)
        if hid is None:
            return False
        path = self._session_path(hid)
        if path.exists():
            path.unlink()
        if hid in self._index:
            del self._index[hid]
            self._save_index()
        logger.info("Session deleted: %s (%s)", hid, ip)
        return True

    def delete_by_id(self, hid: str) -> bool:
        """Delete session by host_id directly."""
        path = self._session_path(hid)
        if path.exists():
            path.unlink()
        if hid in self._index:
            del self._index[hid]
            self._save_index()
            return True
        return path.exists()

    def purge_all(self) -> int:
        """Delete ALL sessions. Returns count of deleted sessions."""
        count = 0
        for f in self._dir.glob("*.json"):
            if f.name != "_index.json":
                f.unlink()
                count += 1
        self._index.clear()
        self._save_index()
        logger.info("Purged %d session(s)", count)
        return count

    def export_session(self, ip: str, mac: str = "") -> str | None:
        """Export a session as formatted JSON string."""
        session = self.load(ip, mac)
        if not session:
            return None
        return json.dumps(session.to_dict(), indent=2, ensure_ascii=False)
