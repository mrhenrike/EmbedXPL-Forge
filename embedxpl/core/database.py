"""EmbedXPL Operational Database — EXFDatabase.

SQLite-based persistence layer for engagement/assessment sessions.
Stores workspaces, discovered hosts/services, vulnerabilities, captured
credentials, loot, module run history, and module index cache.

Works entirely offline; no external dependencies beyond stdlib.

Usage::

    from embedxpl.core.database import EXFDatabase

    db = EXFDatabase()                    # opens ~/.embedxpl/exf.db
    db.workspace("pentest-client-x")     # create/select workspace

    # During assessment
    db.add_host("192.168.1.1", os="RouterOS")
    db.add_service("192.168.1.1", 8291, "tcp", "winbox")
    db.add_vuln("192.168.1.1",
                module_path="embedxpl.modules.exploits.network_os.mikrotik.xpl.winbox_auth",
                cve_ids=["CVE-2018-14847"], severity="critical",
                detail="Winbox credential disclosure")
    db.add_cred("192.168.1.1", "admin", "admin", cred_type="winbox")
    db.add_run("192.168.1.1", "embedxpl...winbox_auth", result="vulnerable")

    # Query
    print(db.hosts())
    print(db.vulns())
    print(db.creds())
    db.stats()
    db.export_xml("report.xml")

Subclassing::

    from embedxpl.core.database import XplDatabase

    class WxfDatabase(XplDatabase):
        _DB_DIR  = Path.home() / ".wirelessxpl"
        _DB_FILE = "wxf.db"
        _TOOL    = "WirelessXPL"

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

import json
import sqlite3
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Generator, Optional


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS workspaces (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT UNIQUE NOT NULL,
    notes      TEXT DEFAULT '',
    created_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS hosts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    address      TEXT NOT NULL,
    os           TEXT DEFAULT '',
    hostname     TEXT DEFAULT '',
    status       TEXT DEFAULT 'unknown',
    last_seen    TEXT DEFAULT '',
    UNIQUE(workspace_id, address)
);

CREATE TABLE IF NOT EXISTS services (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id  INTEGER NOT NULL,
    port     INTEGER NOT NULL,
    proto    TEXT DEFAULT 'tcp',
    name     TEXT DEFAULT '',
    version  TEXT DEFAULT '',
    banner   TEXT DEFAULT '',
    UNIQUE(host_id, port, proto)
);

CREATE TABLE IF NOT EXISTS vulns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL,
    module_path TEXT DEFAULT '',
    cve_ids     TEXT DEFAULT '[]',
    severity    TEXT DEFAULT '',
    detail      TEXT DEFAULT '',
    found_at    TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS creds (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL,
    service_id  INTEGER,
    username    TEXT DEFAULT '',
    password    TEXT DEFAULT '',
    cred_type   TEXT DEFAULT 'password',
    source      TEXT DEFAULT '',
    found_at    TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS loot (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id    INTEGER NOT NULL,
    ltype      TEXT DEFAULT '',
    data       TEXT DEFAULT '',
    path       TEXT DEFAULT '',
    created_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS module_cache (
    path        TEXT PRIMARY KEY,
    name        TEXT DEFAULT '',
    description TEXT DEFAULT '',
    cves        TEXT DEFAULT '[]',
    vendors     TEXT DEFAULT '[]',
    category    TEXT DEFAULT '',
    updated_at  TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS run_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    module_path  TEXT NOT NULL,
    target       TEXT DEFAULT '',
    result       TEXT DEFAULT '',
    detail       TEXT DEFAULT '',
    ran_at       TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_hosts_ws  ON hosts(workspace_id);
CREATE INDEX IF NOT EXISTS idx_svc_host  ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_vuln_host ON vulns(host_id);
CREATE INDEX IF NOT EXISTS idx_cred_host ON creds(host_id);
CREATE INDEX IF NOT EXISTS idx_run_ws    ON run_history(workspace_id);
CREATE INDEX IF NOT EXISTS idx_run_mod   ON run_history(module_path);
"""


# ---------------------------------------------------------------------------
# Base class (subclassable for each XPL tool)
# ---------------------------------------------------------------------------

class XplDatabase:
    """Base operational SQLite database for XPL Suite tools.

    Override `_DB_DIR`, `_DB_FILE`, `_TOOL` in subclasses.
    """

    _DB_DIR:  Path = Path.home() / ".embedxpl"
    _DB_FILE: str  = "exf.db"
    _TOOL:    str  = "EmbedXPL"

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._path = db_path or (self._DB_DIR / self._DB_FILE)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._workspace_id: Optional[int] = None

    # ------------------------------------------------------------------
    # Workspace management
    # ------------------------------------------------------------------

    def workspace(self, name: str = "default") -> "XplDatabase":
        """Create or select a workspace by name."""
        self._conn.execute(
            "INSERT OR IGNORE INTO workspaces(name, created_at) VALUES(?, ?)",
            (name, _now()),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT id FROM workspaces WHERE name=?", (name,)
        ).fetchone()
        self._workspace_id = row["id"]
        return self

    def _ws(self) -> int:
        """Return current workspace id, creating 'default' if needed."""
        if self._workspace_id is None:
            self.workspace("default")
        return self._workspace_id  # type: ignore[return-value]

    def list_workspaces(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute("SELECT * FROM workspaces ORDER BY created_at DESC").fetchall()]

    # ------------------------------------------------------------------
    # Host / Service
    # ------------------------------------------------------------------

    def add_host(
        self,
        address: str,
        os: str = "",
        hostname: str = "",
        status: str = "up",
    ) -> int:
        """Add or update a host. Returns host id."""
        ws = self._ws()
        self._conn.execute(
            "INSERT INTO hosts(workspace_id, address, os, hostname, status, last_seen) "
            "VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(workspace_id, address) DO UPDATE SET "
            "  os=COALESCE(NULLIF(excluded.os,''), os), "
            "  hostname=COALESCE(NULLIF(excluded.hostname,''), hostname), "
            "  status=excluded.status, last_seen=excluded.last_seen",
            (ws, address, os, hostname, status, _now()),
        )
        self._conn.commit()
        return self._conn.execute(
            "SELECT id FROM hosts WHERE workspace_id=? AND address=?", (ws, address)
        ).fetchone()["id"]

    def add_service(
        self,
        address: str,
        port: int,
        proto: str = "tcp",
        name: str = "",
        version: str = "",
        banner: str = "",
    ) -> int:
        """Add or update a service. Auto-creates host if needed. Returns service id."""
        host_id = self.add_host(address)
        self._conn.execute(
            "INSERT INTO services(host_id, port, proto, name, version, banner) "
            "VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(host_id, port, proto) DO UPDATE SET "
            "  name=COALESCE(NULLIF(excluded.name,''), name), "
            "  version=COALESCE(NULLIF(excluded.version,''), version), "
            "  banner=COALESCE(NULLIF(excluded.banner,''), banner)",
            (host_id, port, proto, name, version, banner),
        )
        self._conn.commit()
        return self._conn.execute(
            "SELECT id FROM services WHERE host_id=? AND port=? AND proto=?",
            (host_id, port, proto),
        ).fetchone()["id"]

    def hosts(self, workspace: Optional[str] = None) -> list[dict]:
        """List hosts in current (or named) workspace."""
        ws_id = self._get_ws_id(workspace) or self._ws()
        rows = self._conn.execute(
            "SELECT h.*, "
            " (SELECT COUNT(*) FROM services s WHERE s.host_id=h.id) AS svc_count, "
            " (SELECT COUNT(*) FROM vulns v WHERE v.host_id=h.id) AS vuln_count, "
            " (SELECT COUNT(*) FROM creds c WHERE c.host_id=h.id) AS cred_count "
            "FROM hosts h WHERE h.workspace_id=? ORDER BY h.address",
            (ws_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Vulns
    # ------------------------------------------------------------------

    def add_vuln(
        self,
        address: str,
        module_path: str = "",
        cve_ids: Optional[list[str]] = None,
        severity: str = "",
        detail: str = "",
    ) -> int:
        """Record a vulnerability. Auto-creates host if needed."""
        host_id = self.add_host(address)
        cursor = self._conn.execute(
            "INSERT INTO vulns(host_id, module_path, cve_ids, severity, detail, found_at) "
            "VALUES(?,?,?,?,?,?)",
            (host_id, module_path, json.dumps(cve_ids or []), severity.lower(), detail, _now()),
        )
        self._conn.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def vulns(self, address: Optional[str] = None) -> list[dict]:
        """List all vulns in workspace, optionally filtered by host address."""
        ws_id = self._ws()
        if address:
            rows = self._conn.execute(
                "SELECT v.*, h.address FROM vulns v "
                "JOIN hosts h ON v.host_id=h.id "
                "WHERE h.workspace_id=? AND h.address=? ORDER BY v.found_at DESC",
                (ws_id, address),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT v.*, h.address FROM vulns v "
                "JOIN hosts h ON v.host_id=h.id "
                "WHERE h.workspace_id=? ORDER BY v.found_at DESC",
                (ws_id,),
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["cve_ids"] = json.loads(d["cve_ids"])
            except Exception:
                pass
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Creds
    # ------------------------------------------------------------------

    def add_cred(
        self,
        address: str,
        username: str,
        password: str,
        cred_type: str = "password",
        source: str = "",
        port: Optional[int] = None,
        proto: str = "tcp",
    ) -> int:
        """Record a captured credential."""
        host_id = self.add_host(address)
        svc_id = None
        if port is not None:
            svc_id = self.add_service(address, port, proto)
        cursor = self._conn.execute(
            "INSERT INTO creds(host_id, service_id, username, password, cred_type, source, found_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (host_id, svc_id, username, password, cred_type, source, _now()),
        )
        self._conn.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def creds(self, address: Optional[str] = None) -> list[dict]:
        """List all captured credentials, optionally filtered by host."""
        ws_id = self._ws()
        if address:
            rows = self._conn.execute(
                "SELECT c.*, h.address FROM creds c "
                "JOIN hosts h ON c.host_id=h.id "
                "WHERE h.workspace_id=? AND h.address=? ORDER BY c.found_at DESC",
                (ws_id, address),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT c.*, h.address FROM creds c "
                "JOIN hosts h ON c.host_id=h.id "
                "WHERE h.workspace_id=? ORDER BY c.found_at DESC",
                (ws_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Loot
    # ------------------------------------------------------------------

    def add_loot(self, address: str, ltype: str, data: str, path: str = "") -> int:
        host_id = self.add_host(address)
        cursor = self._conn.execute(
            "INSERT INTO loot(host_id, ltype, data, path, created_at) VALUES(?,?,?,?,?)",
            (host_id, ltype, data, path, _now()),
        )
        self._conn.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def loot(self) -> list[dict]:
        ws_id = self._ws()
        rows = self._conn.execute(
            "SELECT l.*, h.address FROM loot l JOIN hosts h ON l.host_id=h.id "
            "WHERE h.workspace_id=? ORDER BY l.created_at DESC",
            (ws_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Module cache
    # ------------------------------------------------------------------

    def cache_module(
        self,
        path: str,
        name: str = "",
        description: str = "",
        cves: Optional[list[str]] = None,
        vendors: Optional[list[str]] = None,
        category: str = "",
    ) -> None:
        """Upsert a module into the cache (used by search engine)."""
        self._conn.execute(
            "INSERT INTO module_cache(path, name, description, cves, vendors, category, updated_at) "
            "VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(path) DO UPDATE SET "
            "  name=excluded.name, description=excluded.description, "
            "  cves=excluded.cves, vendors=excluded.vendors, "
            "  category=excluded.category, updated_at=excluded.updated_at",
            (path, name, description,
             json.dumps(cves or []), json.dumps(vendors or []),
             category, _now()),
        )

    def get_cached_modules(self, category: str = "") -> list[dict]:
        if category:
            rows = self._conn.execute(
                "SELECT * FROM module_cache WHERE category=? ORDER BY path",
                (category,),
            ).fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM module_cache ORDER BY path").fetchall()
        result = []
        for r in rows:
            d = dict(r)
            for k in ("cves", "vendors"):
                try:
                    d[k] = json.loads(d[k])
                except Exception:
                    pass
            result.append(d)
        return result

    def module_cache_count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM module_cache").fetchone()[0]

    # ------------------------------------------------------------------
    # Run history
    # ------------------------------------------------------------------

    def add_run(
        self,
        target: str,
        module_path: str,
        result: str = "",
        detail: str = "",
    ) -> int:
        """Log a module execution. Called automatically by XplRuntime when DB is active."""
        ws = self._ws()
        cursor = self._conn.execute(
            "INSERT INTO run_history(workspace_id, module_path, target, result, detail, ran_at) "
            "VALUES(?,?,?,?,?,?)",
            (ws, module_path, target, result, detail[:500], _now()),
        )
        self._conn.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def runs(self, module_path: Optional[str] = None, limit: int = 50) -> list[dict]:
        ws_id = self._ws()
        if module_path:
            rows = self._conn.execute(
                "SELECT * FROM run_history WHERE workspace_id=? AND module_path=? "
                "ORDER BY ran_at DESC LIMIT ?",
                (ws_id, module_path, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM run_history WHERE workspace_id=? ORDER BY ran_at DESC LIMIT ?",
                (ws_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats + Export
    # ------------------------------------------------------------------

    def stats(self, print_it: bool = True) -> dict:
        ws_id = self._ws()
        hosts  = self._conn.execute("SELECT COUNT(*) FROM hosts WHERE workspace_id=?",    (ws_id,)).fetchone()[0]
        svcs   = self._conn.execute("SELECT COUNT(*) FROM services WHERE host_id IN (SELECT id FROM hosts WHERE workspace_id=?)", (ws_id,)).fetchone()[0]
        vulns  = self._conn.execute("SELECT COUNT(*) FROM vulns WHERE host_id IN (SELECT id FROM hosts WHERE workspace_id=?)", (ws_id,)).fetchone()[0]
        creds  = self._conn.execute("SELECT COUNT(*) FROM creds WHERE host_id IN (SELECT id FROM hosts WHERE workspace_id=?)", (ws_id,)).fetchone()[0]
        loot   = self._conn.execute("SELECT COUNT(*) FROM loot WHERE host_id IN (SELECT id FROM hosts WHERE workspace_id=?)", (ws_id,)).fetchone()[0]
        runs   = self._conn.execute("SELECT COUNT(*) FROM run_history WHERE workspace_id=?", (ws_id,)).fetchone()[0]
        mcache = self._conn.execute("SELECT COUNT(*) FROM module_cache").fetchone()[0]
        s = {"hosts": hosts, "services": svcs, "vulns": vulns,
             "creds": creds, "loot": loot, "runs": runs, "module_cache": mcache,
             "db_path": str(self._path)}
        if print_it:
            print(f"\n=== {self._TOOL} DB ({self._path}) ===")
            for k, v in s.items():
                print(f"  {k:<14} {v}")
        return s

    def export_xml(self, output_path: str) -> int:
        """Export findings as XML (compatible with Nessus/MSF report format)."""
        ws_id = self._ws()
        root = ET.Element("XPLReport", tool=self._TOOL, exported=_now())

        for host in self.hosts():
            h_el = ET.SubElement(root, "host", address=host["address"], os=host.get("os", ""))
            svcs = self._conn.execute("SELECT * FROM services WHERE host_id=?", (host["id"],)).fetchall()
            for svc in svcs:
                ET.SubElement(h_el, "service", port=str(svc["port"]), proto=svc["proto"],
                              name=svc["name"], version=svc["version"])
            for vuln in self.vulns(host["address"]):
                v_el = ET.SubElement(h_el, "vuln", severity=vuln.get("severity", ""))
                v_el.set("module", vuln.get("module_path", ""))
                v_el.set("cves", ",".join(vuln.get("cve_ids", [])))
                v_el.text = vuln.get("detail", "")
            for cred in self.creds(host["address"]):
                ET.SubElement(h_el, "cred", username=cred["username"],
                              password=cred["password"], type=cred["cred_type"])

        tree = ET.ElementTree(ET.indent(root) or root)
        ET.indent(tree)
        tree.write(output_path, encoding="unicode", xml_declaration=True)
        return len(self.hosts())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_ws_id(self, name: Optional[str]) -> Optional[int]:
        if name is None:
            return None
        row = self._conn.execute("SELECT id FROM workspaces WHERE name=?", (name,)).fetchone()
        return row["id"] if row else None

    def close(self) -> None:
        self._conn.commit()
        self._conn.close()

    def __enter__(self) -> "XplDatabase":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# EmbedXPL concrete database
# ---------------------------------------------------------------------------

class EXFDatabase(XplDatabase):
    """EmbedXPL operational database stored at ~/.embedxpl/exf.db."""

    _DB_DIR  = Path.home() / ".embedxpl"
    _DB_FILE = "exf.db"
    _TOOL    = "EmbedXPL"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")
