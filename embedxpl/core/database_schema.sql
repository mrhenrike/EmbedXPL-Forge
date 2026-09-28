-- EmbedXPL Operational Database Schema
-- Tool: EmbedXPL v5.0.0 / XPL Suite
-- DB path: ~/.embedxpl/exf.db  (each tool has its own path)
-- Engine: SQLite 3 (stdlib, no dependencies)
-- Author: Andre Henrique (@mrhenrike) | Uniao Geek

PRAGMA journal_mode = WAL;

-- Engagement workspaces (one per client / pentest scope)
CREATE TABLE IF NOT EXISTS workspaces (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT UNIQUE NOT NULL,
    notes      TEXT DEFAULT '',
    created_at TEXT DEFAULT ''
);

-- Discovered hosts
CREATE TABLE IF NOT EXISTS hosts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    address      TEXT NOT NULL,       -- IPv4, IPv6, or hostname
    os           TEXT DEFAULT '',     -- "RouterOS", "Linux", "Windows", "embedded"
    hostname     TEXT DEFAULT '',
    status       TEXT DEFAULT 'unknown', -- "up" | "down" | "unknown"
    last_seen    TEXT DEFAULT '',
    UNIQUE(workspace_id, address)
);

-- Open services per host
CREATE TABLE IF NOT EXISTS services (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id  INTEGER NOT NULL REFERENCES hosts(id),
    port     INTEGER NOT NULL,
    proto    TEXT DEFAULT 'tcp',      -- "tcp" | "udp"
    name     TEXT DEFAULT '',         -- "http" | "winbox" | "ssh" | "rtsp"
    version  TEXT DEFAULT '',
    banner   TEXT DEFAULT '',
    UNIQUE(host_id, port, proto)
);

-- Confirmed vulnerabilities
CREATE TABLE IF NOT EXISTS vulns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id),
    module_path TEXT DEFAULT '',      -- Python import path of the module
    cve_ids     TEXT DEFAULT '[]',    -- JSON array: ["CVE-2018-14847"]
    severity    TEXT DEFAULT '',      -- "critical" | "high" | "medium" | "low"
    detail      TEXT DEFAULT '',      -- human-readable finding
    found_at    TEXT DEFAULT ''
);

-- Captured credentials
CREATE TABLE IF NOT EXISTS creds (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id),
    service_id  INTEGER REFERENCES services(id),
    username    TEXT DEFAULT '',
    password    TEXT DEFAULT '',
    cred_type   TEXT DEFAULT 'password',  -- "password" | "hash" | "key" | "token"
    source      TEXT DEFAULT '',          -- module that found these creds
    found_at    TEXT DEFAULT ''
);

-- Exfiltrated data / files
CREATE TABLE IF NOT EXISTS loot (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id    INTEGER NOT NULL REFERENCES hosts(id),
    ltype      TEXT DEFAULT '',   -- "config" | "hash" | "cert" | "file" | "key"
    data       TEXT DEFAULT '',   -- content (truncated if large)
    path       TEXT DEFAULT '',   -- remote path or local save path
    created_at TEXT DEFAULT ''
);

-- Module index cache (replaces in-memory scan on every search)
CREATE TABLE IF NOT EXISTS module_cache (
    path        TEXT PRIMARY KEY,     -- "embedxpl.modules.exploits.routers.dlink..."
    name        TEXT DEFAULT '',
    description TEXT DEFAULT '',
    cves        TEXT DEFAULT '[]',    -- JSON array
    vendors     TEXT DEFAULT '[]',    -- JSON array
    category    TEXT DEFAULT '',      -- "routers" | "cameras" | "firewalls" | ...
    updated_at  TEXT DEFAULT ''
);

-- History of module executions
CREATE TABLE IF NOT EXISTS run_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    module_path  TEXT NOT NULL,
    target       TEXT DEFAULT '',
    result       TEXT DEFAULT '',  -- "vulnerable" | "not_vulnerable" | "error"
    detail       TEXT DEFAULT '',
    ran_at       TEXT DEFAULT ''
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_hosts_ws    ON hosts(workspace_id);
CREATE INDEX IF NOT EXISTS idx_svc_host    ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_vuln_host   ON vulns(host_id);
CREATE INDEX IF NOT EXISTS idx_vuln_sev    ON vulns(severity);
CREATE INDEX IF NOT EXISTS idx_cred_host   ON creds(host_id);
CREATE INDEX IF NOT EXISTS idx_loot_host   ON loot(host_id);
CREATE INDEX IF NOT EXISTS idx_run_ws      ON run_history(workspace_id);
CREATE INDEX IF NOT EXISTS idx_run_mod     ON run_history(module_path);
CREATE INDEX IF NOT EXISTS idx_cache_cat   ON module_cache(category);
