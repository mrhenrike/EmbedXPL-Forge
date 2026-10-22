"""Tests for embedxpl.core.database (SQLite operational database)."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from embedxpl.core.database import EXFDatabase, XplDatabase


@pytest.fixture()
def db(tmp_path: Path) -> XplDatabase:
    """Create a fresh in-memory-like DB at a temp path."""
    return XplDatabase(db_path=tmp_path / "test.db")


@pytest.fixture()
def exf_db(tmp_path: Path) -> EXFDatabase:
    """EXFDatabase with temp path."""
    return EXFDatabase(db_path=tmp_path / "exf_test.db")


# ------------------------------------------------------------------
# Instantiation
# ------------------------------------------------------------------

class TestInstantiation:
    def test_xpl_database_creates_file(self, tmp_path: Path) -> None:
        db_path = tmp_path / "new.db"
        XplDatabase(db_path=db_path)
        assert db_path.exists()

    def test_exf_database_creates_file(self, tmp_path: Path) -> None:
        db_path = tmp_path / "exf.db"
        EXFDatabase(db_path=db_path)
        assert db_path.exists()

    def test_exf_database_inherits_xpl(self) -> None:
        assert issubclass(EXFDatabase, XplDatabase)

    def test_exf_tool_name(self) -> None:
        assert EXFDatabase._TOOL == "EmbedXPL"


# ------------------------------------------------------------------
# Workspace
# ------------------------------------------------------------------

class TestWorkspace:
    def test_workspace_creates_default(self, db: XplDatabase) -> None:
        db.workspace("default")
        ws = db.list_workspaces()
        assert any(w["name"] == "default" for w in ws)

    def test_workspace_returns_self(self, db: XplDatabase) -> None:
        result = db.workspace("pentest-lab")
        assert result is db

    def test_multiple_workspaces(self, db: XplDatabase) -> None:
        db.workspace("ws1")
        db.workspace("ws2")
        db.workspace("ws3")
        names = {w["name"] for w in db.list_workspaces()}
        assert names == {"ws1", "ws2", "ws3"}

    def test_workspace_idempotent(self, db: XplDatabase) -> None:
        db.workspace("repeated")
        db.workspace("repeated")
        count = sum(1 for w in db.list_workspaces() if w["name"] == "repeated")
        assert count == 1

    def test_auto_creates_default_workspace(self, db: XplDatabase) -> None:
        db.add_host("10.0.0.1")
        ws = db.list_workspaces()
        assert any(w["name"] == "default" for w in ws)


# ------------------------------------------------------------------
# Host / Service
# ------------------------------------------------------------------

class TestHostService:
    def test_add_host_returns_id(self, db: XplDatabase) -> None:
        db.workspace("test")
        hid = db.add_host("192.168.1.1", os="RouterOS")
        assert isinstance(hid, int)
        assert hid > 0

    def test_add_host_upsert(self, db: XplDatabase) -> None:
        db.workspace("test")
        id1 = db.add_host("192.168.1.1", os="RouterOS")
        id2 = db.add_host("192.168.1.1", hostname="router.local")
        assert id1 == id2
        hosts = db.hosts()
        assert len(hosts) == 1
        assert hosts[0]["os"] == "RouterOS"
        assert hosts[0]["hostname"] == "router.local"

    def test_hosts_listing(self, db: XplDatabase) -> None:
        db.workspace("test")
        db.add_host("10.0.0.1")
        db.add_host("10.0.0.2")
        db.add_host("10.0.0.3")
        hosts = db.hosts()
        assert len(hosts) == 3
        addrs = [h["address"] for h in hosts]
        assert "10.0.0.1" in addrs

    def test_hosts_include_counts(self, db: XplDatabase) -> None:
        db.workspace("test")
        db.add_host("10.0.0.1")
        db.add_service("10.0.0.1", 22, "tcp", "ssh")
        db.add_service("10.0.0.1", 80, "tcp", "http")
        hosts = db.hosts()
        assert hosts[0]["svc_count"] == 2

    def test_add_service_returns_id(self, db: XplDatabase) -> None:
        db.workspace("test")
        sid = db.add_service("10.0.0.1", 22, "tcp", "ssh", "OpenSSH 8.9")
        assert isinstance(sid, int)
        assert sid > 0

    def test_add_service_auto_creates_host(self, db: XplDatabase) -> None:
        db.workspace("test")
        db.add_service("10.0.0.99", 443, "tcp", "https")
        hosts = db.hosts()
        assert len(hosts) == 1
        assert hosts[0]["address"] == "10.0.0.99"

    def test_service_upsert(self, db: XplDatabase) -> None:
        db.workspace("test")
        db.add_service("10.0.0.1", 80, "tcp", "http")
        db.add_service("10.0.0.1", 80, "tcp", "", "nginx/1.24")
        hosts = db.hosts()
        assert hosts[0]["svc_count"] == 1


# ------------------------------------------------------------------
# Vulns
# ------------------------------------------------------------------

class TestVulns:
    def test_add_vuln_returns_id(self, db: XplDatabase) -> None:
        db.workspace("test")
        vid = db.add_vuln(
            "10.0.0.1",
            module_path="exploits.mikrotik.winbox",
            cve_ids=["CVE-2018-14847"],
            severity="critical",
            detail="Winbox auth bypass",
        )
        assert isinstance(vid, int)
        assert vid > 0

    def test_vulns_listing(self, db: XplDatabase) -> None:
        db.workspace("test")
        db.add_vuln("10.0.0.1", severity="critical")
        db.add_vuln("10.0.0.1", severity="high")
        db.add_vuln("10.0.0.2", severity="medium")
        all_vulns = db.vulns()
        assert len(all_vulns) == 3

    def test_vulns_filter_by_address(self, db: XplDatabase) -> None:
        db.workspace("test")
        db.add_vuln("10.0.0.1", severity="critical")
        db.add_vuln("10.0.0.2", severity="high")
        filtered = db.vulns("10.0.0.1")
        assert len(filtered) == 1
        assert filtered[0]["severity"] == "critical"

    def test_vuln_cve_ids_deserialized(self, db: XplDatabase) -> None:
        db.workspace("test")
        db.add_vuln("10.0.0.1", cve_ids=["CVE-2023-20198", "CVE-2024-3400"])
        vulns = db.vulns()
        assert vulns[0]["cve_ids"] == ["CVE-2023-20198", "CVE-2024-3400"]

    def test_vuln_auto_creates_host(self, db: XplDatabase) -> None:
        db.workspace("test")
        db.add_vuln("10.0.0.50")
        hosts = db.hosts()
        assert any(h["address"] == "10.0.0.50" for h in hosts)
        assert hosts[0]["vuln_count"] == 1


# ------------------------------------------------------------------
# Creds
# ------------------------------------------------------------------

class TestCreds:
    def test_add_cred_returns_id(self, db: XplDatabase) -> None:
        db.workspace("test")
        cid = db.add_cred("10.0.0.1", "admin", "admin", cred_type="telnet")
        assert isinstance(cid, int)

    def test_add_cred_with_port(self, db: XplDatabase) -> None:
        db.workspace("test")
        db.add_cred("10.0.0.1", "root", "toor", port=22, proto="tcp")
        creds = db.creds()
        assert len(creds) == 1
        assert creds[0]["service_id"] is not None

    def test_add_cred_without_port(self, db: XplDatabase) -> None:
        db.workspace("test")
        db.add_cred("10.0.0.1", "admin", "password123")
        creds = db.creds()
        assert len(creds) == 1
        assert creds[0]["service_id"] is None

    def test_creds_filter_by_address(self, db: XplDatabase) -> None:
        db.workspace("test")
        db.add_cred("10.0.0.1", "admin", "pass1")
        db.add_cred("10.0.0.2", "root", "pass2")
        filtered = db.creds("10.0.0.1")
        assert len(filtered) == 1
        assert filtered[0]["username"] == "admin"

    def test_cred_count_in_hosts(self, db: XplDatabase) -> None:
        db.workspace("test")
        db.add_cred("10.0.0.1", "admin", "admin")
        db.add_cred("10.0.0.1", "root", "root")
        hosts = db.hosts()
        assert hosts[0]["cred_count"] == 2


# ------------------------------------------------------------------
# Loot
# ------------------------------------------------------------------

class TestLoot:
    def test_add_loot_returns_id(self, db: XplDatabase) -> None:
        db.workspace("test")
        lid = db.add_loot("10.0.0.1", "config", "router config dump", "/tmp/cfg.txt")
        assert isinstance(lid, int)
        assert lid > 0

    def test_loot_listing(self, db: XplDatabase) -> None:
        db.workspace("test")
        db.add_loot("10.0.0.1", "config", "cfg1")
        db.add_loot("10.0.0.1", "firmware", "fw_data")
        items = db.loot()
        assert len(items) == 2
        types = {item["ltype"] for item in items}
        assert types == {"config", "firmware"}


# ------------------------------------------------------------------
# Run history
# ------------------------------------------------------------------

class TestRunHistory:
    def test_add_run_returns_id(self, db: XplDatabase) -> None:
        db.workspace("test")
        rid = db.add_run("10.0.0.1", "exploits.test", result="vulnerable")
        assert isinstance(rid, int)

    def test_runs_listing(self, db: XplDatabase) -> None:
        db.workspace("test")
        db.add_run("10.0.0.1", "mod.a", result="vulnerable")
        db.add_run("10.0.0.1", "mod.b", result="safe")
        db.add_run("10.0.0.2", "mod.a", result="error")
        runs = db.runs()
        assert len(runs) == 3

    def test_runs_filter_by_module(self, db: XplDatabase) -> None:
        db.workspace("test")
        db.add_run("10.0.0.1", "mod.a", result="vuln")
        db.add_run("10.0.0.1", "mod.b", result="safe")
        db.add_run("10.0.0.1", "mod.a", result="error")
        filtered = db.runs(module_path="mod.a")
        assert len(filtered) == 2
        assert all(r["module_path"] == "mod.a" for r in filtered)

    def test_runs_limit(self, db: XplDatabase) -> None:
        db.workspace("test")
        for i in range(10):
            db.add_run("10.0.0.1", f"mod.{i}", result="ok")
        limited = db.runs(limit=3)
        assert len(limited) == 3

    def test_run_detail_truncated(self, db: XplDatabase) -> None:
        db.workspace("test")
        long_detail = "x" * 1000
        db.add_run("10.0.0.1", "mod.long", detail=long_detail)
        runs = db.runs()
        assert len(runs[0]["detail"]) <= 500


# ------------------------------------------------------------------
# Module cache
# ------------------------------------------------------------------

class TestModuleCache:
    def test_cache_module(self, db: XplDatabase) -> None:
        db.cache_module(
            "exploits.routers.mikrotik.winbox",
            name="MikroTik Winbox Auth Bypass",
            description="CVE-2018-14847",
            cves=["CVE-2018-14847"],
            vendors=["mikrotik"],
            category="exploits",
        )
        modules = db.get_cached_modules()
        assert len(modules) == 1
        assert modules[0]["path"] == "exploits.routers.mikrotik.winbox"
        assert modules[0]["cves"] == ["CVE-2018-14847"]

    def test_cache_module_upsert(self, db: XplDatabase) -> None:
        db.cache_module("mod.a", name="First", category="exploits")
        db.cache_module("mod.a", name="Updated", category="exploits")
        modules = db.get_cached_modules()
        assert len(modules) == 1
        assert modules[0]["name"] == "Updated"

    def test_get_cached_modules_filter_category(self, db: XplDatabase) -> None:
        db.cache_module("mod.exploit", category="exploits")
        db.cache_module("mod.scanner", category="scanners")
        db.cache_module("mod.cred", category="creds")
        exploits = db.get_cached_modules(category="exploits")
        assert len(exploits) == 1
        assert exploits[0]["path"] == "mod.exploit"

    def test_module_cache_count(self, db: XplDatabase) -> None:
        assert db.module_cache_count() == 0
        db.cache_module("mod.a", category="exploits")
        db.cache_module("mod.b", category="scanners")
        assert db.module_cache_count() == 2

    def test_update_module_test_status(self, db: XplDatabase) -> None:
        db.cache_module("mod.a", name="Test Module")
        db.update_module_test_status("mod.a", tested=True, test_evidence="pytest OK")
        modules = db.get_cached_modules()
        assert modules[0]["tested"] == 1
        assert modules[0]["test_evidence"] == "pytest OK"

    def test_update_module_test_status_none(self, db: XplDatabase) -> None:
        db.cache_module("mod.b", name="Untested")
        db.update_module_test_status("mod.b", tested=None)
        modules = db.get_cached_modules()
        assert modules[0]["tested"] is None

    def test_cache_module_preserves_test_status_on_upsert(self, db: XplDatabase) -> None:
        db.cache_module("mod.a", name="v1", tested=True, test_evidence="pass")
        db.cache_module("mod.a", name="v2")
        modules = db.get_cached_modules()
        assert modules[0]["name"] == "v2"
        assert modules[0]["tested"] == 1


# ------------------------------------------------------------------
# Stats
# ------------------------------------------------------------------

class TestStats:
    def test_stats_empty(self, db: XplDatabase) -> None:
        db.workspace("test")
        s = db.stats(print_it=False)
        assert s["hosts"] == 0
        assert s["services"] == 0
        assert s["vulns"] == 0
        assert s["creds"] == 0
        assert s["loot"] == 0
        assert s["runs"] == 0
        assert "db_path" in s

    def test_stats_populated(self, db: XplDatabase) -> None:
        db.workspace("test")
        db.add_host("10.0.0.1")
        db.add_service("10.0.0.1", 22, "tcp", "ssh")
        db.add_vuln("10.0.0.1", severity="high")
        db.add_cred("10.0.0.1", "admin", "admin")
        db.add_loot("10.0.0.1", "config", "data")
        db.add_run("10.0.0.1", "mod.a")
        db.cache_module("mod.a")
        s = db.stats(print_it=False)
        assert s["hosts"] == 1
        assert s["services"] == 1
        assert s["vulns"] == 1
        assert s["creds"] == 1
        assert s["loot"] == 1
        assert s["runs"] == 1
        assert s["module_cache"] == 1

    def test_stats_print(self, db: XplDatabase, capsys: pytest.CaptureFixture[str]) -> None:
        db.workspace("test")
        db.stats(print_it=True)
        captured = capsys.readouterr()
        assert "XplDatabase" in captured.out or "DB" in captured.out


# ------------------------------------------------------------------
# Export XML
# ------------------------------------------------------------------

class TestExportXML:
    def test_export_xml_creates_file(self, db: XplDatabase, tmp_path: Path) -> None:
        db.workspace("test")
        db.add_host("10.0.0.1", os="RouterOS")
        db.add_service("10.0.0.1", 8291, "tcp", "winbox")
        db.add_vuln("10.0.0.1", cve_ids=["CVE-2018-14847"], severity="critical", detail="Auth bypass")
        db.add_cred("10.0.0.1", "admin", "admin", cred_type="winbox")

        xml_path = str(tmp_path / "report.xml")
        count = db.export_xml(xml_path)
        assert count == 1
        assert Path(xml_path).exists()

    def test_export_xml_structure(self, db: XplDatabase, tmp_path: Path) -> None:
        db.workspace("test")
        db.add_host("10.0.0.1")
        db.add_service("10.0.0.1", 22, "tcp", "ssh")
        db.add_vuln("10.0.0.1", severity="high", detail="RCE")
        db.add_cred("10.0.0.1", "root", "toor")

        xml_path = str(tmp_path / "report.xml")
        db.export_xml(xml_path)

        tree = ET.parse(xml_path)
        root = tree.getroot()
        assert root.tag == "XPLReport"
        hosts = root.findall("host")
        assert len(hosts) == 1
        assert hosts[0].get("address") == "10.0.0.1"
        assert len(hosts[0].findall("service")) == 1
        assert len(hosts[0].findall("vuln")) == 1
        assert len(hosts[0].findall("cred")) == 1

    def test_export_xml_empty_workspace(self, db: XplDatabase, tmp_path: Path) -> None:
        db.workspace("empty")
        xml_path = str(tmp_path / "empty.xml")
        count = db.export_xml(xml_path)
        assert count == 0
        assert Path(xml_path).exists()


# ------------------------------------------------------------------
# Context manager and close
# ------------------------------------------------------------------

class TestLifecycle:
    def test_context_manager(self, tmp_path: Path) -> None:
        db_path = tmp_path / "ctx.db"
        with XplDatabase(db_path=db_path) as db:
            db.workspace("test")
            db.add_host("10.0.0.1")
        assert db_path.exists()

    def test_close_is_safe(self, tmp_path: Path) -> None:
        db = XplDatabase(db_path=tmp_path / "close_test.db")
        db.workspace("test")
        db.add_host("10.0.0.1")
        db.close()

    def test_data_persists_after_reopen(self, tmp_path: Path) -> None:
        db_path = tmp_path / "persist.db"
        with XplDatabase(db_path=db_path) as db:
            db.workspace("myws")
            db.add_host("192.168.1.1", os="Linux")
        db2 = XplDatabase(db_path=db_path)
        db2.workspace("myws")
        hosts = db2.hosts()
        assert len(hosts) == 1
        assert hosts[0]["address"] == "192.168.1.1"
        db2.close()


# ------------------------------------------------------------------
# Migrations
# ------------------------------------------------------------------

class TestMigrations:
    def test_fresh_db_has_tested_column(self, db: XplDatabase) -> None:
        db.cache_module("mod.a", tested=True, test_evidence="ok")
        modules = db.get_cached_modules()
        assert modules[0]["tested"] == 1
        assert modules[0]["test_evidence"] == "ok"

    def test_migrations_idempotent(self, tmp_path: Path) -> None:
        db_path = tmp_path / "migrate.db"
        db1 = XplDatabase(db_path=db_path)
        db1.close()
        db2 = XplDatabase(db_path=db_path)
        db2.cache_module("test", tested=False)
        modules = db2.get_cached_modules()
        assert modules[0]["tested"] == 0
        db2.close()


# ------------------------------------------------------------------
# Workspace isolation
# ------------------------------------------------------------------

class TestWorkspaceIsolation:
    def test_hosts_scoped_to_workspace(self, db: XplDatabase) -> None:
        db.workspace("ws1")
        db.add_host("10.0.0.1")
        db.workspace("ws2")
        db.add_host("10.0.0.2")
        hosts_ws2 = db.hosts()
        assert len(hosts_ws2) == 1
        assert hosts_ws2[0]["address"] == "10.0.0.2"
        db.workspace("ws1")
        hosts_ws1 = db.hosts()
        assert len(hosts_ws1) == 1
        assert hosts_ws1[0]["address"] == "10.0.0.1"

    def test_runs_scoped_to_workspace(self, db: XplDatabase) -> None:
        db.workspace("ws1")
        db.add_run("10.0.0.1", "mod.a")
        db.workspace("ws2")
        db.add_run("10.0.0.2", "mod.b")
        runs_ws2 = db.runs()
        assert len(runs_ws2) == 1
        assert runs_ws2[0]["module_path"] == "mod.b"
