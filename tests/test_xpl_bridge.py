"""Tests for embedxpl.core.xpl_bridge: xpl-core integration layer."""
from __future__ import annotations

from embedxpl.core.xpl_bridge import (
    _CATEGORY_MAP,
    _discover_modules,
    exploit_result_to_finding,
    get_config,
    register_all,
)


class TestModuleDiscovery:
    """Verify module discovery walks the expected directory structure."""

    def test_discovers_modules(self) -> None:
        modules = _discover_modules()
        assert len(modules) > 100, "Expected at least 100 modules"

    def test_module_tuples_have_three_elements(self) -> None:
        for entry in _discover_modules()[:20]:
            assert len(entry) == 3
            name, category, import_path = entry
            assert isinstance(name, str) and name
            assert isinstance(category, str) and category
            assert isinstance(import_path, str) and "." in import_path

    def test_categories_are_mapped(self) -> None:
        modules = _discover_modules()
        categories = {cat for _, cat, _ in modules}
        assert "exploit" in categories
        assert "scanner" in categories
        assert "credential" in categories

    def test_category_map_keys_match_dirs(self) -> None:
        for key in _CATEGORY_MAP:
            assert isinstance(key, str)
            assert isinstance(_CATEGORY_MAP[key], str)


class TestRegistration:
    """Verify modules register in xpl-core PluginRegistry."""

    def test_register_all_creates_registry(self) -> None:
        registry = register_all()
        assert registry.count > 100

    def test_register_returns_same_registry(self) -> None:
        from xpl_core.registry import PluginRegistry

        reg = PluginRegistry()
        result = register_all(reg)
        assert result is reg
        assert reg.count > 0

    def test_registered_modules_have_forge_tag(self) -> None:
        registry = register_all()
        for mod in registry.list_modules()[:10]:
            assert mod.forge == "embedxpl"

    def test_search_finds_known_module(self) -> None:
        registry = register_all()
        results = registry.search("rom0")
        assert len(results) >= 1


class TestFindingConversion:
    """Verify exploit results convert to xpl-core Finding schema."""

    def test_basic_finding(self) -> None:
        finding = exploit_result_to_finding(
            module_path="embedxpl.modules.exploits.routers.dlink.rom0",
            target_host="192.168.1.1",
            target_port=80,
            title="D-Link ROM-0 Config Leak",
            severity="high",
        )
        assert finding.forge == "embedxpl"
        assert finding.target is not None
        assert finding.target.host == "192.168.1.1"
        assert finding.target.port == 80
        assert finding.severity == "high"

    def test_finding_with_cves(self) -> None:
        finding = exploit_result_to_finding(
            module_path="test.module",
            target_host="10.0.0.1",
            cves=["CVE-2024-1234", "CVE-2024-5678"],
        )
        assert len(finding.cve) == 2
        assert "CVE-2024-1234" in finding.cve

    def test_finding_with_mitre(self) -> None:
        finding = exploit_result_to_finding(
            module_path="test.module",
            target_host="10.0.0.1",
            mitre_techniques=["T1190", "T1059"],
        )
        assert "attack" in finding.mitre
        assert "T1190" in finding.mitre["attack"]

    def test_finding_with_evidence(self) -> None:
        finding = exploit_result_to_finding(
            module_path="test.module",
            target_host="10.0.0.1",
            evidence_text="HTTP 200 OK: admin panel exposed",
        )
        assert len(finding.evidence) == 1
        assert "admin panel" in finding.evidence[0].data

    def test_finding_to_dict(self) -> None:
        finding = exploit_result_to_finding(
            module_path="test.module",
            target_host="10.0.0.1",
            target_port=443,
            title="Test Finding",
        )
        d = finding.to_dict()
        assert isinstance(d, dict)
        assert d["forge"] == "embedxpl"
        assert d["module"] == "test.module"

    def test_finding_has_uuid_and_timestamp(self) -> None:
        finding = exploit_result_to_finding(
            module_path="test.module",
            target_host="10.0.0.1",
        )
        assert len(finding.id) == 36
        assert "T" in finding.timestamp


class TestForgeConfig:
    """Verify ForgeConfig wrapper works."""

    def test_config_creation(self, tmp_path) -> None:
        config = get_config(config_dir=tmp_path)
        assert config is not None

    def test_config_defaults(self, tmp_path) -> None:
        config = get_config(config_dir=tmp_path)
        assert config.get("forge_version") == "7.0.0-dev"
        assert config.get("default_timeout") == 30
        assert config.get("finding_schema") == "xpl-core/v1"
