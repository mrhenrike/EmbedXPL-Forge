"""Tests for embedxpl.core.apt_catalog."""
from __future__ import annotations

from embedxpl.core.apt_catalog import (
    APTAttack,
    APTGroup,
    find_groups_by_cve,
    find_groups_by_device,
    get_catalog,
    get_group,
    list_groups,
)


class TestAPTAttack:
    def test_init(self):
        a = APTAttack(name="test", description="desc")
        assert a.name == "test"
        assert a.description == "desc"
        assert a.cves == []
        assert a.modules == []

    def test_with_cves(self):
        a = APTAttack(name="t", description="d", cves=["CVE-2023-1234"])
        assert "CVE-2023-1234" in a.cves

    def test_mitre_techniques(self):
        a = APTAttack(name="t", description="d", mitre_techniques=["T1190"])
        assert "T1190" in a.mitre_techniques


class TestAPTGroup:
    def test_init(self):
        g = APTGroup(id="apt28", name="APT28", aliases=["Fancy Bear"],
                     country="Russia", description="Test")
        assert g.id == "apt28"
        assert "Fancy Bear" in g.aliases

    def test_default_lists(self):
        g = APTGroup(id="t", name="t", aliases=[], country="", description="")
        assert g.campaigns == []
        assert g.attacks == []
        assert g.references == []


class TestCatalog:
    def test_get_catalog_returns_dict(self):
        cat = get_catalog()
        assert isinstance(cat, dict)

    def test_catalog_not_empty(self):
        cat = get_catalog()
        assert len(cat) > 0

    def test_known_group_apt28(self):
        g = get_group("apt28")
        assert g is not None
        assert "APT28" in g.name or "apt28" in g.id

    def test_unknown_group_returns_none(self):
        g = get_group("nonexistent_group_xyz")
        assert g is None

    def test_list_groups(self):
        groups = list_groups()
        assert isinstance(groups, list)
        assert len(groups) > 0
        assert all(isinstance(g, APTGroup) for g in groups)

    def test_find_groups_by_device(self):
        results = find_groups_by_device("router")
        assert isinstance(results, list)

    def test_find_groups_by_cve_known(self):
        cat = get_catalog()
        all_cves = []
        for g in cat.values():
            for a in g.attacks:
                all_cves.extend(a.cves)
        if all_cves:
            results = find_groups_by_cve(all_cves[0])
            assert len(results) >= 1

    def test_find_groups_by_cve_unknown(self):
        results = find_groups_by_cve("CVE-9999-99999")
        assert results == []

    def test_all_groups_have_country(self):
        for g in list_groups():
            assert g.country, f"Group {g.id} missing country"

    def test_all_attacks_have_name(self):
        for g in list_groups():
            for a in g.attacks:
                assert a.name, f"Attack in group {g.id} missing name"
