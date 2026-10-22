"""Tests for embedxpl.core.cve.cve_db: CVE catalog, lookup and enrichment."""
from __future__ import annotations

import pytest

from embedxpl.core.cve.cve_db import (
    CVEDatabase,
    CVEEntry,
    _entry_from_mapping,
    _normalize,
    _version_in_range,
)

# -------------------------------------------------------------------
# CVEEntry dataclass
# -------------------------------------------------------------------

class TestCVEEntryProperties:
    def test_is_remote_for_remote_vector(self):
        e = CVEEntry(cve_id="CVE-2024-0001", vendor="test", product="x", access_vector="REMOTE")
        assert e.is_remote is True

    def test_is_remote_for_network_vector(self):
        e = CVEEntry(cve_id="CVE-2024-0002", vendor="test", product="x", access_vector="NETWORK")
        assert e.is_remote is True

    @pytest.mark.parametrize("vector", ["LOCAL", "PHYSICAL", "ADJACENT"])
    def test_is_remote_false_for_non_remote(self, vector: str):
        e = CVEEntry(cve_id="CVE-2024-0003", vendor="test", product="x", access_vector=vector)
        assert e.is_remote is False

    def test_is_exploitable_by_exf_true(self):
        e = CVEEntry(
            cve_id="CVE-2024-0004", vendor="test", product="x",
            access_vector="REMOTE", exf_module="exploits/routers/test.py",
        )
        assert e.is_exploitable_by_exf is True

    def test_is_exploitable_by_exf_false_no_module(self):
        e = CVEEntry(cve_id="CVE-2024-0005", vendor="test", product="x", access_vector="REMOTE")
        assert e.is_exploitable_by_exf is False

    def test_is_exploitable_by_exf_false_local(self):
        e = CVEEntry(
            cve_id="CVE-2024-0006", vendor="test", product="x",
            access_vector="LOCAL", exf_module="exploits/test.py",
        )
        assert e.is_exploitable_by_exf is False

    def test_status_label_exploitable(self):
        e = CVEEntry(
            cve_id="CVE-2024-0007", vendor="test", product="x",
            access_vector="REMOTE", exf_module="exploits/test.py",
        )
        assert "EXPLOITABLE" in e.status_label

    def test_status_label_remote_no_module(self):
        e = CVEEntry(cve_id="CVE-2024-0008", vendor="test", product="x", access_vector="REMOTE")
        assert "REMOTE" in e.status_label
        assert "no exf module" in e.status_label

    def test_status_label_local(self):
        e = CVEEntry(cve_id="CVE-2024-0009", vendor="test", product="x", access_vector="LOCAL")
        assert "LOCAL" in e.status_label

    def test_status_label_physical(self):
        e = CVEEntry(cve_id="CVE-2024-0010", vendor="test", product="x", access_vector="PHYSICAL")
        assert "PHYSICAL" in e.status_label

    def test_defaults(self):
        e = CVEEntry(cve_id="CVE-2024-1111", vendor="v", product="p")
        assert e.affected_versions == ""
        assert e.description == ""
        assert e.cvss_score == 0.0
        assert e.access_vector == "REMOTE"
        assert e.exploit_available is False
        assert e.exf_module == ""
        assert e.references == []


# -------------------------------------------------------------------
# Normalization helpers
# -------------------------------------------------------------------

class TestNormalize:
    @pytest.mark.parametrize(("raw", "expected"), [
        ("TP-Link", "tplink"),
        ("D-Link DIR-655", "dlinkdir655"),
        ("MikroTik RouterOS 6.42", "mikrotikrouteros642"),
        ("NETGEAR", "netgear"),
        ("", ""),
        ("Cisco IOS XE 17.3", "ciscoiosxe173"),
    ])
    def test_normalize(self, raw: str, expected: str):
        assert _normalize(raw) == expected


class TestVersionInRange:
    def test_empty_affected_matches(self):
        assert _version_in_range("6.42.7", "") is True

    def test_empty_actual_matches(self):
        assert _version_in_range("", "R6400, R7000") is True

    def test_both_empty_matches(self):
        assert _version_in_range("", "") is True

    def test_substring_match(self):
        assert _version_in_range("R7000", "R6400, R7000, R8000") is True

    def test_no_match(self):
        assert _version_in_range("R9999", "R6400, R7000") is False

    def test_partial_model_match(self):
        # The separator split uses `,;/|` so "DGN2200v1-v4" is one token.
        # Normalized: "dgn2200v1v4" does not contain "dgn2200v4" as substring.
        assert _version_in_range("DGN2200v4", "DGN2200v1-v4") is False
        # But an exact token match works:
        assert _version_in_range("DGN2200v4", "DGN2200v1,DGN2200v4") is True

    def test_version_string_match(self):
        assert _version_in_range("Archer C9 v1", "Archer C9 v1") is True


# -------------------------------------------------------------------
# _entry_from_mapping
# -------------------------------------------------------------------

class TestEntryFromMapping:
    def test_minimal_mapping(self):
        raw = {"cve_id": "CVE-2024-9999", "vendor": "acme", "product": "widget"}
        entry = _entry_from_mapping(raw)
        assert entry.cve_id == "CVE-2024-9999"
        assert entry.vendor == "acme"
        assert entry.product == "widget"
        assert entry.access_vector == "REMOTE"
        assert entry.cvss_score == 0.0

    def test_full_mapping(self):
        raw = {
            "cve_id": "CVE-2023-1234",
            "vendor": "cisco",
            "product": "rv320",
            "affected_versions": "RV320, RV325",
            "description": "Command injection",
            "cvss_score": 7.2,
            "access_vector": "LOCAL",
            "exploit_available": True,
            "references": ["https://example.com/advisory"],
        }
        entry = _entry_from_mapping(raw)
        assert entry.cve_id == "CVE-2023-1234"
        assert entry.cvss_score == 7.2
        assert entry.access_vector == "LOCAL"
        assert entry.exploit_available is True
        assert len(entry.references) == 1

    def test_roundtrip_preserves_data(self):
        raw = {
            "cve_id": "CVE-2020-5555",
            "vendor": "netgear",
            "product": "r7000",
            "affected_versions": "R7000",
            "description": "test vuln",
            "cvss_score": 9.8,
            "access_vector": "REMOTE",
        }
        entry = _entry_from_mapping(raw)
        assert entry.cve_id == raw["cve_id"]
        assert entry.vendor == raw["vendor"]
        assert entry.cvss_score == raw["cvss_score"]


# -------------------------------------------------------------------
# CVEDatabase
# -------------------------------------------------------------------

@pytest.fixture(scope="module")
def db() -> CVEDatabase:
    return CVEDatabase(modules_root=None)


class TestCVEDatabaseCounts:
    def test_total_positive(self, db: CVEDatabase):
        assert db.total > 0

    def test_remote_count_positive(self, db: CVEDatabase):
        assert db.remote_count > 0

    def test_remote_less_or_equal_total(self, db: CVEDatabase):
        assert db.remote_count <= db.total

    def test_exploitable_less_or_equal_remote(self, db: CVEDatabase):
        assert db.exploitable_count <= db.remote_count


class TestCVEDatabaseLookup:
    def test_lookup_netgear(self, db: CVEDatabase):
        results = db.lookup(vendor="netgear")
        assert len(results) >= 4
        # Results include vendor-specific entries plus "multi"/"generic" wildcards
        for r in results:
            v = _normalize(r.vendor)
            assert v in ("netgear", "multi", "generic") or "netgear" in v

    def test_lookup_cisco_remote_only(self, db: CVEDatabase):
        results = db.lookup(vendor="cisco", remote_only=True)
        assert len(results) >= 1
        assert all(r.is_remote for r in results)
        local_ids = {r.cve_id for r in db.lookup(vendor="cisco")} - {r.cve_id for r in results}
        if local_ids:
            for cid in local_ids:
                entry = next(e for e in db._entries if e.cve_id == cid)
                assert not entry.is_remote

    def test_lookup_tplink_archer_c9(self, db: CVEDatabase):
        results = db.lookup(vendor="tplink", product="archer_c9")
        assert len(results) >= 1
        assert any(r.cve_id == "CVE-2017-11519" for r in results)

    def test_lookup_by_banner_mikrotik(self, db: CVEDatabase):
        results = db.lookup_by_banner("MikroTik RouterOS 6.40")
        assert len(results) >= 1
        assert any("mikrotik" in _normalize(r.vendor) for r in results)

    def test_lookup_no_filters_returns_all(self, db: CVEDatabase):
        results = db.lookup()
        assert len(results) == db.total

    def test_lookup_unknown_vendor_still_returns_multi_generic(self, db: CVEDatabase):
        # vendor "multi"/"generic" entries match any vendor query by design
        results = db.lookup(vendor="nonexistent_vendor_xyz")
        for r in results:
            assert _normalize(r.vendor) in ("multi", "generic")

    def test_lookup_sorted_by_cvss_desc(self, db: CVEDatabase):
        results = db.lookup(vendor="cisco")
        if len(results) >= 2:
            scores = [r.cvss_score for r in results]
            assert scores == sorted(scores, reverse=True)

    def test_lookup_with_version_filter(self, db: CVEDatabase):
        results = db.lookup(vendor="netgear", product="dgn2200", version="DGN2200v4")
        assert len(results) >= 1

    def test_lookup_version_mismatch_filters_known_entries(self, db: CVEDatabase):
        # Module-scanned entries may have empty affected_versions (always match).
        # Among embedded entries with version data, mismatches are filtered.
        all_tplink_c9 = db.lookup(vendor="tplink", product="archer_c9")
        filtered = db.lookup(vendor="tplink", product="archer_c9", version="Archer C5 v99")
        # Filtered set should be <= all (version filter only reduces)
        assert len(filtered) <= len(all_tplink_c9)

    def test_lookup_dlink(self, db: CVEDatabase):
        results = db.lookup(vendor="dlink")
        assert len(results) >= 3

    def test_lookup_fortinet(self, db: CVEDatabase):
        results = db.lookup(vendor="fortinet")
        assert len(results) >= 3
        known_ids = {"CVE-2022-40684", "CVE-2023-27997", "CVE-2024-21762"}
        found_ids = {r.cve_id for r in results}
        assert known_ids.issubset(found_ids)

    def test_lookup_paloalto(self, db: CVEDatabase):
        results = db.lookup(vendor="paloalto")
        assert len(results) >= 1
        assert any(r.cve_id == "CVE-2024-3400" for r in results)


class TestCVEDatabaseSummary:
    def test_summary_keys(self, db: CVEDatabase):
        s = db.summary()
        assert "total_cves" in s
        assert "remote" in s
        assert "exploitable_by_exf" in s
        assert "access_vectors" in s
        assert "vendors_covered" in s

    def test_summary_values_positive(self, db: CVEDatabase):
        s = db.summary()
        assert s["total_cves"] > 0
        assert s["remote"] > 0
        assert s["vendors_covered"] > 0

    def test_summary_vectors_dict(self, db: CVEDatabase):
        vectors = db.summary()["access_vectors"]
        assert isinstance(vectors, dict)
        assert "REMOTE" in vectors
        assert vectors["REMOTE"] > 0

    def test_summary_total_matches_count(self, db: CVEDatabase):
        s = db.summary()
        assert s["total_cves"] == db.total


# -------------------------------------------------------------------
# Edge cases
# -------------------------------------------------------------------

class TestEdgeCases:
    def test_multi_vendor_entries_match_broadly(self, db: CVEDatabase):
        results = db.lookup(vendor="anything")
        multi = [r for r in results if r.vendor in ("multi", "generic")]
        assert len(multi) >= 1

    def test_adjacent_vector_not_remote(self, db: CVEDatabase):
        results = db.lookup(vendor="asus")
        adjacent = [r for r in results if r.access_vector == "ADJACENT"]
        assert len(adjacent) >= 1
        for r in adjacent:
            assert r.is_remote is False

    def test_physical_vector_entry_exists(self, db: CVEDatabase):
        all_entries = db.lookup()
        physical = [r for r in all_entries if r.access_vector == "PHYSICAL"]
        assert len(physical) >= 1

    def test_csv_integrated_vendors_present(self, db: CVEDatabase):
        for vendor, min_count in [("tp-link", 14), ("synology", 6), ("tenda", 3)]:
            results = db.lookup(vendor=vendor)
            assert len(results) >= min_count, f"{vendor}: expected >= {min_count}, got {len(results)}"

    def test_total_exceeds_baseline(self, db: CVEDatabase):
        assert db.total >= 600
