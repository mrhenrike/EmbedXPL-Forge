"""Tests for embedxpl.tools.search identifier normalization and query parsing."""
from __future__ import annotations

import pytest

from embedxpl.tools.search import _normalize_security_id


# ---------------------------------------------------------------------------
# _normalize_security_id
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("raw", "expected_id", "expected_type"), [
    ("cve-2024-4577", "CVE-2024-4577", "cve"),
    ("CVE-2024-4577", "CVE-2024-4577", "cve"),
    ("cve20244577", "CVE-2024-4577", "cve"),
    ("cve2024-4577", "CVE-2024-4577", "cve"),
    ("cve-20244577", "CVE-2024-4577", "cve"),
    ("CVE202612345", "CVE-2026-12345", "cve"),
    ("cve 2024 4577", "CVE-2024-4577", "cve"),
    ("nvd20244577", "CVE-2024-4577", "cve"),
    ("NVD-2024-4577", "CVE-2024-4577", "cve"),
    ("cwe79", "CWE-79", "cwe"),
    ("CWE-79", "CWE-79", "cwe"),
    ("cwe-79", "CWE-79", "cwe"),
    ("cwe787", "CWE-787", "cwe"),
    ("ms17010", "MS17-010", "ms"),
    ("MS17-010", "MS17-010", "ms"),
    ("ms-17-010", "MS17-010", "ms"),
    ("edb36913", "EDB-36913", "edb"),
    ("EDB-36913", "EDB-36913", "edb"),
    ("edb-36913", "EDB-36913", "edb"),
    ("ghsa-abcd-1234-wxyz", "ghsa-abcd-1234-wxyz", "ghsa"),
    ("GHSA-abcd-1234-wxyz", "ghsa-abcd-1234-wxyz", "ghsa"),
    ("dlink", "dlink", ""),
    ("router", "router", ""),
    ("2024", "2024", ""),
])
def test_normalize_security_id(raw: str, expected_id: str, expected_type: str) -> None:
    norm_id, id_type = _normalize_security_id(raw)
    assert norm_id == expected_id, f"Expected {expected_id!r}, got {norm_id!r}"
    assert id_type == expected_type, f"Expected type {expected_type!r}, got {id_type!r}"


def test_normalize_preserves_unknown_tokens() -> None:
    for token in ("exploit", "scanner", "huawei", "fortinet", "type:router"):
        norm, typ = _normalize_security_id(token)
        assert norm == token
        assert typ == ""
