"""OffsecCyber knowledge base — 60K+ offensive security Q&A records.

Dataset: PentesterFlow/OffsecCyber (HuggingFace)
Size: 123 MB, 60,517 records (train 54,484 / val 3,017 / test 3,016)
Format: JSONL with messages (role/content) + metadata (CVE IDs, CVSS, CWE, severity, class)
License: Apache 2.0
Content: CVE Q&A, HackerOne reports, PortSwigger labs, web appsec techniques

Usage:
    kb = OffsecCyberKB()
    kb.load()
    results = kb.search_cve("CVE-2026-98432")
    related = kb.search_text("MPTCP use-after-free")
    high_crit = kb.by_severity("critical")
"""
from __future__ import annotations

from typing import Any


class OffsecCyberKB:
    """
    Wrapper around the PentesterFlow/OffsecCyber dataset.
    Requires: pip install datasets
    """

    DATASET_ID = "PentesterFlow/OffsecCyber"
    _DATA_FILES = {
        "train": "train.jsonl",
        "validation": "valid.jsonl",
        "test": "test.jsonl",
    }

    def __init__(self) -> None:
        self._dataset: Any = None

    def load(self, split: str = "train", cache_dir: str | None = None) -> "OffsecCyberKB":
        try:
            from datasets import load_dataset  # type: ignore[import-untyped]
        except ImportError:
            raise ImportError("Install datasets: pip install datasets") from None

        self._dataset = load_dataset(
            self.DATASET_ID,
            data_files=self._DATA_FILES,
            split=split,
            cache_dir=cache_dir,
        )
        return self

    def _ensure_loaded(self) -> None:
        if self._dataset is None:
            raise RuntimeError("Call .load() first")

    def search_cve(self, cve_id: str) -> list[dict[str, Any]]:
        """Find all records mentioning a specific CVE ID in metadata or content."""
        self._ensure_loaded()
        cve_upper = cve_id.upper()
        results = []
        for record in self._dataset:  # type: ignore[union-attr]
            meta = record.get("metadata") or {}
            cve_list = meta.get("cve_ids") or []
            if cve_upper in [c.upper() for c in cve_list]:
                results.append(record)
                continue
            # Also check message content
            for msg in record.get("messages") or []:
                if cve_upper in (msg.get("content") or "").upper():
                    results.append(record)
                    break
        return results

    def search_text(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        """Full-text search across all message content."""
        self._ensure_loaded()
        q = query.lower()
        results = []
        for record in self._dataset:  # type: ignore[union-attr]
            for msg in record.get("messages") or []:
                if q in (msg.get("content") or "").lower():
                    results.append(record)
                    break
            if len(results) >= limit:
                break
        return results

    def by_severity(self, severity: str, limit: int = 50) -> list[dict[str, Any]]:
        """Filter by CVSS severity label: critical, high, medium, low."""
        self._ensure_loaded()
        sev = severity.lower()
        results = []
        for record in self._dataset:  # type: ignore[union-attr]
            meta = record.get("metadata") or {}
            if (meta.get("severity") or "").lower() == sev:
                results.append(record)
            if len(results) >= limit:
                break
        return results

    def by_class(self, vuln_class: str, limit: int = 50) -> list[dict[str, Any]]:
        """Filter by vulnerability class (e.g. 'sqli', 'rce', 'xss', 'ssrf')."""
        self._ensure_loaded()
        cls = vuln_class.lower()
        results = []
        for record in self._dataset:  # type: ignore[union-attr]
            meta = record.get("metadata") or {}
            if cls in (meta.get("class") or "").lower():
                results.append(record)
            if len(results) >= limit:
                break
        return results

    def get_answer(self, record: dict[str, Any]) -> str:
        """Extract the assistant's answer from a record's messages list."""
        for msg in reversed(record.get("messages") or []):
            if msg.get("role") == "assistant":
                return msg.get("content", "")
        return ""

    def get_question(self, record: dict[str, Any]) -> str:
        """Extract the user question from a record's messages list."""
        for msg in record.get("messages") or []:
            if msg.get("role") == "user":
                return msg.get("content", "")
        return ""
