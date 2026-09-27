"""Banner fingerprint matching via GPU-accelerated cosine similarity.

Matches HTTP Server headers, SSH banners, SNMP sysDescr strings against
a corpus of known device signatures. Uses ComputeBackend from A3 for
GPU-accelerated batch matching when available.

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from embedxpl.core.gpu.backend import ComputeBackend, auto_select_backend

logger = logging.getLogger(__name__)


@dataclass
class FingerprintMatch:
    """Result of matching a banner against known signatures."""
    vendor: str
    model: str = ""
    firmware: str = ""
    confidence: float = 0.0
    matched_banner: str = ""
    source: str = ""  # "corpus", "regex", "oui"


_KNOWN_SIGNATURES: List[Dict[str, str]] = [
    {"banner": "micro_httpd", "vendor": "dlink", "model": "DIR-*", "source": "http_server"},
    {"banner": "GoAhead-Webs", "vendor": "multi", "model": "GoAhead-based", "source": "http_server"},
    {"banner": "GoAhead-http", "vendor": "multi", "model": "GoAhead-based", "source": "http_server"},
    {"banner": "mini_httpd", "vendor": "multi", "model": "mini_httpd-based", "source": "http_server"},
    {"banner": "boa", "vendor": "multi", "model": "Boa-based", "source": "http_server"},
    {"banner": "lighttpd", "vendor": "multi", "model": "lighttpd-based", "source": "http_server"},
    {"banner": "RomPager", "vendor": "multi", "model": "Allegro-RomPager", "source": "http_server"},
    {"banner": "ASUS RT-", "vendor": "asus", "model": "RT-*", "source": "http_title"},
    {"banner": "Archer", "vendor": "tplink", "model": "Archer", "source": "http_title"},
    {"banner": "TP-LINK", "vendor": "tplink", "model": "", "source": "http_title"},
    {"banner": "TP-Link", "vendor": "tplink", "model": "", "source": "http_title"},
    {"banner": "NETGEAR", "vendor": "netgear", "model": "", "source": "http_title"},
    {"banner": "Linksys", "vendor": "linksys", "model": "", "source": "http_title"},
    {"banner": "D-Link", "vendor": "dlink", "model": "", "source": "http_title"},
    {"banner": "DIR-", "vendor": "dlink", "model": "DIR-*", "source": "http_title"},
    {"banner": "DSL-", "vendor": "dlink", "model": "DSL-*", "source": "http_title"},
    {"banner": "Huawei", "vendor": "huawei", "model": "", "source": "http_title"},
    {"banner": "HG8245", "vendor": "huawei", "model": "HG8245", "source": "http_title"},
    {"banner": "ZTE", "vendor": "zte", "model": "", "source": "http_title"},
    {"banner": "MikroTik", "vendor": "mikrotik", "model": "RouterOS", "source": "http_title"},
    {"banner": "RouterOS", "vendor": "mikrotik", "model": "RouterOS", "source": "http_title"},
    {"banner": "Cisco", "vendor": "cisco", "model": "", "source": "http_title"},
    {"banner": "CISCO", "vendor": "cisco", "model": "", "source": "http_title"},
    {"banner": "Ubiquiti", "vendor": "ubiquiti", "model": "", "source": "http_title"},
    {"banner": "UniFi", "vendor": "ubiquiti", "model": "UniFi", "source": "http_title"},
    {"banner": "AirOS", "vendor": "ubiquiti", "model": "AirOS", "source": "http_title"},
    {"banner": "Fortinet", "vendor": "fortinet", "model": "", "source": "http_title"},
    {"banner": "FortiGate", "vendor": "fortinet", "model": "FortiGate", "source": "http_title"},
    {"banner": "OpenWrt", "vendor": "openwrt", "model": "OpenWrt", "source": "http_title"},
    {"banner": "LuCI", "vendor": "openwrt", "model": "OpenWrt", "source": "http_title"},
    {"banner": "DD-WRT", "vendor": "ddwrt", "model": "DD-WRT", "source": "http_title"},
    {"banner": "Tomato", "vendor": "tomato", "model": "Tomato", "source": "http_title"},
    {"banner": "Tenda", "vendor": "tenda", "model": "", "source": "http_title"},
    {"banner": "Comtrend", "vendor": "comtrend", "model": "", "source": "http_title"},
    {"banner": "dropbear", "vendor": "multi", "model": "Dropbear-based", "source": "ssh"},
    {"banner": "OpenSSH", "vendor": "multi", "model": "", "source": "ssh"},
    {"banner": "Cisco SSH", "vendor": "cisco", "model": "", "source": "ssh"},
    {"banner": "HUAWEI", "vendor": "huawei", "model": "", "source": "snmp"},
    {"banner": "Cisco IOS", "vendor": "cisco", "model": "IOS", "source": "snmp"},
    {"banner": "RouterOS", "vendor": "mikrotik", "model": "RouterOS", "source": "snmp"},
    {"banner": "Linux", "vendor": "multi", "model": "Linux-based", "source": "snmp"},
    {"banner": "Juniper", "vendor": "juniper", "model": "", "source": "snmp"},
    {"banner": "Junos", "vendor": "juniper", "model": "Junos", "source": "snmp"},
]

_VENDOR_REGEX: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"D-?Link\s+(DIR|DSL|DAP|DWR)-?(\w+)", re.IGNORECASE), "dlink", r"\1-\2"),
    (re.compile(r"TP-?Link\s+(Archer|TL-|Deco)\s*(\w+)", re.IGNORECASE), "tplink", r"\1 \2"),
    (re.compile(r"NETGEAR\s+(R|RAX|RBK|WAC|WNR|DGN)(\w+)", re.IGNORECASE), "netgear", r"\1\2"),
    (re.compile(r"ASUS\s*(RT-\w+)", re.IGNORECASE), "asus", r"\1"),
    (re.compile(r"Linksys\s+(EA|WRT|E\d)\w*", re.IGNORECASE), "linksys", r"\1"),
    (re.compile(r"Huawei\s+(HG\d+\w*|EchoLife\s*\w+)", re.IGNORECASE), "huawei", r"\1"),
    (re.compile(r"ZTE\s+(ZXV10|ZXHN|F\d+\w*)", re.IGNORECASE), "zte", r"\1"),
    (re.compile(r"MikroTik\s+(RouterOS|hAP|RB\d+)", re.IGNORECASE), "mikrotik", r"\1"),
    (re.compile(r"Cisco\s+(RV\d+|ASA|ISR|ISE|IOS\s+\S+)", re.IGNORECASE), "cisco", r"\1"),
    (re.compile(r"FortiGate-?(\d+\w*)", re.IGNORECASE), "fortinet", r"FortiGate-\1"),
    (re.compile(r"Ubiquiti\s+(UniFi|EdgeRouter|AirMax)", re.IGNORECASE), "ubiquiti", r"\1"),
    (re.compile(r"Tenda\s+(AC\d+|F\d+|W\d+)", re.IGNORECASE), "tenda", r"\1"),
    (re.compile(r"Comtrend\s+(VR-?\d+|CT-?\d+)", re.IGNORECASE), "comtrend", r"\1"),
]


class BannerFingerprinter:
    """Matches device banners against known signatures.

    Supports three matching strategies:
    1. Regex-based vendor/model extraction (fastest, highest confidence)
    2. Substring matching against known signature corpus
    3. GPU-accelerated cosine similarity for fuzzy matching (optional)
    """

    def __init__(self, backend: Optional[ComputeBackend] = None) -> None:
        self._backend = backend or auto_select_backend(compute_mode="auto")
        self._corpus = _KNOWN_SIGNATURES.copy()
        self._corpus_vectors: Optional[np.ndarray] = None

    @property
    def corpus_size(self) -> int:
        """Number of known signatures in the corpus."""
        return len(self._corpus)

    def add_signature(self, banner: str, vendor: str, model: str = "", source: str = "custom") -> None:
        """Add a custom signature to the corpus."""
        self._corpus.append({
            "banner": banner, "vendor": vendor, "model": model, "source": source,
        })
        self._corpus_vectors = None  # invalidate cache

    def match(self, banner: str, source: str = "auto") -> List[FingerprintMatch]:
        """Match a banner string against known signatures.

        Args:
            banner: Raw banner string (HTTP Server header, SSH banner, etc.).
            source: Banner source type: http_server, http_title, ssh, snmp, auto.

        Returns:
            List of FingerprintMatch sorted by confidence (highest first).
        """
        if not banner or not banner.strip():
            return []

        matches: List[FingerprintMatch] = []

        # Strategy 1: Regex extraction (highest confidence)
        regex_matches = self._match_regex(banner)
        matches.extend(regex_matches)

        # Strategy 2: Substring against corpus
        corpus_matches = self._match_corpus(banner, source)
        matches.extend(corpus_matches)

        # Deduplicate by vendor, keep highest confidence
        seen: Dict[str, FingerprintMatch] = {}
        for m in matches:
            key = "{}:{}".format(m.vendor, m.model)
            if key not in seen or m.confidence > seen[key].confidence:
                seen[key] = m

        result = sorted(seen.values(), key=lambda x: x.confidence, reverse=True)
        return result

    def match_batch(self, banners: List[str], source: str = "auto") -> List[List[FingerprintMatch]]:
        """Match multiple banners in batch.

        Args:
            banners: List of banner strings.
            source: Banner source type.

        Returns:
            List of match results per banner.
        """
        return [self.match(b, source) for b in banners]

    def match_cosine(self, banners: List[str], top_k: int = 5) -> List[List[FingerprintMatch]]:
        """GPU-accelerated fuzzy matching using character n-gram cosine similarity.

        Args:
            banners: List of banner strings to match.
            top_k: Number of top matches per banner.

        Returns:
            List of match results per banner.
        """
        if not banners:
            return []

        corpus_texts = [sig["banner"] for sig in self._corpus]
        all_texts = banners + corpus_texts

        # Character n-gram vectorization (lightweight, no external vocab)
        vectors = self._char_ngram_vectorize(all_texts, n=3)
        query_vecs = vectors[:len(banners)]
        corpus_vecs = vectors[len(banners):]

        # Cosine similarity via GPU backend
        sim_matrix = self._backend.cosine_similarity_batch(query_vecs, corpus_vecs)

        results: List[List[FingerprintMatch]] = []
        for i, banner in enumerate(banners):
            scores = sim_matrix[i]
            top_indices = np.argsort(scores)[::-1][:top_k]
            matches: List[FingerprintMatch] = []
            for idx in top_indices:
                if scores[idx] < 0.1:
                    continue
                sig = self._corpus[idx]
                matches.append(FingerprintMatch(
                    vendor=sig["vendor"],
                    model=sig.get("model", ""),
                    confidence=float(scores[idx]),
                    matched_banner=sig["banner"],
                    source="cosine_{}".format(sig.get("source", "unknown")),
                ))
            results.append(matches)

        return results

    def _match_regex(self, banner: str) -> List[FingerprintMatch]:
        """Extract vendor/model using regex patterns."""
        matches: List[FingerprintMatch] = []
        for pattern, vendor, model_group in _VENDOR_REGEX:
            m = pattern.search(banner)
            if m:
                try:
                    model = m.expand(model_group)
                except (IndexError, re.error):
                    model = ""
                matches.append(FingerprintMatch(
                    vendor=vendor,
                    model=model,
                    confidence=0.9,
                    matched_banner=m.group(0),
                    source="regex",
                ))
        return matches

    def _match_corpus(self, banner: str, source: str) -> List[FingerprintMatch]:
        """Substring matching against the signature corpus."""
        matches: List[FingerprintMatch] = []
        banner_lower = banner.lower()

        for sig in self._corpus:
            if source != "auto" and sig.get("source", "") != source:
                continue
            if sig["banner"].lower() in banner_lower:
                conf = min(0.85, 0.5 + len(sig["banner"]) / 50.0)
                matches.append(FingerprintMatch(
                    vendor=sig["vendor"],
                    model=sig.get("model", ""),
                    confidence=conf,
                    matched_banner=sig["banner"],
                    source="corpus_{}".format(sig.get("source", "")),
                ))

        return matches

    @staticmethod
    def _char_ngram_vectorize(texts: List[str], n: int = 3) -> np.ndarray:
        """Simple character n-gram TF vectorization (no external deps)."""
        vocab: Dict[str, int] = {}
        doc_ngrams: List[Dict[int, float]] = []

        for text in texts:
            text_lower = text.lower()
            ngrams: Dict[int, float] = {}
            for i in range(len(text_lower) - n + 1):
                gram = text_lower[i:i + n]
                if gram not in vocab:
                    vocab[gram] = len(vocab)
                idx = vocab[gram]
                ngrams[idx] = ngrams.get(idx, 0) + 1.0
            doc_ngrams.append(ngrams)

        dim = len(vocab)
        if dim == 0:
            return np.zeros((len(texts), 1), dtype=np.float32)

        matrix = np.zeros((len(texts), dim), dtype=np.float32)
        for i, ngrams in enumerate(doc_ngrams):
            for idx, count in ngrams.items():
                matrix[i, idx] = count

        # L2 normalize rows
        norms = np.linalg.norm(matrix, axis=1, keepdims=True) + 1e-10
        matrix = matrix / norms

        return matrix
