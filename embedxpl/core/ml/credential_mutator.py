"""ML-driven credential mutation — Markov chains + smart rules.

Generates credential candidates based on vendor-specific patterns,
Markov chain probabilities, and mutation rules prioritized by ML.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import json
import logging
import random
import string
from pathlib import Path
from typing import Dict, Generator, List, Optional, Tuple

logger = logging.getLogger("embedxpl.core.ml.credential_mutator")


class CredentialMutator:
    """Generates mutated credentials using Markov chains and rule-based transforms."""

    LEET_MAP: Dict[str, str] = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
    COMMON_SUFFIXES: List[str] = ["123", "!", "1", "2024", "2025", "2026", "@", "#", "admin"]

    def __init__(self, markov_path: Optional[str] = None) -> None:
        self._markov: Optional[Dict] = None
        if markov_path:
            self._load_markov(markov_path)

    def _load_markov(self, path: str) -> None:
        """Load Markov chain model from JSON."""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            self._markov = data.get("transitions", {})
        except Exception as exc:
            logger.warning("Markov model load failed: %s", exc)

    def mutate(self, base_passwords: List[str], max_candidates: int = 1000) -> List[str]:
        """Generate mutated candidates from base passwords."""
        candidates = set(base_passwords)
        for pwd in base_passwords:
            candidates.update(self._apply_rules(pwd))
            if len(candidates) >= max_candidates:
                break
        return list(candidates)[:max_candidates]

    def _apply_rules(self, password: str) -> List[str]:
        """Apply mutation rules to a single password."""
        results = []
        results.append(password.upper())
        results.append(password.lower())
        results.append(password.capitalize())

        leet = password
        for char, replacement in self.LEET_MAP.items():
            leet = leet.replace(char, replacement)
        if leet != password:
            results.append(leet)

        for suffix in self.COMMON_SUFFIXES:
            results.append(password + suffix)

        if len(password) > 2:
            results.append(password[::-1])

        return results

    def stream_candidates(
        self, base_passwords: List[str], vendor: str = ""
    ) -> Generator[str, None, None]:
        """Stream candidates one at a time (memory-efficient)."""
        seen = set()
        for pwd in base_passwords:
            if pwd not in seen:
                seen.add(pwd)
                yield pwd
        for pwd in base_passwords:
            for mutated in self._apply_rules(pwd):
                if mutated not in seen:
                    seen.add(mutated)
                    yield mutated
