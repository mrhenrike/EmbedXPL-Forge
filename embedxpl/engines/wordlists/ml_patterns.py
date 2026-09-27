"""
ml_patterns.py - Statistical pattern model for corporate username/password generation.

Learns structural patterns from:
  - Corporate AD exports (CSV): extracts pattern types ONLY - zero raw data stored
  - Existing wordlists (SecLists, BR-specific): password/username structure analysis
  - Username lists: frequency and shape distributions

Privacy guarantees:
  - Only statistical features are extracted during training
  - No actual usernames, passwords, company names, or personal data are stored
  - Model file contains ONLY pattern IDs, weights, length distributions,
    and abstract transition tables
  - Raw training data never appears in any output

The model is a statistical classifier / ranker, NOT a memorizer.
When generating candidates, it ranks existing rule-based patterns
by learned probability - it does NOT reproduce training samples.

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import csv
import json
import logging
import math
import os
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Model storage defaults ─────────────────────────────────────────────────────
DEFAULT_MODEL_DIR  = Path(__file__).parent.parent / ".model"
DEFAULT_MODEL_FILE = DEFAULT_MODEL_DIR / "pattern_model.json"

MODEL_VERSION = "1.0"

# ── Domain sector classification ───────────────────────────────────────────────
# Maps TLD/domain suffix patterns → sector label (no company names stored)
SECTOR_RULES: list[tuple[str, str]] = [
    (r"\.jus\.br$",               "judicial"),
    (r"\.mp\.br$",                "ministerio_publico"),
    (r"\.gov\.br$",               "governo"),
    (r"\.leg\.br$",               "legislativo"),
    (r"\.mil\.br$",               "militar"),
    (r"energia|utilities|power|hydro|electric", "energia_utilities"),
    (r"saude|hospital|clinica|med|health|pharma", "saude"),
    (r"banco|card|financ|credit|invest|segur", "financas"),
    (r"industria|comercio|servicos|cooperativa|associacao", "industria_servicos"),
    (r"educacao|edu\.br|universidade|faculdade", "educacao"),
    (r"\.org\.br$|\.org$",        "ong_institucional"),
    (r"\.local$",                  "ad_local"),
    (r"onmicrosoft\.com$",         "cloud_m365"),
    (r"gmail|yahoo|hotmail|outlook|live\.com", "webmail_pessoal"),
]


def classify_domain_sector(domain: str) -> str:
    """
    Classify a domain into a sector label without storing the domain name.

    Args:
        domain: Domain string (e.g., 'acme.example').

    Returns:
        Sector string label (e.g., 'energia_utilities', 'saude', 'generic').
    """
    d = domain.lower()
    for pattern, sector in SECTOR_RULES:
        if re.search(pattern, d):
            return sector
    return "generic"


# ── Abstract pattern extraction ────────────────────────────────────────────────
# Converts actual usernames/passwords to structural representations.
# This is the privacy boundary: no actual strings cross into the model.

def abstract_username(val: str) -> str:
    """
    Convert a username to its abstract structural pattern.

    Structural tokens:
        W  = contiguous alpha run
        D  = contiguous digit run
        .  _ - @  = literal separator (preserved)
        X  = any other character

    Examples:
        pessoax.corpx     → W.W
        jsantos        → W
        j.santos       → W.W
        svc_backup     → W_W
        00123456       → D
        svc01          → WD
        j.santos01     → W.WD
        svc-helpdesk   → W-W
        fn.ln@dom.br   → W.W@W.W

    Args:
        val: Raw username/local-part string.

    Returns:
        Abstract pattern string.
    """
    result: list[str] = []
    i = 0
    v = val.lower().strip()
    while i < len(v):
        c = v[i]
        if c.isalpha():
            j = i
            while j < len(v) and v[j].isalpha():
                j += 1
            result.append("W")
            i = j
        elif c.isdigit():
            j = i
            while j < len(v) and v[j].isdigit():
                j += 1
            result.append("D")
            i = j
        elif c in (".", "_", "-", "@"):
            result.append(c)
            i += 1
        else:
            result.append("X")
            i += 1
    return "".join(result)


def abstract_password(val: str) -> str:
    """
    Convert a password to its abstract character-class pattern.

    Structural tokens:
        U = uppercase alpha run
        L = lowercase alpha run
        D = digit run
        S = special/symbol run
        X = other

    Examples:
        Senha@2024      → ULSUUD → compacted: ULS@D
        empresa123      → LD
        P@ssw0rd        → ULSLDL
        Password1!      → ULLDUS

    Args:
        val: Raw password string.

    Returns:
        Abstract structural pattern string.
    """
    result: list[str] = []
    i = 0
    while i < len(val):
        c = val[i]
        if c.isupper():
            j = i
            while j < len(val) and val[j].isupper():
                j += 1
            result.append("U")
            i = j
        elif c.islower():
            j = i
            while j < len(val) and val[j].islower():
                j += 1
            result.append("L")
            i = j
        elif c.isdigit():
            j = i
            while j < len(val) and val[j].isdigit():
                j += 1
            result.append("D")
            i = j
        elif c in ("@", "!", "#", "$", "%", "&", "*", "+", "=", "?", "^", "~"):
            result.append("S")
            i += 1
        else:
            result.append("X")
            i += 1
    return "".join(result)


def _char_classes(val: str) -> dict:
    """Return character class composition of a string (fractions, no raw data)."""
    n = len(val) or 1
    return {
        "upper":   sum(c.isupper() for c in val) / n,
        "lower":   sum(c.islower() for c in val) / n,
        "digit":   sum(c.isdigit() for c in val) / n,
        "special": sum(not c.isalnum() for c in val) / n,
        "len":     len(val),
    }


def _norm(s: str) -> str:
    """Normalize: strip accents, lowercase."""
    s = unicodedata.normalize("NFD", s)
    return "".join(c for c in s if unicodedata.category(c) != "Mn").lower()


# ── Pattern Model ──────────────────────────────────────────────────────────────

class PatternModel:
    """
    Privacy-preserving statistical model for corporate credential pattern learning.

    Learns structural patterns from training data without storing any actual
    usernames, passwords, company names, or personal information.

    The model stores only:
      - Pattern type frequency counts (per sector)
      - Separator frequency counts (per sector)
      - Abstract password structural frequencies
      - Length distribution statistics (mean, std, min, max)
      - Abstract shape transition frequencies (for ranking)
    """

    def __init__(self) -> None:
        self._version: str = MODEL_VERSION

        # username pattern counts: sector → {pattern_id: count}
        self._uid_pattern_counts:  dict[str, Counter] = defaultdict(Counter)
        # separator counts: sector → {sep: count}
        self._sep_counts:          dict[str, Counter] = defaultdict(Counter)
        # abstract username shape counts: sector → {abstract_shape: count}
        self._uid_shape_counts:    dict[str, Counter] = defaultdict(Counter)
        # password structural pattern counts: {abstract_pat: count}
        self._pwd_pattern_counts:  Counter = Counter()
        # password abstract shape counts
        self._pwd_shape_counts:    Counter = Counter()
        # username length stats accumulators: sector → [lengths]
        self._uid_lengths:         dict[str, list[int]] = defaultdict(list)
        # password length stats
        self._pwd_lengths:         list[int] = []
        # total training samples
        self._total_uid_samples:   int = 0
        self._total_pwd_samples:   int = 0
        # data source registry (no raw data, just source descriptions)
        self._sources:             list[str] = []

    # ── Training ──────────────────────────────────────────────────────────────

    def train_from_csv(
        self,
        csv_path: str,
        userid_col:      str = "userid",
        employeeid_col:  str = "employeeid",
        workemail_col:   str = "workemail",
        domain_col:      Optional[str] = None,
        max_rows:        int = 0,
    ) -> dict:
        """
        Extract username patterns from a CSV AD export.

        PRIVACY: Only structural patterns are extracted. No actual usernames,
        emails, company names, or personal data are stored or returned.

        Args:
            csv_path: Path to the CSV file.
            userid_col: Column name for username/samaccountname.
            employeeid_col: Column name for employee ID.
            workemail_col: Column name for work email.
            domain_col: Optional explicit domain column.
            max_rows: Max rows to process (0 = all).

        Returns:
            Training summary dict (counts only, no raw data).
        """
        from embedxpl.engines.wordlists.domain_users import CORPORATE_PATTERNS, ALL_DOMAIN_SEPARATORS

        # Build pattern classifier from CORPORATE_PATTERNS fmt strings
        pat_classifiers = _build_pattern_classifiers(CORPORATE_PATTERNS)
        seps = set(ALL_DOMAIN_SEPARATORS) - {""}

        path = Path(csv_path)
        if not path.exists():
            raise FileNotFoundError(f"CSV not found: {csv_path}")

        processed = 0
        uid_found  = 0
        pwd_found  = 0

        with open(path, encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if max_rows and processed >= max_rows:
                    break
                processed += 1

                # ── Determine sector from domain (no company name stored) ──────
                domain = ""
                we = (row.get(workemail_col, "") or "").strip()
                eid = (row.get(employeeid_col, "") or "").strip()
                if "@" in we:
                    domain = we.split("@")[1].lower()
                elif "@" in eid:
                    domain = eid.split("@")[1].lower()
                sector = classify_domain_sector(domain) if domain else "generic"

                # ── Process userid ────────────────────────────────────────────
                for field in (userid_col, employeeid_col):
                    raw = (row.get(field, "") or "").strip()
                    if not raw:
                        continue
                    local = raw.split("@")[0] if "@" in raw else raw
                    if not local or len(local) < 2:
                        continue

                    shape = abstract_username(local)
                    self._uid_shape_counts[sector][shape] += 1
                    self._uid_lengths[sector].append(len(local))

                    # Classify into known pattern IDs
                    pat_id = _classify_uid_to_pattern(local, pat_classifiers)
                    self._uid_pattern_counts[sector][pat_id] += 1

                    # Extract separator
                    sep_found = _extract_separator(local, seps)
                    if sep_found is not None:
                        self._sep_counts[sector][sep_found] += 1
                    elif re.match(r"^[a-z]+$", local):
                        self._sep_counts[sector][""] += 1

                    uid_found += 1
                    self._total_uid_samples += 1

        source_desc = (
            f"CSV: {path.name} "
            f"({processed} rows, {uid_found} uid samples) "
            f"[patterns only, no raw data]"
        )
        self._sources.append(source_desc)
        logger.info(source_desc)

        return {
            "processed_rows":  processed,
            "uid_samples":     uid_found,
            "sectors_found":   list(set(
                s for s in self._uid_pattern_counts
            )),
        }

    def train_from_wordlist(
        self,
        wordlist_path: str,
        mode: str = "password",
        max_lines: int = 500_000,
        source_label: str = "",
    ) -> dict:
        """
        Learn structural patterns from a wordlist file.

        PRIVACY: Only abstract structure patterns are extracted.
        No actual words or passwords are stored.

        Args:
            wordlist_path: Path to wordlist file.
            mode: 'password' or 'username'.
            max_lines: Max lines to process.
            source_label: Human label for this source (no path info stored).

        Returns:
            Training summary dict.
        """
        path = Path(wordlist_path)
        if not path.exists():
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

        processed = 0
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if processed >= max_lines:
                    break
                val = line.strip()
                if not val or val.startswith("#") or len(val) < 3:
                    continue
                # Skip lines that look like actual data headers or comments
                if ":" in val and len(val) > 60:
                    continue

                if mode == "password":
                    shape = abstract_password(val)
                    self._pwd_shape_counts[shape] += 1
                    self._pwd_lengths.append(min(len(val), 64))
                    self._total_pwd_samples += 1
                else:  # username
                    shape = abstract_username(val)
                    self._uid_shape_counts["generic"][shape] += 1
                    self._uid_lengths["generic"].append(len(val))
                    self._total_uid_samples += 1

                processed += 1

        label = source_label or path.name
        self._sources.append(
            f"Wordlist ({mode}): {label} - {processed} samples [patterns only]"
        )
        logger.info("Trained from wordlist: %s (%d samples)", label, processed)
        return {"processed": processed, "mode": mode}

    def train_from_username_list(
        self,
        path: str,
        source_label: str = "",
    ) -> dict:
        """
        Learn username structural patterns from a username list file.

        Args:
            path: Path to username list (one per line).
            source_label: Human label for this source.

        Returns:
            Training summary dict.
        """
        return self.train_from_wordlist(path, mode="username",
                                        source_label=source_label or "username list")

    # ── Serialization ─────────────────────────────────────────────────────────

    def save(self, path: Optional[str] = None) -> str:
        """
        Serialize model to JSON.

        The file contains ONLY statistical summaries:
          - Pattern weights (probabilities)
          - Length distribution statistics
          - Abstract shape frequencies
          - Source descriptions (no paths, no raw data)

        Returns:
            Path where model was saved.
        """
        out = Path(path) if path else DEFAULT_MODEL_FILE
        out.parent.mkdir(parents=True, exist_ok=True)

        # Compute length statistics (mean, std, min, max per sector)
        len_stats: dict = {}
        for sector, lengths in self._uid_lengths.items():
            if lengths:
                n = len(lengths)
                mean = sum(lengths) / n
                std  = math.sqrt(sum((l - mean) ** 2 for l in lengths) / n)
                len_stats[sector] = {
                    "mean": round(mean, 2),
                    "std":  round(std, 2),
                    "min":  min(lengths),
                    "max":  max(lengths),
                    "n":    n,
                }

        pwd_len_stats: dict = {}
        if self._pwd_lengths:
            n = len(self._pwd_lengths)
            mean = sum(self._pwd_lengths) / n
            std  = math.sqrt(sum((l - mean) ** 2 for l in self._pwd_lengths) / n)
            pwd_len_stats = {
                "mean": round(mean, 2),
                "std":  round(std, 2),
                "min":  min(self._pwd_lengths),
                "max":  max(self._pwd_lengths),
                "n":    n,
            }

        # Normalize pattern counts to probabilities
        uid_weights: dict = {}
        for sector, counts in self._uid_pattern_counts.items():
            total = sum(counts.values()) or 1
            uid_weights[sector] = {
                pat: round(cnt / total, 6)
                for pat, cnt in counts.most_common()
            }

        sep_weights: dict = {}
        for sector, counts in self._sep_counts.items():
            total = sum(counts.values()) or 1
            sep_weights[sector] = {
                (sep if sep else "__empty__"): round(cnt / total, 6)
                for sep, cnt in counts.most_common()
            }

        # Top abstract uid shapes (privacy: these are abstract, not actual usernames)
        uid_shapes: dict = {}
        for sector, counts in self._uid_shape_counts.items():
            total = sum(counts.values()) or 1
            uid_shapes[sector] = {
                shape: round(cnt / total, 6)
                for shape, cnt in counts.most_common(50)  # top 50 shapes
            }

        # Top abstract password shapes
        total_pwd = sum(self._pwd_shape_counts.values()) or 1
        pwd_shapes = {
            shape: round(cnt / total_pwd, 6)
            for shape, cnt in self._pwd_shape_counts.most_common(100)
        }

        model_data = {
            "version":             self._version,
            "total_uid_samples":   self._total_uid_samples,
            "total_pwd_samples":   self._total_pwd_samples,
            "sources":             self._sources,
            "uid_pattern_weights": uid_weights,
            "sep_weights":         sep_weights,
            "uid_shape_weights":   uid_shapes,
            "pwd_shape_weights":   pwd_shapes,
            "uid_length_stats":    len_stats,
            "pwd_length_stats":    pwd_len_stats,
        }

        with open(out, "w", encoding="utf-8") as f:
            json.dump(model_data, f, indent=2, ensure_ascii=False)

        logger.info("Model saved to %s (%d uid / %d pwd samples)",
                    out, self._total_uid_samples, self._total_pwd_samples)
        return str(out)

    def load(self, path: Optional[str] = None) -> None:
        """
        Load a previously saved model from JSON.

        Args:
            path: Path to model JSON file (default: DEFAULT_MODEL_FILE).
        """
        src = Path(path) if path else DEFAULT_MODEL_FILE
        if not src.exists():
            raise FileNotFoundError(f"Model file not found: {src}")

        with open(src, encoding="utf-8") as f:
            data = json.load(f)

        self._total_uid_samples = data.get("total_uid_samples", 0)
        self._total_pwd_samples = data.get("total_pwd_samples", 0)
        self._sources           = data.get("sources", [])

        # Restore counters from weight dicts (approximate, for ranking use)
        for sector, weights in data.get("uid_pattern_weights", {}).items():
            self._uid_pattern_counts[sector] = Counter(
                {k: int(v * 10000) for k, v in weights.items()}
            )

        for sector, weights in data.get("sep_weights", {}).items():
            self._sep_counts[sector] = Counter(
                {(k if k != "__empty__" else ""): int(v * 10000)
                 for k, v in weights.items()}
            )

        for sector, weights in data.get("uid_shape_weights", {}).items():
            self._uid_shape_counts[sector] = Counter(
                {k: int(v * 10000) for k, v in weights.items()}
            )

        self._pwd_shape_counts = Counter(
            {k: int(v * 10000)
             for k, v in data.get("pwd_shape_weights", {}).items()}
        )

        logger.info("Model loaded from %s", src)

    # ── Query / Generation ────────────────────────────────────────────────────

    def get_pattern_weights(self, sector: str = "generic") -> dict[str, float]:
        """
        Return learned username pattern weights for a sector.

        Falls back to 'generic' if sector has insufficient training data.

        Args:
            sector: Domain sector label.

        Returns:
            Dict mapping pattern_id → probability weight (sums to ≤ 1).
        """
        counts = self._uid_pattern_counts.get(sector)
        if not counts or sum(counts.values()) < 50:
            counts = self._uid_pattern_counts.get("generic", Counter())

        total = sum(counts.values()) or 1
        return {pat: cnt / total for pat, cnt in counts.most_common()}

    def get_separator_weights(self, sector: str = "generic") -> dict[str, float]:
        """
        Return learned separator weights for a sector.

        Args:
            sector: Domain sector label.

        Returns:
            Dict mapping separator → probability weight.
        """
        counts = self._sep_counts.get(sector)
        if not counts or sum(counts.values()) < 20:
            counts = self._sep_counts.get("generic", Counter())

        total = sum(counts.values()) or 1
        return {sep: cnt / total for sep, cnt in counts.most_common()}

    def rank_candidates(
        self,
        candidates: list[str],
        domain: str = "",
        top_n: int = 0,
    ) -> list[tuple[str, float]]:
        """
        Rank a list of username candidates by learned pattern probability.

        Args:
            candidates: List of username strings (with or without @domain).
            domain: Target domain (used for sector lookup).
            top_n: Return only top N results (0 = all).

        Returns:
            Sorted list of (username, score) tuples, highest score first.
        """
        sector = classify_domain_sector(domain) if domain else "generic"
        pat_weights = self.get_pattern_weights(sector)
        sep_weights = self.get_separator_weights(sector)
        shape_counts = self._uid_shape_counts.get(sector) or \
                       self._uid_shape_counts.get("generic", Counter())
        total_shapes = sum(shape_counts.values()) or 1

        scored: list[tuple[str, float]] = []
        for cand in candidates:
            local = cand.split("@")[0] if "@" in cand else cand
            shape = abstract_username(local)

            # Score components:
            # 1. Pattern ID weight (if classifiable)
            pat_score = 0.0
            from embedxpl.engines.wordlists.domain_users import CORPORATE_PATTERNS
            classifiers = _build_pattern_classifiers(CORPORATE_PATTERNS)
            pat_id = _classify_uid_to_pattern(local, classifiers)
            pat_score = pat_weights.get(pat_id, 0.0)

            # 2. Abstract shape weight
            shape_score = shape_counts.get(shape, 0) / total_shapes

            # 3. Separator weight
            sep_found = _extract_separator(local, {".", "_", "-"})
            sep_score = sep_weights.get(sep_found or "", 0.0)

            # Combined score (weighted)
            score = (pat_score * 0.6) + (shape_score * 0.3) + (sep_score * 0.1)
            scored.append((cand, round(score, 6)))

        scored.sort(key=lambda x: -x[1])
        return scored[:top_n] if top_n else scored

    def rank_and_yield(
        self,
        candidates: list[str],
        domain: str = "",
    ):
        """
        Rank candidates and yield them in probability order.

        Yields strings (no scores exposed), most likely first.
        Falls back to original order if model has no data.

        Args:
            candidates: List of username strings.
            domain: Target domain.

        Yields:
            Username strings in learned probability order.
        """
        if self._total_uid_samples < 100:
            # Not enough training data - preserve rule-based order
            yield from candidates
            return

        ranked = self.rank_candidates(candidates, domain)
        for cand, _ in ranked:
            yield cand

    def describe(self) -> str:
        """
        Return a human-readable model summary (no raw data exposed).

        Returns:
            Multi-line description string.
        """
        lines = [
            f"PatternModel v{self._version}",
            f"  Username samples : {self._total_uid_samples:,}",
            f"  Password samples : {self._total_pwd_samples:,}",
            f"  Sectors learned  : {sorted(self._uid_pattern_counts.keys())}",
            f"  Training sources : {len(self._sources)} source(s)",
        ]
        for src in self._sources:
            lines.append(f"    - {src}")

        # Top patterns per sector
        for sector, counts in sorted(self._uid_pattern_counts.items()):
            total = sum(counts.values()) or 1
            top3 = [(p, f"{c/total*100:.1f}%")
                    for p, c in counts.most_common(3)]
            lines.append(f"  [{sector}] top patterns: {top3}")

        # Top abstract password shapes
        if self._pwd_shape_counts:
            total = sum(self._pwd_shape_counts.values()) or 1
            top5 = [(s, f"{c/total*100:.1f}%")
                    for s, c in self._pwd_shape_counts.most_common(5)]
            lines.append(f"  Password shapes (top 5): {top5}")

        return "\n".join(lines)

    def is_trained(self) -> bool:
        """Return True if the model has sufficient training data."""
        return self._total_uid_samples >= 100

    def get_top_password_shapes(self, n: int = 20) -> list[tuple[str, float]]:
        """
        Return top N abstract password shapes by frequency.

        Args:
            n: Number of shapes to return.

        Returns:
            List of (abstract_shape, probability) tuples.
        """
        total = sum(self._pwd_shape_counts.values()) or 1
        return [
            (shape, round(cnt / total, 4))
            for shape, cnt in self._pwd_shape_counts.most_common(n)
        ]

    def get_expected_uid_length(self, sector: str = "generic") -> dict:
        """
        Return expected username length stats for a sector.

        Args:
            sector: Domain sector label.

        Returns:
            Dict with mean, std, min, max (or defaults if no data).
        """
        lengths = self._uid_lengths.get(sector) or self._uid_lengths.get("generic", [])
        if not lengths:
            return {"mean": 10.0, "std": 3.0, "min": 3, "max": 20}
        n = len(lengths)
        mean = sum(lengths) / n
        std  = math.sqrt(sum((l - mean) ** 2 for l in lengths) / n)
        return {
            "mean": round(mean, 1),
            "std":  round(std, 1),
            "min":  min(lengths),
            "max":  max(lengths),
        }


# ── Internal pattern classifiers ───────────────────────────────────────────────

def _build_pattern_classifiers(corporate_patterns: list[dict]) -> list[tuple]:
    """
    Build a list of (pattern_id, regex_or_callable) classifiers from
    CORPORATE_PATTERNS fmt strings.

    Returns list of (pattern_id, check_fn) where check_fn(local) → bool.
    """
    # We classify by shape rather than regex on actual names
    # Shape → pattern_id mapping (from empirical analysis)
    shape_to_pattern = {
        "W.W":    "fn_sep_ln",
        "W_W":    "fn_sep_ln",
        "W-W":    "fn_sep_ln",
        "WW":     "fn_ln",
        "W.W.W":  "fn_sep_mn_sep_ln",
        "W_W_W":  "fn_sep_mn_sep_ln",
        "W.WD":   "fn_sep_ln_num",
        "W.W.D":  "fn_sep_ln_sep_num",
        "W.W.DD": "fn_sep_ln_sep_num",
        "WD":     "fi_ln_num",       # e.g. pxcorpx01 fallback
        "W.D":    "fn_sep_ln_num",
        "W.W.DDD": "fn_sep_ln_sep_num",
        "W":      "fn_only",
        "D":      "numeric",
        "WW.WW":  "fn_sep_ln",
    }
    # Return as simple mapping (no regex needed, shape is deterministic)
    return list(shape_to_pattern.items())


def _classify_uid_to_pattern(local: str, classifiers: list[tuple]) -> str:
    """
    Classify a username local-part into the closest CORPORATE_PATTERNS id.

    Args:
        local: Username local part (e.g., 'pessoax.corpx').
        classifiers: List of (pattern_id, shape) pairs.

    Returns:
        Pattern ID string, or '?' if no match.
    """
    shape = abstract_username(local)
    shape_map = dict(classifiers)
    pat = shape_map.get(shape)
    if pat:
        return pat
    # Fallback heuristics
    if re.match(r"^\d+$", local):
        return "numeric"
    if re.match(r"^0+\d+$", local):
        return "numeric_padded"
    if re.match(r"^[a-z]{2,8}\d{3,}$", local):
        return "prefix_num"
    if "." in local:
        return "fn_sep_ln"
    if "_" in local:
        return "fn_sep_ln"
    if "-" in local:
        return "fn_sep_ln"
    return "?"


def _extract_separator(local: str, seps: set) -> Optional[str]:
    """Extract the first separator found in a username local-part."""
    for sep in (".", "_", "-"):
        if sep in local and sep in seps:
            return sep
    return None


# ── Convenience singleton ──────────────────────────────────────────────────────

_MODEL_SINGLETON: Optional[PatternModel] = None


def get_model(model_path: Optional[str] = None) -> PatternModel:
    """
    Return the global PatternModel singleton, loading from disk if available.

    Args:
        model_path: Path to model JSON (default: DEFAULT_MODEL_FILE).

    Returns:
        PatternModel instance (may be untrained if no file found).
    """
    global _MODEL_SINGLETON
    if _MODEL_SINGLETON is None:
        _MODEL_SINGLETON = PatternModel()
        mp = Path(model_path) if model_path else DEFAULT_MODEL_FILE
        if mp.exists():
            try:
                _MODEL_SINGLETON.load(str(mp))
            except Exception as e:
                logger.warning("Could not load model: %s", e)
    return _MODEL_SINGLETON
