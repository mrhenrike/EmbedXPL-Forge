"""
benchmark_suite.py - Wordlist quality benchmarking suite.

Measures the effectiveness of generated wordlists against reference datasets
using metrics from academic research (MAYA, PCWQ, CMU PGS).

Metrics:
  - Hit Rate: % of reference passwords matched
  - Coverage: unique matches / reference size
  - Efficiency: hits / total candidates (no duplicates)
  - Duplicate Rate: % of duplicate candidates
  - Diversity Index: Shannon entropy of character distribution
  - Length Distribution: coverage per password length
  - Estimated Crack Time: based on hash rate assumptions

Inspired by MAYA (IEEE S&P 2026) benchmarking framework.

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import json
import logging
import math
import re
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)


# ── MAYA pattern set (r1-r19) ─────────────────────────────────────────────────
# 19 structural password patterns used in the MAYA benchmark (IEEE S&P 2026).
# Each pattern captures a structural class of real passwords found in leaks.
MAYA_PATTERNS: dict[str, re.Pattern] = {
    "r1":  re.compile(r"^[a-z]+$"),
    "r2":  re.compile(r"^[A-Z]+$"),
    "r3":  re.compile(r"^[0-9]+$"),
    "r4":  re.compile(r"^[a-zA-Z]+$"),
    "r5":  re.compile(r"^[a-z]+[0-9]+$"),
    "r6":  re.compile(r"^[A-Z][a-z]+[0-9]+$"),
    "r7":  re.compile(r"^[a-zA-Z]+[0-9]+$"),
    "r8":  re.compile(r"^[0-9]+[a-zA-Z]+$"),
    "r9":  re.compile(r"^[a-z]+[0-9]+[a-z]+$"),
    "r10": re.compile(r"^[A-Z][a-z]+$"),
    "r11": re.compile(r"^[A-Z][a-z]+[A-Z][a-z]+$"),
    "r12": re.compile(r"^[a-zA-Z0-9]+$"),
    "r13": re.compile(r"^[a-zA-Z][a-zA-Z0-9\W_]+[0-9]$"),
    "r14": re.compile(r"^[a-z]+[^a-zA-Z0-9]+$"),
    "r15": re.compile(r"^[a-z]+[^a-zA-Z0-9]+[0-9]+$"),
    "r16": re.compile(r"^[A-Z][a-z]+[^a-zA-Z0-9]+[0-9]+$"),
    "r17": re.compile(r"^[a-z]+[0-9]+[^a-zA-Z0-9]+$"),
    "r18": re.compile(r"^[a-z]+[^a-zA-Z0-9][a-z]+$"),
    "r19": re.compile(r"^.+[!@#$%^&*()\-_=+\[\]{}|;':\",./<>?]$"),
}

HASH_RATES = {
    "md5":       60_000_000_000,
    "sha1":      20_000_000_000,
    "sha256":     8_000_000_000,
    "ntlm":     100_000_000_000,
    "bcrypt_5":          50_000,
    "bcrypt_10":          1_500,
    "scrypt":            10_000,
    "argon2":             2_000,
    "wpa2":             800_000,
}


def _shannon_entropy(text_sample: str) -> float:
    """Compute Shannon entropy of a character distribution."""
    if not text_sample:
        return 0.0
    freq = Counter(text_sample)
    total = len(text_sample)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _jaccard_index(set_a: set, set_b: set) -> float:
    """Compute Jaccard similarity index between two sets."""
    if not set_a and not set_b:
        return 1.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 0.0


class BenchmarkResult:
    """Container for benchmark metrics."""

    def __init__(self) -> None:
        self.total_candidates: int = 0
        self.unique_candidates: int = 0
        self.duplicate_count: int = 0
        self.reference_size: int = 0
        self.hits: int = 0
        self.hit_rate: float = 0.0
        self.efficiency: float = 0.0
        self.duplicate_rate: float = 0.0
        self.diversity_index: float = 0.0
        self.length_coverage: dict[int, dict] = {}
        self.charset_coverage: dict[str, float] = {}
        self.crack_time_estimates: dict[str, str] = {}
        self.top_hits: list[str] = []
        self.top_misses: list[str] = []
        self.elapsed_seconds: float = 0.0

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "total_candidates": self.total_candidates,
            "unique_candidates": self.unique_candidates,
            "duplicate_count": self.duplicate_count,
            "duplicate_rate": round(self.duplicate_rate, 4),
            "reference_size": self.reference_size,
            "hits": self.hits,
            "hit_rate": round(self.hit_rate, 4),
            "efficiency": round(self.efficiency, 6),
            "diversity_index": round(self.diversity_index, 4),
            "length_coverage": self.length_coverage,
            "charset_coverage": self.charset_coverage,
            "crack_time_estimates": self.crack_time_estimates,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
        }

    def describe(self) -> str:
        """Return human-readable benchmark report."""
        lines = [
            "=" * 60,
            "  WORDLIST QUALITY BENCHMARK REPORT",
            "=" * 60,
            "",
            f"  Candidates (total)    : {self.total_candidates:>12,}",
            f"  Candidates (unique)   : {self.unique_candidates:>12,}",
            f"  Duplicates            : {self.duplicate_count:>12,}  ({self.duplicate_rate * 100:.1f}%)",
            "",
            f"  Reference set size    : {self.reference_size:>12,}",
            f"  Hits (matches)        : {self.hits:>12,}",
            f"  HIT RATE              : {self.hit_rate * 100:>11.2f}%",
            f"  EFFICIENCY            : {self.efficiency * 100:>11.4f}%  (hits / unique candidates)",
            f"  DIVERSITY (Shannon)   : {self.diversity_index:>11.4f} bits",
            "",
        ]

        if self.length_coverage:
            lines.append("  Coverage by length:")
            for length in sorted(self.length_coverage.keys()):
                data = self.length_coverage[length]
                lines.append(
                    f"    len={length:2d}: {data['hits']:>6,}/{data['total']:>6,}"
                    f"  ({data['rate'] * 100:5.1f}%)"
                )
            lines.append("")

        if self.charset_coverage:
            lines.append("  Coverage by charset:")
            for cs, rate in sorted(self.charset_coverage.items(), key=lambda x: -x[1]):
                lines.append(f"    {cs:20s}: {rate * 100:5.1f}%")
            lines.append("")

        if self.crack_time_estimates:
            lines.append("  Estimated time to exhaust wordlist:")
            for algo, est in self.crack_time_estimates.items():
                lines.append(f"    {algo:12s}: {est}")
            lines.append("")

        lines.append(f"  Benchmark completed in {self.elapsed_seconds:.2f}s")
        lines.append("=" * 60)
        return "\n".join(lines)


def _classify_charset(password: str) -> str:
    """Classify a password by its character composition."""
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    parts = []
    if has_lower:
        parts.append("lower")
    if has_upper:
        parts.append("upper")
    if has_digit:
        parts.append("digit")
    if has_special:
        parts.append("special")

    return "+".join(parts) if parts else "empty"


def _format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    if seconds < 0.001:
        return "< 1ms"
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}min"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    if seconds < 86400 * 365:
        return f"{seconds / 86400:.1f} days"
    return f"{seconds / (86400 * 365):.1f} years"


def benchmark(
    wordlist_path: str,
    reference_path: str,
    max_candidates: int = 0,
    max_reference: int = 0,
    sample_diversity: int = 100_000,
) -> BenchmarkResult:
    """Run a full benchmark of a wordlist against a reference set.

    Args:
        wordlist_path: Path to the generated wordlist to evaluate.
        reference_path: Path to the reference password set (ground truth).
        max_candidates: Max lines to read from wordlist (0 = all).
        max_reference: Max lines to read from reference (0 = all).
        sample_diversity: Characters to sample for diversity calculation.

    Returns:
        BenchmarkResult with all metrics.
    """
    result = BenchmarkResult()
    start = time.time()

    ref_set: set[str] = set()
    ref_by_length: dict[int, set[str]] = defaultdict(set)
    ref_by_charset: dict[str, set[str]] = defaultdict(set)

    ref_path = Path(reference_path)
    with ref_path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            pw = line.rstrip("\n\r")
            if not pw:
                continue
            if ":" in pw:
                pw = pw.split(":", 1)[-1]
            ref_set.add(pw)
            ref_by_length[len(pw)].add(pw)
            ref_by_charset[_classify_charset(pw)].add(pw)
            if max_reference and len(ref_set) >= max_reference:
                break

    result.reference_size = len(ref_set)

    seen: set[str] = set()
    hits: set[str] = set()
    hits_by_length: dict[int, int] = defaultdict(int)
    hits_by_charset: dict[str, int] = defaultdict(int)
    diversity_sample: list[str] = []
    total = 0

    wl_path = Path(wordlist_path)
    with wl_path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            candidate = line.rstrip("\n\r")
            if not candidate:
                continue
            total += 1

            if candidate in seen:
                result.duplicate_count += 1
            else:
                seen.add(candidate)
                if candidate in ref_set and candidate not in hits:
                    hits.add(candidate)
                    hits_by_length[len(candidate)] += 1
                    hits_by_charset[_classify_charset(candidate)] += 1

                if len(diversity_sample) < sample_diversity:
                    diversity_sample.append(candidate)

            if max_candidates and total >= max_candidates:
                break

    result.total_candidates = total
    result.unique_candidates = len(seen)
    result.hits = len(hits)
    result.hit_rate = result.hits / result.reference_size if result.reference_size else 0.0
    result.efficiency = result.hits / result.unique_candidates if result.unique_candidates else 0.0
    result.duplicate_rate = result.duplicate_count / total if total else 0.0

    all_chars = "".join(diversity_sample[:sample_diversity])
    result.diversity_index = _shannon_entropy(all_chars)

    for length, ref_passwords in sorted(ref_by_length.items()):
        h = hits_by_length.get(length, 0)
        t = len(ref_passwords)
        result.length_coverage[length] = {
            "hits": h, "total": t,
            "rate": h / t if t else 0.0,
        }

    for cs, ref_passwords in sorted(ref_by_charset.items()):
        h = hits_by_charset.get(cs, 0)
        t = len(ref_passwords)
        result.charset_coverage[cs] = h / t if t else 0.0

    for algo, rate in HASH_RATES.items():
        if result.unique_candidates > 0:
            secs = result.unique_candidates / rate
            result.crack_time_estimates[algo] = _format_duration(secs)

    result.elapsed_seconds = time.time() - start
    return result


def benchmark_generator(
    generator: Generator[str, None, None],
    reference_path: str,
    max_candidates: int = 0,
    max_reference: int = 0,
) -> BenchmarkResult:
    """Benchmark a generator directly without writing to file.

    Args:
        generator: Password candidate generator.
        reference_path: Path to reference password set.
        max_candidates: Max candidates to consume (0 = all).
        max_reference: Max reference lines (0 = all).

    Returns:
        BenchmarkResult.
    """
    result = BenchmarkResult()
    start = time.time()

    ref_set: set[str] = set()
    ref_by_length: dict[int, set[str]] = defaultdict(set)

    ref_path = Path(reference_path)
    with ref_path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            pw = line.rstrip("\n\r")
            if not pw:
                continue
            if ":" in pw:
                pw = pw.split(":", 1)[-1]
            ref_set.add(pw)
            ref_by_length[len(pw)].add(pw)
            if max_reference and len(ref_set) >= max_reference:
                break

    result.reference_size = len(ref_set)

    seen: set[str] = set()
    hits: set[str] = set()
    hits_by_length: dict[int, int] = defaultdict(int)
    total = 0

    for candidate in generator:
        total += 1
        if candidate in seen:
            result.duplicate_count += 1
        else:
            seen.add(candidate)
            if candidate in ref_set and candidate not in hits:
                hits.add(candidate)
                hits_by_length[len(candidate)] += 1
        if max_candidates and total >= max_candidates:
            break

    result.total_candidates = total
    result.unique_candidates = len(seen)
    result.hits = len(hits)
    result.hit_rate = result.hits / result.reference_size if result.reference_size else 0.0
    result.efficiency = result.hits / result.unique_candidates if result.unique_candidates else 0.0
    result.duplicate_rate = result.duplicate_count / total if total else 0.0

    for length, ref_passwords in sorted(ref_by_length.items()):
        h = hits_by_length.get(length, 0)
        t = len(ref_passwords)
        result.length_coverage[length] = {
            "hits": h, "total": t,
            "rate": h / t if t else 0.0,
        }

    for algo, rate in HASH_RATES.items():
        if result.unique_candidates > 0:
            result.crack_time_estimates[algo] = _format_duration(result.unique_candidates / rate)

    result.elapsed_seconds = time.time() - start
    return result


# ── MAYA-inspired metrics ─────────────────────────────────────────────────────

def benchmark_known_targets(
    wordlist_path: str,
    targets: list[str],
    max_candidates: int = 0,
) -> dict:
    """
    Verifica se alvos conhecidos estão na wordlist gerada.

    Implementa o cenário de validação profile-targeted descrito no paper MAYA
    (IEEE S&P 2026): dado um conjunto pequeno de senhas conhecidas do alvo,
    mede quantas foram cobertas e quantos candidatos foram necessários.

    Args:
        wordlist_path: Caminho para a wordlist gerada.
        targets: Known-target passwords to score (caller-supplied; never hardcoded org names).
        max_candidates: Limite de candidatos a inspecionar (0 = todos).

    Returns:
        Dict com: hits, misses, hit_rate, first_hit_positions, missing_targets.
    """
    target_set = set(targets)
    found: dict[str, int] = {}
    total = 0

    wl_path = Path(wordlist_path)
    if not wl_path.exists():
        return {"error": f"Wordlist not found: {wordlist_path}"}

    with wl_path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            total += 1
            candidate = line.rstrip("\n\r")
            if candidate in target_set and candidate not in found:
                found[candidate] = total
            if len(found) == len(target_set):
                break
            if max_candidates and total >= max_candidates:
                break

    missing = sorted(t for t in targets if t not in found)
    return {
        "targets_total": len(targets),
        "hits": len(found),
        "misses": len(missing),
        "hit_rate": len(found) / len(targets) if targets else 0.0,
        "candidates_checked": total,
        "first_hit_positions": dict(sorted(found.items(), key=lambda x: x[1])),
        "missing_targets": missing,
    }


def benchmark_known_targets_generator(
    generator: Generator[str, None, None],
    targets: list[str],
    max_candidates: int = 0,
) -> dict:
    """
    Variante streaming de benchmark_known_targets: consome um gerador.

    Args:
        generator: Gerador de candidatos.
        targets: Lista de alvos.
        max_candidates: Limite de candidatos (0 = todos).

    Returns:
        Mesmo formato que benchmark_known_targets.
    """
    target_set = set(targets)
    found: dict[str, int] = {}
    total = 0

    for candidate in generator:
        total += 1
        if candidate in target_set and candidate not in found:
            found[candidate] = total
        if len(found) == len(target_set):
            break
        if max_candidates and total >= max_candidates:
            break

    missing = sorted(t for t in targets if t not in found)
    return {
        "targets_total": len(targets),
        "hits": len(found),
        "misses": len(missing),
        "hit_rate": len(found) / len(targets) if targets else 0.0,
        "candidates_checked": total,
        "first_hit_positions": dict(sorted(found.items(), key=lambda x: x[1])),
        "missing_targets": missing,
    }


def compare_generators(
    wordlist_paths: dict[str, str],
    reference_path: str,
    max_candidates: int = 0,
    max_reference: int = 0,
    include_jaccard: bool = True,
) -> dict[str, dict]:
    """
    Compara múltiplos geradores contra o mesmo conjunto de referência.

    Implementa o cenário de combinação de geradores do paper MAYA:
    mostra o ganho marginal de cada gerador adicional (CUPP → CUPP+PRINCE → etc).
    Opcionalmente calcula o Jaccard index entre cada par de wordlists.

    Args:
        wordlist_paths: Dict de {label: caminho_wordlist}.
        reference_path: Caminho para o conjunto de referência.
        max_candidates: Limite de candidatos por wordlist (0 = todos).
        max_reference: Limite de referências (0 = todas).
        include_jaccard: Se True, adiciona Jaccard entre cada par de wordlists.

    Returns:
        Dict de {label: resultado} com hit_rate, efficiency, jaccard_vs_others, etc.
    """
    ref_set: set[str] = set()
    ref_path = Path(reference_path)
    if ref_path.exists():
        with ref_path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                pw = line.rstrip("\n\r")
                if pw:
                    if ":" in pw:
                        pw = pw.split(":", 1)[-1]
                    ref_set.add(pw)
                    if max_reference and len(ref_set) >= max_reference:
                        break

    # Load all wordlists into hit-sets (intersection with reference)
    hit_sets: dict[str, set[str]] = {}
    cand_sets: dict[str, set[str]] = {}
    results: dict[str, dict] = {}

    for label, wl_path in wordlist_paths.items():
        if not Path(wl_path).exists():
            results[label] = {"error": f"not found: {wl_path}"}
            continue
        r = benchmark(wl_path, reference_path, max_candidates, max_reference)
        results[label] = {
            "unique_candidates": r.unique_candidates,
            "hits": r.hits,
            "hit_rate": round(r.hit_rate * 100, 2),
            "efficiency": round(r.efficiency * 100, 4),
            "duplicate_rate": round(r.duplicate_rate * 100, 2),
        }

        if include_jaccard and ref_set:
            hits: set[str] = set()
            cands: set[str] = set()
            with Path(wl_path).open("r", encoding="utf-8", errors="ignore") as fh:
                for i, line in enumerate(fh):
                    pw = line.rstrip("\n\r")
                    if pw:
                        cands.add(pw)
                        if pw in ref_set:
                            hits.add(pw)
                    if max_candidates and i >= max_candidates:
                        break
            hit_sets[label] = hits
            cand_sets[label] = cands

    if include_jaccard and len(cand_sets) > 1:
        labels = list(cand_sets.keys())
        for i, la in enumerate(labels):
            jaccard_row: dict[str, float] = {}
            for j, lb in enumerate(labels):
                if i != j:
                    jaccard_row[lb] = round(_jaccard_index(cand_sets[la], cand_sets[lb]), 4)
            if la in results:
                results[la]["jaccard_vs_others"] = jaccard_row
                results[la]["mergeability_vs"] = {
                    lb: round(mergeability_index(hit_sets[la], hit_sets.get(lb, set())), 4)
                    for lb in labels if lb != la and lb in hit_sets
                }

    return results


def mergeability_index(matches_a: set[str], matches_b: set[str]) -> float:
    """Compute MAYA mergeability index between two match sets.

    Measures the marginal value of combining generator A with generator B,
    relative to the best single generator. A value of 1.0 means the generators
    are perfectly complementary (no shared hits); 0.0 means full overlap.

    Args:
        matches_a: Passwords from reference matched by generator A.
        matches_b: Passwords from reference matched by generator B.

    Returns:
        Float in [0, 1].
    """
    if not matches_a and not matches_b:
        return 0.0
    union = len(matches_a | matches_b)
    max_alone = max(len(matches_a), len(matches_b))
    if max_alone == 0:
        return 0.0
    return (union - max_alone) / max_alone


def matches_per_pattern(
    wordlist_path: str,
    reference_path: str,
    patterns: Optional[dict[str, re.Pattern]] = None,
    max_candidates: int = 0,
    max_reference: int = 0,
) -> dict[str, dict]:
    """Count matches per MAYA structural pattern (r1-r19).

    For each pattern, reports how many passwords in the reference belong to
    that pattern class and how many of those were found in the wordlist.

    Args:
        wordlist_path: Wordlist to evaluate.
        reference_path: Ground-truth password set.
        patterns: Custom pattern dict; defaults to MAYA_PATTERNS.
        max_candidates: Max lines from wordlist (0 = all).
        max_reference: Max lines from reference (0 = all).

    Returns:
        Dict of {pattern_id: {ref_count, hits, hit_rate, pattern_coverage_pct}}.
    """
    pat = patterns or MAYA_PATTERNS

    ref_set: set[str] = set()
    ref_path = Path(reference_path)
    if not ref_path.exists():
        return {"error": f"Reference not found: {reference_path}"}

    with ref_path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            pw = line.rstrip("\n\r")
            if pw:
                if ":" in pw:
                    pw = pw.split(":", 1)[-1]
                ref_set.add(pw)
                if max_reference and len(ref_set) >= max_reference:
                    break

    ref_total = len(ref_set)

    # Bucket reference passwords by pattern (a password may match multiple)
    ref_by_pattern: dict[str, set[str]] = {pid: set() for pid in pat}
    for pw in ref_set:
        for pid, rx in pat.items():
            if rx.match(pw):
                ref_by_pattern[pid].add(pw)

    wl_path = Path(wordlist_path)
    if not wl_path.exists():
        return {"error": f"Wordlist not found: {wordlist_path}"}

    hits_by_pattern: dict[str, set[str]] = {pid: set() for pid in pat}
    total = 0
    with wl_path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            pw = line.rstrip("\n\r")
            if not pw:
                continue
            total += 1
            if pw in ref_set:
                for pid in pat:
                    if pw in ref_by_pattern[pid]:
                        hits_by_pattern[pid].add(pw)
            if max_candidates and total >= max_candidates:
                break

    result: dict[str, dict] = {}
    for pid in pat:
        rc = len(ref_by_pattern[pid])
        hc = len(hits_by_pattern[pid])
        result[pid] = {
            "ref_count": rc,
            "hits": hc,
            "hit_rate": round(hc / rc, 4) if rc else 0.0,
            "pattern_coverage_pct": round(rc / ref_total * 100, 2) if ref_total else 0.0,
        }

    return result


def multi_model_greedy_rank(
    wordlist_paths: dict[str, str],
    reference_path: str,
    max_candidates: int = 0,
    max_reference: int = 0,
) -> list[dict]:
    """Greedy model selection ranking (MAYA multi_models_attack).

    At each iteration, selects the generator that adds the most new hits to the
    current cumulative set, until all generators are exhausted. Equivalent to
    the greedy set-cover approach used in the MAYA benchmark.

    GPU is not required; this is pure Python set arithmetic.

    Args:
        wordlist_paths: Dict of {label: path_to_wordlist}.
        reference_path: Ground-truth reference password set.
        max_candidates: Max lines per wordlist (0 = all).
        max_reference: Max lines from reference (0 = all).

    Returns:
        Sorted list of dicts, each with:
          - rank, label, marginal_hits, cumulative_hits, cumulative_rate,
            mergeability (vs previous cumulative), marginal_pct.
    """
    ref_set: set[str] = set()
    ref_path = Path(reference_path)
    if not ref_path.exists():
        return [{"error": f"Reference not found: {reference_path}"}]

    with ref_path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            pw = line.rstrip("\n\r")
            if pw:
                if ":" in pw:
                    pw = pw.split(":", 1)[-1]
                ref_set.add(pw)
                if max_reference and len(ref_set) >= max_reference:
                    break

    ref_total = len(ref_set)

    # Load hit-sets for each generator
    hit_sets: dict[str, set[str]] = {}
    for label, wl_path in wordlist_paths.items():
        if not Path(wl_path).exists():
            logger.warning("multi_model_greedy_rank: skipping missing wordlist %s", wl_path)
            continue
        hits: set[str] = set()
        with Path(wl_path).open("r", encoding="utf-8", errors="ignore") as fh:
            for i, line in enumerate(fh):
                pw = line.rstrip("\n\r")
                if pw and pw in ref_set:
                    hits.add(pw)
                if max_candidates and i >= max_candidates:
                    break
        hit_sets[label] = hits

    if not hit_sets:
        return [{"error": "no valid wordlists provided"}]

    ranking: list[dict] = []
    remaining = set(hit_sets.keys())
    cumulative: set[str] = set()

    while remaining:
        best_label: str = ""
        best_new: int = 0
        for label in remaining:
            new_hits = len(hit_sets[label] - cumulative)
            if new_hits > best_new or not best_label:
                best_new = new_hits
                best_label = label

        prev_cumulative = set(cumulative)
        cumulative |= hit_sets[best_label]
        remaining.discard(best_label)

        cum_rate = len(cumulative) / ref_total if ref_total else 0.0
        merg = mergeability_index(prev_cumulative, hit_sets[best_label]) if prev_cumulative else 1.0

        ranking.append({
            "rank": len(ranking) + 1,
            "label": best_label,
            "total_hits": len(hit_sets[best_label]),
            "marginal_hits": best_new,
            "marginal_pct": round(best_new / ref_total * 100, 4) if ref_total else 0.0,
            "cumulative_hits": len(cumulative),
            "cumulative_rate": round(cum_rate * 100, 4),
            "mergeability": round(merg, 4),
        })

    return ranking


def format_maya_report(
    per_pattern: dict[str, dict],
    greedy_rank: Optional[list[dict]] = None,
) -> str:
    """Format matches_per_pattern and multi_model_greedy_rank as a text report."""
    lines = [
        "=" * 64,
        "  MAYA METRICS REPORT",
        "=" * 64,
        "",
        "  Pattern Coverage (r1-r19):",
        f"  {'Pattern':<8} {'Ref%':>6} {'RefN':>6} {'Hits':>6} {'HitRate':>8}",
        "  " + "-" * 42,
    ]
    for pid in sorted(per_pattern.keys(), key=lambda x: int(x[1:])):
        d = per_pattern[pid]
        if "error" in d:
            continue
        lines.append(
            f"  {pid:<8} {d['pattern_coverage_pct']:>5.1f}% {d['ref_count']:>6,}"
            f" {d['hits']:>6,} {d['hit_rate']*100:>7.1f}%"
        )

    if greedy_rank:
        lines += [
            "",
            "  Greedy Generator Ranking (MAYA multi-model attack):",
            f"  {'Rank':<5} {'Generator':<25} {'Marginal':>10} {'Cumul%':>8} {'Merg':>6}",
            "  " + "-" * 58,
        ]
        for entry in greedy_rank:
            if "error" in entry:
                lines.append(f"  ERROR: {entry['error']}")
                continue
            lines.append(
                f"  {entry['rank']:<5} {entry['label']:<25}"
                f" +{entry['marginal_hits']:>8,} {entry['cumulative_rate']:>7.2f}%"
                f" {entry['mergeability']:>6.3f}"
            )

    lines += ["", "=" * 64]
    return "\n".join(lines)


def mask_distribution(
    wordlist_path: str,
    top_n: int = 20,
    max_candidates: int = 0,
) -> dict:
    """
    Calcula distribuição de masks estilo Hashcat para uma wordlist.

    Cada senha é convertida para um padrão de mask:
      ?l = letra minúscula, ?u = maiúscula, ?d = dígito, ?s = especial.

    Útil para entender se os candidatos gerados seguem os padrões reais
    encontrados em leaks de senhas (alinhado com análise PACK/pipal).

    Args:
        wordlist_path: Caminho da wordlist.
        top_n: Quantos masks mais comuns retornar.
        max_candidates: Limite de candidatos (0 = todos).

    Returns:
        Dict com: top_masks (lista de (mask, count, pct)), total_analyzed.
    """
    def _to_mask(pw: str) -> str:
        parts = []
        for ch in pw:
            if ch.islower():
                parts.append("?l")
            elif ch.isupper():
                parts.append("?u")
            elif ch.isdigit():
                parts.append("?d")
            else:
                parts.append("?s")
        return "".join(parts)

    mask_counts: Counter = Counter()
    total = 0

    wl_path = Path(wordlist_path)
    if not wl_path.exists():
        return {"error": f"not found: {wordlist_path}"}

    with wl_path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            pw = line.rstrip("\n\r")
            if not pw:
                continue
            total += 1
            mask_counts[_to_mask(pw)] += 1
            if max_candidates and total >= max_candidates:
                break

    top = [(mask, cnt, round(cnt / total * 100, 2) if total else 0.0)
           for mask, cnt in mask_counts.most_common(top_n)]

    return {
        "total_analyzed": total,
        "unique_masks": len(mask_counts),
        "top_masks": top,
    }


def stress_crc32_dedup(line_count: int = 150_000) -> dict:
    """Stress-test streaming CRC32 dedup with synthetic unique lines."""
    import time

    from embedxpl.engines.wordlists.pipeline_engine import CRC32Deduplicator

    dedup = CRC32Deduplicator()
    false_dupes = 0
    t0 = time.perf_counter()
    for i in range(line_count):
        word = f"wfh_stress_{i:07d}_{(i * 7919) % 100_003}"
        if not dedup.is_new(word):
            false_dupes += 1
    elapsed = time.perf_counter() - t0
    rate = line_count / elapsed if elapsed > 0 else 0.0
    return {
        "lines": line_count,
        "unique_emitted": dedup.count_emitted,
        "false_crc_collisions": false_dupes,
        "elapsed_secs": round(elapsed, 3),
        "lines_per_sec": round(rate, 0),
    }


def format_crc32_stress_report(result: dict) -> str:
    """Format CRC32 dedup stress test results."""
    return "\n".join([
        "=" * 60,
        "  CRC32 DEDUP STRESS TEST",
        "=" * 60,
        "",
        f"  Lines processed : {result.get('lines', 0):,}",
        f"  Unique emitted  : {result.get('unique_emitted', 0):,}",
        f"  False collisions: {result.get('false_crc_collisions', 0):,}",
        f"  Elapsed         : {result.get('elapsed_secs', 0):.3f}s",
        f"  Throughput      : {result.get('lines_per_sec', 0):,.0f} lines/s",
        "",
        "=" * 60,
    ])


def format_known_targets_report(result: dict) -> str:
    """Formata resultado de benchmark_known_targets como texto legível."""
    lines = [
        "=" * 60,
        "  PROFILE-TARGETED VALIDATION REPORT",
        "=" * 60,
        "",
        f"  Targets:   {result.get('targets_total', 0)}",
        f"  Hits:      {result.get('hits', 0)}",
        f"  Misses:    {result.get('misses', 0)}",
        f"  Hit Rate:  {result.get('hit_rate', 0) * 100:.1f}%",
        f"  Candidates checked: {result.get('candidates_checked', 0):,}",
        "",
    ]
    if result.get("first_hit_positions"):
        lines.append("  First hit positions:")
        for pw, pos in result["first_hit_positions"].items():
            lines.append(f"    #{pos:>8,}: {pw}")
        lines.append("")
    if result.get("missing_targets"):
        lines.append("  Missing targets (not in wordlist):")
        for pw in result["missing_targets"]:
            lines.append(f"    - {pw}")
        lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


def format_compare_report(results: dict[str, dict]) -> str:
    """Formata resultado de compare_generators como tabela texto."""
    lines = [
        "=" * 60,
        "  GENERATOR COMPARISON REPORT",
        "=" * 60,
        "",
        f"  {'Generator':<25} {'Unique':>10} {'Hits':>8} {'HitRate%':>10} {'Effic%':>10}",
        "  " + "-" * 57,
    ]
    for label, r in results.items():
        if "error" in r:
            lines.append(f"  {label:<25}  ERROR: {r['error']}")
        else:
            lines.append(
                f"  {label:<25} {r['unique_candidates']:>10,} {r['hits']:>8,}"
                f" {r['hit_rate']:>9.2f}% {r['efficiency']:>9.4f}%"
            )
    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


def handle_benchmark(args, ctx: dict) -> Optional[Generator[str, None, None]]:
    """CLI handler for wordlist benchmarking.

    Args:
        args: Parsed CLI arguments.
        ctx: Global execution context.

    Returns:
        Generator yielding the benchmark report, or None.
    """
    wordlist = getattr(args, "wordlist", None)
    reference = getattr(args, "reference", None)

    if not wordlist or not reference:
        logger.error("Both --wordlist and --reference are required")
        return None

    wl_path = Path(wordlist)
    ref_path = Path(reference)

    if not wl_path.exists():
        logger.error("Wordlist not found: %s", wordlist)
        return None
    if not ref_path.exists():
        logger.error("Reference set not found: %s", reference)
        return None

    result = benchmark(
        str(wl_path), str(ref_path),
        max_candidates=getattr(args, "max_candidates", 0) or 0,
        max_reference=getattr(args, "max_reference", 0) or 0,
    )

    output_json = getattr(args, "json_output", None)
    if output_json:
        out_p = Path(output_json)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with out_p.open("w", encoding="utf-8") as fh:
            json.dump(result.to_dict(), fh, indent=2, ensure_ascii=False)
        logger.info("JSON report saved: %s", output_json)

    return iter([result.describe()])
