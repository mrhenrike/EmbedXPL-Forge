"""
maya_ranker.py - MAYA-inspired password candidate ranker with lazy torch support.

Ranks wordlist candidates by their predicted cracking probability using two backends:

  1. Torch backend (optional, GPU-capable): A shallow embedding + MLP that maps
     character-level features to a probability score, trained in-session on
     MAYA structural patterns. Loaded lazily only when torch is available.

  2. Fallback backend (always available, no deps): Pattern-frequency scoring
     using the 19 MAYA regex patterns + entropy + complexity heuristics, fully
     implemented in pure Python.

GPU usage is optional. Pass ``use_gpu=True`` only if CUDA/ROCm is available.
For VMs without CUDA passthrough, the torch backend will fall back to CPU
automatically, or you can force ``use_gpu=False``.

Public API:
  score_candidates(words, profile_hints, use_gpu, backend) -> list[ScoredCandidate]
  rank_wordlist(input_path, output_path, use_gpu, top_n, backend) -> RankResult
  train_session_model(reference_path, use_gpu) -> bool
  format_rank_report(result) -> str

References:
  MAYA: Measuring the Applicability of Yardsticks for Automated password cracking
  (arXiv 2504.16651v4, 2025)

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
import math
import re
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Lazy torch import ─────────────────────────────────────────────────────────

_torch_available: Optional[bool] = None
_torch_mod = None
_nn_mod = None


def _try_import_torch() -> bool:
    global _torch_available, _torch_mod, _nn_mod
    if _torch_available is not None:
        return _torch_available
    try:
        import torch
        import torch.nn as nn
        _torch_mod = torch
        _nn_mod = nn
        _torch_available = True
        logger.debug("maya_ranker: torch %s available", torch.__version__)
    except ImportError:
        _torch_available = False
        logger.debug("maya_ranker: torch not available, using fallback scorer")
    return _torch_available


# ── MAYA structural patterns (reuse from benchmark_suite if available) ─────────

def _load_maya_patterns() -> dict[str, re.Pattern]:
    try:
        from embedxpl.engines.wordlists.benchmark_suite import MAYA_PATTERNS
        return MAYA_PATTERNS
    except ImportError:
        pass
    return {
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


_MAYA_PATTERNS: dict[str, re.Pattern] = {}

# Pattern empirical weights from MAYA paper frequency analysis (R1-R19).
# Higher weight = pattern appears more frequently in real cracked password sets.
_PATTERN_WEIGHTS: dict[str, float] = {
    "r1": 0.18,   # all lowercase - most common
    "r5": 0.14,   # lowercase + digits
    "r6": 0.11,   # Capitalized + digits
    "r7": 0.10,   # mixed alpha + digits
    "r4": 0.08,   # all alpha mixed case
    "r10": 0.07,  # Capitalized word
    "r12": 0.06,  # alphanumeric
    "r13": 0.05,  # alpha start, digit end
    "r16": 0.04,  # Capitalized + special + digits
    "r19": 0.04,  # ends with special
    "r15": 0.03,
    "r17": 0.03,
    "r3":  0.02,  # all digits
    "r14": 0.02,
    "r18": 0.01,
    "r9":  0.01,
    "r8":  0.005,
    "r11": 0.005,
    "r2":  0.002,
}


# ── Character-level feature extraction ───────────────────────────────────────

_CHAR_CLASSES = {
    "lower": re.compile(r"[a-z]"),
    "upper": re.compile(r"[A-Z]"),
    "digit": re.compile(r"[0-9]"),
    "special": re.compile(r"[^a-zA-Z0-9]"),
}


def _extract_features(word: str) -> list[float]:
    """Extract a 12-dimensional feature vector from a password candidate.

    Features:
      0: length (normalized to [0,1] over [1,32])
      1: fraction lowercase
      2: fraction uppercase
      3: fraction digits
      4: fraction special
      5: Shannon entropy (normalized to [0,1] over [0,5])
      6: starts_with_upper
      7: ends_with_digit
      8: ends_with_special
      9: has_digit_run (2+ consecutive digits)
     10: unique_char_ratio
     11: has_leet (presence of 0/1/3/4/@/$)
    """
    if not word:
        return [0.0] * 12

    n = len(word)

    n_lower = sum(1 for c in word if c.islower())
    n_upper = sum(1 for c in word if c.isupper())
    n_digit = sum(1 for c in word if c.isdigit())
    n_spec = n - n_lower - n_upper - n_digit

    freq: dict[str, int] = {}
    for ch in word:
        freq[ch] = freq.get(ch, 0) + 1
    total = n
    entropy = -sum((c / total) * math.log2(c / total) for c in freq.values() if c > 0)

    has_digit_run = bool(re.search(r"\d{2,}", word))
    leet_chars = set("013@$!")
    has_leet = any(c in leet_chars for c in word)

    return [
        min(n / 32.0, 1.0),
        n_lower / n,
        n_upper / n,
        n_digit / n,
        n_spec / n,
        min(entropy / 5.0, 1.0),
        1.0 if word[0].isupper() else 0.0,
        1.0 if word[-1].isdigit() else 0.0,
        1.0 if not word[-1].isalnum() else 0.0,
        1.0 if has_digit_run else 0.0,
        len(set(word)) / n,
        1.0 if has_leet else 0.0,
    ]


# ── Fallback: pattern-frequency scorer (pure Python) ─────────────────────────

def _fallback_score(word: str, patterns: dict[str, re.Pattern]) -> float:
    """Score a candidate using MAYA pattern weights + entropy heuristics.

    Returns a value in [0, 1] where higher = more likely to crack successfully.
    """
    if not word:
        return 0.0

    base = 0.0
    for pat_id, pattern in patterns.items():
        if pattern.match(word):
            base += _PATTERN_WEIGHTS.get(pat_id, 0.0)

    # Bias toward common password lengths (8-12)
    length = len(word)
    if 8 <= length <= 12:
        base += 0.05
    elif length < 6:
        base -= 0.03

    # Entropy bonus: moderate entropy (1.5-3.5) is more crackable than extremes
    feats = _extract_features(word)
    entropy_norm = feats[5]
    if 0.3 <= entropy_norm <= 0.7:
        base += 0.03

    # Leet bonus (common mutation)
    if feats[11]:
        base += 0.02

    return max(0.0, min(1.0, base))


# ── Torch-based scorer (optional) ─────────────────────────────────────────────

_session_model = None  # Cached model across calls within the same process
_session_model_device = None


def _build_torch_model(input_dim: int = 12, hidden: int = 32) -> object:
    """Build a shallow MLP scorer (12 -> 32 -> 16 -> 1) using torch.nn."""
    torch = _torch_mod
    nn = _nn_mod

    class _MLP(nn.Module):  # type: ignore[misc]
        def __init__(self) -> None:
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(input_dim, hidden),
                nn.ReLU(),
                nn.Linear(hidden, 16),
                nn.ReLU(),
                nn.Linear(16, 1),
                nn.Sigmoid(),
            )

        def forward(self, x):  # type: ignore[override]
            return self.net(x).squeeze(-1)

    return _MLP()


def _torch_score_batch(words: list[str], device: str = "cpu") -> list[float]:
    """Score a batch of words using the torch MLP (session-cached model)."""
    global _session_model, _session_model_device

    torch = _torch_mod
    patterns = _get_patterns()

    if _session_model is None or _session_model_device != device:
        _session_model = _build_torch_model()
        _session_model.to(device)
        _session_model.eval()
        _session_model_device = device
        logger.debug("maya_ranker: new torch model on device=%s", device)

    features = [_extract_features(w) for w in words]

    with torch.no_grad():
        x = torch.tensor(features, dtype=torch.float32, device=device)
        scores = _session_model(x).cpu().tolist()

    # Blend with fallback pattern score for untrained model
    blended = []
    for i, word in enumerate(words):
        torch_s = scores[i] if isinstance(scores, list) else float(scores)
        pattern_s = _fallback_score(word, patterns)
        blended.append(0.4 * torch_s + 0.6 * pattern_s)

    return blended


# ── Session training ──────────────────────────────────────────────────────────

def train_session_model(
    reference_path: str,
    use_gpu: bool = False,
    max_train_samples: int = 50_000,
) -> bool:
    """Train the in-session torch model on a reference password file.

    Uses binary labels: passwords matching high-weight MAYA patterns = 1 (likely
    to crack), others = 0. Training is lightweight (few epochs, small model) and
    intended as session-level fine-tuning, not persistent model storage.

    GPU is optional. Set ``use_gpu=False`` when running inside VMs without
    CUDA passthrough or when GPU is unavailable.

    Args:
        reference_path: Path to reference passwords file (one per line).
        use_gpu: If True, attempts CUDA/ROCm; falls back to CPU on failure.
        max_train_samples: Maximum number of samples to train on.

    Returns:
        True if training succeeded, False if torch unavailable or file missing.
    """
    global _session_model, _session_model_device

    if not _try_import_torch():
        logger.info("maya_ranker: torch not available, skipping session training")
        return False

    ref = Path(reference_path)
    if not ref.is_file():
        logger.warning("maya_ranker: reference file not found: %s", reference_path)
        return False

    torch = _torch_mod
    nn = _nn_mod
    patterns = _get_patterns()

    # Determine device
    device = "cpu"
    if use_gpu:
        if torch.cuda.is_available():
            device = "cuda"
        elif hasattr(torch, "backends") and hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            device = "mps"
        else:
            logger.info("maya_ranker: GPU requested but not available, using CPU")

    # Load reference samples
    words: list[str] = []
    try:
        with ref.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                word = line.rstrip("\n")
                if 4 <= len(word) <= 32:
                    words.append(word)
                if len(words) >= max_train_samples:
                    break
    except OSError as exc:
        logger.error("maya_ranker: error reading reference file: %s", exc)
        return False

    if not words:
        logger.warning("maya_ranker: no valid samples in reference file")
        return False

    high_weight_patterns = {k for k, v in _PATTERN_WEIGHTS.items() if v >= 0.05}

    features = [_extract_features(w) for w in words]
    labels = []
    for w in words:
        hit = any(patterns[pid].match(w) for pid in high_weight_patterns if pid in patterns)
        labels.append(1.0 if hit else 0.0)

    x = torch.tensor(features, dtype=torch.float32, device=device)
    y = torch.tensor(labels, dtype=torch.float32, device=device)

    model = _build_torch_model()
    model.to(device)
    model.train()

    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.BCELoss()

    batch_size = 512
    n_epochs = 5
    n = len(words)

    for epoch in range(n_epochs):
        perm = torch.randperm(n, device=device)
        epoch_loss = 0.0
        batches = 0
        for start in range(0, n, batch_size):
            idx = perm[start: start + batch_size]
            xb, yb = x[idx], y[idx]
            optimizer.zero_grad()
            preds = model(xb)
            loss = criterion(preds, yb)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
            batches += 1
        logger.debug("maya_ranker training epoch %d/%d loss=%.4f", epoch + 1, n_epochs, epoch_loss / max(batches, 1))

    model.eval()
    _session_model = model
    _session_model_device = device
    logger.info("maya_ranker: session model trained on %d samples (device=%s)", n, device)
    return True


# ── Scored candidate container ────────────────────────────────────────────────

@dataclass
class ScoredCandidate:
    """A password candidate with its MAYA rank score."""

    word: str
    score: float
    pattern_matches: list[str] = field(default_factory=list)
    rank: int = 0


# ── Pattern cache helper ──────────────────────────────────────────────────────

def _get_patterns() -> dict[str, re.Pattern]:
    global _MAYA_PATTERNS
    if not _MAYA_PATTERNS:
        _MAYA_PATTERNS = _load_maya_patterns()
    return _MAYA_PATTERNS


# ── Public API ────────────────────────────────────────────────────────────────

def score_candidates(
    words: list[str],
    profile_hints: Optional[dict] = None,
    use_gpu: bool = False,
    backend: str = "auto",
    batch_size: int = 1024,
) -> list[ScoredCandidate]:
    """Score a list of password candidates using MAYA-inspired metrics.

    Args:
        words: Password candidates to score.
        profile_hints: Optional dict with profile keywords to boost score for
            profile-relevant candidates (e.g. {"first_name": "Andre"}).
        use_gpu: Enable GPU for torch backend. Ignored if torch not available.
            GPU is entirely optional; CPU fallback is transparent.
        backend: "torch" forces torch (fails if unavailable), "fallback" forces
            pure Python, "auto" uses torch if available else fallback.
        batch_size: Batch size for torch scoring.

    Returns:
        List of ScoredCandidate sorted by score descending.
    """
    patterns = _get_patterns()
    use_torch = False

    if backend == "torch":
        if not _try_import_torch():
            raise RuntimeError("maya_ranker: torch backend requested but torch is not installed")
        use_torch = True
    elif backend == "auto":
        use_torch = _try_import_torch()

    # Prepare profile keyword set for boosting
    boost_words: set[str] = set()
    if profile_hints:
        for val in profile_hints.values():
            if isinstance(val, str):
                boost_words.add(val.lower())
                boost_words.add(val.lower()[:4])
            elif isinstance(val, list):
                for v in val:
                    if isinstance(v, str):
                        boost_words.add(str(v).lower())

    results: list[ScoredCandidate] = []

    if use_torch:
        device = "cpu"
        if use_gpu:
            torch = _torch_mod
            if torch.cuda.is_available():
                device = "cuda"
            elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                device = "mps"

        for batch_start in range(0, len(words), batch_size):
            batch = words[batch_start: batch_start + batch_size]
            scores = _torch_score_batch(batch, device)
            for word, score in zip(batch, scores):
                pat_hits = [pid for pid, pat in patterns.items() if pat.match(word)]
                boost = 0.05 if any(bw in word.lower() for bw in boost_words) else 0.0
                results.append(ScoredCandidate(
                    word=word,
                    score=min(1.0, score + boost),
                    pattern_matches=pat_hits,
                ))
    else:
        for word in words:
            score = _fallback_score(word, patterns)
            pat_hits = [pid for pid, pat in patterns.items() if pat.match(word)]
            boost = 0.05 if any(bw in word.lower() for bw in boost_words) else 0.0
            results.append(ScoredCandidate(
                word=word,
                score=min(1.0, score + boost),
                pattern_matches=pat_hits,
            ))

    results.sort(key=lambda c: c.score, reverse=True)
    for i, sc in enumerate(results):
        sc.rank = i + 1

    return results


@dataclass
class RankResult:
    """Result of ranking a wordlist file."""

    input_path: str
    output_path: str
    total_scored: int
    top_n_written: int
    top_score: float
    bottom_score: float
    pattern_distribution: dict[str, int] = field(default_factory=dict)
    backend_used: str = "fallback"
    device_used: str = "cpu"


def rank_wordlist(
    input_path: str,
    output_path: str,
    use_gpu: bool = False,
    top_n: int = 0,
    backend: str = "auto",
    profile_hints: Optional[dict] = None,
    chunk_size: int = 10_000,
    min_score: float = 0.0,
) -> RankResult:
    """Rank a wordlist file by MAYA cracking probability.

    Reads candidates from ``input_path`` in chunks, scores them, and writes
    the top-ranked candidates to ``output_path``.

    Args:
        input_path: Path to input wordlist (one candidate per line).
        output_path: Path to write ranked candidates (highest score first).
        use_gpu: Enable GPU for torch backend (optional, transparent fallback).
        top_n: Maximum candidates to write (0 = all, filtered by min_score).
        backend: "auto", "torch", or "fallback".
        profile_hints: Optional profile dict for keyword boosting.
        chunk_size: Lines to score in memory at once.
        min_score: Minimum score threshold to include a candidate.

    Returns:
        RankResult with statistics.
    """
    in_path = Path(input_path)
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not in_path.is_file():
        raise FileNotFoundError(f"Input wordlist not found: {input_path}")

    # Determine actual backend
    actual_backend = "fallback"
    device_used = "cpu"
    if backend in ("auto", "torch") and _try_import_torch():
        actual_backend = "torch"
        if use_gpu:
            torch = _torch_mod
            if torch.cuda.is_available():
                device_used = "cuda"
            elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                device_used = "mps"

    all_scored: list[ScoredCandidate] = []
    seen_crc: set[int] = set()
    total_read = 0

    with in_path.open("r", encoding="utf-8", errors="replace") as fh:
        chunk: list[str] = []
        for line in fh:
            word = line.rstrip("\n")
            if not word or len(word) < 4 or len(word) > 64:
                continue
            crc = zlib.crc32(word.encode("utf-8", errors="replace")) & 0xFFFFFFFF
            if crc in seen_crc:
                continue
            seen_crc.add(crc)
            chunk.append(word)
            total_read += 1

            if len(chunk) >= chunk_size:
                all_scored.extend(score_candidates(
                    chunk, profile_hints=profile_hints,
                    use_gpu=use_gpu, backend=backend,
                ))
                chunk.clear()

        if chunk:
            all_scored.extend(score_candidates(
                chunk, profile_hints=profile_hints,
                use_gpu=use_gpu, backend=backend,
            ))

    # Global sort
    all_scored.sort(key=lambda c: c.score, reverse=True)
    for i, sc in enumerate(all_scored):
        sc.rank = i + 1

    # Filter by min_score
    filtered = [sc for sc in all_scored if sc.score >= min_score]

    # Apply top_n
    if top_n > 0:
        filtered = filtered[:top_n]

    # Pattern distribution
    pat_dist: dict[str, int] = {}
    for sc in filtered:
        for pid in sc.pattern_matches:
            pat_dist[pid] = pat_dist.get(pid, 0) + 1

    # Write output
    with out_path.open("w", encoding="utf-8") as out_fh:
        for sc in filtered:
            out_fh.write(sc.word + "\n")

    top_score = filtered[0].score if filtered else 0.0
    bottom_score = filtered[-1].score if filtered else 0.0

    return RankResult(
        input_path=input_path,
        output_path=output_path,
        total_scored=total_read,
        top_n_written=len(filtered),
        top_score=round(top_score, 4),
        bottom_score=round(bottom_score, 4),
        pattern_distribution=pat_dist,
        backend_used=actual_backend,
        device_used=device_used,
    )


def format_rank_report(result: RankResult) -> str:
    """Format a RankResult as a human-readable text report.

    Args:
        result: RankResult from rank_wordlist().

    Returns:
        Formatted multi-line string report.
    """
    lines = [
        "=" * 60,
        "MAYA RANKER REPORT",
        "=" * 60,
        f"Input:         {result.input_path}",
        f"Output:        {result.output_path}",
        f"Backend:       {result.backend_used} ({result.device_used})",
        f"Total scored:  {result.total_scored:,}",
        f"Written:       {result.top_n_written:,}",
        f"Score range:   {result.bottom_score:.4f} - {result.top_score:.4f}",
        "",
        "Pattern distribution (top candidates):",
    ]

    sorted_pats = sorted(result.pattern_distribution.items(), key=lambda x: x[1], reverse=True)
    for pid, count in sorted_pats[:10]:
        pct = 100.0 * count / max(result.top_n_written, 1)
        lines.append(f"  {pid:<5}  {count:>7,}  ({pct:.1f}%)")

    lines.append("=" * 60)
    return "\n".join(lines)
