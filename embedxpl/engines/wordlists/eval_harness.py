"""
eval_harness.py - Guess-number and coverage evaluation, and list curation.

Two capabilities in the spirit of the MAYA benchmark and weakpass ranking:

- ``evaluate`` compares one or more candidate lists (each representing an engine
  such as pcfg, markov, neural, or a static list) against a reference test set,
  reporting coverage, guess numbers and cumulative hits at configurable cutoffs.
- ``curate`` ranks candidate lists by crack rate against a reference and merges
  the best performing lists into a single deduplicated wordlist.

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)


def _load_set(path: str, max_lines: int = 0) -> set[str]:
    """Load a file into a set of stripped entries."""
    out: set[str] = set()
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"file not found: {path}")
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            e = line.rstrip("\n\r")
            if e:
                out.add(e)
            if max_lines and len(out) >= max_lines:
                break
    return out


def evaluate_candidates(
    candidate_paths: list[str],
    reference_path: str,
    labels: Optional[list[str]] = None,
    cutoffs: Optional[list[int]] = None,
    max_candidates: int = 0,
    max_reference: int = 0,
) -> dict:
    """Evaluate candidate lists against a reference test set.

    Args:
        candidate_paths: Ordered candidate list files.
        reference_path: Reference (ground-truth) password file.
        labels: Optional labels for each candidate list.
        cutoffs: Guess-count cutoffs for cumulative hit reporting.
        max_candidates: Max lines to read per candidate (0 = all).
        max_reference: Max reference entries (0 = all).

    Returns:
        Results dict keyed by label with coverage and cumulative hits.
    """
    cutoffs = cutoffs or [1_000, 10_000, 100_000, 1_000_000, 10_000_000]
    reference = _load_set(reference_path, max_reference)
    total_ref = len(reference)
    labels = labels or [Path(p).stem for p in candidate_paths]

    results: dict[str, dict] = {}
    for path, label in zip(candidate_paths, labels):
        p = Path(path)
        if not p.exists():
            logger.warning("candidate not found: %s", path)
            continue
        found_rank: dict[str, int] = {}
        rank = 0
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                cand = line.rstrip("\n\r")
                if not cand:
                    continue
                rank += 1
                if cand in reference and cand not in found_rank:
                    found_rank[cand] = rank
                if max_candidates and rank >= max_candidates:
                    break
        cumulative = {}
        ranks = sorted(found_rank.values())
        for cut in cutoffs:
            cumulative[cut] = sum(1 for r in ranks if r <= cut)
        hits = len(found_rank)
        results[label] = {
            "candidates_read": rank,
            "hits": hits,
            "coverage": (hits / total_ref) if total_ref else 0.0,
            "cumulative": cumulative,
            "median_guess": ranks[len(ranks) // 2] if ranks else 0,
        }
    return {"reference_total": total_ref, "cutoffs": cutoffs, "engines": results}


def format_evaluation(report: dict) -> list[str]:
    """Format an evaluation report as aligned text lines."""
    lines = [
        f"Reference set: {report['reference_total']:,} passwords",
        "",
    ]
    cutoffs = report["cutoffs"]
    header = f"{'engine':16s} {'read':>12s} {'hits':>10s} {'coverage':>9s} "
    header += " ".join(f"@{c:<10,}" for c in cutoffs)
    lines.append(header)
    lines.append("-" * len(header))
    for label, r in report["engines"].items():
        row = (
            f"{label:16.16s} {r['candidates_read']:>12,} {r['hits']:>10,} "
            f"{r['coverage'] * 100:>8.2f}% "
        )
        row += " ".join(f"{r['cumulative'][c]:<11,}" for c in cutoffs)
        lines.append(row)
    return lines


def curate_lists(
    candidate_paths: list[str],
    reference_path: str,
    metric: str = "hitrate",
    top_k: int = 2,
    max_reference: int = 0,
) -> dict:
    """Rank candidate lists by crack rate and pick the best.

    Args:
        candidate_paths: Candidate list files.
        reference_path: Reference password file.
        metric: ``hitrate`` (hits per line) or ``hits`` (absolute).
        top_k: Number of top lists to keep for merging.
        max_reference: Max reference entries (0 = all).

    Returns:
        Dict with the ranking and the selected files.
    """
    reference = _load_set(reference_path, max_reference)
    ranking: list[dict] = []
    for path in candidate_paths:
        p = Path(path)
        if not p.exists():
            logger.warning("candidate not found: %s", path)
            continue
        lines = 0
        hits: set[str] = set()
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                c = line.rstrip("\n\r")
                if not c:
                    continue
                lines += 1
                if c in reference:
                    hits.add(c)
        hitrate = (len(hits) / lines) if lines else 0.0
        ranking.append({
            "path": path,
            "lines": lines,
            "hits": len(hits),
            "hitrate": hitrate,
        })
    key = "hitrate" if metric == "hitrate" else "hits"
    ranking.sort(key=lambda x: x[key], reverse=True)
    selected = [r["path"] for r in ranking[: max(1, top_k)]]
    return {"ranking": ranking, "selected": selected}


def merge_selected(selected: list[str]) -> Generator[str, None, None]:
    """Yield deduplicated entries from the selected files, in selection order."""
    seen: set[str] = set()
    for path in selected:
        p = Path(path)
        if not p.exists():
            continue
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                e = line.rstrip("\n\r")
                if e and e not in seen:
                    seen.add(e)
                    yield e


def handle_evaluate(args, ctx: dict):
    """CLI handler for the ``evaluate`` command.

    Returns:
        A tuple ('lines', iterator) or None on error.
    """
    candidates = getattr(args, "candidates", None) or []
    reference = getattr(args, "reference", None)
    if not candidates or not reference:
        logger.error("evaluate requires --candidates FILE ... and --reference FILE")
        return None
    labels_raw = getattr(args, "labels", None)
    labels = [s.strip() for s in labels_raw.split(",")] if labels_raw else None
    cutoffs_raw = getattr(args, "cutoffs", None)
    cutoffs = None
    if cutoffs_raw:
        cutoffs = [int(float(c)) for c in cutoffs_raw.split(",") if c.strip()]
    try:
        report = evaluate_candidates(
            candidates, reference, labels, cutoffs,
            max_candidates=int(getattr(args, "max_candidates", 0) or 0),
            max_reference=int(getattr(args, "max_reference", 0) or 0),
        )
    except FileNotFoundError as exc:
        logger.error(str(exc))
        return None
    return ("lines", iter(format_evaluation(report)))


def handle_curate(args, ctx: dict):
    """CLI handler for the ``curate`` command.

    Returns:
        A tuple ('curate', (ranking_lines, merge_generator_or_None)) or None.
    """
    candidates = getattr(args, "candidates", None) or []
    reference = getattr(args, "reference", None)
    if not candidates or not reference:
        logger.error("curate requires --candidates FILE ... and --reference FILE")
        return None
    try:
        result = curate_lists(
            candidates, reference,
            metric=getattr(args, "metric", "hitrate") or "hitrate",
            top_k=int(getattr(args, "top_k", 2) or 2),
            max_reference=int(getattr(args, "max_reference", 0) or 0),
        )
    except FileNotFoundError as exc:
        logger.error(str(exc))
        return None
    lines = ["Curation ranking (best first):",
             f"{'list':40s} {'lines':>12s} {'hits':>10s} {'hitrate':>10s}"]
    for r in result["ranking"]:
        lines.append(
            f"{Path(r['path']).name:40.40s} {r['lines']:>12,} "
            f"{r['hits']:>10,} {r['hitrate'] * 100:>9.4f}%"
        )
    lines.append("")
    lines.append("Selected: " + ", ".join(Path(s).name for s in result["selected"]))
    merge_gen = merge_selected(result["selected"])
    return ("curate", (lines, merge_gen))
