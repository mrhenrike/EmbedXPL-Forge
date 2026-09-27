"""
markov_engine.py - OMEN-style positional Markov chain password generator.

Learns character transition probabilities per position from a training
corpus, then generates candidates in ascending "cost" order (lowest cost =
highest probability). Inspired by OMEN (Ordered Markov ENumerator) from
RUB-SysSec.

Key differences from classic Markov:
  - Per-position n-gram tables (position-aware transitions)
  - Integer cost system (0-10) for fast comparison
  - Length-cost factor for penalizing very long/short candidates
  - Ordered enumeration via priority queue

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import heapq
import json
import logging
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

COST_LEVELS = 10
INITIAL_TOKEN = "\x02"
END_TOKEN = "\x03"


class MarkovModel:
    """Positional Markov model with integer cost enumeration."""

    def __init__(self, order: int = 3, smoothing: float = 0.01) -> None:
        self.order: int = order
        self.smoothing: float = max(0.0, smoothing)
        self.ngrams: dict[int, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
        self.length_dist: Counter = Counter()
        self.total_trained: int = 0
        self.alphabet: set[str] = set()

    def train(self, password: str) -> None:
        """Train on a single password."""
        password = password.strip()
        if not password or len(password) < 2:
            return

        self.length_dist[len(password)] += 1
        self.total_trained += 1

        padded = INITIAL_TOKEN * self.order + password + END_TOKEN
        for i in range(len(padded) - self.order):
            context = padded[i:i + self.order]
            next_char = padded[i + self.order]
            pos = min(i, 20)
            self.ngrams[pos][context][next_char] += 1

        self.alphabet.update(password)

    def train_from_file(self, filepath: str, max_lines: int = 0) -> dict:
        """Train from a password file.

        Args:
            filepath: Path to password file.
            max_lines: Maximum lines to process (0 = unlimited).

        Returns:
            Training statistics.
        """
        processed = 0
        path = Path(filepath)
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                pw = line.rstrip("\n\r")
                if not pw:
                    continue
                if ":" in pw:
                    pw = pw.split(":", 1)[-1]
                self.train(pw)
                processed += 1
                if max_lines and processed >= max_lines:
                    break

        return {
            "processed": processed,
            "positions": len(self.ngrams),
            "alphabet_size": len(self.alphabet),
        }

    def _cost(self, pos: int, context: str, char: str) -> int:
        """Compute integer cost (0 = most probable, COST_LEVELS = least/unseen).

        The cost is derived from the rank of the character among transitions
        from the given context at the given position.
        """
        capped_pos = min(pos, 20)
        counter = self.ngrams.get(capped_pos, {}).get(context, Counter())
        alpha = self.smoothing
        vocab_size = max(len(self.alphabet) + 2, 36)
        total = sum(counter.values()) if counter else 0
        count = counter.get(char, 0) if counter else 0
        prob = (count + alpha) / (total + alpha * vocab_size)
        cost = max(0, min(COST_LEVELS, int(-math.log2(max(prob, 1e-15)) * COST_LEVELS / 16)))
        return cost

    def _length_cost(self, length: int) -> int:
        """Cost penalty based on length distribution."""
        total = sum(self.length_dist.values())
        if total == 0:
            return 0
        alpha = self.smoothing
        vocab_size = max(len(self.length_dist) + 1, 16)
        count = self.length_dist.get(length, 0)
        prob = (count + alpha) / (total + alpha * vocab_size)
        return max(0, min(COST_LEVELS, int(-math.log2(max(prob, 1e-15)) * COST_LEVELS / 8)))

    def generate(
        self,
        max_candidates: int = 0,
        min_length: int = 4,
        max_length: int = 16,
        max_cost: int = 0,
    ) -> Generator[str, None, None]:
        """Generate passwords in ascending cost order.

        Uses a priority queue (min-heap) with beam search to enumerate
        candidates from lowest to highest cost.

        Args:
            max_candidates: Maximum candidates (0 = unlimited).
            min_length: Minimum password length.
            max_length: Maximum password length.
            max_cost: Maximum total cost threshold (0 = no limit).

        Yields:
            Password strings in approximate probability order.
        """
        if not self.ngrams:
            return

        sorted_alpha = sorted(self.alphabet)
        if not sorted_alpha:
            return

        initial_context = INITIAL_TOKEN * self.order
        heap: list[tuple[int, int, str, str]] = []
        seq_id = 0

        for char in sorted_alpha:
            cost = self._cost(0, initial_context, char)
            heapq.heappush(heap, (cost, seq_id, char, initial_context[1:] + char))
            seq_id += 1

        seen: set[str] = set()
        count = 0
        beam_limit = 5_000_000

        while heap and (beam_limit > 0):
            beam_limit -= 1
            total_cost, _, current, context = heapq.heappop(heap)

            if max_cost and total_cost > max_cost:
                continue

            cur_len = len(current)

            if cur_len >= min_length:
                end_cost = self._cost(cur_len, context, END_TOKEN)
                candidate_cost = total_cost + end_cost + self._length_cost(cur_len)

                if not max_cost or candidate_cost <= max_cost:
                    if current not in seen:
                        seen.add(current)
                        yield current
                        count += 1
                        if max_candidates and count >= max_candidates:
                            return

            if cur_len < max_length:
                pos = cur_len
                for char in sorted_alpha:
                    ext_cost = self._cost(pos, context, char)
                    new_total = total_cost + ext_cost
                    if max_cost and new_total > max_cost * 1.5:
                        continue
                    next_ctx = context[1:] + char if len(context) >= self.order else context + char
                    heapq.heappush(heap, (new_total, seq_id, current + char, next_ctx))
                    seq_id += 1

    def save(self, filepath: str) -> str:
        """Serialize model to JSON."""
        data = {
            "version": "1.0.0",
            "order": self.order,
            "smoothing": self.smoothing,
            "total_trained": self.total_trained,
            "alphabet": sorted(self.alphabet),
            "length_dist": dict(self.length_dist),
            "ngrams": {},
        }
        for pos, contexts in self.ngrams.items():
            pos_key = str(pos)
            data["ngrams"][pos_key] = {}
            for ctx, counter in contexts.items():
                data["ngrams"][pos_key][ctx] = dict(counter.most_common(50))

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, separators=(",", ":"))
        return str(path)

    def load(self, filepath: str) -> None:
        """Load model from JSON."""
        path = Path(filepath)
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)

        self.order = data.get("order", 3)
        self.smoothing = float(data.get("smoothing", 0.01))
        self.total_trained = data.get("total_trained", 0)
        self.alphabet = set(data.get("alphabet", []))
        self.length_dist = Counter({int(k): v for k, v in data.get("length_dist", {}).items()})
        self.ngrams = defaultdict(lambda: defaultdict(Counter))
        for pos_key, contexts in data.get("ngrams", {}).items():
            pos = int(pos_key)
            for ctx, counts in contexts.items():
                self.ngrams[pos][ctx] = Counter(counts)

    def describe(self) -> str:
        """Return a summary of the model."""
        total_ngrams = sum(
            sum(c.total() for c in contexts.values())
            for contexts in self.ngrams.values()
        )
        lines = [
            "Markov Model Summary",
            f"  Trained on       : {self.total_trained:,} passwords",
            f"  Order (n-gram)   : {self.order}",
            f"  Alphabet size    : {len(self.alphabet)}",
            f"  Positions tracked: {len(self.ngrams)}",
            f"  Total n-grams    : {total_ngrams:,}",
        ]
        if self.length_dist:
            top_lens = self.length_dist.most_common(5)
            total = sum(self.length_dist.values())
            lines.append("  Top lengths:")
            for length, cnt in top_lens:
                lines.append(f"    {length:3d} chars: {cnt / total * 100:5.1f}%")
        return "\n".join(lines)


def handle_markov(args, ctx: dict) -> Optional[Generator[str, None, None]]:
    """CLI handler: train or generate using Markov model.

    Args:
        args: Parsed CLI arguments.
        ctx: Global execution context.

    Returns:
        Generator yielding password candidates, or None.
    """
    action = getattr(args, "markov_action", "generate")
    order = getattr(args, "order", 3) or 3
    smoothing = getattr(args, "smoothing", 0.01) or 0.01
    model = MarkovModel(order=order, smoothing=smoothing)

    if action == "train":
        sources = getattr(args, "wordlist", None) or []
        if not sources:
            logger.error("No training files provided (--wordlist)")
            return None

        for src in sources:
            path = Path(src)
            if not path.exists():
                logger.warning("File not found: %s", src)
                continue
            stats = model.train_from_file(str(path),
                                          max_lines=getattr(args, "max_lines", 0))
            logger.info("Trained %s: %d passwords", path.name, stats["processed"])

        out = getattr(args, "model_output", None) or ".model/markov_model.json"
        saved = model.save(out)
        logger.info("Model saved: %s", saved)
        return iter([model.describe()])

    model_path = getattr(args, "model", None) or ".model/markov_model.json"
    p = Path(model_path)
    if not p.exists():
        logger.error("Markov model not found: %s - train first with `markov train`", model_path)
        return None

    model.load(str(p))
    logger.info("Loaded Markov model: %s (%d trained, order %d)",
                p.name, model.total_trained, model.order)

    return model.generate(
        max_candidates=getattr(args, "limit", 0) or 0,
        min_length=getattr(args, "min_len", 4),
        max_length=getattr(args, "max_len", 16),
        max_cost=getattr(args, "max_cost", 0) or 0,
    )
