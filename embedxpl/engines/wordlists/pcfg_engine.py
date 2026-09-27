"""
pcfg_engine.py - Probabilistic Context-Free Grammar password generator.

Trains a grammar from a password corpus, decomposing passwords into
terminal classes (alpha, digit, special, keyboard-walk fragments) and
learning probability distributions for each production rule. Generates
candidates in approximate probability order using a priority queue.

Based on research by Matt Weir et al. (IEEE S&P 2009) with optimizations
from PCFG Cracker v4.x.

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import heapq
import json
import logging
import math
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

_DIGIT_RE = re.compile(r"\d+")
_ALPHA_RE = re.compile(r"[A-Za-z]+")
_SPECIAL_RE = re.compile(r"[^A-Za-z0-9]+")

_CAPITALIZATION_PATTERNS = {
    "all_lower": lambda s: s == s.lower(),
    "all_upper": lambda s: s == s.upper() and s != s.lower(),
    "capitalize": lambda s: s == s.capitalize() and len(s) > 1,
    "mixed": lambda _: True,
}

# ── Detection rules leves (pcfg_cracker parity) ─────────────────────────────

_KB_ROWS: list[str] = [
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]

# Precomputed adjacency pairs (both directions, lowercase)
_KB_ADJACENT: frozenset[tuple[str, str]] = frozenset(
    pair
    for row in _KB_ROWS
    for i in range(len(row) - 1)
    for pair in [(row[i], row[i + 1]), (row[i + 1], row[i])]
)

_LEET_CHARS: frozenset[str] = frozenset("013456789@$!|+")
_LEET_DETECT_MAP: dict[str, str] = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "@": "a", "$": "s", "!": "i",
}

_YEAR_RE = re.compile(r"^(19[0-9]{2}|20[0-2][0-9]|2030)$")
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"
)
_WEBSITE_RE = re.compile(
    r"(^www\.|^https?://|\.com|\.br|\.org|\.net|\.io|\.gov)",
    re.IGNORECASE,
)
_PHONE_RE = re.compile(r"^\+?[0-9]{7,15}$")


def detect_keyboard_walk(segment: str, min_run: int = 3) -> bool:
    """Detect QWERTY/QWERTZ/AZERTY keyboard walk patterns in a segment.

    Returns True if there is a run of at least *min_run* characters where
    every consecutive pair is horizontally adjacent on a keyboard row.
    """
    low = segment.lower()
    if len(low) < min_run:
        return False
    run = 1
    for i in range(1, len(low)):
        if (low[i - 1], low[i]) in _KB_ADJACENT:
            run += 1
            if run >= min_run:
                return True
        else:
            run = 1
    return False


def detect_leet(segment: str) -> bool:
    """Detect if segment contains leet-speak substitutions.

    Checks for: 0->o, 1->i, 3->e, 4->a, 5->s, @->a, $->s, !->i.
    """
    return any(ch in _LEET_DETECT_MAP for ch in segment)


def detect_year(segment: str) -> bool:
    """Detect if segment is a 4-digit year in range 1900-2030."""
    return bool(_YEAR_RE.match(segment.strip()))


def detect_email(password: str) -> bool:
    """Detect if password matches email pattern (user@domain.tld)."""
    return bool(_EMAIL_RE.match(password.strip()))


def detect_website(password: str) -> bool:
    """Detect if password matches website pattern (www., http, .com, .br, .org)."""
    return bool(_WEBSITE_RE.search(password))


def detect_phone(segment: str) -> bool:
    """Detect if segment is a phone number (7-15 digits, may start with +)."""
    return bool(_PHONE_RE.match(segment.strip()))


def tag_segments(password: str) -> list[dict]:
    """Tag each segment of a password with detection results.

    Splits the password into contiguous alpha / digit / special segments,
    then applies all detection rules and assigns a primary type tag.

    Returns:
        List of dicts with keys:
          - ``segment``: the raw segment string
          - ``type``: primary type char (L=alpha, D=digit, S=special)
          - ``detected_tags``: list of secondary tag chars applied
              K=keyboard_walk, Y=year, E=email, W=website

    Note: E and W tags are only applied to the full password (not sub-segments).
    """
    results: list[dict] = []
    i = 0
    pw = password

    # Full-password level tags
    full_tags: list[str] = []
    if detect_email(pw):
        full_tags.append("E")
    elif detect_website(pw):
        full_tags.append("W")

    while i < len(pw):
        if pw[i].isalpha():
            j = i
            while j < len(pw) and pw[j].isalpha():
                j += 1
            seg = pw[i:j]
            tags: list[str] = []
            if detect_keyboard_walk(seg):
                tags.append("K")
            if full_tags:
                tags.extend(full_tags)
            results.append({"segment": seg, "type": "L", "detected_tags": tags})
            i = j
        elif pw[i].isdigit():
            j = i
            while j < len(pw) and pw[j].isdigit():
                j += 1
            seg = pw[i:j]
            tags = []
            if detect_year(seg):
                tags.append("Y")
            if detect_keyboard_walk(seg):
                tags.append("K")
            if full_tags:
                tags.extend(full_tags)
            results.append({"segment": seg, "type": "D", "detected_tags": tags})
            i = j
        else:
            j = i
            while j < len(pw) and not pw[j].isalpha() and not pw[j].isdigit():
                j += 1
            seg = pw[i:j]
            results.append({"segment": seg, "type": "S", "detected_tags": list(full_tags)})
            i = j

    return results


class PCFGGrammar:
    """Probabilistic context-free grammar for password generation.

    The grammar decomposes passwords into structural templates (e.g., L4D3S1)
    and learns terminal distributions for each class+length pair.
    """

    def __init__(self) -> None:
        self.structure_counts: Counter = Counter()
        self.terminals: dict[str, Counter] = defaultdict(Counter)
        self.cap_patterns: dict[str, Counter] = defaultdict(Counter)
        self.total_trained: int = 0

    def _classify_segment(self, segment: str) -> tuple[str, str, str]:
        """Classify a password segment into (class, length_key, normalized).

        Returns:
            Tuple of (class_char, class+len key, normalized_value).
        """
        if segment.isdigit():
            return "D", f"D{len(segment)}", segment
        if segment.isalpha():
            cap = "all_lower"
            for name, check in _CAPITALIZATION_PATTERNS.items():
                if check(segment):
                    cap = name
                    break
            return "L", f"L{len(segment)}", segment.lower()
        return "S", f"S{len(segment)}", segment

    def _decompose(
        self,
        password: str,
        use_detection: bool = False,
    ) -> tuple[str, list[tuple[str, str, str]]]:
        """Decompose a password into structural template and segments.

        When *use_detection* is True, segment boundaries and capitalization
        hints come from :func:`tag_segments` (keyboard walk, leet, year tags).

        Returns:
            Tuple of (template_string, list of (class, key, value) tuples).
        """
        if use_detection:
            return self._decompose_detected(password)

        segments: list[tuple[str, str, str]] = []
        template_parts: list[str] = []

        i = 0
        while i < len(password):
            if password[i].isalpha():
                j = i
                while j < len(password) and password[j].isalpha():
                    j += 1
                seg = password[i:j]
                cls, key, norm = self._classify_segment(seg)
                cap = "all_lower"
                for name, check in _CAPITALIZATION_PATTERNS.items():
                    if check(seg):
                        cap = name
                        break
                segments.append((key, norm, cap))
                template_parts.append(f"L{j - i}")
                i = j
            elif password[i].isdigit():
                j = i
                while j < len(password) and password[j].isdigit():
                    j += 1
                seg = password[i:j]
                segments.append((f"D{j - i}", seg, ""))
                template_parts.append(f"D{j - i}")
                i = j
            else:
                j = i
                while j < len(password) and not password[j].isalpha() and not password[j].isdigit():
                    j += 1
                seg = password[i:j]
                segments.append((f"S{j - i}", seg, ""))
                template_parts.append(f"S{j - i}")
                i = j

        template = "".join(template_parts)
        return template, segments

    def _decompose_detected(
        self,
        password: str,
    ) -> tuple[str, list[tuple[str, str, str]]]:
        """Decompose using :func:`tag_segments` detection rules."""
        segments: list[tuple[str, str, str]] = []
        template_parts: list[str] = []

        for item in tag_segments(password):
            seg = item["segment"]
            typ = item["type"]
            tags = item.get("detected_tags") or []

            if typ == "L":
                cls, key, norm = self._classify_segment(seg)
                if "K" in tags:
                    cap = "keyboard_walk"
                elif detect_leet(seg):
                    cap = "leet"
                else:
                    cap = "all_lower"
                    for name, check in _CAPITALIZATION_PATTERNS.items():
                        if check(seg):
                            cap = name
                            break
                segments.append((key, norm, cap))
                template_parts.append(f"L{len(seg)}")
            elif typ == "D":
                segments.append((f"D{len(seg)}", seg, ""))
                template_parts.append(f"D{len(seg)}")
            else:
                segments.append((f"S{len(seg)}", seg, ""))
                template_parts.append(f"S{len(seg)}")

        return "".join(template_parts), segments

    def train(self, password: str, use_detection: bool = False) -> None:
        """Train the grammar on a single password."""
        password = password.strip()
        if not password or len(password) < 2:
            return

        template, segments = self._decompose(password, use_detection=use_detection)
        self.structure_counts[template] += 1

        for key, value, cap in segments:
            self.terminals[key][value] += 1
            if cap:
                self.cap_patterns[key][cap] += 1

        self.total_trained += 1

    def train_from_file(self, filepath: str, max_lines: int = 0) -> dict:
        """Train from a password file (one password per line).

        Args:
            filepath: Path to the password file.
            max_lines: Maximum lines to process (0 = unlimited).

        Returns:
            Training statistics dict.
        """
        processed = 0
        skipped = 0
        path = Path(filepath)

        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                pw = line.rstrip("\n\r")
                if not pw:
                    skipped += 1
                    continue
                if ":" in pw:
                    pw = pw.split(":", 1)[-1]
                self.train(pw)
                processed += 1
                if max_lines and processed >= max_lines:
                    break

        return {
            "processed": processed,
            "skipped": skipped,
            "structures": len(self.structure_counts),
            "terminal_classes": len(self.terminals),
        }

    def _get_sorted_structures(self) -> list[tuple[str, float]]:
        """Return structures sorted by probability (descending)."""
        total = sum(self.structure_counts.values())
        if total == 0:
            return []
        return sorted(
            [(s, c / total) for s, c in self.structure_counts.items()],
            key=lambda x: -x[1],
        )

    def _get_sorted_terminals(self, key: str) -> list[tuple[str, float]]:
        """Return terminals for a class sorted by probability (descending)."""
        counter = self.terminals.get(key, Counter())
        total = sum(counter.values())
        if total == 0:
            return []
        return sorted(
            [(t, c / total) for t, c in counter.items()],
            key=lambda x: -x[1],
        )

    def _apply_capitalization(self, word: str, key: str) -> list[str]:
        """Apply learned capitalization patterns to a lowercase word."""
        cap_dist = self.cap_patterns.get(key, Counter())
        if not cap_dist:
            return [word]

        total = sum(cap_dist.values())
        variants = set()

        for pattern, count in cap_dist.most_common(4):
            if count / total < 0.02:
                break
            if pattern == "all_lower":
                variants.add(word.lower())
            elif pattern == "all_upper":
                variants.add(word.upper())
            elif pattern == "capitalize":
                variants.add(word.capitalize())
            elif pattern == "mixed":
                variants.add(word.lower())
                variants.add(word.capitalize())

        if not variants:
            variants.add(word)

        return list(variants)

    def generate(
        self,
        max_candidates: int = 0,
        min_length: int = 1,
        max_length: int = 64,
        top_structures: int = 0,
        top_terminals: int = 0,
    ) -> Generator[str, None, None]:
        """Generate password candidates in approximate probability order.

        Uses a priority queue to emit the most probable candidates first.
        For each structure template, expands terminals by probability and
        combines them via cartesian product with early cutoff.

        Args:
            max_candidates: Maximum candidates to generate (0 = unlimited).
            min_length: Minimum password length.
            max_length: Maximum password length.
            top_structures: Limit structures to top N (0 = all).
            top_terminals: Limit terminals per class to top N (0 = all).

        Yields:
            Password candidates in approximate probability order.
        """
        structures = self._get_sorted_structures()
        if top_structures:
            structures = structures[:top_structures]

        seen: set[str] = set()
        count = 0

        heap: list[tuple[float, int, str]] = []
        batch_id = 0

        for struct_str, struct_prob in structures:
            segments = re.findall(r"[LDS]\d+", struct_str)
            if not segments:
                continue

            terminal_lists: list[list[tuple[str, float]]] = []
            skip = False
            for seg_key in segments:
                terminals = self._get_sorted_terminals(seg_key)
                if not terminals:
                    skip = True
                    break
                if top_terminals:
                    terminals = terminals[:top_terminals]
                terminal_lists.append(terminals)

            if skip:
                continue

            neg_log_struct = -math.log(max(struct_prob, 1e-15))

            def _expand(
                depth: int,
                current: list[str],
                cum_neg_log: float,
                seg_keys: list[str],
            ):
                nonlocal batch_id
                if depth == len(terminal_lists):
                    candidate_base = "".join(current)
                    cap_variants = [candidate_base]
                    for idx, seg_key in enumerate(seg_keys):
                        if seg_key.startswith("L"):
                            new_variants = []
                            for v in cap_variants:
                                parts = re.findall(r"[LDS]\d+", struct_str)
                                offset = sum(
                                    int(p[1:]) for p in parts[:idx]
                                )
                                seg_len = int(seg_key[1:])
                                prefix = v[:offset]
                                seg_text = v[offset:offset + seg_len]
                                suffix = v[offset + seg_len:]
                                for cap_v in self._apply_capitalization(seg_text, seg_key):
                                    new_variants.append(prefix + cap_v + suffix)
                            cap_variants = new_variants

                    for variant in cap_variants:
                        if min_length <= len(variant) <= max_length:
                            heapq.heappush(heap, (cum_neg_log, batch_id, variant))
                            batch_id += 1
                    return

                for term_val, term_prob in terminal_lists[depth]:
                    term_neg_log = -math.log(max(term_prob, 1e-15))
                    current.append(term_val)
                    _expand(
                        depth + 1, current,
                        cum_neg_log + term_neg_log,
                        seg_keys,
                    )
                    current.pop()

            _expand(0, [], neg_log_struct, segments)

        while heap:
            _, _, candidate = heapq.heappop(heap)
            if candidate in seen:
                continue
            seen.add(candidate)
            yield candidate
            count += 1
            if max_candidates and count >= max_candidates:
                return

    def save(self, filepath: str) -> str:
        """Serialize grammar to JSON."""
        data = {
            "version": "1.0.0",
            "total_trained": self.total_trained,
            "structures": dict(self.structure_counts.most_common()),
            "terminals": {k: dict(v.most_common()) for k, v in self.terminals.items()},
            "cap_patterns": {k: dict(v.most_common()) for k, v in self.cap_patterns.items()},
        }
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=1)
        return str(path)

    def load(self, filepath: str) -> None:
        """Load grammar from JSON."""
        path = Path(filepath)
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)

        self.total_trained = data.get("total_trained", 0)
        self.structure_counts = Counter(data.get("structures", {}))
        self.terminals = defaultdict(Counter)
        for k, v in data.get("terminals", {}).items():
            self.terminals[k] = Counter(v)
        self.cap_patterns = defaultdict(Counter)
        for k, v in data.get("cap_patterns", {}).items():
            self.cap_patterns[k] = Counter(v)

    def describe(self) -> str:
        """Return a human-readable summary of the grammar."""
        lines = [
            "PCFG Grammar Summary",
            f"  Trained on        : {self.total_trained:,} passwords",
            f"  Structures        : {len(self.structure_counts):,}",
            f"  Terminal classes   : {len(self.terminals):,}",
        ]
        top = self.structure_counts.most_common(10)
        if top:
            lines.append("  Top structures:")
            total = sum(self.structure_counts.values())
            for struct, cnt in top:
                pct = cnt / total * 100
                lines.append(f"    {struct:25s} {pct:6.2f}%  ({cnt:,})")
        return "\n".join(lines)


def handle_pcfg(args, ctx: dict) -> Optional[Generator[str, None, None]]:
    """CLI handler: train or generate using PCFG grammar.

    Args:
        args: Parsed CLI arguments.
        ctx: Global execution context.

    Returns:
        Generator yielding password candidates, or None.
    """
    action = getattr(args, "pcfg_action", "generate")
    grammar = PCFGGrammar()

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
            stats = grammar.train_from_file(str(path),
                                            max_lines=getattr(args, "max_lines", 0))
            logger.info("Trained %s: %d passwords, %d structures",
                        path.name, stats["processed"], stats["structures"])

        out = getattr(args, "model_output", None) or ".model/pcfg_grammar.json"
        saved = grammar.save(out)
        logger.info("Grammar saved: %s", saved)
        return iter([grammar.describe()])

    model_path = getattr(args, "model", None) or ".model/pcfg_grammar.json"
    p = Path(model_path)
    if not p.exists():
        logger.error("Grammar file not found: %s - train first with `pcfg train`", model_path)
        return None

    grammar.load(str(p))
    logger.info("Loaded PCFG grammar: %s (%d structures, %d terminal classes)",
                p.name, len(grammar.structure_counts), len(grammar.terminals))

    return grammar.generate(
        max_candidates=getattr(args, "limit", 0) or 0,
        min_length=getattr(args, "min_len", 1),
        max_length=getattr(args, "max_len", 64),
        top_structures=getattr(args, "top_structures", 0) or 0,
        top_terminals=getattr(args, "top_terminals", 0) or 0,
    )
