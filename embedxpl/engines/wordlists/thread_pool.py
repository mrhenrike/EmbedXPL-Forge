"""
thread_pool.py - Smart thread pool for parallel wordlist generation in WFH.

Provides a SmartPool abstraction with:
  - Thread count validation (1-300)
  - Consumption warnings (>50 → WARNING, >100 → ALERT)
  - Automatic throttle based on available CPU threads
  - Optional progress tracking via callbacks
  - Drop-in replacement for direct ThreadPoolExecutor use

Adapted from RouterXPL-Forge patterns (github.com/mrhenrike/RouterXPL-Forge).

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
import os
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Any, Callable, Generator, Iterable, Optional

logger = logging.getLogger(__name__)

# ── Thread count constants ────────────────────────────────────────────────────

MIN_THREADS        = 1
MAX_THREADS        = 300
DEFAULT_THREADS    = 5
WARN_THRESHOLD     = 50    # → WARNING message
ALERT_THRESHOLD    = 100   # → ALERT message (high resource consumption)
CRITICAL_THRESHOLD = 200   # → CRITICAL warning (may destabilize system)


def validate_thread_count(
    n:        int,
    clamp:    bool = True,
    silent:   bool = False,
) -> int:
    """
    Validate and optionally clamp thread count to [MIN_THREADS, MAX_THREADS].

    Prints consumption warnings for high counts.

    Args:
        n: Requested thread count.
        clamp: If True, clamp to [MIN_THREADS, MAX_THREADS] instead of raising.
        silent: If True, suppress warning messages.

    Returns:
        Validated (and possibly clamped) thread count.

    Raises:
        ValueError: If n is out of range and clamp=False.
    """
    if n < MIN_THREADS or n > MAX_THREADS:
        if clamp:
            clamped = max(MIN_THREADS, min(MAX_THREADS, n))
            if not silent:
                logger.warning(
                    "Thread count %d out of range [%d, %d]. Clamped to %d.",
                    n, MIN_THREADS, MAX_THREADS, clamped,
                )
            return clamped
        raise ValueError(
            f"Thread count {n} out of range [{MIN_THREADS}, {MAX_THREADS}]."
        )

    cpu_logical = os.cpu_count() or 1

    if n >= CRITICAL_THRESHOLD and not silent:
        print(
            f"\033[91m[CRITICAL]\033[0m Thread count {n} is extremely high "
            f"({n}/{cpu_logical} CPU logical threads). "
            "May destabilize system or trigger OOM. Proceed with caution."
        )
    elif n >= ALERT_THRESHOLD and not silent:
        print(
            f"\033[93m[ALERT]\033[0m Thread count {n} is very high "
            f"({n}/{cpu_logical} CPU logical threads). "
            "High RAM and CPU consumption expected."
        )
    elif n >= WARN_THRESHOLD and not silent:
        logger.warning(
            "Thread count %d exceeds recommended limit (%d). "
            "Monitor system resources.",
            n, WARN_THRESHOLD,
        )

    return n


# ── SmartPool ─────────────────────────────────────────────────────────────────

class SmartPool:
    """
    Thread pool for parallel wordlist generation with validation and monitoring.

    Usage:
        pool = SmartPool(threads=10)
        results = list(pool.map(my_fn, items))
        pool.shutdown()

    Context manager:
        with SmartPool(threads=8) as pool:
            for result in pool.map(fn, items):
                ...
    """

    def __init__(
        self,
        threads:             int = DEFAULT_THREADS,
        thread_name_prefix:  str = "wfh-pool",
        silent_validation:   bool = False,
    ) -> None:
        """
        Initialize SmartPool.

        Args:
            threads: Number of worker threads (1-300).
            thread_name_prefix: Prefix for worker thread names.
            silent_validation: Suppress thread count warnings.
        """
        self._threads  = validate_thread_count(threads, clamp=True, silent=silent_validation)
        self._prefix   = thread_name_prefix
        self._executor: Optional[ThreadPoolExecutor] = None
        self._lock     = threading.Lock()
        self._active   = True

    @property
    def threads(self) -> int:
        return self._threads

    def _get_executor(self) -> ThreadPoolExecutor:
        with self._lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=self._threads,
                    thread_name_prefix=self._prefix,
                )
        return self._executor

    def submit(self, fn: Callable, *args, **kwargs) -> Future:
        """
        Submit a single callable for execution.

        Args:
            fn: Callable to execute.
            *args, **kwargs: Arguments forwarded to fn.

        Returns:
            Future representing the result.
        """
        return self._get_executor().submit(fn, *args, **kwargs)

    def map(
        self,
        fn:       Callable,
        items:    Iterable,
        timeout:  Optional[float] = None,
    ) -> Generator:
        """
        Map fn over items using the thread pool, yielding results as they complete.

        Args:
            fn: Callable applied to each item.
            items: Iterable of items to process.
            timeout: Per-item timeout in seconds (None = no timeout).

        Yields:
            Results in completion order (not input order).
        """
        executor = self._get_executor()
        futures  = {executor.submit(fn, item): item for item in items}

        for future in as_completed(futures, timeout=timeout):
            try:
                yield future.result()
            except Exception as exc:
                logger.error("Worker error for item %r: %s", futures[future], exc)

    def map_ordered(
        self,
        fn:    Callable,
        items: list,
    ) -> list:
        """
        Map fn over items and return results in INPUT order.

        Args:
            fn: Callable applied to each item.
            items: List of items.

        Returns:
            List of results in the same order as items.
        """
        results = [None] * len(items)
        executor = self._get_executor()

        futures = {executor.submit(fn, item): idx for idx, item in enumerate(items)}
        for future in as_completed(futures):
            idx = futures[future]
            try:
                results[idx] = future.result()
            except Exception as exc:
                logger.error("Worker error at index %d: %s", idx, exc)
                results[idx] = None

        return results

    def run_parallel_generators(
        self,
        generators: list[Callable[[], Iterable[str]]],
        dedup:      bool = True,
    ) -> Generator[str, None, None]:
        """
        Run multiple generator functions in parallel and yield their outputs.

        Used for parallel wordlist generation across multiple names/domains.

        Args:
            generators: List of zero-arg callables that return iterables of strings.
            dedup: If True, deduplicate across all generator outputs.

        Yields:
            Strings from all generators in completion order.
        """
        seen: set[str] = set()
        executor = self._get_executor()

        futures = [executor.submit(lambda g=gen: list(g())) for gen in generators]
        for future in as_completed(futures):
            try:
                results = future.result() or []
                for val in results:
                    if dedup:
                        if val not in seen:
                            seen.add(val)
                            yield val
                    else:
                        yield val
            except Exception as exc:
                logger.error("Generator worker error: %s", exc)

    def shutdown(self, wait: bool = True) -> None:
        """Shutdown the thread pool, optionally waiting for pending tasks."""
        with self._lock:
            if self._executor:
                self._executor.shutdown(wait=wait)
                self._executor = None
        self._active = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.shutdown()


# ── Parallel wordlist generation helper ───────────────────────────────────────

def parallel_generate(
    generator_fn: Callable[[Any], Iterable[str]],
    items:        list,
    threads:      int = DEFAULT_THREADS,
    dedup:        bool = True,
    progress_cb:  Optional[Callable[[int, int], None]] = None,
) -> Generator[str, None, None]:
    """
    Run generator_fn(item) in parallel for each item, yielding merged results.

    This is the main entry point for parallel wordlist generation.
    If threads=1, runs serially (no pool overhead).

    Args:
        generator_fn: Function that takes one item and returns an iterable of strings.
        items: List of items to process (e.g., list of names).
        threads: Number of parallel workers.
        dedup: Deduplicate output across all items.
        progress_cb: Optional callback(done, total) called after each item completes.

    Yields:
        Wordlist strings from all items.
    """
    threads = validate_thread_count(threads, clamp=True)
    total   = len(items)

    if threads == 1 or total == 1:
        # Serial path - no overhead
        seen: set[str] = set()
        for i, item in enumerate(items):
            for val in generator_fn(item):
                if dedup:
                    if val not in seen:
                        seen.add(val)
                        yield val
                else:
                    yield val
            if progress_cb:
                progress_cb(i + 1, total)
        return

    # Parallel path
    seen2: set[str] = set()
    done_count = 0

    with SmartPool(threads=threads, thread_name_prefix="wfh-gen") as pool:
        futures = {pool.submit(lambda x=item: list(generator_fn(x))): i
                   for i, item in enumerate(items)}

        for future in as_completed(futures):
            done_count += 1
            try:
                batch = future.result() or []
                for val in batch:
                    if dedup:
                        if val not in seen2:
                            seen2.add(val)
                            yield val
                    else:
                        yield val
            except Exception as exc:
                logger.error("parallel_generate worker failed: %s", exc)

            if progress_cb:
                progress_cb(done_count, total)


def recommend_threads(cpu_bound: bool = True) -> int:
    """
    Recommend a safe thread count for the current machine.

    Args:
        cpu_bound: True for CPU-heavy tasks; False for I/O-bound (allows more threads).

    Returns:
        Recommended thread count.
    """
    logical = os.cpu_count() or 1
    if cpu_bound:
        return max(1, min(logical, 16))
    else:
        return max(1, min(logical * 4, 64))
