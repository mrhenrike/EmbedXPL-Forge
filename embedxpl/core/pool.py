"""SmartPool -- adaptive thread/process pool with automatic strategy selection.

Chooses between ThreadPoolExecutor (I/O-bound) and ProcessPoolExecutor
(CPU-bound) based on the workload type. Provides a unified interface for
concurrent execution across the framework.

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

import os
import logging
import time
import threading
from concurrent.futures import (
    ThreadPoolExecutor,
    ProcessPoolExecutor,
    Future,
    as_completed,
)
from enum import Enum
from typing import Any, Callable, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)


class PoolStrategy(Enum):
    """Execution strategy for the SmartPool."""
    THREADS = "threads"
    PROCESSES = "processes"
    AUTO = "auto"


def cpu_count() -> int:
    """Return available CPU count with a sane minimum."""
    try:
        count = os.cpu_count() or 1
    except Exception:
        count = 1
    return max(1, count)


class SmartPool:
    """Adaptive pool that selects ThreadPool or ProcessPool based on workload.

    For I/O-bound work (HTTP requests, socket connections, banner grabs),
    threads are optimal because they release the GIL during I/O waits.

    For CPU-bound work (hash cracking, payload mutation, wordlist generation),
    processes bypass the GIL for true parallelism.

    Args:
        max_workers: Maximum concurrent workers. 0 = auto (cpu_count * 2 for
                     threads, cpu_count for processes).
        strategy: Execution strategy. AUTO selects based on max_workers vs
                  cpu_count heuristic.
        thread_name_prefix: Prefix for thread names (threads strategy only).
    """

    def __init__(
        self,
        max_workers: int = 0,
        strategy: PoolStrategy = PoolStrategy.AUTO,
        thread_name_prefix: str = "exf-pool",
    ):
        self._cpus = cpu_count()
        self._strategy = strategy
        self._thread_prefix = thread_name_prefix
        self._executor = None
        self._max_workers = self._resolve_workers(max_workers)
        self._resolved_strategy = self._resolve_strategy()

    def _resolve_workers(self, requested: int) -> int:
        """Determine actual worker count."""
        if requested > 0:
            return requested
        return min(self._cpus * 2, 32)

    def _resolve_strategy(self) -> PoolStrategy:
        """Choose between threads and processes based on heuristics."""
        if self._strategy != PoolStrategy.AUTO:
            return self._strategy
        if self._max_workers > self._cpus * 2:
            return PoolStrategy.PROCESSES
        return PoolStrategy.THREADS

    def _create_executor(self):
        """Lazily create the appropriate executor."""
        if self._executor is not None:
            return

        if self._resolved_strategy == PoolStrategy.PROCESSES:
            self._executor = ProcessPoolExecutor(
                max_workers=min(self._max_workers, self._cpus),
            )
            logger.debug(
                "SmartPool: ProcessPoolExecutor with %d workers (CPU-bound)",
                min(self._max_workers, self._cpus),
            )
        else:
            self._executor = ThreadPoolExecutor(
                max_workers=self._max_workers,
                thread_name_prefix=self._thread_prefix,
            )
            logger.debug(
                "SmartPool: ThreadPoolExecutor with %d workers (I/O-bound)",
                self._max_workers,
            )

    @property
    def strategy(self) -> str:
        """Active strategy name."""
        return self._resolved_strategy.value

    @property
    def max_workers(self) -> int:
        """Configured worker count."""
        return self._max_workers

    def submit(self, fn: Callable, *args, **kwargs) -> Future:
        """Submit a callable to the pool.

        Args:
            fn: Function to execute.
            *args: Positional arguments for fn.
            **kwargs: Keyword arguments for fn.

        Returns:
            Future representing the pending result.
        """
        self._create_executor()
        return self._executor.submit(fn, *args, **kwargs)

    def map_unordered(
        self,
        fn: Callable,
        items: Iterable,
        timeout_per_item: float = 0,
        on_result: Optional[Callable] = None,
        on_error: Optional[Callable] = None,
    ) -> List[Any]:
        """Execute fn for each item, collecting results as they complete.

        Args:
            fn: Callable accepting one item.
            items: Iterable of items to process.
            timeout_per_item: Per-item timeout in seconds (0 = no timeout).
            on_result: Optional callback(item, result) on success.
            on_error: Optional callback(item, exception) on failure.

        Returns:
            List of (item, result) tuples for successful executions.
        """
        self._create_executor()
        items_list = list(items)
        future_to_item = {}

        for item in items_list:
            future = self._executor.submit(fn, item)
            future_to_item[future] = item

        results = []
        for future in as_completed(future_to_item):
            item = future_to_item[future]
            try:
                if timeout_per_item > 0:
                    result = future.result(timeout=timeout_per_item)
                else:
                    result = future.result()
                results.append((item, result))
                if on_result:
                    on_result(item, result)
            except Exception as exc:
                if on_error:
                    on_error(item, exc)
                else:
                    logger.debug("SmartPool item failed: %s — %s", item, exc)

        return results

    def run_threaded_workers(
        self,
        threads_number: int,
        target_function: Callable,
        stop_event: threading.Event,
        *args,
        **kwargs,
    ) -> float:
        """Legacy-compatible threaded execution matching Exploit.run_threads() semantics.

        Creates N threads that each call target_function(stop_event, *args, **kwargs).
        Threads share a stop_event for cooperative cancellation.

        This preserves backward compatibility with existing modules that use
        LockedIterator patterns while benefiting from the SmartPool infrastructure.

        Args:
            threads_number: Number of threads to spawn.
            target_function: Worker function. Must accept (stop_event, *args, **kwargs).
            stop_event: Threading event; cleared to signal workers to stop.
            *args: Extra positional args forwarded to target_function.
            **kwargs: Extra kwargs forwarded to target_function.

        Returns:
            Elapsed wall-clock seconds.
        """
        from itertools import chain as iterchain

        threads = []
        for tid in range(int(threads_number)):
            thread = threading.Thread(
                target=target_function,
                args=tuple(iterchain((stop_event,), args)),
                kwargs=kwargs,
                name="{}-{}".format(self._thread_prefix, tid),
            )
            thread.daemon = True
            threads.append(thread)
            try:
                thread.start()
            except Exception:
                stop_event.clear()
                raise

        start = time.monotonic()
        try:
            while any(w.is_alive() for w in threads):
                for w in threads:
                    w.join(0.2)
        except KeyboardInterrupt:
            stop_event.clear()

        for t in threads:
            t.join(timeout=2.0)

        return time.monotonic() - start

    def shutdown(self, wait: bool = False) -> None:
        """Shutdown the pool executor."""
        if self._executor is None:
            return
        try:
            self._executor.shutdown(wait=wait, cancel_futures=True)
        except TypeError:
            self._executor.shutdown(wait=wait)
        self._executor = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.shutdown(wait=False)

    def __repr__(self) -> str:
        return "<SmartPool strategy={} workers={} cpus={}>".format(
            self._resolved_strategy.value, self._max_workers, self._cpus,
        )
