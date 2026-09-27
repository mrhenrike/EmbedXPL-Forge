"""AsyncScanEngine -- concurrent module execution via asyncio + ThreadPoolExecutor.

Wraps existing synchronous exploit modules (check/run) inside
``loop.run_in_executor`` so hundreds of modules can be dispatched
concurrently without blocking the event loop.

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, List, Optional

logger = logging.getLogger(__name__)


class ScanResult:
    """Outcome of a single module execution against one target."""

    __slots__ = (
        "target", "port", "protocol", "module_path",
        "vulnerable", "error", "elapsed_s",
    )

    def __init__(
        self,
        target: str,
        port: int,
        protocol: str,
        module_path: str,
        vulnerable: Optional[bool],
        error: Optional[str] = None,
        elapsed_s: float = 0.0,
    ):
        self.target = target
        self.port = port
        self.protocol = protocol
        self.module_path = module_path
        self.vulnerable = vulnerable
        self.error = error
        self.elapsed_s = elapsed_s

    def __repr__(self) -> str:
        status = "VULN" if self.vulnerable else ("SAFE" if self.vulnerable is False else "UNKNOWN")
        return "<ScanResult {}:{} {} {} {:.2f}s>".format(
            self.target, self.port, self.module_path, status, self.elapsed_s,
        )


class AsyncScanEngine:
    """Execute exploit modules concurrently using asyncio + ThreadPoolExecutor.

    Existing modules are synchronous (blocking I/O via ``requests``, ``paramiko``).
    This engine wraps each module's ``check()`` / ``run()`` inside
    ``loop.run_in_executor()`` so that many modules run in parallel on the
    thread pool while asyncio manages scheduling, timeouts and cancellation.

    Args:
        max_workers: Maximum concurrent module executions (maps to Semaphore value
                     AND ThreadPoolExecutor worker count).
        module_timeout_s: Per-module timeout in seconds. 0 disables timeout.
        delay_between_modules_s: Optional delay injected after each module
                                 completes (useful for stealth/polite modes).
    """

    def __init__(
        self,
        max_workers: int = 8,
        module_timeout_s: int = 20,
        delay_between_modules_s: float = 0.0,
    ):
        self.max_workers: int = max(1, max_workers)
        self.module_timeout_s: int = module_timeout_s
        self.delay_s: float = max(0.0, delay_between_modules_s)
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._executor: Optional[ThreadPoolExecutor] = None
        self._results: List[ScanResult] = []
        self._cancelled: bool = False
        self._start_time: float = 0.0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _exec_in_pool(self, fn: Callable, timeout: float = 0) -> Any:
        """Run *fn* in the thread-pool executor with optional timeout."""
        loop = asyncio.get_running_loop()
        if timeout > 0:
            return await asyncio.wait_for(
                loop.run_in_executor(self._executor, fn),
                timeout=timeout,
            )
        return await loop.run_in_executor(self._executor, fn)

    async def _check_module(self, exploit: Any) -> Optional[bool]:
        """Run ``exploit.check()`` in the thread pool."""
        timeout = float(self.module_timeout_s) if self.module_timeout_s > 0 else 0
        try:
            return await self._exec_in_pool(exploit.check, timeout)
        except asyncio.TimeoutError:
            raise RuntimeError(
                "check() timed out after {}s".format(self.module_timeout_s)
            )

    async def _run_module(self, exploit: Any) -> None:
        """Run ``exploit.run()`` in the thread pool (longer timeout)."""
        timeout = float(self.module_timeout_s * 3) if self.module_timeout_s > 0 else 0
        try:
            await self._exec_in_pool(exploit.run, timeout)
        except asyncio.TimeoutError:
            raise RuntimeError(
                "run() timed out after {}s".format(self.module_timeout_s * 3)
            )

    # ------------------------------------------------------------------
    # Public API -- single module
    # ------------------------------------------------------------------

    async def scan_module(
        self,
        module_class: type,
        target: str,
        port: int,
        configure_fn: Optional[Callable] = None,
        confirm_passes: int = 1,
        run_on_vulnerable: bool = False,
    ) -> ScanResult:
        """Execute one module against one target, respecting the semaphore.

        Args:
            module_class: Exploit class to instantiate.
            target: Target IP / hostname.
            port: Target port.
            configure_fn: Optional ``callable(exploit_instance)`` to set extra
                          options (ssl, protocol overrides, etc.) before execution.
            confirm_passes: How many consecutive ``check() == True`` results are
                            required to confirm vulnerability.
            run_on_vulnerable: If True, call ``exploit.run()`` when confirmed
                               vulnerable (useful for non-AutoPwn single-module
                               execution).

        Returns:
            ScanResult with outcome.
        """
        async with self._semaphore:
            if self._cancelled:
                return ScanResult(target, port, "", str(module_class), None, "cancelled")

            t0 = time.monotonic()
            module_path = ""
            protocol = "custom"
            try:
                exploit = module_class()
                exploit.target = target
                exploit.port = port
                if configure_fn:
                    configure_fn(exploit)

                module_path = str(exploit)
                protocol = getattr(exploit, "target_protocol", "custom")

                result = await self._check_module(exploit)

                if result is True and confirm_passes > 1:
                    for _ in range(confirm_passes - 1):
                        if await self._check_module(exploit) is not True:
                            result = None
                            break

                if result is True and run_on_vulnerable:
                    await self._run_module(exploit)

                elapsed = time.monotonic() - t0
                if self.delay_s > 0:
                    await asyncio.sleep(self.delay_s)
                return ScanResult(target, port, protocol, module_path, result, elapsed_s=elapsed)

            except Exception as err:
                elapsed = time.monotonic() - t0
                logger.debug("Module %s failed: %s", module_path or module_class, err)
                return ScanResult(target, port, protocol, module_path or str(module_class), None, str(err), elapsed)

    # ------------------------------------------------------------------
    # Public API -- batch scan
    # ------------------------------------------------------------------

    async def scan_all(
        self,
        modules: List[type],
        target: str,
        port: int,
        configure_fn: Optional[Callable] = None,
        confirm_passes: int = 1,
        run_on_vulnerable: bool = False,
        on_result: Optional[Callable] = None,
    ) -> List[ScanResult]:
        """Scan one target with multiple modules concurrently.

        Args:
            modules: List of exploit classes.
            target: Target IP / hostname.
            port: Target port.
            configure_fn: Optional configurator callback.
            confirm_passes: Confirmation passes per module.
            run_on_vulnerable: Run exploit payload on confirmed vulns.
            on_result: Optional ``callback(result, completed, total)`` fired
                       as each module finishes.

        Returns:
            List of ScanResult (order may differ from input).
        """
        self._semaphore = asyncio.Semaphore(self.max_workers)
        self._executor = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="exf-scan",
        )
        self._results = []
        self._cancelled = False
        self._start_time = time.monotonic()

        tasks = [
            asyncio.create_task(
                self.scan_module(
                    mc, target, port, configure_fn, confirm_passes, run_on_vulnerable,
                )
            )
            for mc in modules
        ]

        completed = 0
        total = len(tasks)

        for coro in asyncio.as_completed(tasks):
            try:
                result = await coro
            except Exception as err:
                result = ScanResult(target, port, "", "unknown", None, str(err))

            self._results.append(result)
            completed += 1

            if on_result:
                try:
                    on_result(result, completed, total)
                except Exception:
                    pass

        self._shutdown_executor()
        return self._results

    async def scan_targets(
        self,
        modules: List[type],
        targets: List[str],
        port: int,
        configure_fn: Optional[Callable] = None,
        confirm_passes: int = 1,
        run_on_vulnerable: bool = False,
        on_result: Optional[Callable] = None,
    ) -> List[ScanResult]:
        """Scan multiple targets with multiple modules concurrently.

        Flattens all (module x target) combinations into a single async pool.

        Args:
            modules: List of exploit classes.
            targets: List of target IPs / hostnames.
            port: Target port.
            configure_fn: Optional configurator callback.
            confirm_passes: Confirmation passes per module.
            run_on_vulnerable: Run exploit payload on confirmed vulns.
            on_result: Optional ``callback(result, completed, total)`` fired
                       per module completion.

        Returns:
            Aggregated list of ScanResult.
        """
        self._semaphore = asyncio.Semaphore(self.max_workers)
        self._executor = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="exf-scan",
        )
        self._results = []
        self._cancelled = False
        self._start_time = time.monotonic()

        tasks = []
        for t in targets:
            for mc in modules:
                tasks.append(
                    asyncio.create_task(
                        self.scan_module(
                            mc, t, port, configure_fn, confirm_passes, run_on_vulnerable,
                        )
                    )
                )

        completed = 0
        total = len(tasks)

        for coro in asyncio.as_completed(tasks):
            try:
                result = await coro
            except Exception as err:
                result = ScanResult("?", port, "", "unknown", None, str(err))

            self._results.append(result)
            completed += 1

            if on_result:
                try:
                    on_result(result, completed, total)
                except Exception:
                    pass

        self._shutdown_executor()
        return self._results

    # ------------------------------------------------------------------
    # Control
    # ------------------------------------------------------------------

    def _shutdown_executor(self) -> None:
        """Shutdown the thread pool without blocking on running threads."""
        if self._executor is None:
            return
        import sys
        if sys.version_info >= (3, 9):
            self._executor.shutdown(wait=False, cancel_futures=True)
        else:
            self._executor.shutdown(wait=False)

    def cancel(self) -> None:
        """Signal pending (not yet started) tasks to skip execution."""
        self._cancelled = True

    @property
    def elapsed(self) -> float:
        """Wall-clock seconds since the current scan started."""
        if self._start_time:
            return time.monotonic() - self._start_time
        return 0.0

    # ------------------------------------------------------------------
    # Sync entry point (for existing CLI / interpreter)
    # ------------------------------------------------------------------

    def run_sync(
        self,
        modules: List[type],
        target: str,
        port: int,
        **kwargs,
    ) -> List[ScanResult]:
        """Synchronous wrapper around :meth:`scan_all`.

        Creates its own event loop; safe to call from blocking code
        (EmbedXPLInterpreter, CLI, scripts).

        Args:
            modules: List of exploit classes.
            target: Target IP / hostname.
            port: Target port.
            **kwargs: Forwarded to :meth:`scan_all`.

        Returns:
            List of ScanResult.
        """
        try:
            asyncio.get_running_loop()
            in_loop = True
        except RuntimeError:
            in_loop = False

        if in_loop:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    asyncio.run,
                    self.scan_all(modules, target, port, **kwargs),
                )
                return future.result()

        return asyncio.run(self.scan_all(modules, target, port, **kwargs))

    def run_sync_multi(
        self,
        modules: List[type],
        targets: List[str],
        port: int,
        **kwargs,
    ) -> List[ScanResult]:
        """Synchronous wrapper around :meth:`scan_targets`.

        Args:
            modules: List of exploit classes.
            targets: List of target IPs / hostnames.
            port: Target port.
            **kwargs: Forwarded to :meth:`scan_targets`.

        Returns:
            List of ScanResult.
        """
        try:
            asyncio.get_running_loop()
            in_loop = True
        except RuntimeError:
            in_loop = False

        if in_loop:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    asyncio.run,
                    self.scan_targets(modules, targets, port, **kwargs),
                )
                return future.result()

        return asyncio.run(self.scan_targets(modules, targets, port, **kwargs))
