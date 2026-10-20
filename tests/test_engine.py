"""Tests for embedxpl.core.engine (AsyncScanEngine)."""
from __future__ import annotations

import asyncio

import pytest

from embedxpl.core.engine import AsyncScanEngine, ScanResult


class TestScanResult:
    def test_init(self):
        r = ScanResult("10.0.0.1", 80, "http", "exploits/web/test", True)
        assert r.target == "10.0.0.1"
        assert r.port == 80
        assert r.protocol == "http"
        assert r.module_path == "exploits/web/test"
        assert r.vulnerable is True
        assert r.error is None
        assert r.elapsed_s == 0.0

    def test_repr_vulnerable(self):
        r = ScanResult("10.0.0.1", 80, "http", "mod", True, elapsed_s=1.5)
        s = repr(r)
        assert "VULN" in s
        assert "10.0.0.1" in s

    def test_repr_safe(self):
        r = ScanResult("10.0.0.1", 80, "http", "mod", False)
        assert "SAFE" in repr(r)

    def test_repr_unknown(self):
        r = ScanResult("10.0.0.1", 80, "http", "mod", None)
        assert "UNKNOWN" in repr(r)

    def test_with_error(self):
        r = ScanResult("10.0.0.1", 80, "http", "mod", None, "timeout")
        assert r.error == "timeout"


class TestAsyncScanEngine:
    def test_init_defaults(self):
        e = AsyncScanEngine()
        assert e.max_workers == 8
        assert e.module_timeout_s == 20
        assert e.delay_s == 0.0

    def test_init_custom(self):
        e = AsyncScanEngine(max_workers=4, module_timeout_s=10, delay_between_modules_s=0.5)
        assert e.max_workers == 4
        assert e.module_timeout_s == 10
        assert e.delay_s == 0.5

    def test_max_workers_min_one(self):
        e = AsyncScanEngine(max_workers=0)
        assert e.max_workers == 1

    def test_negative_delay_clamped(self):
        e = AsyncScanEngine(delay_between_modules_s=-1.0)
        assert e.delay_s == 0.0

    def test_scan_module_with_mock(self):
        from embedxpl.core.exploit.exploit import Exploit
        from embedxpl.core.exploit.option import OptIP, OptPort

        class FakeExploit(Exploit):
            __info__ = {"name": "fake"}
            target = OptIP("", "t")
            port = OptPort(80, "p")
            def check(self):
                return True
            def run(self):
                pass

        async def _run():
            engine = AsyncScanEngine(max_workers=2, module_timeout_s=5)
            engine._semaphore = asyncio.Semaphore(2)
            from concurrent.futures import ThreadPoolExecutor
            engine._executor = ThreadPoolExecutor(max_workers=2)
            result = await engine.scan_module(FakeExploit, "10.0.0.1", 80)
            engine._executor.shutdown(wait=False)
            return result

        result = asyncio.run(_run())
        assert result.vulnerable is True
        assert result.target == "10.0.0.1"

    def test_scan_all_empty_modules(self):
        async def _run():
            engine = AsyncScanEngine(max_workers=2, module_timeout_s=5)
            results = await engine.scan_all([], "10.0.0.1", 80)
            return results

        results = asyncio.run(_run())
        assert results == []

    def test_scan_module_exception(self):
        from embedxpl.core.exploit.exploit import Exploit
        from embedxpl.core.exploit.option import OptIP, OptPort

        class FailingExploit(Exploit):
            __info__ = {"name": "fail"}
            target = OptIP("", "t")
            port = OptPort(80, "p")
            def check(self):
                raise RuntimeError("boom")
            def run(self):
                pass

        async def _run():
            engine = AsyncScanEngine(max_workers=2, module_timeout_s=5)
            engine._semaphore = asyncio.Semaphore(2)
            from concurrent.futures import ThreadPoolExecutor
            engine._executor = ThreadPoolExecutor(max_workers=2)
            result = await engine.scan_module(FailingExploit, "10.0.0.1", 80)
            engine._executor.shutdown(wait=False)
            return result

        result = asyncio.run(_run())
        assert result.vulnerable is None
        assert "boom" in (result.error or "")
