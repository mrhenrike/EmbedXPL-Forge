"""Comprehensive tests for config.py, pool.py, completion.py, hw_profiler.py,
hardware.py, multi_lang_module.py, banner.py, and related infra modules."""

import json
import os
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ── Config ──

class TestConfig:
    def setup_method(self):
        from embedxpl.core import config
        config.reset_cache()
        self._orig_file = config._CONFIG_FILE

    def teardown_method(self):
        from embedxpl.core import config
        config._CONFIG_FILE = self._orig_file
        config.reset_cache()

    def test_defaults_exist(self):
        from embedxpl.core.config import _DEFAULTS
        assert "compute_mode" in _DEFAULTS
        assert "output_format" in _DEFAULTS
        assert "max_threads" in _DEFAULTS

    def test_get_default(self):
        from embedxpl.core import config
        config._CONFIG_FILE = Path("/nonexistent/path.json")
        config.reset_cache()
        assert config.get("compute_mode") == "auto"
        assert config.get("max_threads") == 10

    def test_get_with_fallback(self):
        from embedxpl.core import config
        config._CONFIG_FILE = Path("/nonexistent/path.json")
        config.reset_cache()
        assert config.get("nonexistent_key", "fallback") == "fallback"

    def test_set_val_valid(self):
        from embedxpl.core import config
        config._CONFIG_FILE = Path("/nonexistent/path.json")
        config.reset_cache()
        config.set_val("compute_mode", "gpu", persist=False)
        assert config.get("compute_mode") == "gpu"

    def test_set_val_invalid_constrained(self):
        from embedxpl.core import config
        config._CONFIG_FILE = Path("/nonexistent/path.json")
        config.reset_cache()
        with pytest.raises(ValueError):
            config.set_val("compute_mode", "quantum", persist=False)

    def test_set_val_unconstrained(self):
        from embedxpl.core import config
        config._CONFIG_FILE = Path("/nonexistent/path.json")
        config.reset_cache()
        config.set_val("custom_key", "custom_value", persist=False)
        assert config.get("custom_key") == "custom_value"

    def test_load_from_file(self, tmp_path):
        from embedxpl.core import config
        cfg_file = tmp_path / "test_config.json"
        cfg_file.write_text(json.dumps({"compute_mode": "cpu", "max_threads": 20}))
        config._CONFIG_FILE = cfg_file
        config.reset_cache()
        assert config.get("compute_mode") == "cpu"
        assert config.get("max_threads") == 20

    def test_load_corrupt_file(self, tmp_path):
        from embedxpl.core import config
        cfg_file = tmp_path / "bad.json"
        cfg_file.write_text("not json!")
        config._CONFIG_FILE = cfg_file
        config.reset_cache()
        assert config.get("compute_mode") == "auto"

    def test_env_override_bool(self, monkeypatch):
        from embedxpl.core import config
        config._CONFIG_FILE = Path("/nonexistent/path.json")
        config.reset_cache()
        monkeypatch.setenv("EXF_COLOR", "false")
        config.reset_cache()
        assert config.get("color") is False

    def test_env_override_int(self, monkeypatch):
        from embedxpl.core import config
        config._CONFIG_FILE = Path("/nonexistent/path.json")
        config.reset_cache()
        monkeypatch.setenv("EXF_MAX_THREADS", "50")
        config.reset_cache()
        assert config.get("max_threads") == 50

    def test_env_override_string(self, monkeypatch):
        from embedxpl.core import config
        config._CONFIG_FILE = Path("/nonexistent/path.json")
        config.reset_cache()
        monkeypatch.setenv("EXF_DEFAULT_WORKSPACE", "production")
        config.reset_cache()
        assert config.get("default_workspace") == "production"

    def test_env_invalid_int(self, monkeypatch):
        from embedxpl.core import config
        config._CONFIG_FILE = Path("/nonexistent/path.json")
        config.reset_cache()
        monkeypatch.setenv("EXF_MAX_THREADS", "not_a_number")
        config.reset_cache()
        assert config.get("max_threads") == 10

    def test_validate_clean(self):
        from embedxpl.core import config
        config._CONFIG_FILE = Path("/nonexistent/path.json")
        config.reset_cache()
        warnings = config.validate()
        assert warnings == []

    def test_validate_bad_value(self):
        from embedxpl.core import config
        config._CONFIG_FILE = Path("/nonexistent/path.json")
        config.reset_cache()
        config._load()["compute_mode"] = "quantum"
        warnings = config.validate()
        assert any("compute_mode" in w for w in warnings)

    def test_validate_max_threads_bounds(self):
        from embedxpl.core import config
        config._CONFIG_FILE = Path("/nonexistent/path.json")
        config.reset_cache()
        config._load()["max_threads"] = 999
        warnings = config.validate()
        assert any("max_threads" in w for w in warnings)

    def test_validate_timeout_negative(self):
        from embedxpl.core import config
        config._CONFIG_FILE = Path("/nonexistent/path.json")
        config.reset_cache()
        config._load()["timeout_s"] = -1
        warnings = config.validate()
        assert any("timeout_s" in w for w in warnings)

    def test_all_values(self):
        from embedxpl.core import config
        config._CONFIG_FILE = Path("/nonexistent/path.json")
        config.reset_cache()
        vals = config.all_values()
        assert isinstance(vals, dict)
        assert "compute_mode" in vals

    def test_config_path(self):
        from embedxpl.core import config
        p = config.config_path()
        assert isinstance(p, Path)

    def test_save(self, tmp_path):
        from embedxpl.core import config
        cfg_file = tmp_path / "save_test.json"
        config._CONFIG_FILE = cfg_file
        config.reset_cache()
        config.set_val("custom", "value", persist=True)
        assert cfg_file.exists()
        data = json.loads(cfg_file.read_text())
        assert data["custom"] == "value"


# ── Pool ──

class TestPoolStrategy:
    def test_enum_values(self):
        from embedxpl.core.pool import PoolStrategy
        assert PoolStrategy.THREADS.value == "threads"
        assert PoolStrategy.PROCESSES.value == "processes"
        assert PoolStrategy.AUTO.value == "auto"


class TestCpuCount:
    def test_returns_positive(self):
        from embedxpl.core.pool import cpu_count
        assert cpu_count() >= 1

    def test_fallback_on_exception(self):
        from embedxpl.core.pool import cpu_count
        with patch("os.cpu_count", side_effect=Exception("fail")):
            assert cpu_count() == 1

    def test_none_returns_1(self):
        from embedxpl.core.pool import cpu_count
        with patch("os.cpu_count", return_value=None):
            assert cpu_count() == 1


class TestSmartPool:
    def test_default_init(self):
        from embedxpl.core.pool import SmartPool
        pool = SmartPool()
        assert pool._executor is None
        assert pool.max_workers > 0

    def test_explicit_workers(self):
        from embedxpl.core.pool import SmartPool
        pool = SmartPool(max_workers=5)
        assert pool.max_workers == 5

    def test_auto_workers(self):
        from embedxpl.core.pool import SmartPool
        pool = SmartPool(max_workers=0)
        assert pool.max_workers > 0

    def test_threads_strategy(self):
        from embedxpl.core.pool import SmartPool, PoolStrategy
        pool = SmartPool(strategy=PoolStrategy.THREADS)
        assert pool.strategy == "threads"

    def test_processes_strategy(self):
        from embedxpl.core.pool import SmartPool, PoolStrategy
        pool = SmartPool(strategy=PoolStrategy.PROCESSES)
        assert pool.strategy == "processes"

    def test_auto_strategy_low_workers(self):
        from embedxpl.core.pool import SmartPool, PoolStrategy
        pool = SmartPool(max_workers=2, strategy=PoolStrategy.AUTO)
        assert pool.strategy == "threads"

    def test_submit_creates_executor(self):
        from embedxpl.core.pool import SmartPool
        pool = SmartPool(max_workers=2)
        assert pool._executor is None
        future = pool.submit(lambda: 42)
        assert pool._executor is not None
        assert future.result() == 42
        pool.shutdown()

    def test_map_unordered(self):
        from embedxpl.core.pool import SmartPool
        pool = SmartPool(max_workers=2)
        results = pool.map_unordered(lambda x: x * 2, [1, 2, 3])
        items = {item for item, _ in results}
        values = {val for _, val in results}
        assert items == {1, 2, 3}
        assert values == {2, 4, 6}
        pool.shutdown()

    def test_map_unordered_with_callbacks(self):
        from embedxpl.core.pool import SmartPool
        pool = SmartPool(max_workers=2)
        successes = []
        pool.map_unordered(
            lambda x: x + 1, [10, 20],
            on_result=lambda item, res: successes.append((item, res)),
        )
        assert len(successes) == 2
        pool.shutdown()

    def test_map_unordered_error_callback(self):
        from embedxpl.core.pool import SmartPool
        pool = SmartPool(max_workers=2)
        errors = []

        def fail(x):
            raise ValueError("boom")

        pool.map_unordered(
            fail, [1],
            on_error=lambda item, exc: errors.append((item, str(exc))),
        )
        assert len(errors) == 1
        assert "boom" in errors[0][1]
        pool.shutdown()

    def test_context_manager(self):
        from embedxpl.core.pool import SmartPool
        with SmartPool(max_workers=2) as pool:
            f = pool.submit(lambda: "ok")
            assert f.result() == "ok"

    def test_shutdown_before_use(self):
        from embedxpl.core.pool import SmartPool
        pool = SmartPool()
        pool.shutdown()

    def test_repr(self):
        from embedxpl.core.pool import SmartPool
        pool = SmartPool(max_workers=4)
        r = repr(pool)
        assert "SmartPool" in r
        assert "workers=4" in r

    def test_run_threaded_workers(self):
        from embedxpl.core.pool import SmartPool
        pool = SmartPool(max_workers=2)
        results = []
        stop = threading.Event()
        stop.set()

        def worker(stop_event):
            results.append(threading.current_thread().name)

        elapsed = pool.run_threaded_workers(2, worker, stop)
        assert elapsed >= 0
        assert len(results) == 2
        pool.shutdown()


# ── Completion ──

class TestCompletion:
    def test_build_parser(self):
        from embedxpl.core.completion import build_parser
        parser = build_parser()
        assert parser is not None
        assert parser.prog == "exf"

    def test_get_module_completions(self):
        from embedxpl.core.completion import get_module_completions
        modules = ["exploits/routers/a", "exploits/routers/b", "creds/database"]
        result = get_module_completions("exploits/routers/", modules)
        assert len(result) == 2

    def test_get_module_completions_empty(self):
        from embedxpl.core.completion import get_module_completions
        result = get_module_completions("xxx", ["a", "b"])
        assert result == []

    def test_enable_completion_no_argcomplete(self):
        from embedxpl.core.completion import enable_completion
        enable_completion()


# ── HW Profiler ──

class TestGPUDevice:
    def test_summary(self):
        from embedxpl.core.hw_profiler import GPUDevice
        gpu = GPUDevice(
            name="RTX 4090", vendor="nvidia", vram_mb=24576,
            driver="535.129", compute_cap="8.9", backend="cuda",
        )
        s = gpu.summary()
        assert "RTX 4090" in s
        assert "24576 MB" in s
        assert "cuda" in s

    def test_summary_no_vram(self):
        from embedxpl.core.hw_profiler import GPUDevice
        gpu = GPUDevice(name="GPU", vendor="other", backend="opencl")
        s = gpu.summary()
        assert "unknown VRAM" in s


class TestHWProfile:
    def test_has_gpu_false(self):
        from embedxpl.core.hw_profiler import HWProfile
        p = HWProfile()
        assert p.has_gpu() is False

    def test_has_gpu_true(self):
        from embedxpl.core.hw_profiler import HWProfile, GPUDevice
        p = HWProfile(gpus=[GPUDevice(name="G", vendor="v", backend="b")])
        assert p.has_gpu() is True

    def test_gpu_summary_none(self):
        from embedxpl.core.hw_profiler import HWProfile
        assert HWProfile().gpu_summary() == "No GPU detected"

    def test_gpu_summary_with_gpu(self):
        from embedxpl.core.hw_profiler import HWProfile, GPUDevice
        p = HWProfile(gpus=[GPUDevice(name="RTX", vendor="nvidia", vram_mb=8192, backend="cuda")])
        s = p.gpu_summary()
        assert "RTX" in s
        assert "8192MB" in s

    def test_one_liner(self):
        from embedxpl.core.hw_profiler import HWProfile
        p = HWProfile(cpu_model="i9", cpu_threads=16, ram_total_mb=32768)
        line = p.one_liner()
        assert "i9" in line
        assert "16T" in line
        assert "32768MB" in line

    def test_one_liner_auto_mode(self):
        from embedxpl.core.hw_profiler import HWProfile
        p = HWProfile(compute_mode="auto")
        assert "auto->cpu" in p.one_liner()


# ── Hardware ──

class TestHWReq:
    def test_enum_values(self):
        from embedxpl.core.hardware import HWReq
        assert HWReq.WIFI_MONITOR == "wifi_monitor_mode"
        assert HWReq.BLE_ADAPTER == "ble_adapter"
        assert HWReq.UART_ADAPTER == "uart_ttl_adapter"

    def test_all_have_descriptions(self):
        from embedxpl.core.hardware import HWReq, HARDWARE_DESCRIPTIONS
        for member in HWReq:
            assert member in HARDWARE_DESCRIPTIONS

    def test_all_have_examples(self):
        from embedxpl.core.hardware import HWReq, HARDWARE_EXAMPLES
        for member in HWReq:
            assert member in HARDWARE_EXAMPLES
            ex = HARDWARE_EXAMPLES[member]
            assert "product_name" in ex
            assert "chipset" in ex


# ── MultiLangModule ──

class TestMultiLangModule:
    def test_workspace_tmp(self):
        from embedxpl.core.multi_lang_module import _workspace_tmp
        tmp = _workspace_tmp()
        assert tmp.exists()

    def test_run_c_source_missing(self):
        from embedxpl.core.multi_lang_module import MultiLangModule
        m = MultiLangModule()
        result = m.run_c_source("/definitely/nonexistent/file.c")
        assert "error" in result
        assert result["returncode"] == -1

    def test_run_c_source_no_compiler(self):
        from embedxpl.core.multi_lang_module import MultiLangModule
        m = MultiLangModule()
        with patch("shutil.which", return_value=None):
            result = m.run_c_source(__file__)
        assert "error" in result


# ── Banner ──

class TestBanner:
    def test_tool_banners_mapping(self):
        from embedxpl.core.banner import TOOL_BANNERS
        assert "embedxpl" in TOOL_BANNERS
        assert "industrialxpl" in TOOL_BANNERS
        for key, path in TOOL_BANNERS.items():
            assert isinstance(path, Path)

    def test_color_constants(self):
        from embedxpl.core import banner
        assert banner._CYAN.startswith("\033[")
        assert banner._GREEN.startswith("\033[")
