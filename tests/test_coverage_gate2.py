"""Gate-2 coverage tests for EmbedXPL-Forge core modules."""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# embedxpl.version
# ---------------------------------------------------------------------------

def test_version_attrs() -> None:
    from embedxpl.version import __codename__, __release_date__, __version__, __version_info__
    assert isinstance(__version__, str)
    assert len(__version__.split(".")) == 3
    assert isinstance(__version_info__, tuple)
    assert len(__version_info__) == 3
    assert isinstance(__release_date__, str)
    assert isinstance(__codename__, str)


# ---------------------------------------------------------------------------
# embedxpl.core.config
# ---------------------------------------------------------------------------

def test_config_get_default() -> None:
    from embedxpl.core import config
    config.reset_cache()
    val = config.get("compute_mode")
    assert val == "auto"


def test_config_get_missing_key() -> None:
    from embedxpl.core import config
    config.reset_cache()
    val = config.get("nonexistent_key_xyz", "fallback")
    assert val == "fallback"


def test_config_set_val_no_persist(tmp_path) -> None:
    from embedxpl.core import config
    config.reset_cache()
    orig_file = config._CONFIG_FILE
    config._CONFIG_FILE = tmp_path / "test_config.json"
    try:
        config.set_val("test_key", 42, persist=False)
        assert config.get("test_key") == 42
        assert not config._CONFIG_FILE.exists()
    finally:
        config._CONFIG_FILE = orig_file
        config.reset_cache()


def test_config_set_val_persist(tmp_path) -> None:
    from embedxpl.core import config
    config.reset_cache()
    orig_file = config._CONFIG_FILE
    config._CONFIG_FILE = tmp_path / "test_config.json"
    try:
        config.set_val("persist_key", "hello", persist=True)
        assert config._CONFIG_FILE.exists()
        data = json.loads(config._CONFIG_FILE.read_text())
        assert data["persist_key"] == "hello"
    finally:
        config._CONFIG_FILE = orig_file
        config.reset_cache()


def test_config_all_values() -> None:
    from embedxpl.core import config
    config.reset_cache()
    vals = config.all_values()
    assert isinstance(vals, dict)
    assert "compute_mode" in vals


def test_config_reset_cache() -> None:
    from embedxpl.core import config
    config.reset_cache()
    assert config._cache is None
    config.get("compute_mode")
    assert config._cache is not None
    config.reset_cache()
    assert config._cache is None


# ---------------------------------------------------------------------------
# embedxpl.core.session — host_id, ModuleResult, HostSession
# ---------------------------------------------------------------------------

def test_host_id_deterministic() -> None:
    from embedxpl.core.session import host_id
    h1 = host_id("192.168.1.1", "AA:BB:CC:DD:EE:FF")
    h2 = host_id("192.168.1.1", "AA:BB:CC:DD:EE:FF")
    assert h1 == h2
    assert len(h1) == 16


def test_host_id_different_macs() -> None:
    from embedxpl.core.session import host_id
    h1 = host_id("192.168.1.1", "AA:BB:CC:DD:EE:FF")
    h2 = host_id("192.168.1.1", "11:22:33:44:55:66")
    assert h1 != h2


def test_host_id_no_mac() -> None:
    from embedxpl.core.session import host_id
    h = host_id("10.0.0.1")
    assert len(h) == 16


def test_module_result_defaults() -> None:
    from embedxpl.core.session import ModuleResult
    r = ModuleResult(module_path="exploit/test")
    assert r.module_path == "exploit/test"
    assert r.vulnerable is None
    assert r.error is None
    assert r.elapsed_s == 0.0


def test_module_result_to_dict() -> None:
    from embedxpl.core.session import ModuleResult
    r = ModuleResult(module_path="scanner/http", vulnerable=True, port=80, protocol="tcp")
    d = r.to_dict()
    assert d["module_path"] == "scanner/http"
    assert d["vulnerable"] is True
    assert d["port"] == 80


def test_module_result_from_dict_roundtrip() -> None:
    from embedxpl.core.session import ModuleResult
    r = ModuleResult(module_path="test/mod", vulnerable=False, elapsed_s=1.234, details="ok")
    d = r.to_dict()
    r2 = ModuleResult.from_dict(d)
    assert r2.module_path == r.module_path
    assert r2.vulnerable == r.vulnerable
    assert r2.elapsed_s == round(r.elapsed_s, 3)


def test_host_session_defaults() -> None:
    from embedxpl.core.session import HostSession
    hs = HostSession(host_id="abc123", ip="10.0.0.1")
    assert hs.ip == "10.0.0.1"
    assert hs.mac == ""
    assert hs.module_results == []


# ---------------------------------------------------------------------------
# embedxpl.core.pool — PoolStrategy, SmartPool, cpu_count
# ---------------------------------------------------------------------------

def test_cpu_count_positive() -> None:
    from embedxpl.core.pool import cpu_count
    assert cpu_count() >= 1


def test_pool_strategy_values() -> None:
    from embedxpl.core.pool import PoolStrategy
    assert PoolStrategy.THREADS.value == "threads"
    assert PoolStrategy.PROCESSES.value == "processes"
    assert PoolStrategy.AUTO.value == "auto"


def test_smart_pool_default_init() -> None:
    from embedxpl.core.pool import PoolStrategy, SmartPool
    pool = SmartPool()
    assert pool._resolved_strategy in (PoolStrategy.THREADS, PoolStrategy.PROCESSES)
    assert pool._max_workers >= 1


def test_smart_pool_threads_strategy() -> None:
    from embedxpl.core.pool import PoolStrategy, SmartPool
    pool = SmartPool(max_workers=4, strategy=PoolStrategy.THREADS)
    assert pool._resolved_strategy == PoolStrategy.THREADS
    assert pool._max_workers == 4


def test_smart_pool_processes_strategy() -> None:
    from embedxpl.core.pool import PoolStrategy, SmartPool
    pool = SmartPool(max_workers=2, strategy=PoolStrategy.PROCESSES)
    assert pool._resolved_strategy == PoolStrategy.PROCESSES


# ---------------------------------------------------------------------------
# embedxpl.core.oui — normalize_vendor
# ---------------------------------------------------------------------------

def test_normalize_vendor_known() -> None:
    from embedxpl.core.oui import normalize_vendor
    assert normalize_vendor("HUAWEI TECHNOLOGIES CO.,LTD") == "huawei"
    assert normalize_vendor("TP-LINK TECHNOLOGIES CO.,LTD.") == "tplink"
    assert normalize_vendor("Cisco Systems, Inc") == "cisco"


def test_normalize_vendor_unknown() -> None:
    from embedxpl.core.oui import normalize_vendor
    result = normalize_vendor("SomeRandomVendor Inc.")
    assert isinstance(result, str)
    assert len(result) > 0


def test_lookup_invalid_mac() -> None:
    from embedxpl.core.oui import lookup
    assert lookup("") == ""
    assert lookup("zz:zz:zz") == ""


def test_clear_session_cache() -> None:
    from embedxpl.core.oui import clear_session_cache
    clear_session_cache()


def test_get_stats() -> None:
    from embedxpl.core.oui import get_stats
    stats = get_stats()
    assert isinstance(stats, dict)


# ---------------------------------------------------------------------------
# embedxpl.core.banner — TOOL_BANNERS dict
# ---------------------------------------------------------------------------

def test_tool_banners_dict() -> None:
    from embedxpl.core.banner import TOOL_BANNERS
    assert isinstance(TOOL_BANNERS, dict)
    assert "embedxpl" in TOOL_BANNERS
    assert "tupaxpl" in TOOL_BANNERS


def test_banner_invalidate_cache() -> None:
    from embedxpl.core.banner import invalidate_cache
    invalidate_cache()


# ---------------------------------------------------------------------------
# embedxpl.runtime.toolchain
# ---------------------------------------------------------------------------

def test_toolchain_available() -> None:
    from embedxpl.runtime.toolchain import available
    avail = available()
    assert isinstance(avail, dict)
    assert "gcc" in avail
    assert "python3" in avail


def test_toolchain_get_c_compiler() -> None:
    from embedxpl.runtime.toolchain import get_c_compiler
    cc = get_c_compiler("x64")
    # may be None if no gcc/clang — that's ok
    assert cc is None or isinstance(cc, str)


def test_toolchain_get_cpp_compiler() -> None:
    from embedxpl.runtime.toolchain import get_cpp_compiler
    cc = get_cpp_compiler("x64")
    assert cc is None or isinstance(cc, str)


def test_toolchain_report() -> None:
    from embedxpl.runtime.toolchain import report
    r = report()
    assert isinstance(r, str)
    assert "Toolchain" in r


def test_toolchain_constants() -> None:
    from embedxpl.runtime.toolchain import CROSS_COMPILERS, CROSS_CPP_COMPILERS
    assert isinstance(CROSS_COMPILERS, dict)
    assert "arm" in CROSS_COMPILERS
    assert isinstance(CROSS_CPP_COMPILERS, dict)


# ---------------------------------------------------------------------------
# embedxpl.runtime.cache
# ---------------------------------------------------------------------------

def test_cache_info() -> None:
    from embedxpl.runtime.cache import cache_info
    info = cache_info()
    assert isinstance(info, dict)
    assert "path" in info
    assert "entries" in info


def test_cache_get_nonexistent(tmp_path) -> None:
    from embedxpl.runtime.cache import get_cached_binary
    fake_src = tmp_path / "nonexistent.c"
    fake_src.write_text("int main() {}")
    result = get_cached_binary(fake_src, arch="x64")
    assert result is None


def test_cache_store_and_retrieve(tmp_path) -> None:
    from embedxpl.runtime import cache
    orig_cache_dir = cache._CACHE_DIR
    cache._CACHE_DIR = tmp_path / "test_cache"
    try:
        src = tmp_path / "hello.c"
        src.write_text("int main() { return 0; }")
        binary = tmp_path / "hello"
        binary.write_bytes(b"\x7fELF_fake_binary")

        cached_path = cache.store_binary(src, binary, arch="x64")
        assert cached_path.exists()

        found = cache.get_cached_binary(src, arch="x64")
        assert found is not None
        assert found.exists()
    finally:
        cache._CACHE_DIR = orig_cache_dir


def test_cache_clear(tmp_path) -> None:
    from embedxpl.runtime import cache
    orig_cache_dir = cache._CACHE_DIR
    cache._CACHE_DIR = tmp_path / "test_cache"
    try:
        cache._ensure_cache_dir()
        old_file = cache._CACHE_DIR / "old_entry"
        old_file.write_bytes(b"old")
        os.utime(old_file, (0, 0))
        removed = cache.clear_cache(older_than_days=0)
        assert removed >= 1
    finally:
        cache._CACHE_DIR = orig_cache_dir


# ---------------------------------------------------------------------------
# embedxpl.runtime.executor — XplRuntime, get_runtime
# ---------------------------------------------------------------------------

def test_get_runtime_returns_instance() -> None:
    from embedxpl.runtime.executor import XplRuntime, get_runtime
    rt = get_runtime()
    assert isinstance(rt, XplRuntime)


def test_xpl_runtime_class() -> None:
    from embedxpl.runtime.executor import XplRuntime
    rt = XplRuntime()
    assert rt is not None


# ---------------------------------------------------------------------------
# embedxpl.core.engine — ScanResult, AsyncScanEngine
# ---------------------------------------------------------------------------

def test_scan_result_dataclass() -> None:
    from embedxpl.core.engine import ScanResult
    sr = ScanResult(target="10.0.0.1", port=80, protocol="tcp", module_path="test/mod", vulnerable=None)
    assert sr.target == "10.0.0.1"
    assert sr.port == 80


def test_async_scan_engine_init() -> None:
    from embedxpl.core.engine import AsyncScanEngine
    eng = AsyncScanEngine(max_workers=2)
    assert eng is not None


# ---------------------------------------------------------------------------
# embedxpl.core.discovery — DiscoveredHost, TimingProfile, PROBE_PORTS
# ---------------------------------------------------------------------------

def test_discovered_host_dataclass() -> None:
    from embedxpl.core.discovery import DiscoveredHost
    dh = DiscoveredHost(ip="10.0.0.1")
    assert dh.ip == "10.0.0.1"


def test_probe_ports_list() -> None:
    from embedxpl.core.discovery import PROBE_PORTS, PROBE_PORTS_EXTENDED
    assert isinstance(PROBE_PORTS, (list, tuple))
    assert len(PROBE_PORTS) > 0
    assert isinstance(PROBE_PORTS_EXTENDED, (list, tuple))


def test_timing_profile_class() -> None:
    from embedxpl.core.discovery import TimingProfile
    assert hasattr(TimingProfile, "get") or hasattr(TimingProfile, "nmap_args_for")
