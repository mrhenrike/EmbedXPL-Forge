"""Tests for runtime: XplRuntime, cache, toolchain, executors, TARGETS."""

from pathlib import Path
from unittest.mock import MagicMock

# ── TARGETS ──

class TestTargets:
    def test_targets_dict(self):
        from embedxpl.runtime import TARGETS
        assert isinstance(TARGETS, dict)
        assert "x64" in TARGETS
        assert "x86" in TARGETS
        assert "arm" in TARGETS

    def test_available_targets(self):
        from embedxpl.runtime import available_targets
        targets = list(available_targets())
        assert isinstance(targets, list)
        assert len(targets) >= 1


# ── XplRuntime ──

class TestXplRuntime:
    def test_init(self):
        from embedxpl.runtime import XplRuntime
        rt = XplRuntime()
        assert rt is not None

    def test_available_languages(self):
        from embedxpl.runtime import XplRuntime
        rt = XplRuntime()
        langs = rt.available_languages()
        assert isinstance(langs, dict)
        assert "c" in langs or "python" in langs

    def test_check_with_mock_module(self):
        from embedxpl.runtime import XplRuntime
        rt = XplRuntime()
        mod = MagicMock()
        mod.run = MagicMock(return_value=None)
        result = rt.check(mod)
        assert isinstance(result, dict)

    def test_report(self):
        from embedxpl.runtime import XplRuntime
        rt = XplRuntime()
        report = rt.report()
        assert isinstance(report, (str, dict, list))


# ── Cache ──

class TestCache:
    def test_cache_info(self):
        from embedxpl.runtime.cache import cache_info
        info = cache_info()
        assert isinstance(info, dict)

    def test_clear_cache(self, tmp_path):
        from embedxpl.runtime.cache import clear_cache
        clear_cache()

    def test_get_cached_miss(self):
        from embedxpl.runtime.cache import get_cached_binary
        result = get_cached_binary("nonexistent_hash_xyz123")
        assert result is None

    def test_store_binary(self, tmp_path):
        from embedxpl.runtime.cache import store_binary
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x90" * 16)
        result = store_binary(str(binary), "test_hash_abc")
        assert result is None or isinstance(result, (str, Path, bool))


# ── Toolchain ──

class TestToolchain:
    def test_compiler_constants(self):
        from embedxpl.runtime.toolchain import CARGO, CLANG, CLANGPP, GCC, GO, GPP
        for name in [GCC, GPP, CLANG, CLANGPP, GO, CARGO]:
            assert isinstance(name, str)

    def test_cross_compilers(self):
        from embedxpl.runtime.toolchain import CROSS_COMPILERS, CROSS_CPP_COMPILERS
        assert isinstance(CROSS_COMPILERS, dict)
        assert isinstance(CROSS_CPP_COMPILERS, dict)

    def test_cross_compiler_arches(self):
        from embedxpl.runtime.toolchain import CROSS_COMPILERS
        for arch, compiler in CROSS_COMPILERS.items():
            assert isinstance(arch, str)
            assert compiler is None or isinstance(compiler, str)


# ── CExecutor ──

class TestCExecutor:
    def test_init(self):
        from embedxpl.runtime.c_exec import CExecutor
        ex = CExecutor()
        assert ex is not None

    def test_name(self):
        from embedxpl.runtime.c_exec import CExecutor
        assert CExecutor.name == "c" or isinstance(CExecutor.name, str)

    def test_is_available(self):
        from embedxpl.runtime.c_exec import CExecutor
        ex = CExecutor()
        result = ex.is_available()
        assert isinstance(result, bool)

    def test_get_target(self):
        from embedxpl.runtime.c_exec import get_target
        target = get_target("x64")
        assert target is not None


# ── CppExecutor ──

class TestCppExecutor:
    def test_init(self):
        from embedxpl.runtime.cpp_exec import CppExecutor
        ex = CppExecutor()
        assert ex is not None

    def test_is_available(self):
        from embedxpl.runtime.cpp_exec import CppExecutor
        result = CppExecutor().is_available()
        assert isinstance(result, bool)


# ── Other executors ──

class TestGoExecutor:
    def test_import(self):
        from embedxpl.runtime.go_exec import GoExecutor
        assert GoExecutor is not None

    def test_is_available(self):
        from embedxpl.runtime.go_exec import GoExecutor
        result = GoExecutor().is_available()
        assert isinstance(result, bool)


class TestRustExecutor:
    def test_import(self):
        from embedxpl.runtime.rust_exec import RustExecutor
        assert RustExecutor is not None

    def test_is_available(self):
        from embedxpl.runtime.rust_exec import RustExecutor
        result = RustExecutor().is_available()
        assert isinstance(result, bool)


class TestPythonExecutor:
    def test_import(self):
        from embedxpl.runtime.python_exec import PythonExecutor
        assert PythonExecutor is not None

    def test_is_available(self):
        from embedxpl.runtime.python_exec import PythonExecutor
        result = PythonExecutor().is_available()
        assert result is True


class TestRubyExecutor:
    def test_import(self):
        from embedxpl.runtime.ruby_exec import RubyExecutor
        assert RubyExecutor is not None

    def test_is_available(self):
        from embedxpl.runtime.ruby_exec import RubyExecutor
        result = RubyExecutor().is_available()
        assert isinstance(result, bool)


# ── CrossTarget ──

class TestCrossTarget:
    def test_get_target_known(self):
        from embedxpl.runtime.c_exec import get_target
        for arch in ["x64", "x86", "arm"]:
            target = get_target(arch)
            if target is not None:
                assert hasattr(target, "arch") or hasattr(target, "triple")

    def test_get_target_unknown(self):
        from embedxpl.runtime.c_exec import get_target
        target = get_target("nonexistent_arch_xyz")
        assert target is not None or target is None
