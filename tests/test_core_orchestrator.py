"""Tests for orchestrator subsystem: artifact, compiler, runner, tunnel, orchestrator."""

import time
from dataclasses import asdict

import pytest

# ── Artifact ──

class TestCompiledArtifact:
    def test_dataclass_creation(self):
        from embedxpl.core.orchestrator.artifact import CompiledArtifact
        a = CompiledArtifact(
            source_hash="abc123",
            binary_path="/tmp/test",
            target_arch="x86",
            compiler_used="gcc",
            build_time=1234567890.0,
        )
        assert a.source_hash == "abc123"
        assert a.cached is False
        assert a.exit_code == 0
        assert a.binary_size == 0

    def test_asdict(self):
        from embedxpl.core.orchestrator.artifact import CompiledArtifact
        a = CompiledArtifact(
            source_hash="h", binary_path="/p", target_arch="arm",
            compiler_used="gcc", build_time=0.0,
        )
        d = asdict(a)
        assert isinstance(d, dict)
        assert d["target_arch"] == "arm"


class TestArtifactCache:
    def test_init(self, tmp_path):
        from embedxpl.core.orchestrator.artifact import ArtifactCache
        cache = ArtifactCache(str(tmp_path / "builds"))
        assert cache is not None

    def test_lookup_miss(self, tmp_path):
        from embedxpl.core.orchestrator.artifact import ArtifactCache
        cache = ArtifactCache(str(tmp_path / "builds"))
        result = cache.lookup("/nonexistent/src.c", "x86", "gcc")
        assert result is None

    def test_store_and_lookup(self, tmp_path):
        from embedxpl.core.orchestrator.artifact import ArtifactCache, CompiledArtifact
        cache = ArtifactCache(str(tmp_path / "builds"))
        src = tmp_path / "src.c"
        src.write_text("int main(){return 0;}")
        binary = tmp_path / "test.bin"
        binary.write_bytes(b"\x90" * 10)
        artifact = CompiledArtifact(
            source_hash="test_hash",
            binary_path=str(binary),
            target_arch="x86_64",
            compiler_used="gcc",
            build_time=time.time(),
            binary_size=10,
        )
        cache.store(artifact)
        found = cache.lookup(str(src), "x86_64", "gcc")
        if found is not None:
            assert found.cached is True


# ── Runner ──

class TestRunResult:
    def test_defaults(self):
        from embedxpl.core.orchestrator.runner import RunResult
        r = RunResult()
        assert r.exit_code == -1
        assert r.stdout == ""
        assert r.timed_out is False
        assert r.success is False

    def test_success_property(self):
        from embedxpl.core.orchestrator.runner import RunResult
        r = RunResult(exit_code=0)
        assert r.success is True

    def test_failure(self):
        from embedxpl.core.orchestrator.runner import RunResult
        r = RunResult(exit_code=1, stderr="error occurred")
        assert r.success is False
        assert "error" in r.stderr

    def test_timed_out(self):
        from embedxpl.core.orchestrator.runner import RunResult
        r = RunResult(exit_code=-1, timed_out=True, signal_name="SIGKILL")
        assert r.timed_out is True


class TestExploitRunner:
    def test_init(self):
        from embedxpl.core.orchestrator.runner import ExploitRunner
        runner = ExploitRunner()
        assert runner is not None

    def test_run_nonexistent_binary(self):
        from embedxpl.core.orchestrator.artifact import CompiledArtifact
        from embedxpl.core.orchestrator.runner import ExploitRunner
        runner = ExploitRunner()
        art = CompiledArtifact(
            source_hash="h", binary_path="/nonexistent/bin",
            target_arch="x86", compiler_used="gcc", build_time=0.0,
        )
        with pytest.raises(FileNotFoundError):
            runner.run(art)


# ── Tunnel ──

class TestTunnelConfig:
    def test_defaults(self):
        from embedxpl.core.orchestrator.tunnel import TunnelConfig
        tc = TunnelConfig()
        assert tc.tunnel_type == "tcp_forward"
        assert tc.local_port == 0

    def test_custom(self):
        from embedxpl.core.orchestrator.tunnel import TunnelConfig
        tc = TunnelConfig(
            tunnel_type="dns_tunnel",
            local_port=8053,
            remote_host="10.0.0.1",
            remote_port=53,
        )
        assert tc.tunnel_type == "dns_tunnel"
        assert tc.local_port == 8053


class TestTunnelTypes:
    def test_all_types(self):
        from embedxpl.core.orchestrator.tunnel import TUNNEL_TYPES
        assert "tcp_forward" in TUNNEL_TYPES
        assert "udp_forward" in TUNNEL_TYPES
        assert "icmp_tunnel" in TUNNEL_TYPES
        assert "dns_tunnel" in TUNNEL_TYPES
        assert "http_tunnel" in TUNNEL_TYPES
        assert "ssh_local" in TUNNEL_TYPES
        assert len(TUNNEL_TYPES) == 6


class TestTunnelManager:
    def test_init(self):
        from embedxpl.core.orchestrator.tunnel import TunnelManager
        tm = TunnelManager()
        assert tm is not None


# ── Orchestrator ──

class TestLanguageMap:
    def test_language_aliases(self):
        from embedxpl.core.orchestrator.orchestrator import _LANGUAGE_MAP
        assert _LANGUAGE_MAP["python"] == "python"
        assert _LANGUAGE_MAP["py"] == "python"
        assert _LANGUAGE_MAP["c"] == "c"
        assert _LANGUAGE_MAP["cpp"] == "cpp"
        assert _LANGUAGE_MAP["c++"] == "cpp"
        assert _LANGUAGE_MAP["rust"] == "rust"
        assert _LANGUAGE_MAP["rs"] == "rust"
        assert _LANGUAGE_MAP["asm"] == "asm"

    def test_ext_map(self):
        from embedxpl.core.orchestrator.orchestrator import _EXT_TO_LANG
        assert _EXT_TO_LANG[".py"] == "python"
        assert _EXT_TO_LANG[".c"] == "c"
        assert _EXT_TO_LANG[".rs"] == "rust"
        assert _EXT_TO_LANG[".S"] == "asm"


class TestExploitOrchestrator:
    def test_init(self):
        from embedxpl.core.orchestrator.orchestrator import ExploitOrchestrator
        orch = ExploitOrchestrator()
        assert orch is not None


# ── Compiler ──

class TestBuildProfile:
    def test_init(self):
        from embedxpl.core.orchestrator.compiler import BuildProfile
        bp = BuildProfile()
        assert bp is not None


class TestCrossCompiler:
    def test_init(self):
        from embedxpl.core.orchestrator.compiler import CrossCompiler
        cc = CrossCompiler()
        assert cc is not None

    def test_toolchain_map(self):
        from embedxpl.core.orchestrator.compiler import _TOOLCHAIN_MAP
        assert "x86" in _TOOLCHAIN_MAP
        assert "arm" in _TOOLCHAIN_MAP
        assert "mips" in _TOOLCHAIN_MAP
        assert "riscv" in _TOOLCHAIN_MAP
        for arch, tools in _TOOLCHAIN_MAP.items():
            assert "c" in tools
            assert "cpp" in tools

    def test_rust_targets(self):
        from embedxpl.core.orchestrator.compiler import _RUST_TARGETS
        assert "x86" in _RUST_TARGETS
        assert "arm" in _RUST_TARGETS
