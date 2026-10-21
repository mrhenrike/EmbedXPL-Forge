"""Tests for embedxpl.core.orchestrator package."""
from __future__ import annotations

from embedxpl.core.orchestrator import (
    ArtifactCache,
    BuildProfile,
    CompiledArtifact,
    ExploitOrchestrator,
    RunnerRegistry,
    RunResult,
    TunnelConfig,
    TunnelManager,
)


class TestRunnerRegistry:
    def test_instantiation(self):
        r = RunnerRegistry()
        assert r is not None


class TestExploitOrchestrator:
    def test_instantiation(self):
        o = ExploitOrchestrator()
        assert o is not None


class TestBuildProfile:
    def test_instantiation(self):
        bp = BuildProfile(target_arch="x86_64", language="c")
        assert bp.target_arch == "x86_64"


class TestRunResult:
    def test_instantiation(self):
        r = RunResult(exit_code=0, stdout="ok")
        assert r.exit_code == 0


class TestTunnelConfig:
    def test_instantiation(self):
        tc = TunnelConfig(local_port=8080, remote_host="10.0.0.1", remote_port=80)
        assert tc.local_port == 8080


class TestTunnelManager:
    def test_instantiation(self):
        tm = TunnelManager()
        assert tm is not None


class TestCompiledArtifact:
    def test_instantiation(self):
        ca = CompiledArtifact(source_hash="abc", binary_path="/tmp/test", target_arch="x86_64", compiler_used="gcc", build_time=1.0)
        assert ca.binary_path == "/tmp/test"


class TestArtifactCache:
    def test_instantiation(self):
        ac = ArtifactCache()
        assert ac is not None
