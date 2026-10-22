"""Functional tests for embedxpl.core.gpu compute backends.

Validates the abstract interface, CPU fallback (always available),
auto-selection logic, and structural compliance of GPU-specific backends
(CUDA, ROCm, OpenCL) without requiring actual GPU hardware.
"""
from __future__ import annotations

import numpy as np
import pytest

from embedxpl.core.gpu.backend import ComputeBackend, auto_select_backend
from embedxpl.core.gpu.cpu_backend import CPUBackend


class TestComputeBackendABC:
    """Verify the abstract base class contract."""

    def test_abstract_methods_defined(self) -> None:
        abstract_methods = {
            "is_available", "device_info", "array_from_numpy",
            "to_numpy", "matmul", "cosine_similarity_batch",
        }
        for name in abstract_methods:
            assert hasattr(ComputeBackend, name)

    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            ComputeBackend()

    def test_hash_batch_default_implementation(self) -> None:
        backend = CPUBackend()
        hashes = backend.hash_batch([b"hello", b"world"], algorithm="md5")
        assert len(hashes) == 2
        assert all(len(h) == 32 for h in hashes)

    def test_hash_batch_sha256(self) -> None:
        backend = CPUBackend()
        hashes = backend.hash_batch([b"test"], algorithm="sha256")
        assert len(hashes[0]) == 64


class TestCPUBackend:
    """CPU backend: always available, uses NumPy."""

    def test_is_available(self) -> None:
        backend = CPUBackend()
        assert backend.is_available() is True

    def test_name(self) -> None:
        backend = CPUBackend()
        assert backend.name == "cpu"

    def test_device_info_contains_cpu(self) -> None:
        backend = CPUBackend()
        info = backend.device_info()
        assert "CPU" in info
        assert "NumPy" in info

    def test_array_from_numpy_identity(self) -> None:
        backend = CPUBackend()
        arr = np.array([1.0, 2.0, 3.0], dtype=np.float32)
        result = backend.array_from_numpy(arr)
        assert result is arr

    def test_to_numpy(self) -> None:
        backend = CPUBackend()
        arr = [1.0, 2.0, 3.0]
        result = backend.to_numpy(arr)
        assert isinstance(result, np.ndarray)
        np.testing.assert_array_equal(result, [1.0, 2.0, 3.0])

    def test_matmul(self) -> None:
        backend = CPUBackend()
        a = np.array([[1.0, 2.0], [3.0, 4.0]], dtype=np.float32)
        b = np.array([[5.0, 6.0], [7.0, 8.0]], dtype=np.float32)
        result = backend.matmul(a, b)
        expected = np.matmul(a, b)
        np.testing.assert_array_almost_equal(result, expected)

    def test_cosine_similarity_batch_orthogonal(self) -> None:
        backend = CPUBackend()
        queries = np.array([[1.0, 0.0]], dtype=np.float32)
        corpus = np.array([[0.0, 1.0]], dtype=np.float32)
        sim = backend.cosine_similarity_batch(queries, corpus)
        assert sim.shape == (1, 1)
        assert abs(sim[0, 0]) < 0.01

    def test_cosine_similarity_batch_identical(self) -> None:
        backend = CPUBackend()
        queries = np.array([[1.0, 1.0]], dtype=np.float32)
        corpus = np.array([[1.0, 1.0]], dtype=np.float32)
        sim = backend.cosine_similarity_batch(queries, corpus)
        assert abs(sim[0, 0] - 1.0) < 0.01

    def test_cosine_similarity_batch_multiple(self) -> None:
        backend = CPUBackend()
        queries = np.array([[1.0, 0.0], [0.0, 1.0]], dtype=np.float32)
        corpus = np.array([[1.0, 0.0], [0.0, 1.0], [1.0, 1.0]], dtype=np.float32)
        sim = backend.cosine_similarity_batch(queries, corpus)
        assert sim.shape == (2, 3)
        assert abs(sim[0, 0] - 1.0) < 0.01
        assert abs(sim[1, 1] - 1.0) < 0.01

    def test_hash_batch_deterministic(self) -> None:
        backend = CPUBackend()
        h1 = backend.hash_batch([b"test123"], "sha1")
        h2 = backend.hash_batch([b"test123"], "sha1")
        assert h1 == h2


class TestCUDABackend:
    """Structural tests for CUDA backend (no GPU required)."""

    def test_import(self) -> None:
        from embedxpl.core.gpu.cuda_backend import CUDABackend
        assert CUDABackend is not None

    def test_inherits_compute_backend(self) -> None:
        from embedxpl.core.gpu.cuda_backend import CUDABackend
        assert issubclass(CUDABackend, ComputeBackend)

    def test_name(self) -> None:
        from embedxpl.core.gpu.cuda_backend import CUDABackend
        assert CUDABackend.name == "cuda"

    def test_instantiate(self) -> None:
        from embedxpl.core.gpu.cuda_backend import CUDABackend
        backend = CUDABackend()
        assert backend is not None

    def test_is_available_returns_bool(self) -> None:
        from embedxpl.core.gpu.cuda_backend import CUDABackend
        backend = CUDABackend()
        assert isinstance(backend.is_available(), bool)

    def test_implements_all_abstract_methods(self) -> None:
        from embedxpl.core.gpu.cuda_backend import CUDABackend
        required = ["is_available", "device_info", "array_from_numpy",
                     "to_numpy", "matmul", "cosine_similarity_batch"]
        for method in required:
            assert hasattr(CUDABackend, method)
            assert callable(getattr(CUDABackend, method))


class TestROCmBackend:
    """Structural tests for ROCm backend (no GPU required)."""

    def test_import(self) -> None:
        from embedxpl.core.gpu.rocm_backend import ROCmBackend
        assert ROCmBackend is not None

    def test_inherits_compute_backend(self) -> None:
        from embedxpl.core.gpu.rocm_backend import ROCmBackend
        assert issubclass(ROCmBackend, ComputeBackend)

    def test_name(self) -> None:
        from embedxpl.core.gpu.rocm_backend import ROCmBackend
        assert ROCmBackend.name == "rocm"

    def test_instantiate(self) -> None:
        from embedxpl.core.gpu.rocm_backend import ROCmBackend
        backend = ROCmBackend()
        assert backend is not None

    def test_is_available_returns_bool(self) -> None:
        from embedxpl.core.gpu.rocm_backend import ROCmBackend
        backend = ROCmBackend()
        assert isinstance(backend.is_available(), bool)

    def test_implements_all_abstract_methods(self) -> None:
        from embedxpl.core.gpu.rocm_backend import ROCmBackend
        required = ["is_available", "device_info", "array_from_numpy",
                     "to_numpy", "matmul", "cosine_similarity_batch"]
        for method in required:
            assert hasattr(ROCmBackend, method)


class TestOpenCLBackend:
    """Structural tests for OpenCL backend (no GPU required)."""

    def test_import(self) -> None:
        from embedxpl.core.gpu.opencl_backend import OpenCLBackend
        assert OpenCLBackend is not None

    def test_inherits_compute_backend(self) -> None:
        from embedxpl.core.gpu.opencl_backend import OpenCLBackend
        assert issubclass(OpenCLBackend, ComputeBackend)

    def test_name(self) -> None:
        from embedxpl.core.gpu.opencl_backend import OpenCLBackend
        assert OpenCLBackend.name == "opencl"

    def test_instantiate(self) -> None:
        from embedxpl.core.gpu.opencl_backend import OpenCLBackend
        backend = OpenCLBackend()
        assert backend is not None

    def test_is_available_returns_bool(self) -> None:
        from embedxpl.core.gpu.opencl_backend import OpenCLBackend
        backend = OpenCLBackend()
        assert isinstance(backend.is_available(), bool)

    def test_implements_all_abstract_methods(self) -> None:
        from embedxpl.core.gpu.opencl_backend import OpenCLBackend
        required = ["is_available", "device_info", "array_from_numpy",
                     "to_numpy", "matmul", "cosine_similarity_batch"]
        for method in required:
            assert hasattr(OpenCLBackend, method)


class TestAutoSelectBackend:
    """auto_select_backend() selection logic."""

    def test_cpu_mode_returns_cpu(self) -> None:
        backend = auto_select_backend(compute_mode="cpu")
        assert isinstance(backend, CPUBackend)

    def test_auto_mode_returns_backend(self) -> None:
        backend = auto_select_backend(compute_mode="auto")
        assert isinstance(backend, ComputeBackend)
        assert backend.is_available() is True

    def test_gpu_mode_fallback_to_cpu(self) -> None:
        backend = auto_select_backend(compute_mode="gpu")
        assert isinstance(backend, ComputeBackend)
        assert backend.is_available() is True

    def test_selected_backend_can_matmul(self) -> None:
        backend = auto_select_backend(compute_mode="auto")
        a = np.eye(3, dtype=np.float32)
        b = np.ones((3, 2), dtype=np.float32)
        result = backend.to_numpy(backend.matmul(
            backend.array_from_numpy(a),
            backend.array_from_numpy(b),
        ))
        np.testing.assert_array_almost_equal(result, np.ones((3, 2)))

    def test_selected_backend_cosine(self) -> None:
        backend = auto_select_backend(compute_mode="auto")
        q = np.array([[1.0, 0.0, 0.0]], dtype=np.float32)
        c = np.array([[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]], dtype=np.float32)
        sim = backend.cosine_similarity_batch(q, c)
        assert abs(sim[0, 0] - 1.0) < 0.01
        assert abs(sim[0, 1]) < 0.01


class TestGPUInitExports:
    """Verify gpu __init__.py exports."""

    def test_exports(self) -> None:
        from embedxpl.core.gpu import ComputeBackend, CPUBackend, auto_select_backend
        assert CPUBackend is not None
        assert ComputeBackend is not None
        assert callable(auto_select_backend)
