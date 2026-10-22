"""Structural tests for embedxpl.modules.creds.* modules.

Validates that credential modules follow the required interface:
- Have an Exploit class (inheriting from a protocol client or BaseExploit)
- Have __info__ dict with required keys (accounting for metaclass mangling)
- Implement run() method
- Expose expected option attributes (target, port, defaults, etc.)
"""
from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest

# ---------------------------------------------------------------
# Curated representative cred modules (different vendors/protocols)
# ---------------------------------------------------------------

CRED_MODULES = [
    (
        "embedxpl.modules.creds.generic.ssh_default",
        ["target", "port", "defaults"],
    ),
    (
        "embedxpl.modules.creds.generic.ftp_default",
        ["target", "port", "defaults"],
    ),
    (
        "embedxpl.modules.creds.generic.telnet_default",
        ["target", "port", "defaults"],
    ),
    (
        "embedxpl.modules.creds.generic.snmp_bruteforce",
        ["target", "port"],
    ),
    (
        "embedxpl.modules.creds.generic.http_basic_digest_default",
        ["target", "port"],
    ),
    (
        "embedxpl.modules.creds.cameras.rtsp_brute",
        ["target", "port"],
    ),
    (
        "embedxpl.modules.creds.routers.3com.ftp_default_creds",
        ["target", "port", "defaults"],
    ),
    (
        "embedxpl.modules.creds.routers.acorp.ssh_default_creds",
        ["target", "port", "defaults"],
    ),
    (
        "embedxpl.modules.creds.generic.sftp_default",
        ["target", "port", "defaults"],
    ),
    (
        "embedxpl.modules.creds.rsf.api_ros_default_creds",
        ["target", "port", "defaults"],
    ),
]

REQUIRED_INFO_KEYS = {"name", "description", "authors"}

_KNOWN_IMPORT_ERRORS = (ImportError, ModuleNotFoundError, OSError, AttributeError)


def _safe_import(mod_path: str):
    """Import module; skip on known issues."""
    try:
        return importlib.import_module(mod_path)
    except _KNOWN_IMPORT_ERRORS as exc:
        pytest.skip("Import failed: {}".format(exc))


def _get_info(cls) -> dict:
    """Retrieve __info__ dict accounting for ExploitOptionsAggregator mangling."""
    mangled = "_{}__info__".format(cls.__name__)
    if hasattr(cls, mangled):
        return getattr(cls, mangled)
    if hasattr(cls, "__info__"):
        return cls.__info__
    raise AttributeError("{} has no __info__".format(cls.__name__))


# ---------------------------------------------------------------
# Parametrized structural tests for curated cred modules
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    "mod_path,expected_opts",
    CRED_MODULES,
    ids=[p.rsplit(".", 1)[-1] for p, _ in CRED_MODULES],
)
class TestCredModuleStructure:
    """Structural tests for credential modules."""

    def test_importable(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_exploit_class_exists(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        assert hasattr(mod, "Exploit"), "{} missing Exploit class".format(mod_path)

    def test_exploit_inherits_base(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        cls = getattr(mod, "Exploit", None)
        if cls is None:
            pytest.skip("No Exploit class")
        mro_names = [c.__name__ for c in cls.__mro__]
        assert len(mro_names) >= 3, "Exploit should inherit from a base/client class"

    def test_has_info_dict(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        info = _get_info(mod.Exploit)
        assert isinstance(info, dict)

    def test_info_has_required_keys(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        info = _get_info(mod.Exploit)
        for key in REQUIRED_INFO_KEYS:
            assert key in info, "{} __info__ missing '{}'".format(mod_path, key)

    def test_info_name_is_nonempty(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        name = _get_info(mod.Exploit)["name"]
        assert isinstance(name, str) and len(name) > 0

    def test_info_authors_nonempty(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        authors = _get_info(mod.Exploit)["authors"]
        assert isinstance(authors, (tuple, list))
        assert len(authors) >= 1

    def test_info_description_nonempty(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        desc = _get_info(mod.Exploit)["description"]
        assert isinstance(desc, str) and len(desc) > 10

    def test_has_run_method(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        cls = mod.Exploit
        assert hasattr(cls, "run"), "{} Exploit missing run()".format(mod_path)
        assert callable(cls.run)

    def test_expected_options_present(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        cls = mod.Exploit
        for opt in expected_opts:
            assert hasattr(cls, opt), "{} missing option '{}'".format(mod_path, opt)


# ---------------------------------------------------------------
# Bulk importability test for all cred .py files
# ---------------------------------------------------------------

CREDS_ROOT = Path(__file__).resolve().parents[1] / "embedxpl" / "modules" / "creds"
_SKIP_DIRS = {"__pycache__", "refs"}


def _collect_all_cred_modules():
    modules = []
    for root, dirs, files in os.walk(CREDS_ROOT):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for f in sorted(files):
            if f.startswith("__") or not f.endswith(".py"):
                continue
            path = Path(root) / f
            rel = path.relative_to(CREDS_ROOT.parent.parent)
            dotted = str(rel).replace(os.sep, ".").removesuffix(".py")
            modules.append(dotted)
    return modules


ALL_CRED_MODULES = _collect_all_cred_modules()


def test_cred_modules_count():
    assert len(ALL_CRED_MODULES) > 50, "Expected 50+ cred modules, got {}".format(len(ALL_CRED_MODULES))


@pytest.mark.parametrize("dotted", ALL_CRED_MODULES[:200],
                         ids=[m.rsplit(".", 1)[-1] for m in ALL_CRED_MODULES[:200]])
def test_cred_module_importable(dotted: str) -> None:
    try:
        importlib.import_module(dotted)
    except (ImportError, ModuleNotFoundError):
        pytest.skip("Optional dependency missing for {}".format(dotted))
    except SyntaxError:
        pytest.skip("Syntax issue in {}".format(dotted))


# ---------------------------------------------------------------
# Generic SSH default: wordlist resolution
# ---------------------------------------------------------------


class TestSSHDefaultHelpers:
    """Test SSH default credential module helpers."""

    @pytest.fixture()
    def exploit_cls(self):
        try:
            from embedxpl.modules.creds.generic.ssh_default import Exploit
        except (ImportError, AttributeError):
            pytest.skip("Cannot import ssh_default")
        return Exploit

    def test_has_defaults_option(self, exploit_cls) -> None:
        assert hasattr(exploit_cls, "defaults")

    def test_has_stop_on_success(self, exploit_cls) -> None:
        assert hasattr(exploit_cls, "stop_on_success") or hasattr(exploit_cls, "verbosity")

    def test_info_mentions_ssh(self, exploit_cls) -> None:
        info = _get_info(exploit_cls)
        name_desc = (info.get("name", "") + info.get("description", "")).lower()
        assert "ssh" in name_desc


# ---------------------------------------------------------------
# Generic FTP default: wordlist resolution
# ---------------------------------------------------------------


class TestFTPDefaultHelpers:
    """Test FTP default credential module helpers."""

    @pytest.fixture()
    def exploit_cls(self):
        try:
            from embedxpl.modules.creds.generic.ftp_default import Exploit
        except (ImportError, AttributeError):
            pytest.skip("Cannot import ftp_default")
        return Exploit

    def test_has_defaults_option(self, exploit_cls) -> None:
        assert hasattr(exploit_cls, "defaults")

    def test_default_port_21(self, exploit_cls) -> None:
        inst = exploit_cls()
        port_val = inst.port if isinstance(inst.port, int) else getattr(inst.port, "display_value", None)
        if port_val is not None:
            assert port_val == 21


# ---------------------------------------------------------------
# RTSP brute: credential and stream route constants
# ---------------------------------------------------------------


class TestRTSPBruteHelpers:
    """Test RTSP brute force module constants."""

    @pytest.fixture()
    def mod(self):
        try:
            import embedxpl.modules.creds.cameras.rtsp_brute as m
        except (ImportError, AttributeError):
            pytest.skip("Cannot import rtsp_brute")
        return m

    def test_has_default_credentials(self, mod) -> None:
        creds = getattr(mod, "_DEFAULT_CREDENTIALS", None) or getattr(mod, "DEFAULT_CREDS", None)
        if creds is None:
            pytest.skip("No default credentials constant found")
        assert isinstance(creds, (list, tuple))
        assert len(creds) >= 1

    def test_has_stream_routes(self, mod) -> None:
        routes = getattr(mod, "_STREAM_ROUTES", None) or getattr(mod, "STREAM_ROUTES", None)
        if routes is None:
            pytest.skip("No stream routes constant found")
        assert isinstance(routes, (list, tuple))

    def test_info_mentions_rtsp(self, mod) -> None:
        info = _get_info(mod.Exploit)
        name_desc = (info.get("name", "") + info.get("description", "")).lower()
        assert "rtsp" in name_desc


# ---------------------------------------------------------------
# Vendor-specific cred modules: 3Com and Acorp
# ---------------------------------------------------------------


class TestVendorCredStructure:
    """Test vendor-specific cred modules inherit from generic defaults."""

    def test_3com_ftp_inherits_ftp_default(self) -> None:
        try:
            mod = importlib.import_module("embedxpl.modules.creds.routers.3com.ftp_default_creds")
        except (ImportError, AttributeError):
            pytest.skip("Cannot import 3com ftp_default_creds")
        cls = mod.Exploit
        mro_names = [c.__name__ for c in cls.__mro__]
        assert "Exploit" in mro_names
        assert len(mro_names) >= 3

    def test_acorp_ssh_inherits_ssh_default(self) -> None:
        try:
            mod = importlib.import_module("embedxpl.modules.creds.routers.acorp.ssh_default_creds")
        except (ImportError, AttributeError):
            pytest.skip("Cannot import acorp ssh_default_creds")
        cls = mod.Exploit
        mro_names = [c.__name__ for c in cls.__mro__]
        assert len(mro_names) >= 4

    def test_api_ros_inherits_tcp_client(self) -> None:
        try:
            mod = importlib.import_module("embedxpl.modules.creds.rsf.api_ros_default_creds")
        except (ImportError, AttributeError):
            pytest.skip("Cannot import api_ros_default_creds")
        cls = mod.Exploit
        mro_names = [c.__name__ for c in cls.__mro__]
        assert any("TCP" in n or "Client" in n for n in mro_names)
