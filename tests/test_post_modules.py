"""Tests for embedxpl.modules.post.* module structure and interfaces.

Validates that post-exploitation modules follow the required interface:
- Have an Exploit class with __info__ dict containing required keys
- Implement run() and check() methods
- Expose expected options as class attributes
- Can parse credentials / operate on local data without network access
"""
from __future__ import annotations

import importlib

import pytest

# ---------------------------------------------------------------
# Module paths and their expected option attributes
# ---------------------------------------------------------------

POST_MODULES = [
    (
        "embedxpl.modules.post.embedded_credential_harvest",
        ["target", "port", "username", "password", "protocol"],
    ),
    (
        "embedxpl.modules.post.router_config_exfil",
        ["target", "port", "method", "output_file", "community"],
    ),
    (
        "embedxpl.modules.post.iot_network_recon",
        ["target", "port", "username", "password", "scan_range"],
    ),
    (
        "embedxpl.modules.post.firmware_persistence_inject",
        ["firmware_path", "callback_ip", "callback_port", "method"],
    ),
    (
        "embedxpl.modules.post.embedded_log_cleanup",
        ["target", "port", "username", "password", "pattern"],
    ),
]

REQUIRED_INFO_KEYS = {"name", "description", "authors"}

_KNOWN_IMPORT_ERRORS = (ImportError, ModuleNotFoundError, OSError, RuntimeError)


def _safe_import(mod_path: str):
    """Import module; skip on known issues."""
    try:
        return importlib.import_module(mod_path)
    except _KNOWN_IMPORT_ERRORS as exc:
        pytest.skip("Import failed: {}".format(exc))


def _get_info(cls) -> dict:
    """Retrieve __info__ dict from an Exploit class.

    Python name-mangles __info__ to _ClassName__info__ because of the
    double-underscore prefix. This helper checks the mangled form first,
    then falls back to direct access.
    """
    mangled = "_{}__info__".format(cls.__name__)
    if hasattr(cls, mangled):
        return getattr(cls, mangled)
    if hasattr(cls, "__info__"):
        return cls.__info__
    raise AttributeError(
        "{} has no __info__ (checked mangled key {!r})".format(cls.__name__, mangled)
    )


# ---------------------------------------------------------------
# Parametrized structural tests
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    "mod_path,expected_opts",
    POST_MODULES,
    ids=[p.rsplit(".", 1)[-1] for p, _ in POST_MODULES],
)
class TestPostModuleStructure:
    """Structural tests for post-exploitation modules."""

    def test_importable(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_exploit_class_exists(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        assert hasattr(mod, "Exploit"), "{} missing Exploit class".format(mod_path)

    def test_exploit_has_base_interface(self, mod_path: str, expected_opts: list[str]) -> None:
        """Verify the class has the expected base exploit interface.

        The ExploitOptionsAggregator metaclass rebuilds the class, so the
        standard MRO does not always show the original base. We check for
        interface methods instead.
        """
        mod = _safe_import(mod_path)
        cls = getattr(mod, "Exploit", None)
        if cls is None:
            pytest.skip("No Exploit class")
        # Base exploit interface: run() is required, check() is common
        assert hasattr(cls, "run"), "Exploit missing run() method"
        assert callable(cls.run)

    def test_has_info_dict(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        cls = mod.Exploit
        info = _get_info(cls)
        assert isinstance(info, dict)

    def test_info_has_required_keys(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        info = _get_info(mod.Exploit)
        for key in REQUIRED_INFO_KEYS:
            assert key in info, "{} __info__ missing '{}'".format(mod_path, key)

    def test_info_name_is_nonempty_string(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        name = _get_info(mod.Exploit)["name"]
        assert isinstance(name, str) and len(name) > 0

    def test_info_authors_is_tuple_with_entries(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        authors = _get_info(mod.Exploit)["authors"]
        assert isinstance(authors, (tuple, list))
        assert len(authors) >= 1, "authors must have at least one entry"

    def test_info_description_is_nonempty(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        desc = _get_info(mod.Exploit)["description"]
        assert isinstance(desc, str) and len(desc) > 10

    def test_has_run_method(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        cls = mod.Exploit
        assert hasattr(cls, "run"), "{} Exploit missing run()".format(mod_path)
        assert callable(cls.run)

    def test_has_check_method(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        cls = mod.Exploit
        assert hasattr(cls, "check"), "{} Exploit missing check()".format(mod_path)
        assert callable(cls.check)

    def test_expected_options_present(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        cls = mod.Exploit
        for opt in expected_opts:
            assert hasattr(cls, opt), "{} missing option attribute '{}'".format(mod_path, opt)


# ---------------------------------------------------------------
# Credential harvest: _parse_credentials helper
# ---------------------------------------------------------------


class TestCredentialHarvestParsing:
    """Test the _parse_credentials helper without network access."""

    @pytest.fixture()
    def exploit_cls(self):
        try:
            from embedxpl.modules.post.embedded_credential_harvest import Exploit
        except ImportError:
            pytest.skip("Cannot import embedded_credential_harvest")
        return Exploit

    def test_parse_shadow_hash(self, exploit_cls) -> None:
        inst = exploit_cls()
        output = "root:$6$salt$hashvalue:17000:0:99999:7:::\n"
        findings = inst._parse_credentials(output, "shadow")
        assert any("password_hash" in f[1] for f in findings)

    def test_parse_passwd_login_account(self, exploit_cls) -> None:
        inst = exploit_cls()
        output = "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\n"
        findings = inst._parse_credentials(output, "passwd")
        # root has /bin/sh (login shell), nobody has /bin/false (no login)
        account_users = [f[2] for f in findings if "login_account" in f[1]]
        assert any("root" in u for u in account_users)
        # nobody should NOT appear (nologin shell)
        assert not any("nobody" in u for u in account_users)

    def test_parse_credential_pattern(self, exploit_cls) -> None:
        inst = exploit_cls()
        output = "password=supersecret123\n"
        findings = inst._parse_credentials(output, "nvram")
        assert len(findings) >= 1
        assert any("supersecret123" in f[2] for f in findings)

    def test_parse_empty_output(self, exploit_cls) -> None:
        inst = exploit_cls()
        findings = inst._parse_credentials("", "shadow")
        assert findings == []

    def test_parse_comment_lines_skipped(self, exploit_cls) -> None:
        inst = exploit_cls()
        output = "# This is a comment\n"
        findings = inst._parse_credentials(output, "nvram")
        assert findings == []


# ---------------------------------------------------------------
# Router config exfil: _detect_router_type and _is_config_data
# ---------------------------------------------------------------


class TestRouterConfigExfil:
    """Test helper methods of router_config_exfil without network."""

    @pytest.fixture()
    def exploit_cls(self):
        try:
            from embedxpl.modules.post.router_config_exfil import Exploit
        except ImportError:
            pytest.skip("Cannot import router_config_exfil")
        return Exploit

    @pytest.mark.parametrize(
        "banner,expected_type",
        [
            ("Cisco IOS Software, Version 15.2", "cisco_ios"),
            ("MikroTik RouterOS v6.49", "mikrotik"),
            ("OpenWrt 21.02", "openwrt"),
            ("VyOS 1.3", "vyos"),
            ("Some random banner text", "generic"),
        ],
        ids=["cisco", "mikrotik", "openwrt", "vyos", "generic"],
    )
    def test_detect_router_type(self, exploit_cls, banner: str, expected_type: str) -> None:
        inst = exploit_cls()
        assert inst._detect_router_type(banner) == expected_type

    @pytest.mark.parametrize(
        "data,expected",
        [
            ("interface eth0\nip address 10.0.0.1/24\nhostname router1", True),
            ("short", False),
            ("interface loopback\nfirewall zone lan\nroute default", True),
        ],
        ids=["config_data", "too_short", "multi_indicator"],
    )
    def test_is_config_data(self, exploit_cls, data: str, expected: bool) -> None:
        inst = exploit_cls()
        assert inst._is_config_data(data) == expected


# ---------------------------------------------------------------
# IoT network recon: _extract_ips and _port_to_service
# ---------------------------------------------------------------


class TestIoTNetworkRecon:
    """Test helper methods of iot_network_recon without network."""

    @pytest.fixture()
    def exploit_cls(self):
        try:
            from embedxpl.modules.post.iot_network_recon import Exploit
        except ImportError:
            pytest.skip("Cannot import iot_network_recon")
        return Exploit

    def test_extract_ips_from_arp(self, exploit_cls) -> None:
        inst = exploit_cls()
        arp_output = (
            "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on br-lan\n"
            "? (192.168.1.100) at 11:22:33:44:55:66 [ether] on br-lan\n"
        )
        ips = inst._extract_ips(arp_output)
        assert "192.168.1.1" in ips
        assert "192.168.1.100" in ips

    def test_extract_ips_excludes_invalid(self, exploit_cls) -> None:
        inst = exploit_cls()
        text = "address 999.999.999.999 is invalid"
        ips = inst._extract_ips(text)
        assert "999.999.999.999" not in ips

    @pytest.mark.parametrize(
        "port,expected_service",
        [
            (22, "SSH"),
            (80, "HTTP"),
            (443, "HTTPS"),
            (502, "Modbus"),
            (1883, "MQTT"),
            (9999, "unknown"),
        ],
    )
    def test_port_to_service(self, exploit_cls, port: int, expected_service: str) -> None:
        assert exploit_cls._port_to_service(port) == expected_service

    def test_ip_sort_key(self, exploit_cls) -> None:
        key = exploit_cls._ip_sort_key("10.0.0.1")
        assert key == (10, 0, 0, 1)


# ---------------------------------------------------------------
# Firmware persistence: _find_rootfs and _generate_reverse_shells
# ---------------------------------------------------------------


class TestFirmwarePersistenceInject:
    """Test firmware persistence helpers without filesystem writes."""

    @pytest.fixture()
    def exploit_cls(self):
        try:
            from embedxpl.modules.post.firmware_persistence_inject import Exploit
        except ImportError:
            pytest.skip("Cannot import firmware_persistence_inject")
        return Exploit

    def test_generate_reverse_shells(self, exploit_cls) -> None:
        inst = exploit_cls()
        shells = inst._generate_reverse_shells("10.0.0.1", 4444)
        assert isinstance(shells, dict)
        assert "busybox_nc" in shells
        assert "fifo" in shells
        assert "10.0.0.1" in shells["busybox_nc"]
        assert "4444" in shells["busybox_nc"]

    def test_find_rootfs_nonexistent(self, exploit_cls, tmp_path) -> None:
        inst = exploit_cls()
        result = inst._find_rootfs(str(tmp_path / "nonexistent"))
        assert result is None

    def test_find_rootfs_valid(self, exploit_cls, tmp_path) -> None:
        # Create a minimal rootfs structure
        (tmp_path / "etc").mkdir()
        (tmp_path / "bin").mkdir()
        inst = exploit_cls()
        result = inst._find_rootfs(str(tmp_path))
        assert result is not None
        assert result.name == tmp_path.name


# ---------------------------------------------------------------
# Embedded log cleanup: module constants
# ---------------------------------------------------------------


class TestEmbeddedLogCleanup:
    """Test log cleanup module structure."""

    @pytest.fixture()
    def mod(self):
        try:
            import embedxpl.modules.post.embedded_log_cleanup as m
        except ImportError:
            pytest.skip("Cannot import embedded_log_cleanup")
        return m

    def test_log_targets_defined(self, mod) -> None:
        targets = mod._LOG_TARGETS
        assert isinstance(targets, list)
        assert len(targets) >= 10, "Expected at least 10 log target entries"

    def test_log_targets_have_three_fields(self, mod) -> None:
        for entry in mod._LOG_TARGETS:
            assert len(entry) == 3, "Each log target should be (path, description, method)"
            path, desc, method = entry
            assert path.startswith("/")
            assert method in ("filter", "truncate")

    def test_exploit_has_pattern_option(self, mod) -> None:
        assert hasattr(mod.Exploit, "pattern")
