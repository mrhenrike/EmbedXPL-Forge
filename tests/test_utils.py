"""Tests for embedxpl.core.exploit.utils."""
from __future__ import annotations

from embedxpl.core.exploit.utils import (
    MODULES_DIR,
    RESOURCES_DIR,
    _module_path_disabled,
    is_ipv4,
    is_ipv6,
    random_text,
)


class TestIsIPv4:
    def test_valid(self):
        assert is_ipv4("192.168.1.1") is True

    def test_loopback(self):
        assert is_ipv4("127.0.0.1") is True

    def test_broadcast(self):
        assert is_ipv4("255.255.255.255") is True

    def test_zeros(self):
        assert is_ipv4("0.0.0.0") is True

    def test_invalid_octet(self):
        assert is_ipv4("256.1.1.1") is False

    def test_too_few_octets(self):
        assert is_ipv4("192.168.1") is False

    def test_empty(self):
        assert is_ipv4("") is False

    def test_hostname(self):
        assert is_ipv4("example.com") is False

    def test_ipv6_rejected(self):
        assert is_ipv4("::1") is False


class TestIsIPv6:
    def test_loopback(self):
        assert is_ipv6("::1%lo") is True

    def test_full_address(self):
        assert is_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334%eth0") is True

    def test_empty_not_valid(self):
        assert is_ipv6("") is False


class TestRandomText:
    def test_length(self):
        result = random_text(10)
        assert len(result) == 10

    def test_zero_length(self):
        assert random_text(0) == ""

    def test_custom_alphabet(self):
        result = random_text(20, alph="abc")
        assert all(c in "abc" for c in result)

    def test_uniqueness(self):
        results = {random_text(32) for _ in range(10)}
        assert len(results) > 1


class TestModulePathDisabled:
    def test_empty_domains_not_disabled(self):
        assert _module_path_disabled("exploits/routers/mikrotik") is False


class TestDirectoryConstants:
    def test_modules_dir_exists(self):
        import os
        assert os.path.isdir(MODULES_DIR)

    def test_resources_dir_exists(self):
        import os
        assert os.path.isdir(RESOURCES_DIR)
