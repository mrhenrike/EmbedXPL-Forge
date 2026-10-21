"""Tests for embedxpl.core.exploit.option Option types."""
from __future__ import annotations

import os
import tempfile

import pytest

from embedxpl.core.exploit.exceptions import OptionValidationError
from embedxpl.core.exploit.option import (
    OptBool,
    OptFloat,
    OptInteger,
    Option,
    OptIP,
    OptMAC,
    OptPort,
    OptString,
    OptWordlist,
)


class TestOption:
    def test_default_value(self):
        o = Option("hello", "desc")
        assert o.value == "hello"

    def test_zero_default(self):
        o = Option(0, "zero")
        assert o.value == 0

    def test_empty_default(self):
        o = Option("", "empty")
        assert o.value == ""

    def test_description(self):
        o = Option("v", "my description")
        assert o.description == "my description"

    def test_advanced_default_false(self):
        o = Option("v", "d")
        assert o.advanced is False

    def test_advanced_true(self):
        o = Option("v", "d", advanced=True)
        assert o.advanced is True


class TestOptIP:
    def test_valid_ipv4(self):
        o = OptIP("192.168.1.1", "IP")
        assert o.value == "192.168.1.1"

    def test_valid_ipv6(self):
        OptIP("::1%lo", "IP")

    def test_file_uri(self):
        o = OptIP("", "IP")
        o.__set__(None, "file:///targets.txt")
        assert o.value == "file:///targets.txt"

    def test_empty_allowed(self):
        o = OptIP("", "IP")
        assert o.value == ""

    def test_invalid_raises(self):
        o = OptIP("", "IP")
        with pytest.raises(OptionValidationError):
            o.__set__(None, "not-an-ip")


class TestOptPort:
    def test_valid_port(self):
        o = OptPort(80, "port")
        assert o.value == 80

    def test_max_port(self):
        o = OptPort(65535, "port")
        assert o.value == 65535

    def test_min_port(self):
        o = OptPort(1, "port")
        assert o.value == 1

    def test_zero_port_raises(self):
        with pytest.raises(OptionValidationError):
            OptPort(0, "port")

    def test_negative_raises(self):
        with pytest.raises(OptionValidationError):
            OptPort(-1, "port")

    def test_over_max_raises(self):
        with pytest.raises(OptionValidationError):
            OptPort(65536, "port")

    def test_string_cast(self):
        o = OptPort(8080, "port")
        o.__set__(None, "443")
        assert o.value == 443

    def test_non_numeric_raises(self):
        o = OptPort(80, "port")
        with pytest.raises(OptionValidationError):
            o.__set__(None, "abc")


class TestOptBool:
    def test_true(self):
        o = OptBool(True, "flag")
        assert o.value is True
        assert o.display_value == "true"

    def test_false(self):
        o = OptBool(False, "flag")
        assert o.value is False
        assert o.display_value == "false"

    def test_set_true_string(self):
        o = OptBool(False, "flag")
        o.__set__(None, "true")
        assert o.value is True

    def test_set_false_string(self):
        o = OptBool(True, "flag")
        o.__set__(None, "false")
        assert o.value is False

    def test_invalid_string_raises(self):
        o = OptBool(True, "flag")
        with pytest.raises(OptionValidationError):
            o.__set__(None, "yes")


class TestOptInteger:
    def test_decimal(self):
        o = OptInteger(42, "int")
        assert o.value == 42

    def test_string_decimal(self):
        o = OptInteger(0, "int")
        o.__set__(None, "100")
        assert o.value == 100

    def test_hex(self):
        o = OptInteger(0, "int")
        o.__set__(None, "0xff")
        assert o.value == 255

    def test_invalid_raises(self):
        o = OptInteger(0, "int")
        with pytest.raises(OptionValidationError):
            o.__set__(None, "not_a_number")


class TestOptFloat:
    def test_float(self):
        o = OptFloat(3.14, "float")
        assert o.value == pytest.approx(3.14)

    def test_string_float(self):
        o = OptFloat(0.0, "float")
        o.__set__(None, "2.5")
        assert o.value == pytest.approx(2.5)

    def test_invalid_raises(self):
        o = OptFloat(0.0, "float")
        with pytest.raises(OptionValidationError):
            o.__set__(None, "abc")


class TestOptString:
    def test_string(self):
        o = OptString("hello", "str")
        assert o.value == "hello"

    def test_set(self):
        o = OptString("", "str")
        o.__set__(None, "world")
        assert o.value == "world"


class TestOptMAC:
    def test_valid_mac(self):
        o = OptMAC("aa:bb:cc:dd:ee:ff", "mac")
        assert o.value == "aa:bb:cc:dd:ee:ff"

    def test_uppercase_mac(self):
        o = OptMAC("AA:BB:CC:DD:EE:FF", "mac")
        assert o.value == "AA:BB:CC:DD:EE:FF"

    def test_invalid_raises(self):
        o = OptMAC("", "mac")
        with pytest.raises(OptionValidationError):
            o.__set__(None, "not-a-mac")

    def test_short_octets(self):
        o = OptMAC("a:b:c:d:e:f", "mac")
        assert o.value == "a:b:c:d:e:f"


class TestOptWordlist:
    def test_comma_separated(self):
        o = OptWordlist("a,b,c", "wordlist")
        assert o.__get__(None, None) == ["a", "b", "c"]

    def test_file_uri(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("word1\nword2\nword3\n")
            path = f.name
        try:
            o = OptWordlist(f"file://{path}", "wordlist")
            result = o.__get__(None, None)
            assert "word1" in result
            assert "word2" in result
            assert len(result) == 3
        finally:
            os.unlink(path)

    def test_nonexistent_file_raises(self):
        with pytest.raises(OptionValidationError):
            o = OptWordlist("", "wl")
            o.__set__(None, "file:///nonexistent/file.txt")
