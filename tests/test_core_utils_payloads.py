"""Comprehensive tests for utils.py and payloads.py."""

import os
import string
from unittest.mock import MagicMock, patch

import pytest

from embedxpl.core.exploit.exceptions import OptionValidationError
from embedxpl.core.exploit.utils import (
    Version,
    _module_path_disabled,
    convert_ip,
    convert_port,
    detect_file_content,
    humanize_path,
    is_ipv4,
    is_ipv6,
    lookup_vendor,
    module_required,
    pythonize_path,
    random_text,
    stop_after,
)


class TestIsIpv4:
    @pytest.mark.parametrize("addr", [
        "192.168.1.1", "0.0.0.0", "255.255.255.255", "10.0.0.1",
        "172.16.0.1", "127.0.0.1", "1.2.3.4",
    ])
    def test_valid(self, addr):
        assert is_ipv4(addr) is True

    @pytest.mark.parametrize("addr", [
        "256.1.1.1", "1.1.1.256", "1.1.1", "1.1.1.1.1",
        "abc", "", "192.168.1.1/24", "::1",
    ])
    def test_invalid(self, addr):
        assert is_ipv4(addr) is False


class TestIsIpv6:
    @pytest.mark.parametrize("addr", [
        "::1%eth0", "fe80::1%lo", "2001:db8::1%0",
    ])
    def test_valid_with_zone(self, addr):
        assert is_ipv6(addr) is True

    def test_plain_ipv4_not_ipv6(self):
        assert is_ipv6("192.168.1.1") is False

    def test_empty(self):
        assert is_ipv6("") is False


class TestConvertIp:
    def test_basic(self):
        assert convert_ip("192.168.1.1") == bytes([192, 168, 1, 1])

    def test_zeros(self):
        assert convert_ip("0.0.0.0") == bytes([0, 0, 0, 0])

    def test_max(self):
        assert convert_ip("255.255.255.255") == bytes([255, 255, 255, 255])


class TestConvertPort:
    @pytest.mark.parametrize("port,expected_hex", [
        (80, "0050"), (443, "01bb"), (8080, "1f90"), (1, "0001"), (65535, "ffff"),
    ])
    def test_ports(self, port, expected_hex):
        assert convert_port(port) == bytes.fromhex(expected_hex)


class TestRandomText:
    def test_length(self):
        assert len(random_text(10)) == 10

    def test_zero(self):
        assert random_text(0) == ""

    def test_custom_alphabet(self):
        result = random_text(20, alph="ab")
        assert all(c in "ab" for c in result)


class TestPythonizePath:
    @pytest.mark.parametrize("inp,expected", [
        ("foo/bar/baz", "foo.bar.baz"), ("single", "single"), ("", ""),
    ])
    def test_conversion(self, inp, expected):
        assert pythonize_path(inp) == expected


class TestHumanizePath:
    @pytest.mark.parametrize("inp,expected", [
        ("foo.bar.baz", "foo/bar/baz"), ("single", "single"), ("", ""),
    ])
    def test_conversion(self, inp, expected):
        assert humanize_path(inp) == expected


class TestModulePathDisabled:
    def test_empty_disabled_domains(self):
        assert _module_path_disabled("anything") is False

    def test_with_disabled_domain(self):
        import embedxpl.core.exploit.utils as utils_mod
        original = utils_mod.DISABLED_MODULE_DOMAINS
        utils_mod.DISABLED_MODULE_DOMAINS = ("exploits",)
        try:
            assert utils_mod._module_path_disabled("exploits.routers.test") is True
            assert utils_mod._module_path_disabled("creds.database") is False
        finally:
            utils_mod.DISABLED_MODULE_DOMAINS = original


class TestModuleRequired:
    def test_no_module(self):
        class Interp:
            current_module = None

            @module_required
            def do_run(self):
                return "executed"

        with patch("embedxpl.core.exploit.utils.print_error"):
            assert Interp().do_run() is None

    def test_with_module(self):
        class Interp:
            current_module = "some"

            @module_required
            def do_run(self):
                return "executed"

        assert Interp().do_run() == "executed"

    def test_has_decorators_attr(self):
        class Interp:
            current_module = None

            @module_required
            def do_run(self):
                pass

        assert "module_required" in Interp.do_run.__decorators__


class TestStopAfter:
    def test_stops(self):
        class Interp:
            @stop_after(2)
            def complete_use(self, text, line, *a):
                return ["opt1"]

        assert Interp().complete_use("", "use exploits/test ") == []

    def test_continues(self):
        class Interp:
            @stop_after(2)
            def complete_use(self, text, line, *a):
                return ["opt1"]

        assert Interp().complete_use("", "use exploits") == ["opt1"]


class TestVersion:
    @pytest.mark.parametrize("v1,v2", [
        ("1.0", "2.0"), ("1.0.0", "1.0.1"), ("1.9", "1.10"), ("0.1", "0.2"),
    ])
    def test_lt(self, v1, v2):
        assert Version(v1) < Version(v2)

    @pytest.mark.parametrize("v1,v2", [
        ("1.0", "1.0"), ("1.0.0", "1.0"), ("2.0", "2.0.0"),
    ])
    def test_eq(self, v1, v2):
        assert Version(v1) == Version(v2)

    def test_ne(self):
        assert Version("1.0") != Version("2.0")

    def test_gt(self):
        assert Version("2.0") > Version("1.0")

    def test_ge(self):
        assert Version("2.0") >= Version("1.0")
        assert Version("1.0") >= Version("1.0")

    def test_le(self):
        assert Version("1.0") <= Version("2.0")
        assert Version("1.0") <= Version("1.0")

    def test_coerce_from_string(self):
        assert Version("1.0") < "2.0"
        assert Version("2.0") > "1.0"

    def test_repr(self):
        assert repr(Version("1.2.3")) == "Version('1.2.3')"

    def test_non_numeric(self):
        assert Version("1.2.3b") == Version("1.2.3.0")

    def test_compare_static(self):
        assert Version._compare_versions("1.0", "2.0") == -1
        assert Version._compare_versions("2.0", "1.0") == 1
        assert Version._compare_versions("1.0", "1.0") == 0


class TestDetectFileContent:
    def test_passwd_root(self):
        assert detect_file_content("root:x:0:0:root:/root:/bin/bash") is True

    def test_passwd_admin(self):
        assert detect_file_content("admin:x:1000:1000:Admin:/home/admin:/bin/sh") is True

    def test_shadow(self):
        assert detect_file_content("root:$6$abc:18000:0:99999:7:::", "/etc/shadow") is True

    def test_no_match(self):
        assert detect_file_content("hello world") is False

    def test_unknown_file(self):
        assert detect_file_content("any content", "/etc/hosts") is False


class TestLookupVendor:
    def test_found(self, tmp_path):
        vendors_dir = tmp_path / "vendors"
        vendors_dir.mkdir()
        (vendors_dir / "oui.dat").write_text("# comment\n\n001122 TestVendor Inc\n")
        assert lookup_vendor("00:11:22:33:44:55", str(tmp_path)) == "TestVendor Inc"

    def test_not_found(self, tmp_path):
        vendors_dir = tmp_path / "vendors"
        vendors_dir.mkdir()
        (vendors_dir / "oui.dat").write_text("001122 TestVendor\n")
        assert lookup_vendor("FF:FF:FF:00:00:00", str(tmp_path)) is None


# ── Payloads ──

from embedxpl.core.exploit.payloads import (
    ARCH_ELF_HEADERS,
    Architectures,
    ArchitectureSpecificPayload,
    BasePayload,
    BindTCPPayloadMixin,
    GenericPayload,
    PayloadHandlers,
    ReverseTCPPayloadMixin,
)


class TestArchitectures:
    @pytest.mark.parametrize("attr,val", [
        ("ARMLE", "armle"), ("MIPSBE", "mipsbe"), ("MIPSLE", "mipsle"),
        ("X86", "x86"), ("X64", "x64"), ("PERL", "perl"), ("PHP", "php"), ("PYTHON", "python"),
    ])
    def test_values(self, attr, val):
        assert getattr(Architectures, attr) == val


class TestPayloadHandlers:
    def test_bind(self):
        assert PayloadHandlers.BIND_TCP == "bind_tcp"

    def test_reverse(self):
        assert PayloadHandlers.REVERSE_TCP == "reverse_tcp"


class TestArchElfHeaders:
    def test_all_arches(self):
        for arch in [Architectures.ARMLE, Architectures.MIPSBE, Architectures.MIPSLE,
                     Architectures.X86, Architectures.X64]:
            assert arch in ARCH_ELF_HEADERS
            assert ARCH_ELF_HEADERS[arch][:4] == b"\x7fELF"


class TestReverseTCPMixin:
    def test_handler(self):
        assert ReverseTCPPayloadMixin.handler == PayloadHandlers.REVERSE_TCP

    def test_exploit_attributes(self):
        assert "lhost" in ReverseTCPPayloadMixin.exploit_attributes
        assert "lport" in ReverseTCPPayloadMixin.exploit_attributes


class TestBindTCPMixin:
    def test_handler(self):
        assert BindTCPPayloadMixin.handler == PayloadHandlers.BIND_TCP

    def test_exploit_attributes(self):
        assert "rport" in BindTCPPayloadMixin.exploit_attributes


def _make_x86_payload_cls():
    class TestPayload(ReverseTCPPayloadMixin, ArchitectureSpecificPayload):
        __info__ = {"name": "test_arch", "description": "test"}
        architecture = Architectures.X86

        def generate(self):
            return b"\xcc" * 20

    return TestPayload


class TestBasePayload:
    def test_invalid_handler(self):
        class Bad(BasePayload):
            handler = "nope"

        with pytest.raises(OptionValidationError):
            Bad()

    def test_valid_handler(self):
        class Good(ReverseTCPPayloadMixin, BasePayload):
            __info__ = {"name": "t", "description": "t"}
            def generate(self):
                return b""

        p = Good()
        assert p.handler == "reverse_tcp"

    def test_generate_not_implemented(self):
        class Min(ReverseTCPPayloadMixin, BasePayload):
            __info__ = {"name": "t", "description": "t"}

        with pytest.raises(NotImplementedError):
            Min().generate()

    def test_run_not_implemented(self):
        class Min(ReverseTCPPayloadMixin, BasePayload):
            __info__ = {"name": "t", "description": "t"}

        with pytest.raises(NotImplementedError):
            Min().run()


class TestArchSpecPayload:
    def test_init_valid(self):
        cls = _make_x86_payload_cls()
        p = cls()
        assert p.header is not None
        assert p.bigendian is False

    def test_init_invalid_arch(self):
        class Bad(ReverseTCPPayloadMixin, ArchitectureSpecificPayload):
            __info__ = {"name": "b", "description": "b"}
            architecture = "bad"

        with pytest.raises(OptionValidationError):
            Bad()

    def test_generate_elf_32(self):
        p = _make_x86_payload_cls()()
        elf = p.generate_elf(b"\xcc" * 20)
        assert elf[:4] == b"\x7fELF"

    def test_generate_elf_64(self):
        class X64(ReverseTCPPayloadMixin, ArchitectureSpecificPayload):
            __info__ = {"name": "x64", "description": "x64"}
            architecture = Architectures.X64
            def generate(self):
                return b"\x90" * 10

        elf = X64().generate_elf(b"\x90" * 10)
        assert elf[4] == 2

    def test_generate_elf_bigendian(self):
        class MIPS(ReverseTCPPayloadMixin, ArchitectureSpecificPayload):
            __info__ = {"name": "mips", "description": "be"}
            architecture = Architectures.MIPSBE
            def generate(self):
                return b"\x00" * 10

        p = MIPS()
        assert p.bigendian is True

    def test_generate_c(self):
        result = ArchitectureSpecificPayload.generate_c(b"\x41\x42\x43")
        assert "unsigned char sh[]" in result
        assert "\\x41" in result

    def test_generate_python(self):
        result = ArchitectureSpecificPayload.generate_python(b"\x41\x42")
        assert "payload = (" in result

    def test_run_elf(self, tmp_path):
        p = _make_x86_payload_cls()()
        p.output = "elf"
        p.filepath = str(tmp_path / "p.elf")
        with patch("embedxpl.core.exploit.payloads.print_status"), \
             patch("embedxpl.core.exploit.payloads.print_success"), \
             patch("embedxpl.core.exploit.payloads.print_info"):
            p.run()
        assert (tmp_path / "p.elf").exists()

    def test_run_c(self):
        p = _make_x86_payload_cls()()
        p.output = "c"
        with patch("embedxpl.core.exploit.payloads.print_status"), \
             patch("embedxpl.core.exploit.payloads.print_success"), \
             patch("embedxpl.core.exploit.payloads.print_info"):
            r = p.run()
        assert "unsigned char" in r

    def test_run_python(self):
        p = _make_x86_payload_cls()()
        p.output = "python"
        with patch("embedxpl.core.exploit.payloads.print_status"), \
             patch("embedxpl.core.exploit.payloads.print_success"), \
             patch("embedxpl.core.exploit.payloads.print_info"):
            r = p.run()
        assert "payload = (" in r

    def test_run_invalid(self):
        p = _make_x86_payload_cls()()
        p.output = "invalid"
        with patch("embedxpl.core.exploit.payloads.print_status"), \
             patch("embedxpl.core.exploit.payloads.print_error"):
            with pytest.raises(OptionValidationError):
                p.run()


class TestGenericPayload:
    def test_run_no_encoder(self):
        class Gen(ReverseTCPPayloadMixin, GenericPayload):
            __info__ = {"name": "g", "description": "g"}
            encoder = None
            def generate(self):
                return "raw"

        with patch("embedxpl.core.exploit.payloads.print_status"), \
             patch("embedxpl.core.exploit.payloads.print_info"):
            assert Gen().run() == "raw"

    def test_run_with_encoder(self):
        enc = MagicMock()
        enc.encode.return_value = "encoded"

        class Gen(ReverseTCPPayloadMixin, GenericPayload):
            __info__ = {"name": "g", "description": "g"}
            encoder = enc
            def generate(self):
                return "raw"

        with patch("embedxpl.core.exploit.payloads.print_status"), \
             patch("embedxpl.core.exploit.payloads.print_info"):
            assert Gen().run() == "encoded"

    def test_run_with_fmt(self):
        class Gen(ReverseTCPPayloadMixin, GenericPayload):
            __info__ = {"name": "g", "description": "g"}
            encoder = None
            fmt = "wrap({})"
            def generate(self):
                return "inner"

        with patch("embedxpl.core.exploit.payloads.print_status"), \
             patch("embedxpl.core.exploit.payloads.print_info"):
            assert Gen().run() == "wrap(inner)"
