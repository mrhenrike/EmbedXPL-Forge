"""Tests for embedxpl.modules.exploits.evasion.* module structure and helpers.

Validates that evasion modules follow the required interface and that
exposed helper functions produce correct results without network access.
"""
from __future__ import annotations

import base64
import binascii
import importlib
import struct

import pytest

# ---------------------------------------------------------------
# Module paths and their expected option attributes
# ---------------------------------------------------------------

EVASION_MODULES = [
    (
        "embedxpl.modules.exploits.evasion.dns_tunnel_exfil",
        ["dns_server", "port", "domain", "data", "data_file", "encoding", "chunk_delay"],
    ),
    (
        "embedxpl.modules.exploits.evasion.icmp_covert_channel",
        ["target", "data", "data_file", "xor_key", "chunk_size", "mode"],
    ),
    (
        "embedxpl.modules.exploits.evasion.http_header_steganography",
        ["target", "port", "data", "path", "headers_to_use", "encoding"],
    ),
    (
        "embedxpl.modules.exploits.evasion.firmware_integrity_bypass",
        ["firmware_path", "method", "checksum_offset", "checksum_algo"],
    ),
]

REQUIRED_INFO_KEYS = {"name", "description", "authors"}

_KNOWN_IMPORT_ERRORS = (ImportError, ModuleNotFoundError, OSError)


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
# Parametrized structural tests
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    "mod_path,expected_opts",
    EVASION_MODULES,
    ids=[p.rsplit(".", 1)[-1] for p, _ in EVASION_MODULES],
)
class TestEvasionModuleStructure:
    """Structural tests for evasion modules."""

    def test_importable(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_exploit_class_exists(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        assert hasattr(mod, "Exploit"), "{} missing Exploit class".format(mod_path)

    def test_has_info_dict(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        info = _get_info(mod.Exploit)
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
        assert len(authors) >= 1

    def test_has_run_method(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        assert hasattr(mod.Exploit, "run") and callable(mod.Exploit.run)

    def test_expected_options_present(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        cls = mod.Exploit
        for opt in expected_opts:
            assert hasattr(cls, opt), "{} missing option '{}'".format(mod_path, opt)


# ---------------------------------------------------------------
# DNS Tunnel Exfil: helper functions
# ---------------------------------------------------------------


class TestDnsTunnelExfil:
    """Test DNS tunnel helper functions without network access."""

    @pytest.fixture()
    def mod(self):
        try:
            import embedxpl.modules.exploits.evasion.dns_tunnel_exfil as m
        except ImportError:
            pytest.skip("Cannot import dns_tunnel_exfil")
        return m

    def test_encode_chunk_base32(self, mod) -> None:
        encoded = mod._encode_chunk(b"hello", "base32")
        assert isinstance(encoded, str)
        assert len(encoded) > 0
        # base32 encode "hello" -> "nbswy3dp" (lowercase, no padding)
        expected = base64.b32encode(b"hello").decode("ascii").rstrip("=").lower()
        assert encoded == expected

    def test_encode_chunk_hex(self, mod) -> None:
        encoded = mod._encode_chunk(b"\xde\xad", "hex")
        assert encoded == "dead"

    @pytest.mark.parametrize(
        "data,encoding",
        [
            (b"A", "base32"),
            (b"A" * 100, "base32"),
            (b"\x00\xff", "hex"),
        ],
        ids=["short_b32", "long_b32", "binary_hex"],
    )
    def test_encode_chunk_roundtrip_is_decodable(self, mod, data: bytes, encoding: str) -> None:
        encoded = mod._encode_chunk(data, encoding)
        assert isinstance(encoded, str)
        # Verify it only contains DNS-safe characters
        assert all(c.isalnum() or c in "-_=" for c in encoded)

    def test_build_dns_query_produces_valid_packet(self, mod) -> None:
        packet = mod._build_dns_query("test.example.com", mod._DNS_TYPE_TXT)
        assert isinstance(packet, bytes)
        # DNS header is 12 bytes minimum
        assert len(packet) >= 12
        # First 2 bytes: transaction ID (non-zero typically)
        # Bytes 4-5: question count should be 1
        qdcount = struct.unpack("!H", packet[4:6])[0]
        assert qdcount == 1

    def test_calculate_label_capacity_base32(self, mod) -> None:
        cap = mod._calculate_label_capacity("exfil.example.com", "base32")
        assert cap > 0
        # base32: (63 - 3) * 5 / 8 = 37 bytes
        assert cap == 37

    def test_calculate_label_capacity_hex(self, mod) -> None:
        cap = mod._calculate_label_capacity("exfil.example.com", "hex")
        assert cap > 0
        # hex: (63 - 3) / 2 = 30 bytes
        assert cap == 30

    def test_calculate_max_labels(self, mod) -> None:
        labels = mod._calculate_max_labels("exfil.example.com")
        assert labels >= 1
        # 253 - (len("exfil.example.com") + 1) = 253 - 18 = 235
        # 235 / (63 + 1) = 3 labels
        assert labels == 3

    def test_parse_dns_response_empty(self, mod) -> None:
        result = mod._parse_dns_response(b"")
        assert result == []

    def test_parse_dns_response_too_short(self, mod) -> None:
        result = mod._parse_dns_response(b"\x00" * 5)
        assert result == []


# ---------------------------------------------------------------
# ICMP Covert Channel: checksum and encoding helpers
# ---------------------------------------------------------------


class TestIcmpCovertChannel:
    """Test ICMP helper functions without raw sockets."""

    @pytest.fixture()
    def mod(self):
        try:
            import embedxpl.modules.exploits.evasion.icmp_covert_channel as m
        except ImportError:
            pytest.skip("Cannot import icmp_covert_channel")
        return m

    def test_internet_checksum_known_value(self, mod) -> None:
        # RFC 1071 example: for data b"\x00\x01\xf2\x03..."
        # Simple test: checksum of all zeros should be 0xFFFF
        data = b"\x00\x00\x00\x00"
        cksum = mod._internet_checksum(data)
        assert cksum == 0xFFFF

    def test_internet_checksum_nonzero(self, mod) -> None:
        data = b"\x08\x00\x00\x00\x00\x01\x00\x01"  # ICMP echo with zero checksum
        cksum = mod._internet_checksum(data)
        assert isinstance(cksum, int)
        assert 0 <= cksum <= 0xFFFF

    def test_internet_checksum_odd_length(self, mod) -> None:
        # Odd-length data should be padded with zero byte
        data = b"\x01\x02\x03"
        cksum = mod._internet_checksum(data)
        assert isinstance(cksum, int)
        assert 0 <= cksum <= 0xFFFF

    def test_xor_encode_roundtrip(self, mod) -> None:
        original = b"Hello World"
        key = 0x41
        encoded = mod._xor_encode(original, key)
        decoded = mod._xor_encode(encoded, key)
        assert decoded == original

    def test_xor_encode_changes_data(self, mod) -> None:
        data = b"AAAA"
        encoded = mod._xor_encode(data, 0x42)
        assert encoded != data

    def test_xor_encode_key_zero_is_identity(self, mod) -> None:
        data = b"test data"
        encoded = mod._xor_encode(data, 0x00)
        assert encoded == data

    def test_build_icmp_echo_produces_valid_packet(self, mod) -> None:
        payload = b"testpayload"
        packet = mod._build_icmp_echo(seq=1, identifier=0x1234, payload=payload)
        assert isinstance(packet, bytes)
        # ICMP header is 8 bytes + payload
        assert len(packet) == 8 + len(payload)
        # Type should be 8 (echo request)
        assert packet[0] == 8
        # Code should be 0
        assert packet[1] == 0

    def test_build_icmp_echo_checksum_validates(self, mod) -> None:
        payload = b"checksum_test"
        packet = mod._build_icmp_echo(seq=0, identifier=0xBEEF, payload=payload)
        # Verify checksum: the checksum of the entire packet should be 0
        verify_cksum = mod._internet_checksum(packet)
        assert verify_cksum == 0, "ICMP packet checksum verification failed"

    def test_parse_icmp_reply_too_short(self, mod) -> None:
        result = mod._parse_icmp_reply(b"\x00" * 10)
        assert result is None

    def test_parse_icmp_reply_not_echo_reply(self, mod) -> None:
        # Build a fake IP header (20 bytes) + ICMP with type 8 (request, not reply)
        ip_header = b"\x45" + b"\x00" * 19
        icmp_data = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1) + b"payload"
        result = mod._parse_icmp_reply(ip_header + icmp_data)
        assert result is None  # Type 8 is request, not reply


# ---------------------------------------------------------------
# HTTP Header Steganography: encoding and header formatting
# ---------------------------------------------------------------


class TestHttpHeaderSteganography:
    """Test HTTP header steganography helpers without network."""

    @pytest.fixture()
    def mod(self):
        try:
            import embedxpl.modules.exploits.evasion.http_header_steganography as m
        except ImportError:
            pytest.skip("Cannot import http_header_steganography")
        return m

    def test_encode_data_base64(self, mod) -> None:
        data = b"secret data"
        encoded = mod._encode_data(data, "base64")
        assert isinstance(encoded, str)
        # URL-safe base64 should be decodable
        # Add padding back for decoding
        padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        assert decoded == data

    def test_encode_data_hex(self, mod) -> None:
        data = b"\xca\xfe"
        encoded = mod._encode_data(data, "hex")
        assert encoded == "cafe"

    @pytest.mark.parametrize(
        "header_name",
        ["X-Request-ID", "Cookie", "ETag", "If-None-Match", "Accept-Language"],
    )
    def test_make_header_value_nonempty(self, mod, header_name: str) -> None:
        value = mod._make_header_value("dGVzdA", header_name)
        assert isinstance(value, str)
        assert len(value) > 0

    def test_make_header_cookie_format(self, mod) -> None:
        value = mod._make_header_value("encoded_data", "Cookie")
        assert "session=" in value

    def test_make_header_etag_format(self, mod) -> None:
        value = mod._make_header_value("encoded_data", "ETag")
        assert value.startswith('W/"')

    def test_build_http_request_format(self, mod) -> None:
        request = mod._build_http_request(
            host="10.0.0.1",
            port=80,
            path="/test",
            headers={"X-Custom": "value123"},
        )
        assert isinstance(request, bytes)
        decoded = request.decode("ascii")
        assert "GET /test HTTP/1.1" in decoded
        assert "Host: 10.0.0.1:80" in decoded
        assert "X-Custom: value123" in decoded
        assert decoded.endswith("\r\n\r\n")

    def test_parse_http_response_valid(self, mod) -> None:
        raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
        status, headers, body = mod._parse_http_response(raw)
        assert status == 200
        assert headers.get("Content-Type") == "text/html"
        assert body == b"<html></html>"

    def test_parse_http_response_empty(self, mod) -> None:
        status, headers, body = mod._parse_http_response(b"")
        assert status == 0
        assert headers == {}

    def test_calculate_header_capacity_positive(self, mod) -> None:
        cap = mod._calculate_header_capacity(
            ["X-Request-ID", "Cookie", "ETag"], "base64",
        )
        assert cap > 0

    def test_header_max_lengths_defined(self, mod) -> None:
        assert isinstance(mod._HEADER_MAX_LENGTHS, dict)
        assert len(mod._HEADER_MAX_LENGTHS) >= 4
        for name, length in mod._HEADER_MAX_LENGTHS.items():
            assert isinstance(name, str)
            assert isinstance(length, int)
            assert length > 0


# ---------------------------------------------------------------
# Firmware Integrity Bypass: checksum and detection helpers
# ---------------------------------------------------------------


class TestFirmwareIntegrityBypass:
    """Test firmware integrity bypass helpers on sample bytes."""

    @pytest.fixture()
    def mod(self):
        try:
            import embedxpl.modules.exploits.evasion.firmware_integrity_bypass as m
        except ImportError:
            pytest.skip("Cannot import firmware_integrity_bypass")
        return m

    def test_compute_checksum_crc32(self, mod) -> None:
        data = b"test firmware data"
        result = mod._compute_checksum(data, "crc32")
        assert isinstance(result, bytes)
        assert len(result) == 4
        # Verify against stdlib
        expected_crc = binascii.crc32(data) & 0xFFFFFFFF
        actual_crc = struct.unpack("!I", result)[0]
        assert actual_crc == expected_crc

    def test_compute_checksum_md5(self, mod) -> None:
        import hashlib
        data = b"firmware payload"
        result = mod._compute_checksum(data, "md5")
        assert len(result) == 16
        assert result == hashlib.md5(data).digest()

    def test_compute_checksum_sha256(self, mod) -> None:
        import hashlib
        data = b"firmware payload sha256"
        result = mod._compute_checksum(data, "sha256")
        assert len(result) == 32
        assert result == hashlib.sha256(data).digest()

    def test_compute_checksum_sha1(self, mod) -> None:
        import hashlib
        data = b"sha1 test"
        result = mod._compute_checksum(data, "sha1")
        assert len(result) == 20
        assert result == hashlib.sha1(data).digest()

    def test_compute_checksum_unsupported_raises(self, mod) -> None:
        with pytest.raises(ValueError, match="Unsupported"):
            mod._compute_checksum(b"data", "blowfish")

    @pytest.mark.parametrize(
        "data,expected_fmt",
        [
            (b"\x27\x05\x19\x56" + b"\x00" * 60, "uImage"),
            (b"HDR0" + b"\x00" * 24, "trx"),
            (b"hsqs" + b"\x00" * 92, "squashfs_le"),
            (b"\x7fELF" + b"\x00" * 60, "elf"),
            (b"\x1f\x8b" + b"\x00" * 20, "gzip"),
            (b"UNKN" + b"\x00" * 60, "unknown"),
        ],
        ids=["uImage", "trx", "squashfs", "elf", "gzip", "unknown"],
    )
    def test_detect_firmware_format(self, mod, data: bytes, expected_fmt: str) -> None:
        assert mod._detect_firmware_format(data) == expected_fmt

    def test_detect_architecture_elf_x86(self, mod) -> None:
        # ELF header with e_machine = 0x03 (EM_386) at offset 18
        elf_header = bytearray(b"\x7fELF" + b"\x00" * 60)
        struct.pack_into("<H", elf_header, 18, 0x03)
        assert mod._detect_architecture(bytes(elf_header)) == "x86"

    def test_detect_architecture_elf_arm(self, mod) -> None:
        elf_header = bytearray(b"\x7fELF" + b"\x00" * 60)
        struct.pack_into("<H", elf_header, 18, 0x28)  # EM_ARM
        assert mod._detect_architecture(bytes(elf_header)) == "arm"

    def test_detect_architecture_elf_mips(self, mod) -> None:
        elf_header = bytearray(b"\x7fELF" + b"\x00" * 60)
        struct.pack_into("<H", elf_header, 18, 0x08)  # EM_MIPS
        assert mod._detect_architecture(bytes(elf_header)) == "mips"

    def test_detect_architecture_unknown(self, mod) -> None:
        assert mod._detect_architecture(b"\x00" * 64) == "unknown"

    def test_crc32_recalculation_sample(self, mod) -> None:
        """Verify CRC32 recalculation on a sample byte buffer."""
        sample = b"abcdefghijklmnop"
        crc_bytes = mod._compute_checksum(sample, "crc32")
        crc_val = struct.unpack("!I", crc_bytes)[0]
        expected = binascii.crc32(sample) & 0xFFFFFFFF
        assert crc_val == expected

    def test_firmware_magics_dict_defined(self, mod) -> None:
        assert isinstance(mod._FIRMWARE_MAGICS, dict)
        assert len(mod._FIRMWARE_MAGICS) >= 10, "Expected at least 10 firmware magic signatures"

    def test_verify_patterns_dict_defined(self, mod) -> None:
        assert isinstance(mod._VERIFY_PATTERNS, dict)
        assert "arm" in mod._VERIFY_PATTERNS
        assert "mips" in mod._VERIFY_PATTERNS
        assert "x86" in mod._VERIFY_PATTERNS

    def test_supported_checksum_algos(self, mod) -> None:
        assert "crc32" in mod._SUPPORTED_CHECKSUM_ALGOS
        assert "md5" in mod._SUPPORTED_CHECKSUM_ALGOS
        assert "sha256" in mod._SUPPORTED_CHECKSUM_ALGOS

    def test_find_checksum_in_header_uimage(self, mod) -> None:
        """uImage header: CRC32 at offset 4."""
        data = b"\x27\x05\x19\x56" + b"\x00" * 60
        result = mod._find_checksum_in_header(data, "", "crc32")
        assert result is not None
        offset, length = result
        assert offset == 4
        assert length == 4

    def test_find_checksum_in_header_explicit_offset(self, mod) -> None:
        data = b"\x00" * 64
        result = mod._find_checksum_in_header(data, "0x10", "crc32")
        assert result is not None
        offset, length = result
        assert offset == 16
        assert length == 4

    def test_find_checksum_in_header_trx(self, mod) -> None:
        """TRX header: CRC32 at offset 8."""
        data = b"HDR0" + b"\x00" * 24
        result = mod._find_checksum_in_header(data, "", "crc32")
        assert result is not None
        offset, length = result
        assert offset == 8
        assert length == 4
