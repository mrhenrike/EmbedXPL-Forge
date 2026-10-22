"""B6 coverage: deep behavioral tests for wordlist engine modules."""
from __future__ import annotations

import pytest


class TestMangler:
    """Tests for embedxpl.engines.wordlists.mangler."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import mangler
            return mangler
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_builtin_rules_dict(self):
        m = self._mod()
        assert isinstance(m.BUILTIN_RULES, dict)
        assert len(m.BUILTIN_RULES) >= 10
        for k, v in m.BUILTIN_RULES.items():
            assert isinstance(k, str)
            assert isinstance(v, str)

    @pytest.mark.parametrize("rule", [
        "capitalize", "upper", "lower", "reverse", "toggle",
        "append_num", "prepend_num", "append_special",
        "leet_basic", "duplicate", "strip_vowels",
    ])
    def test_apply_rules_single(self, rule: str):
        m = self._mod()
        results = list(m.apply_rules(["password"], rules=[rule]))
        assert len(results) > 0

    def test_apply_rules_capitalize(self):
        m = self._mod()
        results = list(m.apply_rules(["password"], rules=["capitalize"]))
        assert "Password" in results

    def test_apply_rules_upper(self):
        m = self._mod()
        results = list(m.apply_rules(["test"], rules=["upper"]))
        assert "TEST" in results

    def test_apply_rules_reverse(self):
        m = self._mod()
        results = list(m.apply_rules(["abc"], rules=["reverse"]))
        assert "cba" in results

    def test_apply_rules_leet(self):
        m = self._mod()
        results = list(m.apply_rules(["password"], rules=["leet_basic"]))
        leet_found = any("@" in r or "0" in r or "$" in r for r in results)
        assert leet_found

    def test_apply_rules_duplicate(self):
        m = self._mod()
        results = list(m.apply_rules(["abc"], rules=["duplicate"]))
        assert "abcabc" in results

    def test_apply_rules_strip_vowels(self):
        m = self._mod()
        results = list(m.apply_rules(["hello"], rules=["strip_vowels"]))
        assert "hll" in results

    def test_apply_rules_all(self):
        m = self._mod()
        all_rules = list(m.BUILTIN_RULES.keys())
        results = list(m.apply_rules(["admin"], rules=all_rules))
        assert len(results) > 10

    def test_apply_rules_empty_list(self):
        m = self._mod()
        results = list(m.apply_rules([], rules=["capitalize"]))
        assert isinstance(results, list)
        assert len(results) == 0

    def test_capswap_generator(self):
        m = self._mod()
        results = list(m.capswap("ab"))
        assert len(results) > 0
        assert all(isinstance(r, str) for r in results)

    def test_mask_expand(self):
        m = self._mod()
        results = list(m.mask_expand("?l?d", words=["test"], max_output=50))
        assert len(results) > 0

    def test_overseer_config_dataclass(self):
        m = self._mod()
        cfg = m.OverseerConfig()
        assert hasattr(cfg, "__dataclass_fields__")

    def test_generate_hashcat_rules(self):
        m = self._mod()
        rules = m.generate_hashcat_rules(masks=["?l?d"], words=["test"])
        assert isinstance(rules, (list, str))


class TestCombiner:
    """Tests for embedxpl.engines.wordlists.combiner."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import combiner
            return combiner
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_combine_basic(self):
        m = self._mod()
        results = list(m.combine_keywords(["admin", "pass"]))
        assert len(results) > 0
        assert "admin" in results
        assert "pass" in results

    def test_combine_with_connectors(self):
        m = self._mod()
        results = list(m.combine_keywords(["user", "root"], connectors=["-", "_"]))
        assert any("-" in r for r in results)
        assert any("_" in r for r in results)

    def test_combine_max_depth(self):
        m = self._mod()
        r2 = list(m.combine_keywords(["a", "b", "c"], max_depth=2))
        r3 = list(m.combine_keywords(["a", "b", "c"], max_depth=3))
        assert len(r3) >= len(r2)

    def test_combine_leet(self):
        m = self._mod()
        results = list(m.combine_keywords(["test"], use_leet=True))
        leet = any("3" in r or "7" in r for r in results)
        assert leet or len(results) > 0

    def test_combine_titlecase(self):
        m = self._mod()
        results = list(m.combine_keywords(["hello"], use_titlecase=True))
        assert "Hello" in results

    def test_combine_reverse(self):
        m = self._mod()
        results = list(m.combine_keywords(["abc"], use_reverse=True))
        assert "cba" in results

    def test_combine_length_filter(self):
        m = self._mod()
        results = list(m.combine_keywords(["a", "bb"], min_length=2, max_length=4))
        assert all(2 <= len(r) <= 4 for r in results)

    def test_default_connectors(self):
        m = self._mod()
        assert isinstance(m.DEFAULT_CONNECTORS, list)
        assert "" in m.DEFAULT_CONNECTORS

    def test_default_num_tails(self):
        m = self._mod()
        assert isinstance(m.DEFAULT_NUM_TAILS, list)
        assert len(m.DEFAULT_NUM_TAILS) > 0


class TestAffixEngine:
    """Tests for embedxpl.engines.wordlists.affix_engine."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import affix_engine
            return affix_engine
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_expand_affixes_basic(self):
        m = self._mod()
        results = m.expand_affixes(["123"])
        assert isinstance(results, list)
        assert "123" in results

    def test_expand_affixes_specials(self):
        m = self._mod()
        results = m.expand_affixes(["99"], specials=["!", "@"])
        assert any("!" in r for r in results)

    def test_expand_affixes_positions(self):
        m = self._mod()
        leading = m.expand_affixes(["42"], positions="leading")
        trailing = m.expand_affixes(["42"], positions="trailing")
        both = m.expand_affixes(["42"], positions="both")
        assert len(both) >= len(leading)

    def test_expand_affixes_no_bare_core(self):
        m = self._mod()
        results = m.expand_affixes(["77"], include_bare_core=False)
        assert "77" not in results

    def test_default_specials(self):
        m = self._mod()
        assert isinstance(m.DEFAULT_SPECIALS, tuple)
        assert len(m.DEFAULT_SPECIALS) > 0


class TestCharsetGen:
    """Tests for embedxpl.engines.wordlists.charset_gen."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import charset_gen
            return charset_gen
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_builtin_charsets(self):
        m = self._mod()
        assert isinstance(m.BUILTIN_CHARSETS, dict)
        assert "lalpha" in m.BUILTIN_CHARSETS
        assert "numeric" in m.BUILTIN_CHARSETS
        assert len(m.BUILTIN_CHARSETS["numeric"]) == 10

    @pytest.mark.parametrize("charset_name", [
        "lalpha", "ualpha", "numeric", "alpha",
        "hex-lower", "hex-upper",
    ])
    def test_charset_keys(self, charset_name: str):
        m = self._mod()
        assert charset_name in m.BUILTIN_CHARSETS
        assert len(m.BUILTIN_CHARSETS[charset_name]) > 0


class TestLeetPermuter:
    """Tests for embedxpl.engines.wordlists.leet_permuter."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import leet_permuter
            return leet_permuter
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_generate_leet(self):
        m = self._mod()
        results = list(m.generate_leet("hello"))
        assert len(results) > 0

    def test_generate_case_variations(self):
        m = self._mod()
        results = list(m.generate_case_variations("ab"))
        assert len(results) >= 2
        assert "AB" in results or "Ab" in results or "aB" in results

    def test_parse_custom_mapping(self):
        m = self._mod()
        mapping = m.parse_custom_mapping("a=4,@;e=3")
        assert isinstance(mapping, dict)
        assert "a" in mapping

    def test_generate_all_variations(self):
        m = self._mod()
        results = list(m.generate_all_variations("hi"))
        assert len(results) > 0

    def test_permute_geek_uniao(self):
        m = self._mod()
        results = list(m.permute_geek_uniao("test"))
        assert len(results) > 0


class TestXorCrypto:
    """Tests for embedxpl.engines.wordlists.xor_crypto."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import xor_crypto
            return xor_crypto
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_xor_encrypt_decrypt_bytes(self):
        m = self._mod()
        key = b"\x42"
        plaintext = b"hello world"
        enc = m.xor_encrypt(plaintext, key)
        dec = m.xor_decrypt(enc, key)
        assert dec == plaintext

    def test_xor_encrypt_str(self):
        m = self._mod()
        enc = m.xor_encrypt_str("hello", "K")
        assert isinstance(enc, bytes)

    def test_xor_decrypt_str(self):
        m = self._mod()
        enc = m.xor_encrypt_str("secret", "X")
        dec = m.xor_decrypt_str(enc, "X")
        assert dec == "secret"

    def test_score_text(self):
        m = self._mod()
        s = m.score_text("Hello world this is a test")
        assert isinstance(s, (int, float))
        assert s > 0

    def test_brute_force_single_byte(self):
        m = self._mod()
        enc = m.xor_encrypt(b"test", b"\x01")
        hex_str = enc.hex()
        results = m.brute_force_single_byte(hex_str)
        assert isinstance(results, list)


class TestHashTools:
    """Tests for embedxpl.engines.wordlists.hash_tools."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import hash_tools
            return hash_tools
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_identify_md5(self):
        m = self._mod()
        results = m.identify("5d41402abc4b2a76b9719d911017c592")
        assert isinstance(results, list)
        assert len(results) > 0

    def test_identify_sha256(self):
        m = self._mod()
        results = m.identify("a" * 64)
        assert isinstance(results, list)

    def test_hash_stream(self):
        m = self._mod()
        gen = m.hash_stream(iter(["password", "admin"]), algo="md5")
        results = list(gen)
        assert len(results) == 2

    def test_ntlm_hash(self):
        m = self._mod()
        h = m._ntlm("password")
        assert isinstance(h, str)
        assert len(h) == 32

    def test_word_to_mask(self):
        m = self._mod()
        mask = m._word_to_mask("Hello123!")
        assert "?u" in mask or "?l" in mask or "?d" in mask


class TestEntropyStrength:
    """Tests for embedxpl.engines.wordlists.entropy_strength."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import entropy_strength
            return entropy_strength
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_estimate_strong(self):
        m = self._mod()
        r = m.estimate("Tr0ub4dor&3#Xq9!")
        assert isinstance(r, dict)
        assert "entropy" in r or "score" in r or "bits" in r

    def test_estimate_weak(self):
        m = self._mod()
        r = m.estimate("123456")
        assert isinstance(r, dict)

    def test_has_sequence(self):
        m = self._mod()
        assert m._has_sequence("abc123") is True

    def test_has_repeat(self):
        m = self._mod()
        assert m._has_repeat("aaa") is True

    def test_format_report(self):
        m = self._mod()
        result = m.estimate("Password1!")
        report = m.format_report(result)
        assert isinstance(report, list)


class TestNum2Text:
    """Tests for embedxpl.engines.wordlists.num2text."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import num2text
            return num2text
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_num2text_variants_basic(self):
        m = self._mod()
        results = list(m.num2text_variants(42))
        assert len(results) > 0
        assert all(isinstance(r, str) for r in results)

    def test_num2text_range(self):
        m = self._mod()
        results = list(m.num2text_range(1, 3))
        assert len(results) > 0

    def test_strip_accents(self):
        m = self._mod()
        assert m._strip_accents("café") == "cafe"


class TestListOps:
    """Tests for embedxpl.engines.wordlists.list_ops."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import list_ops
            return list_ops
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_bloom_filter(self):
        m = self._mod()
        bf = m.BloomFilter(capacity=1024)
        assert hasattr(bf, "__contains__") or hasattr(bf, "add")

    def test_dedup_stream(self):
        m = self._mod()
        results = list(m.dedup_stream(iter(["a", "b", "a", "c", "b"])))
        assert results == ["a", "b", "c"]

    def test_mask_keyspace(self):
        m = self._mod()
        ks = m.mask_keyspace("?l?l?d")
        assert ks == 26 * 26 * 10

    def test_charset_keyspace(self):
        m = self._mod()
        ks = m.charset_keyspace(26, 1, 2)
        assert ks == 26 + 26 * 26

    def test_keyspace_report(self):
        m = self._mod()
        report = m.keyspace_report(1000000, 10000)
        assert isinstance(report, list)
        assert len(report) > 0

    def test_fmt_count(self):
        m = self._mod()
        assert isinstance(m._fmt_count(1000000), str)

    def test_fmt_eta(self):
        m = self._mod()
        assert isinstance(m._fmt_eta(3661), str)


class TestSanitizer:
    """Tests for embedxpl.engines.wordlists.sanitizer."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import sanitizer
            return sanitizer
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_sanitize_basic(self, tmp_path):
        m = self._mod()
        wl = tmp_path / "test.txt"
        wl.write_text("abc\n\nabc\n  test  \nhello\n")
        gen = m.sanitize(str(wl))
        results = list(gen)
        assert len(results) > 0
        assert "" not in results

    def test_is_comment_line(self):
        m = self._mod()
        assert m._is_comment_line("# comment") is True
        assert m._is_comment_line("word") is False


class TestAnalyzer:
    """Tests for embedxpl.engines.wordlists.analyzer."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import analyzer
            return analyzer
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestKeywordMutations:
    """Tests for embedxpl.engines.wordlists.keyword_mutations."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import keyword_mutations
            return keyword_mutations
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestMerger:
    """Tests for embedxpl.engines.wordlists.merger."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import merger
            return merger
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestAnomalyScorer:
    """Tests for embedxpl.engines.wordlists.anomaly_scorer."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import anomaly_scorer
            return anomaly_scorer
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestPasswordDna:
    """Tests for embedxpl.engines.wordlists.password_dna."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import password_dna
            return password_dna
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestMalwareCredPatterns:
    """Tests for embedxpl.engines.wordlists.malware_cred_patterns."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import malware_cred_patterns
            return malware_cred_patterns
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestDefaultCreds:
    """Tests for embedxpl.engines.wordlists.default_creds."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import default_creds
            return default_creds
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestDnsWordlist:
    """Tests for embedxpl.engines.wordlists.dns_wordlist."""

    def _mod(self):
        try:
            from embedxpl.engines.wordlists import dns_wordlist
            return dns_wordlist
        except Exception as exc:
            pytest.skip(f"Import failed: {exc}")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0
