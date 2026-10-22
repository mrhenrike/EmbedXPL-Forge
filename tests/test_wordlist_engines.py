"""Tests for wordlist engines: affix, analyzer, charset_gen, combiner, anomaly_scorer."""

import json

# ── Affix Engine ──

class TestAffixConstants:
    def test_default_specials(self):
        from embedxpl.engines.wordlists.affix_engine import DEFAULT_SPECIALS
        assert isinstance(DEFAULT_SPECIALS, (list, tuple, set))
        assert len(DEFAULT_SPECIALS) > 0


class TestCaseVariants:
    def test_basic(self):
        from embedxpl.engines.wordlists.affix_engine import case_variants
        result = case_variants("abc")
        assert "abc" in result
        assert "Abc" in result
        assert "ABC" in result

    def test_single_char(self):
        from embedxpl.engines.wordlists.affix_engine import case_variants
        result = case_variants("a")
        assert "a" in result
        assert "A" in result


class TestExpandAffixes:
    def test_basic(self):
        from embedxpl.engines.wordlists.affix_engine import expand_affixes
        result = expand_affixes(["password"], specials=["!", "@"])
        assert isinstance(result, list)
        assert "password" in result
        assert any("!" in w for w in result)

    def test_no_specials(self):
        from embedxpl.engines.wordlists.affix_engine import expand_affixes
        result = expand_affixes(["test"])
        assert "test" in result

    def test_positions_prefix(self):
        from embedxpl.engines.wordlists.affix_engine import expand_affixes
        result = expand_affixes(["word"], specials=["#"], positions="prefix")
        assert isinstance(result, list)

    def test_positions_suffix(self):
        from embedxpl.engines.wordlists.affix_engine import expand_affixes
        result = expand_affixes(["word"], specials=["#"], positions="suffix")
        assert isinstance(result, list)


class TestBuildRuleset:
    def test_returns_list(self):
        from embedxpl.engines.wordlists.affix_engine import build_ruleset
        rules = build_ruleset(["admin", "root"], specials=["!", "@"])
        assert isinstance(rules, list)
        assert len(rules) > 0

    def test_with_titlecase(self):
        from embedxpl.engines.wordlists.affix_engine import build_ruleset
        rules = build_ruleset(["test"], include_titlecase=True)
        assert isinstance(rules, list)

    def test_minimal(self):
        from embedxpl.engines.wordlists.affix_engine import build_ruleset
        rules = build_ruleset(["a"])
        assert isinstance(rules, list)


class TestApplyAffixLayer:
    def test_basic(self):
        from embedxpl.engines.wordlists.affix_engine import apply_affix_layer
        result = list(apply_affix_layer(["admin"], ["root", "pass"]))
        assert len(result) >= 1

    def test_with_specials(self):
        from embedxpl.engines.wordlists.affix_engine import apply_affix_layer
        result = list(apply_affix_layer(["user"], ["admin"], specials=["!"]))
        assert len(result) >= 1


# ── Analyzer ──

class TestAnalyzeWordlist:
    def test_basic(self, tmp_path):
        from embedxpl.engines.wordlists.analyzer import analyze_wordlist
        wl = tmp_path / "test.txt"
        wl.write_text("password\nadmin\nroot\n123456\ntest\n")
        stats = analyze_wordlist(str(wl))
        assert isinstance(stats, dict)

    def test_empty_file(self, tmp_path):
        from embedxpl.engines.wordlists.analyzer import analyze_wordlist
        wl = tmp_path / "empty.txt"
        wl.write_text("")
        stats = analyze_wordlist(str(wl))
        assert isinstance(stats, dict)


class TestAnalyzeMasks:
    def test_basic(self, tmp_path):
        from embedxpl.engines.wordlists.analyzer import analyze_masks
        wl = tmp_path / "masks.txt"
        wl.write_text("password1\nadmin123\nroot\n")
        result = analyze_masks(str(wl))
        assert isinstance(result, dict)


class TestAnalyzerExport:
    def test_export_stats_json(self, tmp_path):
        from embedxpl.engines.wordlists.analyzer import analyze_masks, analyze_wordlist, export_stats_json
        wl = tmp_path / "test.txt"
        wl.write_text("password\nadmin\nroot\n")
        stats = analyze_wordlist(str(wl))
        masks = analyze_masks(str(wl))
        result = export_stats_json(stats, str(wl), mask_data=masks)
        assert isinstance(result, str)
        data = json.loads(result)
        assert "summary" in data

    def test_export_stats_markdown(self, tmp_path):
        from embedxpl.engines.wordlists.analyzer import analyze_masks, analyze_wordlist, export_stats_markdown
        wl = tmp_path / "test.txt"
        wl.write_text("password\nadmin\nroot\n")
        stats = analyze_wordlist(str(wl))
        masks = analyze_masks(str(wl))
        result = export_stats_markdown(stats, str(wl), mask_data=masks)
        assert isinstance(result, str)
        assert "Total" in result or "total" in result

    def test_export_stats_csv(self, tmp_path):
        from embedxpl.engines.wordlists.analyzer import analyze_masks, analyze_wordlist, export_stats_csv
        wl = tmp_path / "test.txt"
        wl.write_text("password\nadmin\nroot\n")
        stats = analyze_wordlist(str(wl))
        masks = analyze_masks(str(wl))
        result = export_stats_csv(stats, mask_data=masks)
        assert isinstance(result, str)


class TestCharPositionFrequency:
    def test_basic(self, tmp_path):
        from embedxpl.engines.wordlists.analyzer import analyze_char_position_frequency
        wl = tmp_path / "freq.txt"
        wl.write_text("abc\nabd\naez\n")
        result = analyze_char_position_frequency(str(wl))
        assert isinstance(result, dict)


# ── Charset Generator ──

class TestBuiltinCharsets:
    def test_contains_lalpha(self):
        from embedxpl.engines.wordlists.charset_gen import BUILTIN_CHARSETS
        assert "lalpha" in BUILTIN_CHARSETS
        assert "ualpha" in BUILTIN_CHARSETS
        assert "numeric" in BUILTIN_CHARSETS

    def test_hashcat_mask_map(self):
        from embedxpl.engines.wordlists.charset_gen import HASHCAT_MASK_MAP
        assert isinstance(HASHCAT_MASK_MAP, dict)
        assert "?l" in HASHCAT_MASK_MAP
        assert "?u" in HASHCAT_MASK_MAP
        assert "?d" in HASHCAT_MASK_MAP

    def test_pt_br_accented(self):
        from embedxpl.engines.wordlists.charset_gen import BUILTIN_CHARSETS
        assert "pt-br-accented" in BUILTIN_CHARSETS
        assert "ç" in BUILTIN_CHARSETS["pt-br-accented"]


class TestGenerateByCharset:
    def test_basic(self):
        from embedxpl.engines.wordlists.charset_gen import generate_by_charset
        result = list(generate_by_charset("ab", min_len=1, max_len=2))
        assert "a" in result
        assert "b" in result
        assert "aa" in result
        assert "ab" in result

    def test_single_char(self):
        from embedxpl.engines.wordlists.charset_gen import generate_by_charset
        result = list(generate_by_charset("x", min_len=1, max_len=1))
        assert result == ["x"]


class TestEstimateSize:
    def test_basic(self):
        from embedxpl.engines.wordlists.charset_gen import estimate_size
        count, human = estimate_size(3, min_len=1, max_len=3)
        assert count == 3 + 9 + 27

    def test_mask_size(self):
        from embedxpl.engines.wordlists.charset_gen import estimate_mask_size
        count, human = estimate_mask_size("?d?d?d")
        assert count == 1000


class TestGenerateByMask:
    def test_basic(self):
        from embedxpl.engines.wordlists.charset_gen import generate_by_mask
        result = list(generate_by_mask("?d?d"))
        assert len(result) == 100
        assert "00" in result
        assert "99" in result


class TestDDDS:
    def test_br_ddds(self):
        from embedxpl.engines.wordlists.charset_gen import DDDS_BR
        assert isinstance(DDDS_BR, (list, tuple, dict))


class TestPlaceholderMap:
    def test_exists(self):
        from embedxpl.engines.wordlists.charset_gen import PLACEHOLDER_MAP
        assert isinstance(PLACEHOLDER_MAP, dict)


# ── Combiner ──

class TestCombinerConstants:
    def test_default_connectors(self):
        from embedxpl.engines.wordlists.combiner import DEFAULT_CONNECTORS
        assert isinstance(DEFAULT_CONNECTORS, (list, tuple))
        assert "" in DEFAULT_CONNECTORS

    def test_leet_map(self):
        from embedxpl.engines.wordlists.combiner import LEET_MAP
        assert isinstance(LEET_MAP, dict)
        assert "a" in LEET_MAP or "e" in LEET_MAP

    def test_default_num_tails(self):
        from embedxpl.engines.wordlists.combiner import DEFAULT_NUM_TAILS
        assert isinstance(DEFAULT_NUM_TAILS, (list, tuple))


class TestCombineKeywords:
    def test_basic(self):
        from embedxpl.engines.wordlists.combiner import combine_keywords
        result = list(combine_keywords(["admin", "pass"]))
        assert len(result) > 0
        assert any("admin" in w for w in result)

    def test_single_keyword(self):
        from embedxpl.engines.wordlists.combiner import combine_keywords
        result = list(combine_keywords(["test"]))
        assert "test" in result


# ── Anomaly Scorer ──

class TestDeleet:
    def test_basic(self):
        from embedxpl.engines.wordlists.anomaly_scorer import deleet
        result = deleet("p@$$w0rd")
        assert isinstance(result, str)

    def test_no_leet(self):
        from embedxpl.engines.wordlists.anomaly_scorer import deleet
        assert deleet("password") == "password"


class TestPolicyCheck:
    def test_basic(self):
        from embedxpl.engines.wordlists.anomaly_scorer import policy_check
        result = policy_check("Password1!")
        assert isinstance(result, (bool, dict, tuple))

    def test_weak_password(self):
        from embedxpl.engines.wordlists.anomaly_scorer import policy_check
        result = policy_check("a")
        assert isinstance(result, (bool, dict, tuple))


class TestFilterByPolicy:
    def test_basic(self):
        from embedxpl.engines.wordlists.anomaly_scorer import filter_by_policy
        words = ["password", "P@ssw0rd!", "a"]
        result = list(filter_by_policy(words))
        assert isinstance(result, list)
