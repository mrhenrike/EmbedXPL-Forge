"""Tests for embedxpl.core.wordlist.generator (offline, no network)."""
from __future__ import annotations

from embedxpl.core.wordlist.generator import (
    CORPORATE_BASE_WORDS,
    PERSONAL_BASE_WORDS,
    ROUTER_COMMON_USERNAMES,
    GenerationResult,
    TargetProfile,
    _case_mutations,
    _clean_word,
    _collect_seed_words,
    _combine_words,
    _date_mutations,
    _generate_usernames,
    _leet_speak,
    _number_mutations,
    estimate_size_human,
    generate_wordlist,
    save_wordlist,
)

# -------------------------------------------------------
# TargetProfile dataclass
# -------------------------------------------------------


class TestTargetProfile:
    def test_defaults(self):
        p = TargetProfile()
        assert p.profile_type == "corporate"
        assert p.company_name == ""
        assert p.first_name == ""
        assert p.min_length == 4
        assert p.max_length == 16
        assert p.enable_leet is True
        assert p.max_candidates == 50000
        assert isinstance(p.custom_words, list)

    def test_corporate_profile(self):
        p = TargetProfile(
            profile_type="corporate",
            company_name="AcmeCorp",
            company_acronym="AC",
            admin_name="John Admin",
        )
        assert p.company_name == "AcmeCorp"
        assert p.company_acronym == "AC"

    def test_personal_profile(self):
        p = TargetProfile(
            profile_type="personal",
            first_name="Alice",
            last_name="Smith",
            nickname="ally",
            birth_date="15031990",
        )
        assert p.first_name == "Alice"
        assert p.birth_date == "15031990"


# -------------------------------------------------------
# GenerationResult dataclass
# -------------------------------------------------------


class TestGenerationResult:
    def test_basic(self):
        r = GenerationResult(
            passwords=["a", "b", "c"],
            usernames=["admin"],
            estimated_size_bytes=10,
            profile_type="corporate",
            base_words_used=3,
            mutations_applied=5,
        )
        assert len(r.passwords) == 3
        assert r.usernames == ["admin"]
        assert r.estimated_size_bytes == 10

    def test_defaults(self):
        r = GenerationResult(passwords=[], usernames=[])
        assert r.passwords_file is None
        assert r.usernames_file is None
        assert r.estimated_size_bytes == 0


# -------------------------------------------------------
# Helper functions
# -------------------------------------------------------


class TestCleanWord:
    def test_strips_whitespace(self):
        assert _clean_word("  hello  ") == "hello"

    def test_empty(self):
        assert _clean_word("") == ""


class TestLeetSpeak:
    def test_basic_substitutions(self):
        results = _leet_speak("password")
        assert "password" in results
        assert any("@" in w or "0" in w for w in results if w != "password")

    def test_empty_string(self):
        results = _leet_speak("")
        assert results == [""]

    def test_no_leet_chars(self):
        results = _leet_speak("xyz")
        assert results == ["xyz"]


class TestCaseMutations:
    def test_produces_variants(self):
        results = _case_mutations("admin")
        assert "admin" in results
        assert "ADMIN" in results
        assert "Admin" in results

    def test_already_upper(self):
        results = _case_mutations("ABC")
        assert "ABC" in results
        assert "abc" in results
        assert "Abc" in results

    def test_single_char(self):
        results = _case_mutations("a")
        assert "a" in results
        assert "A" in results

    def test_no_duplicates(self):
        results = _case_mutations("test")
        assert len(results) == len(set(results))


class TestNumberMutations:
    def test_appends_suffixes(self):
        results = _number_mutations("admin")
        assert "admin" in results
        assert "admin1" in results
        assert "admin123" in results
        assert "admin!" in results

    def test_prepends_prefixes(self):
        results = _number_mutations("root")
        assert "!root" in results
        assert "@root" in results

    def test_empty_base(self):
        results = _number_mutations("")
        assert isinstance(results, list)
        assert len(results) > 0


class TestDateMutations:
    def test_full_date(self):
        results = _date_mutations("admin", "15031990")
        assert any("1990" in w for w in results)
        assert any("90" in w for w in results)
        assert any("15" in w for w in results)

    def test_short_date(self):
        results = _date_mutations("admin", "2024")
        assert "admin2024" in results
        assert "2024admin" in results

    def test_empty_date(self):
        results = _date_mutations("admin", "")
        assert results == []

    def test_date_with_separators(self):
        results = _date_mutations("test", "15/03/1990")
        assert any("1990" in w for w in results)


class TestCombineWords:
    def test_two_words(self):
        results = _combine_words(["admin", "root"])
        assert any("admin" in w and "root" in w for w in results)

    def test_single_word_no_combinations(self):
        results = _combine_words(["solo"])
        assert results == []

    def test_empty_list(self):
        results = _combine_words([])
        assert results == []

    def test_custom_separators(self):
        results = _combine_words(["a", "b"], separators=["_"])
        assert "a_b" in results
        assert "b_a" in results


# -------------------------------------------------------
# Seed word collection
# -------------------------------------------------------


class TestCollectSeedWords:
    def test_corporate_profile(self):
        p = TargetProfile(
            profile_type="corporate",
            company_name="AcmeCorp",
            admin_name="John",
        )
        seeds = _collect_seed_words(p)
        assert "AcmeCorp" in seeds
        assert "John" in seeds
        for base in CORPORATE_BASE_WORDS[:3]:
            assert base in seeds

    def test_personal_profile(self):
        p = TargetProfile(
            profile_type="personal",
            first_name="Alice",
            last_name="Smith",
        )
        seeds = _collect_seed_words(p)
        assert "Alice" in seeds
        assert "Smith" in seeds
        for base in PERSONAL_BASE_WORDS[:3]:
            assert base in seeds

    def test_shared_fields(self):
        p = TargetProfile(ssid_name="MyWifi", device_vendor="TP-Link")
        seeds = _collect_seed_words(p)
        assert "MyWifi" in seeds
        assert "TP-Link" in seeds

    def test_custom_words(self):
        p = TargetProfile(custom_words=["secret", "letmein"])
        seeds = _collect_seed_words(p)
        assert "secret" in seeds
        assert "letmein" in seeds

    def test_no_duplicates(self):
        p = TargetProfile(custom_words=["admin"])
        seeds = _collect_seed_words(p)
        assert seeds.count("admin") == 1

    def test_empty_profile(self):
        p = TargetProfile()
        seeds = _collect_seed_words(p)
        assert isinstance(seeds, list)
        assert len(seeds) > 0


# -------------------------------------------------------
# Username generation
# -------------------------------------------------------


class TestGenerateUsernames:
    def test_includes_common(self):
        p = TargetProfile()
        usernames = _generate_usernames(p)
        for u in ROUTER_COMMON_USERNAMES[:5]:
            assert u in usernames

    def test_corporate_admin_name(self):
        p = TargetProfile(
            profile_type="corporate",
            admin_name="John Doe",
        )
        usernames = _generate_usernames(p)
        assert "john.doe" in usernames
        assert "johndoe" in usernames
        assert "jdoe" in usernames

    def test_personal_names(self):
        p = TargetProfile(
            profile_type="personal",
            first_name="Alice",
            last_name="Smith",
        )
        usernames = _generate_usernames(p)
        assert "alice" in usernames
        assert "smith" in usernames
        assert "asmith" in usernames

    def test_device_vendor(self):
        p = TargetProfile(device_vendor="TP-Link")
        usernames = _generate_usernames(p)
        assert "tplink" in usernames

    def test_no_duplicates(self):
        p = TargetProfile(
            profile_type="corporate",
            admin_name="Admin User",
            company_acronym="AU",
        )
        usernames = _generate_usernames(p)
        assert len(usernames) == len(set(usernames))


# -------------------------------------------------------
# Full generation
# -------------------------------------------------------


class TestGenerateWordlist:
    def test_corporate_basic(self):
        p = TargetProfile(
            profile_type="corporate",
            company_name="TestCorp",
        )
        result = generate_wordlist(p)
        assert isinstance(result, GenerationResult)
        assert len(result.passwords) > 0
        assert result.profile_type == "corporate"
        assert result.base_words_used > 0

    def test_personal_basic(self):
        p = TargetProfile(
            profile_type="personal",
            first_name="Bob",
            last_name="Jones",
        )
        result = generate_wordlist(p)
        assert len(result.passwords) > 0
        lower = [w.lower() for w in result.passwords]
        assert any("bob" in w for w in lower)

    def test_max_candidates_cap(self):
        p = TargetProfile(
            profile_type="corporate",
            company_name="Test",
            max_candidates=100,
        )
        result = generate_wordlist(p)
        assert len(result.passwords) <= 100

    def test_length_filtering(self):
        p = TargetProfile(min_length=6, max_length=10)
        result = generate_wordlist(p)
        for pwd in result.passwords:
            assert 6 <= len(pwd) <= 10

    def test_with_birth_date(self):
        p = TargetProfile(
            profile_type="personal",
            first_name="User",
            birth_date="01011990",
        )
        result = generate_wordlist(p)
        assert any("1990" in w or "90" in w for w in result.passwords)

    def test_no_duplicates(self):
        p = TargetProfile(
            profile_type="personal",
            first_name="Alice",
            last_name="Bob",
        )
        result = generate_wordlist(p)
        assert len(result.passwords) == len(set(result.passwords))

    def test_usernames_generated(self):
        p = TargetProfile(
            profile_type="personal",
            first_name="Alice",
            generate_usernames=True,
        )
        result = generate_wordlist(p)
        assert len(result.usernames) > 0

    def test_usernames_disabled(self):
        p = TargetProfile(generate_usernames=False)
        result = generate_wordlist(p)
        assert result.usernames == []

    def test_leet_disabled(self):
        p = TargetProfile(enable_leet=False, custom_words=["test"])
        result = generate_wordlist(p)
        assert isinstance(result.passwords, list)

    def test_estimated_size(self):
        p = TargetProfile(custom_words=["admin"])
        result = generate_wordlist(p)
        assert result.estimated_size_bytes > 0


# -------------------------------------------------------
# Save wordlist
# -------------------------------------------------------


class TestSaveWordlist:
    def test_save_to_file(self, tmp_path):
        output = tmp_path / "wordlist.txt"
        words = ["admin", "root", "password123"]
        save_wordlist(words, str(output))
        lines = output.read_text().strip().splitlines()
        assert lines == words

    def test_save_empty_list(self, tmp_path):
        output = tmp_path / "empty.txt"
        save_wordlist([], str(output))
        content = output.read_text()
        assert content == "\n"

    def test_creates_parent_dirs(self, tmp_path):
        output = tmp_path / "subdir" / "deep" / "wordlist.txt"
        save_wordlist(["test"], str(output))
        assert output.exists()
        assert output.read_text().strip() == "test"


# -------------------------------------------------------
# Utility
# -------------------------------------------------------


class TestEstimateSizeHuman:
    def test_bytes(self):
        assert "B" in estimate_size_human(500)

    def test_kilobytes(self):
        result = estimate_size_human(2048)
        assert "KB" in result

    def test_megabytes(self):
        result = estimate_size_human(5 * 1024 * 1024)
        assert "MB" in result

    def test_zero(self):
        result = estimate_size_human(0)
        assert "0" in result
