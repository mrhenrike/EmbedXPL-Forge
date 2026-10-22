"""Tests for registry categories, audit_suite, hw_install_notice, db_init."""

from pathlib import Path

# ── Registry: Categories ──

class TestCategoryDescriptions:
    def test_iot_category(self):
        from embedxpl.registry.categories import CATEGORY_DESCRIPTIONS
        assert "iot" in CATEGORY_DESCRIPTIONS
        assert isinstance(CATEGORY_DESCRIPTIONS["iot"], str)

    def test_ot_category(self):
        from embedxpl.registry.categories import CATEGORY_DESCRIPTIONS
        assert "ot" in CATEGORY_DESCRIPTIONS

    def test_routers(self):
        from embedxpl.registry.categories import CATEGORY_DESCRIPTIONS
        assert "routers" in CATEGORY_DESCRIPTIONS

    def test_printers(self):
        from embedxpl.registry.categories import CATEGORY_DESCRIPTIONS
        assert "printers" in CATEGORY_DESCRIPTIONS

    def test_firewalls(self):
        from embedxpl.registry.categories import CATEGORY_DESCRIPTIONS
        assert "firewalls" in CATEGORY_DESCRIPTIONS

    def test_all_base_categories_described(self):
        from embedxpl.registry.categories import CATEGORY_DESCRIPTIONS
        for cat in ["iot", "ot", "routers", "printers", "firewalls", "smart-home"]:
            assert cat in CATEGORY_DESCRIPTIONS


class TestCategoryModules:
    def test_iot_modules(self):
        from embedxpl.registry.categories import CATEGORY_MODULES
        assert "iot" in CATEGORY_MODULES
        assert isinstance(CATEGORY_MODULES["iot"], (list, tuple))

    def test_routers_modules(self):
        from embedxpl.registry.categories import CATEGORY_MODULES
        assert "routers" in CATEGORY_MODULES

    def test_printers_modules(self):
        from embedxpl.registry.categories import CATEGORY_MODULES
        assert "printers" in CATEGORY_MODULES


class TestListCategories:
    def test_returns_collection(self):
        from embedxpl.registry.categories import list_categories
        cats = list_categories()
        assert isinstance(cats, (list, tuple, dict))
        assert len(cats) >= 5

    def test_contains_iot(self):
        from embedxpl.registry.categories import list_categories
        cats = list_categories()
        if isinstance(cats, dict):
            assert "iot" in cats
        else:
            assert "iot" in cats


class TestResolveCategory:
    def test_known_category(self):
        from embedxpl.registry.categories import resolve_category
        result = resolve_category("iot")
        assert result is not None

    def test_routers(self):
        from embedxpl.registry.categories import resolve_category
        result = resolve_category("routers")
        assert isinstance(result, (list, tuple))

    def test_all(self):
        from embedxpl.registry.categories import resolve_category
        result = resolve_category("all")
        assert isinstance(result, (list, tuple))


class TestGetCategoryGlobs:
    def test_iot(self):
        from embedxpl.registry.categories import get_category_globs
        globs = get_category_globs("iot")
        assert isinstance(globs, (list, tuple))
        assert len(globs) > 0


class TestCountModules:
    def test_returns_dict(self):
        from embedxpl.registry.categories import count_modules_by_category
        counts = count_modules_by_category()
        assert isinstance(counts, dict)
        assert len(counts) > 0


# ── Tools: Audit Suite ──

class TestAuditSuite:
    def test_audit_metadata(self):
        from embedxpl.tools.audit_suite import audit_metadata
        root = Path(__file__).resolve().parent.parent / "embedxpl"
        result = audit_metadata(root)
        assert isinstance(result, list)

    def test_audit_git(self):
        from embedxpl.tools.audit_suite import audit_git
        result = audit_git()
        assert isinstance(result, list)

    def test_audit_deps(self):
        from embedxpl.tools.audit_suite import audit_deps
        root = Path(__file__).resolve().parent.parent / "embedxpl"
        result = audit_deps(root)
        assert isinstance(result, list)

    def test_audit_patterns(self):
        from embedxpl.tools.audit_suite import audit_patterns
        root = Path(__file__).resolve().parent.parent / "embedxpl"
        result = audit_patterns(root)
        assert isinstance(result, list)

    def test_audit_banner_stats(self):
        from embedxpl.tools.audit_suite import audit_banner_stats
        result = audit_banner_stats()
        assert isinstance(result, list)


# ── Tools: HW Install Notice ──

class TestHWInstallNotice:
    def test_importable(self):
        from embedxpl.tools.hw_install_notice import generate_json, generate_notice
        assert callable(generate_notice)
        assert callable(generate_json)


# ── Tools: DB Init ──

class TestDBInit:
    def test_exf_database_import(self):
        from embedxpl.tools.db_init import EXFDatabase
        assert EXFDatabase is not None

    def test_index_modules_callable(self):
        from embedxpl.tools.db_init import index_modules
        assert callable(index_modules)
