"""Tests for shell tab-completion support."""


from embedxpl.core.completion import (
    build_parser,
    enable_completion,
    get_module_completions,
)


class TestBuildParser:
    def test_returns_parser(self):
        parser = build_parser()
        assert parser.prog == "exf"

    def test_subcommands_exist(self):
        parser = build_parser()
        args = parser.parse_args(["version"])
        assert args.command == "version"

    def test_use_module_arg(self):
        parser = build_parser()
        args = parser.parse_args(["use", "exploits/routers/foo"])
        assert args.module == "exploits/routers/foo"

    def test_run_with_target(self):
        parser = build_parser()
        args = parser.parse_args(["run", "--target", "192.168.1.1", "--port", "80"])
        assert args.target == "192.168.1.1"
        assert args.port == 80

    def test_search_keyword(self):
        parser = build_parser()
        args = parser.parse_args(["search", "netgear"])
        assert args.keyword == "netgear"


class TestEnableCompletion:
    def test_no_crash_without_argcomplete(self):
        parser = build_parser()
        enable_completion(parser)

    def test_none_parser(self):
        enable_completion(None)


class TestModuleCompletions:
    def test_prefix_match(self):
        modules = [
            "exploits/routers/netgear",
            "exploits/routers/tplink",
            "exploits/printers/hp",
            "scanners/ble",
        ]
        result = get_module_completions("exploits/routers/", modules)
        assert len(result) == 2
        assert "exploits/routers/netgear" in result

    def test_empty_prefix(self):
        modules = ["a", "b", "c"]
        assert get_module_completions("", modules) == modules

    def test_no_match(self):
        assert get_module_completions("zzz", ["abc", "def"]) == []
