"""Tests for embedxpl.core.exploit.printer."""
from __future__ import annotations

from embedxpl.core.exploit.printer import (
    PrinterThread,
    PrintResource,
    color_blue,
    color_green,
    color_red,
    console,
    create_scan_progress,
    pprint_dict_in_order,
    print_banner,
    print_error,
    print_info,
    print_panel,
    print_status,
    print_success,
    print_table,
    print_warning,
)


class TestPrintFunctions:
    def test_print_error_no_crash(self, capsys):
        print_error("test error")

    def test_print_status_no_crash(self, capsys):
        print_status("test status")

    def test_print_success_no_crash(self, capsys):
        print_success("test success")

    def test_print_info_no_crash(self, capsys):
        print_info("test info")

    def test_print_warning_no_crash(self, capsys):
        print_warning("test warning")

    def test_print_multiple_args(self, capsys):
        print_status("hello", "world")


class TestColorFunctions:
    def test_color_blue_returns_string(self):
        result = color_blue("test")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_color_green_returns_string(self):
        result = color_green("test")
        assert isinstance(result, str)

    def test_color_red_returns_string(self):
        result = color_red("test")
        assert isinstance(result, str)


class TestPrintTable:
    def test_basic_table(self, capsys):
        print_table(["Col1", "Col2"], ["a", "b"], ["c", "d"])

    def test_empty_table(self, capsys):
        print_table(["Col1", "Col2"])


class TestPprintDictInOrder:
    def test_basic(self, capsys):
        pprint_dict_in_order({"key": "value"})

    def test_with_order(self, capsys):
        pprint_dict_in_order({"b": ["val2"], "a": ["val1"]}, order=("a", "b"))


class TestPrintBannerPanel:
    def test_print_banner(self, capsys):
        print_banner("TEST BANNER")

    def test_print_panel(self, capsys):
        print_panel("content", title="Title")


class TestScanProgress:
    def test_create_returns_progress(self):
        p = create_scan_progress()
        assert p is not None


class TestPrinterThread:
    def test_instantiation(self):
        pt = PrinterThread()
        assert isinstance(pt, PrinterThread)


class TestPrintResource:
    def test_namedtuple(self):
        pr = PrintResource(content="test", sep=" ", end="\n", file=None, thread=None)
        assert pr.content == "test"


class TestConsole:
    def test_console_exists(self):
        assert console is not None
