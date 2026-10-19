"""Tests for embedxpl.core.shells shim re-exporting from xpl-core."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from embedxpl.core import shells


def test_shim_imports_successfully():
    assert hasattr(shells, "ShellEngine")
    assert hasattr(shells, "ShellHandler")
    assert hasattr(shells, "SessionManager")


def test_all_list_populated():
    assert isinstance(shells.__all__, list)
    assert len(shells.__all__) >= 20


def test_shell_engine_is_abc():
    import abc
    assert issubclass(shells.ShellEngine, abc.ABC)


def test_shell_status_enum():
    assert hasattr(shells.ShellStatus, "DISCONNECTED")
    assert hasattr(shells.ShellStatus, "CONNECTED")


def test_shell_mode_enum():
    assert hasattr(shells.ShellMode, "REVERSE")
    assert hasattr(shells.ShellMode, "BIND")


def test_error_hierarchy():
    assert issubclass(shells.ShellConnectionError, shells.ShellError)
    assert issubclass(shells.ShellTimeoutError, shells.ShellError)
    assert issubclass(shells.ShellIOError, shells.ShellError)


def test_generate_payload_callable():
    assert callable(shells.generate_payload)


def test_generate_payload_bash():
    payload = shells.generate_payload("bash", "10.0.0.1", 4444)
    assert "10.0.0.1" in payload
    assert "4444" in payload
    assert "bash" in payload.lower() or "/bin/" in payload


def test_shell_types_collection():
    assert isinstance(shells.SHELL_TYPES, (dict, tuple, list))
    assert "bash" in shells.SHELL_TYPES


def test_tty_upgrade_commands():
    cmds = shells.tty_upgrade_commands()
    assert isinstance(cmds, list)
    assert len(cmds) > 0


def test_reverse_shell_payload():
    payload = shells.reverse_shell_payload("192.168.1.1", 9999)
    assert "192.168.1.1" in payload
    assert "9999" in payload


def test_concrete_engines_importable():
    assert shells.RawTCPShell is not None
    assert shells.RawUDPShell is not None
    assert shells.DNSTunnelShell is not None
    assert shells.HTTPPollShell is not None
    assert shells.ICMPCovertShell is not None
    assert shells.MQTTShell is not None
    assert shells.InternalShell is not None
    assert shells.MeterpreterBridge is not None


def test_session_manager_importable():
    assert shells.SessionManager is not None
    assert shells.SessionState is not None
    assert shells.ShellSession is not None


def test_stager_mixin_importable():
    assert shells.ShellStagingMixin is not None
    import inspect
    assert inspect.isclass(shells.ShellStagingMixin)


def test_listener_importable():
    assert shells.ReverseListener is not None
    assert callable(shells.start_listener)
