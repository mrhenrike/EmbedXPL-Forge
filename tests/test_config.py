"""Tests for embedxpl.core.config persistent user configuration."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from embedxpl.core import config


def _reset():
    config.reset_cache()


def test_defaults_compute_mode():
    _reset()
    with patch.object(config, "_CONFIG_FILE", Path("/nonexistent/fake.json")):
        _reset()
        assert config.get("compute_mode") == "auto"


def test_defaults_include_new_keys():
    _reset()
    with patch.object(config, "_CONFIG_FILE", Path("/nonexistent/fake.json")):
        _reset()
        vals = config.all_values()
        assert vals["output_format"] == "table"
        assert vals["verbosity"] == 1
        assert vals["default_workspace"] == "default"
        assert vals["max_threads"] == 10
        assert vals["timeout_s"] == 30
        assert vals["color"] is True


def test_get_missing_key_returns_default():
    _reset()
    with patch.object(config, "_CONFIG_FILE", Path("/nonexistent/fake.json")):
        _reset()
        assert config.get("no_such_key") is None
        assert config.get("no_such_key", 42) == 42


def test_set_val_and_get(tmp_path):
    _reset()
    fake_cfg = tmp_path / "test_config.json"
    with patch.object(config, "_CONFIG_FILE", fake_cfg):
        _reset()
        config.set_val("compute_mode", "gpu")
        assert config.get("compute_mode") == "gpu"
        assert fake_cfg.exists()
        data = json.loads(fake_cfg.read_text())
        assert data["compute_mode"] == "gpu"


def test_set_val_no_persist(tmp_path):
    _reset()
    fake_cfg = tmp_path / "no_persist.json"
    with patch.object(config, "_CONFIG_FILE", fake_cfg):
        _reset()
        config.set_val("compute_mode", "cpu", persist=False)
        assert config.get("compute_mode") == "cpu"
        assert not fake_cfg.exists()


def test_set_val_validates_constrained_keys(tmp_path):
    _reset()
    fake_cfg = tmp_path / "val.json"
    with patch.object(config, "_CONFIG_FILE", fake_cfg):
        _reset()
        with pytest.raises(ValueError, match="invalid value"):
            config.set_val("output_format", "yaml")
        with pytest.raises(ValueError, match="invalid value"):
            config.set_val("compute_mode", "quantum")
        config.set_val("output_format", "json")
        assert config.get("output_format") == "json"


def test_all_values_returns_copy(tmp_path):
    _reset()
    fake_cfg = tmp_path / "allvals.json"
    with patch.object(config, "_CONFIG_FILE", fake_cfg):
        _reset()
        vals = config.all_values()
        assert isinstance(vals, dict)
        assert "compute_mode" in vals
        vals["compute_mode"] = "CHANGED"
        assert config.get("compute_mode") != "CHANGED"


def test_load_from_disk(tmp_path):
    _reset()
    fake_cfg = tmp_path / "disk.json"
    fake_cfg.write_text(json.dumps({"compute_mode": "cpu", "custom_key": 99}))
    with patch.object(config, "_CONFIG_FILE", fake_cfg):
        _reset()
        assert config.get("compute_mode") == "cpu"
        assert config.get("custom_key") == 99


def test_load_corrupt_file(tmp_path):
    _reset()
    fake_cfg = tmp_path / "corrupt.json"
    fake_cfg.write_text("{invalid json!!!")
    with patch.object(config, "_CONFIG_FILE", fake_cfg):
        _reset()
        assert config.get("compute_mode") == "auto"


def test_reset_cache_clears():
    _reset()
    with patch.object(config, "_CONFIG_FILE", Path("/nonexistent/fake2.json")):
        _reset()
        config.set_val("max_threads", 50, persist=False)
        assert config.get("max_threads") == 50
        config.reset_cache()
        assert config.get("max_threads") == 10


def test_env_override_string(tmp_path):
    _reset()
    fake_cfg = tmp_path / "env.json"
    with patch.object(config, "_CONFIG_FILE", fake_cfg):
        with patch.dict(os.environ, {"EXF_OUTPUT_FORMAT": "csv"}):
            _reset()
            assert config.get("output_format") == "csv"


def test_env_override_int(tmp_path):
    _reset()
    fake_cfg = tmp_path / "env_int.json"
    with patch.object(config, "_CONFIG_FILE", fake_cfg):
        with patch.dict(os.environ, {"EXF_MAX_THREADS": "25"}):
            _reset()
            assert config.get("max_threads") == 25


def test_env_override_bool(tmp_path):
    _reset()
    fake_cfg = tmp_path / "env_bool.json"
    with patch.object(config, "_CONFIG_FILE", fake_cfg):
        with patch.dict(os.environ, {"EXF_COLOR": "false"}):
            _reset()
            assert config.get("color") is False


def test_env_override_invalid_int_ignored(tmp_path):
    _reset()
    fake_cfg = tmp_path / "env_bad.json"
    with patch.object(config, "_CONFIG_FILE", fake_cfg):
        with patch.dict(os.environ, {"EXF_MAX_THREADS": "not_a_number"}):
            _reset()
            assert config.get("max_threads") == 10


def test_validate_clean(tmp_path):
    _reset()
    fake_cfg = tmp_path / "clean.json"
    with patch.object(config, "_CONFIG_FILE", fake_cfg):
        _reset()
        warnings = config.validate()
        assert warnings == []


def test_validate_bad_values(tmp_path):
    _reset()
    fake_cfg = tmp_path / "bad.json"
    fake_cfg.write_text(json.dumps({
        "output_format": "yaml",
        "max_threads": 999,
        "timeout_s": -5,
    }))
    with patch.object(config, "_CONFIG_FILE", fake_cfg):
        _reset()
        warnings = config.validate()
        assert len(warnings) == 3
        assert any("output_format" in w for w in warnings)
        assert any("max_threads" in w for w in warnings)
        assert any("timeout_s" in w for w in warnings)


def test_config_path():
    p = config.config_path()
    assert p.name == ".exf_config.json"
