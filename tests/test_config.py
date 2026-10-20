"""Tests for embedxpl.core.config persistent user configuration."""


import json
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from embedxpl.core import config


def _reset():
    config.reset_cache()


def test_defaults_compute_mode():
    _reset()
    with patch.object(config, "_CONFIG_FILE", Path("/nonexistent/fake.json")):
        _reset()
        assert config.get("compute_mode") == "auto"


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
    fake_cfg.write_text(json.dumps({"compute_mode": "hybrid", "custom_key": 99}))
    with patch.object(config, "_CONFIG_FILE", fake_cfg):
        _reset()
        assert config.get("compute_mode") == "hybrid"
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
        config.set_val("x", 1, persist=False)
        assert config.get("x") == 1
        config.reset_cache()
        assert config.get("x") is None
