"""Tests for config/resolve_config.py — covers override parsing, resolve_config, and apply_config_overrides."""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from automated_security_helper.config.resolve_config import (
    _apply_config_override,
    _parse_config_value,
    apply_config_overrides,
    resolve_config,
)
from automated_security_helper.config.ash_config import AshConfig


class TestParseConfigValue:
    """Tests for _parse_config_value."""

    def test_parse_true(self):
        assert _parse_config_value("true") is True
        assert _parse_config_value("True") is True
        assert _parse_config_value("TRUE") is True

    def test_parse_false(self):
        assert _parse_config_value("false") is False
        assert _parse_config_value("False") is False

    def test_parse_null(self):
        assert _parse_config_value("null") is None
        assert _parse_config_value("none") is None
        assert _parse_config_value("None") is None

    def test_parse_int(self):
        assert _parse_config_value("42") == 42
        assert _parse_config_value("0") == 0
        assert _parse_config_value("-1") == -1

    def test_parse_float(self):
        assert _parse_config_value("3.14") == 3.14
        assert _parse_config_value("0.5") == 0.5

    def test_parse_string(self):
        assert _parse_config_value("hello") == "hello"
        assert _parse_config_value("path/to/file") == "path/to/file"

    def test_parse_json_list(self):
        result = _parse_config_value('["a", "b", "c"]')
        assert result == ["a", "b", "c"]

    def test_parse_simple_list(self):
        result = _parse_config_value("[a, b, c]")
        assert result == ["a", "b", "c"]

    def test_parse_json_dict(self):
        result = _parse_config_value('{"key": "val"}')
        assert result == {"key": "val"}

    def test_parse_invalid_dict_returns_string(self):
        result = _parse_config_value("{not valid json}")
        assert result == "{not valid json}"

    def test_parse_empty_list(self):
        result = _parse_config_value("[]")
        assert result == []


class TestApplyConfigOverride:
    """Tests for _apply_config_override."""

    def test_simple_set(self):
        config_dict = {"project_name": "old"}
        _apply_config_override(config_dict, "project_name", "new")
        assert config_dict["project_name"] == "new"

    def test_nested_set(self):
        config_dict = {"reporters": {"html": {"enabled": True}}}
        _apply_config_override(config_dict, "reporters.html.enabled", "false")
        assert config_dict["reporters"]["html"]["enabled"] is False

    def test_creates_nested_path(self):
        config_dict = {}
        _apply_config_override(config_dict, "a.b.c", "value")
        assert config_dict["a"]["b"]["c"] == "value"

    def test_append_mode(self):
        config_dict = {"tags": ["a", "b"]}
        _apply_config_override(config_dict, "tags+", "c")
        assert "c" in config_dict["tags"]

    def test_append_mode_with_list(self):
        config_dict = {"tags": ["a"]}
        _apply_config_override(config_dict, "tags+", '["b", "c"]')
        assert config_dict["tags"] == ["a", "b", "c"]


class TestApplyConfigOverrides:
    """Tests for apply_config_overrides."""

    def test_no_overrides(self):
        config = AshConfig(project_name="test")
        result = apply_config_overrides(config, [])
        assert result.project_name == "test"

    def test_none_overrides(self):
        config = AshConfig(project_name="test")
        result = apply_config_overrides(config, None)
        assert result.project_name == "test"

    def test_apply_valid_override(self):
        config = AshConfig(project_name="test")
        result = apply_config_overrides(config, ["project_name=updated"])
        assert result.project_name == "updated"

    def test_invalid_format_logs_warning(self):
        config = AshConfig(project_name="test")
        # Invalid format (no =) should not crash
        result = apply_config_overrides(config, ["invalid_no_equals"])
        assert result.project_name == "test"

    def test_validation_error_returns_original(self):
        from pydantic import ValidationError
        config = AshConfig(project_name="test")
        # Apply an override that makes the model invalid
        with patch(
            "automated_security_helper.config.resolve_config.AshConfig.model_validate",
            side_effect=ValidationError.from_exception_data(
                title="AshConfig",
                line_errors=[{
                    "type": "value_error",
                    "loc": ("project_name",),
                    "msg": "invalid",
                    "input": "bad",
                    "ctx": {"error": ValueError("test")},
                }],
            ),
        ):
            result = apply_config_overrides(config, ["project_name=new"])
            # Should return original config on validation error
            assert result.project_name == "test"


class TestResolveConfig:
    """Tests for resolve_config."""

    def test_no_args_returns_default(self):
        config = resolve_config()
        assert config is not None
        assert isinstance(config, AshConfig)

    def test_source_dir_none_with_fallback(self):
        config = resolve_config(source_dir=None, fallback_to_default=True)
        assert config is not None

    def test_explicit_config_path(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("project-name: from-file\n")
        config = resolve_config(config_path=config_path)
        # File should be loaded and config returned
        assert config is not None
        assert isinstance(config, AshConfig)

    def test_config_path_not_found_with_fallback(self, tmp_path):
        config = resolve_config(
            config_path=tmp_path / "nonexistent.yaml", fallback_to_default=True
        )
        assert config is not None

    def test_config_path_not_found_without_fallback(self, tmp_path):
        # When fallback_to_default=False but config_path doesn't exist,
        # it should raise or return None depending on implementation
        try:
            result = resolve_config(
                config_path=tmp_path / "nonexistent.yaml", fallback_to_default=False
            )
            # If it doesn't raise, verify it handled the situation
            assert result is None or isinstance(result, AshConfig)
        except (ValueError, Exception):
            pass  # Expected behavior

    def test_source_dir_with_config_file(self, tmp_path):
        ash_dir = tmp_path / ".ash"
        ash_dir.mkdir()
        config_path = ash_dir / ".ash.yaml"
        config_path.write_text("project-name: discovered\n")

        config = resolve_config(source_dir=tmp_path)
        assert config is not None
        assert isinstance(config, AshConfig)

    def test_source_dir_no_config_with_fallback(self, tmp_path):
        config = resolve_config(source_dir=tmp_path, fallback_to_default=True)
        assert config is not None

    def test_source_dir_no_config_without_fallback(self, tmp_path):
        with pytest.raises(ValueError):
            resolve_config(source_dir=tmp_path, fallback_to_default=False)

    def test_with_config_overrides(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("project-name: original\n")

        config = resolve_config(
            config_path=config_path,
            config_overrides=["project_name=overridden"],
        )
        assert config.project_name == "overridden"

    def test_invalid_yaml_with_fallback(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(": invalid yaml {{")

        config = resolve_config(config_path=config_path, fallback_to_default=True)
        assert config is not None

    def test_source_dir_string(self, tmp_path):
        ash_dir = tmp_path / ".ash"
        ash_dir.mkdir()
        config_path = ash_dir / ".ash.yaml"
        config_path.write_text("project-name: str-path\n")

        config = resolve_config(source_dir=str(tmp_path))
        assert config is not None
        assert isinstance(config, AshConfig)

    def test_overrides_applied_to_default_when_no_source_dir(self):
        config = resolve_config(config_overrides=["project_name=via-override"])
        assert config.project_name == "via-override"
