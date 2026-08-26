"""Tests for config/resolve_config.py — covers override parsing, resolve_config, and apply_config_overrides."""

from pathlib import Path
from unittest.mock import patch
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
                line_errors=[
                    {
                        "type": "value_error",
                        "loc": ("project_name",),
                        "msg": "invalid",
                        "input": "bad",
                        "ctx": {"error": ValueError("test")},
                    }
                ],
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
        # project_name, not project-name: there is no kebab-case alias for this
        # field, so the hyphenated spelling is dropped by extra="ignore" and the
        # assertion below would pass against the default config.
        config_path.write_text("project_name: from-file\n")
        config = resolve_config(config_path=config_path)
        assert config.project_name == "from-file"
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
        config_path.write_text("project_name: discovered\n")

        config = resolve_config(source_dir=tmp_path)
        assert isinstance(config, AshConfig)
        # Asserts the file was actually discovered under <source_dir>/.ash/,
        # which a not-None assertion cannot distinguish from the default config.
        assert config.project_name == "discovered"

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
        config_path.write_text("project_name: str-path\n")

        config = resolve_config(source_dir=str(tmp_path))
        assert isinstance(config, AshConfig)
        assert config.project_name == "str-path"

    def test_overrides_applied_to_default_when_no_source_dir(self):
        config = resolve_config(config_overrides=["project_name=via-override"])
        assert config.project_name == "via-override"


class TestConfigPathHonoredWithoutSourceDir:
    """An explicit config_path must win even when source_dir is not supplied.

    Why this class exists
    ---------------------
    resolve_config used to return the default config whenever source_dir was
    None, before it ever looked at config_path. `ash report --config <file>`
    calls resolve_config(config_path=..., config_overrides=...) and passes no
    source_dir, so the option was accepted and then silently ignored: the
    command reported against default settings while appearing to honour the
    file. `ash config` (cli/config.py) has the same call shape.

    Why it was not caught
    ---------------------
    The pre-existing tests in this file wrote `project-name:` into the fixture
    and then only asserted `config is not None`. Two things were wrong with
    that: project_name has no kebab-case alias, so `project-name` is dropped by
    extra="ignore" and never populates the field at all, and a not-None
    assertion passes just as happily on the default config as on a loaded one.
    Every test below asserts on a value that can only come from the file.
    """

    def test_config_path_is_loaded_when_source_dir_omitted(self, tmp_path):
        """The `ash report --config <file>` shape: config_path, no source_dir."""
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("project_name: from-file\n")

        config = resolve_config(config_path=config_path)

        assert config.project_name == "from-file"

    def test_config_path_is_loaded_when_source_dir_is_explicitly_none(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("project_name: from-file\n")

        config = resolve_config(config_path=config_path, source_dir=None)

        assert config.project_name == "from-file"

    def test_overrides_apply_on_top_of_config_path_without_source_dir(self, tmp_path):
        """report.py passes config_path and config_overrides together.

        The override must win over the file, and the file must still be read for
        anything the override does not mention.
        """
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("project_name: from-file\nfail_on_findings: false\n")

        config = resolve_config(
            config_path=config_path,
            config_overrides=["project_name=from-override"],
        )

        assert config.project_name == "from-override"
        assert config.fail_on_findings is False

    def test_default_is_still_returned_when_neither_is_supplied(self):
        """Guard against over-correcting.

        With no config_path and no source_dir there is nothing to resolve, so
        the default config is still the right answer. This is the case
        test_source_dir_none_with_fallback covers, restated here so that a
        future change to the config_path branch cannot quietly break it.
        """
        config = resolve_config()

        assert config is not None
        assert isinstance(config, AshConfig)

    def test_relative_config_path_resolves_without_source_dir(
        self, tmp_path, monkeypatch
    ):
        """A relative --config path is resolved against the process cwd.

        resolve_config falls back to Path.cwd() for source_dir. That fallback is
        only reachable once the source_dir-is-None short circuit is gone, so
        this pins the behaviour rather than leaving it to chance.
        """
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("project_name: from-relative\n")
        monkeypatch.chdir(tmp_path)

        config = resolve_config(config_path=Path(".ash.yaml"))

        assert config.project_name == "from-relative"
