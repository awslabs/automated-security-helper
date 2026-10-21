# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for mcp_validate_config tool."""

from pathlib import Path

import pytest
import yaml

from automated_security_helper.cli.mcp_tools import mcp_validate_config


def _write_yaml(path: Path, data: dict) -> None:
    path.write_text(yaml.dump(data))


class TestValidConfigReturnsValidTrue:
    def test_valid_config_returns_valid_true(self, tmp_path):
        config_file = tmp_path / ".ash.yaml"
        _write_yaml(
            config_file,
            {
                "project_name": "test-project",
                "global_settings": {"severity_threshold": "HIGH"},
            },
        )

        result = mcp_validate_config(config_path=str(config_file))

        assert result["valid"] is True
        assert result["errors"] == []

    def test_valid_config_has_expected_structure(self, tmp_path):
        config_file = tmp_path / ".ash.yaml"
        _write_yaml(config_file, {"project_name": "my-project"})

        result = mcp_validate_config(config_path=str(config_file))

        assert "valid" in result
        assert "errors" in result
        assert isinstance(result["errors"], list)


class TestUnknownFieldReturnsStructuredError:
    def test_unknown_plugin_field_returns_structured_error(self, tmp_path):
        """An unknown key is listed, typed, and leaves the config valid: a scan
        ignores it."""
        config_file = tmp_path / ".ash.yaml"
        # unknown_field is not in VALID_TOP_LEVEL_FIELDS
        _write_yaml(
            config_file,
            {
                "project_name": "test-project",
                "unknown_top_level_field": "bad-value",
            },
        )

        result = mcp_validate_config(config_path=str(config_file))

        assert result["valid"] is True
        assert result["errors"] == []
        types = [e["type"] for e in result["warnings"]]
        assert "unknown_field" in types

    def test_unknown_field_error_has_field_and_message(self, tmp_path):
        config_file = tmp_path / ".ash.yaml"
        _write_yaml(
            config_file,
            {
                "project_name": "test-project",
                "bad_field": 123,
            },
        )

        result = mcp_validate_config(config_path=str(config_file))

        unknown_errors = [e for e in result["warnings"] if e["type"] == "unknown_field"]
        assert len(unknown_errors) >= 1
        err = unknown_errors[0]
        assert "field" in err
        assert "message" in err
        assert "bad_field" in err["message"]


class TestMissingRequiredFieldReturnsStructuredError:
    def test_missing_required_field_returns_structured_error(self, tmp_path):
        """A missing project_name is listed; a scan accepts the config without it."""
        config_file = tmp_path / ".ash.yaml"
        _write_yaml(config_file, {"global_settings": {"severity_threshold": "HIGH"}})

        result = mcp_validate_config(config_path=str(config_file))

        assert result["valid"] is True
        types = [e["type"] for e in result["warnings"]]
        assert "missing_required_field" in types

    def test_error_types_are_distinguishable(self, tmp_path):
        """unknown_field and missing_required_field must have different type strings."""
        config_file = tmp_path / ".ash.yaml"
        # missing project_name (required) AND has unknown field
        _write_yaml(config_file, {"mystery_key": "value"})

        result = mcp_validate_config(config_path=str(config_file))

        types = {e["type"] for e in result["warnings"]}
        assert "missing_required_field" in types
        assert "unknown_field" in types


class TestMalformedYamlReturnsStructuredError:
    def test_malformed_yaml_returns_structured_error(self, tmp_path):
        config_file = tmp_path / ".ash.yaml"
        config_file.write_text("not: : yaml")

        result = mcp_validate_config(config_path=str(config_file))

        assert result["valid"] is False
        assert len(result["errors"]) >= 1
        types = [e["type"] for e in result["errors"]]
        assert "yaml_parse_error" in types

    def test_malformed_yaml_error_has_message(self, tmp_path):
        config_file = tmp_path / ".ash.yaml"
        config_file.write_text("not: : yaml")

        result = mcp_validate_config(config_path=str(config_file))

        yaml_errors = [e for e in result["errors"] if e["type"] == "yaml_parse_error"]
        assert yaml_errors[0]["message"]


class TestValidateByContentString:
    def test_validate_by_content_string_valid(self, tmp_path):
        content = yaml.dump({"project_name": "test-project"})

        result = mcp_validate_config(config_content=content)

        assert result["valid"] is True
        assert result["errors"] == []

    def test_validate_by_content_string_invalid(self):
        content = "not: : yaml"

        result = mcp_validate_config(config_content=content)

        assert result["valid"] is False
        types = [e["type"] for e in result["errors"]]
        assert "yaml_parse_error" in types

    def test_validate_by_content_string_unknown_field(self):
        content = yaml.dump({"project_name": "ok", "bad_key": "oops"})

        result = mcp_validate_config(config_content=content)

        # A scan ignores the unknown key, so the config is valid; it is listed.
        assert result["valid"] is True
        types = [e["type"] for e in result["warnings"]]
        assert "unknown_field" in types


class TestValidateWithExplicitPath:
    def test_validate_with_explicit_path_valid(self, tmp_path):
        config_file = tmp_path / "my_config.yaml"
        _write_yaml(config_file, {"project_name": "explicit-path-project"})

        result = mcp_validate_config(config_path=str(config_file))

        assert result["valid"] is True

    def test_validate_with_explicit_path_invalid(self, tmp_path):
        config_file = tmp_path / "bad_config.yaml"
        _write_yaml(config_file, {"fail_on_findings": "maybe"})

        result = mcp_validate_config(config_path=str(config_file))

        assert result["valid"] is False

    def test_nonexistent_path_returns_error(self, tmp_path):
        result = mcp_validate_config(config_path=str(tmp_path / "nonexistent.yaml"))

        assert result["valid"] is False
        types = [e["type"] for e in result["errors"]]
        assert "file_not_found" in types


class TestAnExtendsErrorIsNotAYamlError:
    """A base that cannot be resolved is reported as such, whatever its file is named.

    Were validate_config to type an error as yaml_parse_error whenever its
    message contains "yaml", every "Config extends error" naming a base such as
    base.yaml would read as a syntax error in the file being validated, and one
    naming base.json would fall through to the generic validation_error. Both
    are extends_error, and yaml_parse_error is the parser's own message only.
    """

    @pytest.mark.parametrize("base", ["missing-base.yaml", "missing-base.json"])
    def test_a_base_that_does_not_exist(self, tmp_path, base):
        config = tmp_path / ".ash.yaml"
        config.write_text(f"project_name: demo\nextends: {base}\n", encoding="utf-8")

        result = mcp_validate_config(config_path=str(config))

        assert result["valid"] is False
        types = {e["type"] for e in result["errors"]}
        assert "yaml_parse_error" not in types, result["errors"]
        assert "extends_error" in types, result["errors"]

    def test_a_path_warning_naming_a_yaml_file_is_not_a_parse_error(self, tmp_path):
        """The validator's path check names the path, and this one ends in .yaml.

        Typing by whether a message mentions "yaml" made this, and any other
        message naming a YAML file, a parse error of the file being validated.
        """
        (tmp_path / "rules.yaml").mkdir()
        config = tmp_path / ".ash.yaml"
        config.write_text(
            "project_name: demo\n"
            "global_settings:\n"
            "  ignore_paths:\n"
            "    - path: rules.yaml\n"
            "      reason: generated\n",
            encoding="utf-8",
        )

        result = mcp_validate_config(config_path=str(config))

        # Errors and warnings are typed alike; the path check is a warning.
        reported = result["errors"] + result["warnings"]
        assert [e["message"] for e in reported if "rules.yaml" in e["message"]], (
            reported
        )
        assert {e["type"] for e in reported} == {"validation_error"}, reported

    def test_a_toml_config_that_does_not_parse(self, tmp_path):
        """A TOML syntax error is a parse error, not a field of the config."""
        config = tmp_path / ".ash.toml"
        config.write_text('project_name = "demo\n[[broken\n', encoding="utf-8")

        result = mcp_validate_config(config_path=str(config))

        assert result["valid"] is False
        errors = result["errors"]
        assert [e["type"] for e in errors] == ["toml_parse_error"], errors
        assert errors[0]["field"] == "", errors

    @pytest.mark.parametrize(
        "name,text,expected",
        [
            pytest.param(
                ".ash.toml",
                'project_name = "demo\n[[broken\n',
                "toml_parse_error",
                id="toml",
            ),
            pytest.param(
                ".ash.yaml",
                "project_name: [unclosed\n",
                "yaml_parse_error",
                id="yaml",
            ),
            pytest.param(
                ".ash.json", '{"project_name": \n', "json_parse_error", id="json"
            ),
        ],
    )
    def test_a_parse_error_is_typed_by_its_category_whatever_its_words(
        self, tmp_path, monkeypatch, name, text, expected
    ):
        """The type comes from the validator's category prefix, never from the
        shared refusal's words or the parser's class name: with both reworded,
        each format's refusal keeps its type."""
        from automated_security_helper.config import config_sources, config_validator

        real = config_sources.unparsed_config_reason

        def reworded(path, error):
            return (
                real(path, error)
                .replace("could not be parsed", "was refused")
                .replace("Error", "Fault")
            )

        monkeypatch.setattr(config_sources, "unparsed_config_reason", reworded)
        monkeypatch.setattr(config_validator, "unparsed_config_reason", reworded)
        config = tmp_path / name
        config.write_text(text, encoding="utf-8")

        result = mcp_validate_config(config_path=str(config))

        errors = result["errors"]
        # The control: the refusal carries the reworded text.
        assert "was refused" in errors[0]["message"], errors
        assert "could not be parsed" not in errors[0]["message"], errors
        assert [e["type"] for e in errors] == [expected], errors

    @pytest.mark.parametrize("fmt", ["TOML", "YAML", "JSON"])
    def test_a_field_named_like_a_parse_prefix_is_not_a_parse_error(
        self, tmp_path, fmt
    ):
        """The classifier reads each parse prefix at the start of the message:
        one that merely holds the prefix's words, such as the unknown-field
        warning for a top-level key named after them, keeps its own type."""
        from automated_security_helper.config.config_validator import ConfigValidator

        prefix = ConfigValidator.PARSE_ERROR_PREFIXES[fmt].rstrip(" ")
        config = tmp_path / ".ash.yaml"
        config.write_text(f'project_name: demo\n"{prefix} x": 1\n', encoding="utf-8")

        result = mcp_validate_config(config_path=str(config))

        reported = result["errors"] + result["warnings"]
        named = [e for e in reported if prefix in e["message"]]
        # The control: the key's words reached a message.
        assert named, reported
        parse_types = {"toml_parse_error", "yaml_parse_error", "json_parse_error"}
        assert all(e["type"] not in parse_types for e in named), reported
        # And it keeps the type it is: the unknown-field warning.
        assert [e["type"] for e in named] == ["unknown_field"], reported

    def test_a_yaml_config_that_is_not_utf8_is_a_parse_error(self, tmp_path):
        """A non-UTF-8 file is typed by its category prefix, as the YAML and
        JSON syntax errors are: without one, the type falls to the keyword
        checks, which scan the message, path included."""
        config = tmp_path / ".ash.yaml"
        config.write_bytes(b"project_name: \xff\n")

        result = mcp_validate_config(config_path=str(config))

        assert result["valid"] is False
        errors = result["errors"]
        assert [e["type"] for e in errors] == ["yaml_parse_error"], errors
        assert "not UTF-8 at byte offset 14" in errors[0]["message"], errors
        assert "xff" not in errors[0]["message"].lower(), errors

    def test_a_json_config_that_is_not_utf8_is_a_parse_error(self, tmp_path):
        """The same for a JSON file: the suffix picks the category."""
        config = tmp_path / ".ash.json"
        config.write_bytes(b'{"project_name": "\xff"}')

        result = mcp_validate_config(config_path=str(config))

        assert result["valid"] is False
        errors = result["errors"]
        assert [e["type"] for e in errors] == ["json_parse_error"], errors
        assert "not UTF-8 at byte offset 18" in errors[0]["message"], errors
        assert "xff" not in errors[0]["message"].lower(), errors

    @pytest.mark.parametrize(
        "name,expected",
        [
            pytest.param(".ash.yaml", "yaml_parse_error", id="yaml"),
            pytest.param(".ash.json", "json_parse_error", id="json"),
        ],
    )
    def test_a_config_nested_past_the_recursion_limit_is_typed_by_its_format(
        self, tmp_path, name, expected
    ):
        """A file nested past the interpreter's recursion limit does not parse.
        It is reported as a parse error of its own format, as its syntax errors
        are, and is not taken for a TOML failure."""
        config = tmp_path / name
        config.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")

        result = mcp_validate_config(config_path=str(config))

        assert result["valid"] is False
        errors = result["errors"]
        assert [e["type"] for e in errors] == [expected], errors
        assert "could not be parsed" in errors[0]["message"], errors

    def test_a_pyproject_with_no_ash_table_is_not_a_parse_error(self, tmp_path):
        config = tmp_path / "pyproject.toml"
        config.write_text('[project]\nname = "demo"\n', encoding="utf-8")

        result = mcp_validate_config(config_path=str(config))

        types = [e["type"] for e in result["errors"]]
        assert types and "toml_parse_error" not in types, result["errors"]

    def test_a_base_that_does_not_parse(self, tmp_path):
        (tmp_path / "base.yaml").write_text("key: [unclosed\n", encoding="utf-8")
        config = tmp_path / ".ash.yaml"
        config.write_text("project_name: demo\nextends: base.yaml\n", encoding="utf-8")

        result = mcp_validate_config(config_path=str(config))

        types = [e["type"] for e in result["errors"]]
        assert types and set(types) <= {"extends_error"}, result["errors"]
