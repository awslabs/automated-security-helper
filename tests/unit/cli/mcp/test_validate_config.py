# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for mcp_validate_config tool."""

import textwrap
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

        assert result["valid"] is False
        assert len(result["errors"]) >= 1
        types = [e["type"] for e in result["errors"]]
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

        unknown_errors = [e for e in result["errors"] if e["type"] == "unknown_field"]
        assert len(unknown_errors) >= 1
        err = unknown_errors[0]
        assert "field" in err
        assert "message" in err
        assert "bad_field" in err["message"]


class TestMissingRequiredFieldReturnsStructuredError:
    def test_missing_required_field_returns_structured_error(self, tmp_path):
        config_file = tmp_path / ".ash.yaml"
        # project_name is required — omit it
        _write_yaml(config_file, {"global_settings": {"severity_threshold": "HIGH"}})

        result = mcp_validate_config(config_path=str(config_file))

        assert result["valid"] is False
        types = [e["type"] for e in result["errors"]]
        assert "missing_required_field" in types

    def test_error_types_are_distinguishable(self, tmp_path):
        """unknown_field and missing_required_field must have different type strings."""
        config_file = tmp_path / ".ash.yaml"
        # missing project_name (required) AND has unknown field
        _write_yaml(config_file, {"mystery_key": "value"})

        result = mcp_validate_config(config_path=str(config_file))

        types = {e["type"] for e in result["errors"]}
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

        assert result["valid"] is False
        types = [e["type"] for e in result["errors"]]
        assert "unknown_field" in types


class TestValidateWithExplicitPath:
    def test_validate_with_explicit_path_valid(self, tmp_path):
        config_file = tmp_path / "my_config.yaml"
        _write_yaml(config_file, {"project_name": "explicit-path-project"})

        result = mcp_validate_config(config_path=str(config_file))

        assert result["valid"] is True

    def test_validate_with_explicit_path_invalid(self, tmp_path):
        config_file = tmp_path / "bad_config.yaml"
        _write_yaml(config_file, {"not_a_real_field": "value"})

        result = mcp_validate_config(config_path=str(config_file))

        assert result["valid"] is False

    def test_nonexistent_path_returns_error(self, tmp_path):
        result = mcp_validate_config(config_path=str(tmp_path / "nonexistent.yaml"))

        assert result["valid"] is False
        types = [e["type"] for e in result["errors"]]
        assert "file_not_found" in types
