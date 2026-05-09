# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for mcp_get_config and ash://schema/config resource."""

import json
from pathlib import Path

import pytest
import yaml

from automated_security_helper.cli.mcp_tools import mcp_get_config
from automated_security_helper.config.default_config import get_default_config


def _write_config(path: Path, data: dict) -> None:
    path.write_text(yaml.dump(data))


class TestGetConfigResolved:
    def test_returns_resolved_dict(self, tmp_path):
        config_file = tmp_path / ".ash.yaml"
        _write_config(config_file, {"global_settings": {"severity_threshold": "HIGH"}})

        result = mcp_get_config(config_path=str(config_file))

        assert isinstance(result, dict)
        assert result["global_settings"]["severity_threshold"] == "HIGH"
        # defaults merged: scanners key should be present
        assert "scanners" in result

    def test_defaults_merged_for_non_overridden_fields(self, tmp_path):
        config_file = tmp_path / ".ash.yaml"
        _write_config(
            config_file, {"global_settings": {"severity_threshold": "CRITICAL"}}
        )

        result = mcp_get_config(config_path=str(config_file))
        default = get_default_config().model_dump()

        # overridden field reflected
        assert result["global_settings"]["severity_threshold"] == "CRITICAL"
        # a non-overridden top-level field should match the default
        assert result.get("fail_on_findings") == default.get("fail_on_findings")


class TestGetConfigRaw:
    def test_raw_returns_unmerged(self, tmp_path):
        config_file = tmp_path / ".ash.yaml"
        raw_data = {"global_settings": {"severity_threshold": "LOW"}}
        _write_config(config_file, raw_data)

        result = mcp_get_config(config_path=str(config_file), raw=True)

        assert result == raw_data
        # defaults NOT merged: no top-level scanners key
        assert "scanners" not in result

    def test_raw_returns_exact_file_contents(self, tmp_path):
        config_file = tmp_path / ".ash.yaml"
        raw_data = {
            "global_settings": {"severity_threshold": "MEDIUM"},
            "fail_on_findings": True,
        }
        _write_config(config_file, raw_data)

        result = mcp_get_config(config_path=str(config_file), raw=True)

        assert result["global_settings"]["severity_threshold"] == "MEDIUM"
        assert result["fail_on_findings"] is True


class TestGetConfigMissingFile:
    def test_missing_explicit_path_returns_default(self, tmp_path):
        result = mcp_get_config(config_path=str(tmp_path / "nonexistent.yaml"))

        default = get_default_config().model_dump()
        assert isinstance(result, dict)
        assert (
            result["global_settings"]["severity_threshold"]
            == default["global_settings"]["severity_threshold"]
        )
        assert "scanners" in result

    def test_no_config_in_directory_returns_default(self, tmp_path):
        # Pass no config_path — auto-discovery in tmp_path finds nothing
        result = mcp_get_config(config_path=None, search_dir=str(tmp_path))

        default = get_default_config().model_dump()
        assert (
            result["global_settings"]["severity_threshold"]
            == default["global_settings"]["severity_threshold"]
        )


class TestGetConfigExplicitPath:
    def test_explicit_path_loads_that_file(self, tmp_path):
        config_a = tmp_path / "a.yaml"
        config_b = tmp_path / "b.yaml"
        _write_config(config_a, {"global_settings": {"severity_threshold": "LOW"}})
        _write_config(config_b, {"global_settings": {"severity_threshold": "CRITICAL"}})

        result_a = mcp_get_config(config_path=str(config_a))
        result_b = mcp_get_config(config_path=str(config_b))

        assert result_a["global_settings"]["severity_threshold"] == "LOW"
        assert result_b["global_settings"]["severity_threshold"] == "CRITICAL"


def _resolve_schema_properties(schema: dict) -> dict:
    """Resolve $ref into $defs and return the properties dict."""
    ref = schema.get("$ref", "")
    if ref.startswith("#/$defs/"):
        def_name = ref.split("/")[-1]
        defn = schema.get("$defs", {}).get(def_name, {})
        return defn.get("properties", {})
    return schema.get("properties", {})


class TestSchemaResource:
    def test_schema_resource_returns_valid_json(self):
        from automated_security_helper.cli.mcp_server import _read_ash_config_schema

        content = _read_ash_config_schema()
        parsed = json.loads(content)
        # Valid JSON Schema: either top-level markers or a $ref into $defs
        assert any(k in parsed for k in ("$schema", "title", "properties", "$ref", "$defs", "type"))

    def test_schema_resource_contains_global_settings(self):
        from automated_security_helper.cli.mcp_server import _read_ash_config_schema

        content = _read_ash_config_schema()
        parsed = json.loads(content)
        props = _resolve_schema_properties(parsed)
        assert "global_settings" in props
