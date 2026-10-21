# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ValueError raised while a config's values are constructed is a parse refusal.

``api_key: !!int s3cretcanary`` makes YAML's constructor call ``int()``, whose
ValueError quotes the file ("invalid literal for int() with base 10:
's3cretcanary'"). The scan, the workspace check and validate each refuse it as
a parse error through unparsed_config_reason, giving the type only and nothing
from the file.

ASH's own refusals and pydantic's ValidationError are ValueErrors by
inheritance, and their messages are built to be shown, so the classifier's
ValueError branch excludes them (the direct cell below).
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

#: The value's text must never reach the refusal.
CANARY = "s3cretcanary"

TAGS = {"int": "!!int", "float": "!!float"}


@pytest.fixture
def quoting_config(request, tmp_path, monkeypatch):
    for name in ("ASH_CONFIG", "ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "constructed.yaml"
    config.write_text(
        f"project_name: t\napi_key: {TAGS[request.param]} {CANARY}\n",
        encoding="utf-8",
    )
    return config


def _a_parse_refusal_without_the_value(output: str) -> None:
    assert "could not be parsed" in output, output
    assert CANARY not in output, output
    assert "invalid literal" not in output, output


@pytest.mark.parametrize("quoting_config", TAGS, indirect=True)
def test_the_scan_refuses_it_without_the_value(tmp_path, quoting_config):
    source = tmp_path / "src"
    source.mkdir()

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--source-dir",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--no-progress",
            "--config",
            str(quoting_config),
        ],
    )

    assert result.exit_code == 3, result.output
    _a_parse_refusal_without_the_value(result.output)
    assert "could not be resolved" not in result.output, result.output


@pytest.mark.parametrize("quoting_config", TAGS, indirect=True)
def test_the_workspace_check_refuses_it_without_the_value(tmp_path, quoting_config):
    import json

    (tmp_path / "api").mkdir()
    workspace = tmp_path / "dev.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--workspace",
            str(workspace),
            "--config",
            str(quoting_config),
            "--dry-run",
        ],
    )

    assert result.exit_code == 3, result.output
    _a_parse_refusal_without_the_value(result.output)


@pytest.mark.parametrize("quoting_config", TAGS, indirect=True)
def test_validate_refuses_it_without_the_value(quoting_config):
    result = CliRunner().invoke(
        app, ["config", "validate", "--config", str(quoting_config)]
    )

    assert result.exit_code == 3, result.output
    _a_parse_refusal_without_the_value(result.output)


def test_the_scan_refuses_an_ash_config_value_error_without_the_value(
    tmp_path, monkeypatch
):
    """The ASH_CONFIG loader refuses a constructor's ValueError as a parse error,
    so the scan's output holds nothing of the value."""
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "env.yaml"
    config.write_text(f"project_name: t\napi_key: !!int {CANARY}\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))
    source = tmp_path / "src"
    source.mkdir()

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--source-dir",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--no-progress",
        ],
    )

    assert result.exit_code == 3, result.output
    _a_parse_refusal_without_the_value(result.output)


def test_the_default_config_refuses_a_value_error_without_the_value(
    tmp_path, monkeypatch
):
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    config = tmp_path / "env.yaml"
    config.write_text(f"project_name: t\napi_key: !!int {CANARY}\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))

    with pytest.raises(ASHConfigValidationError) as info:
        get_default_config()

    assert "could not be parsed" in str(info.value), str(info.value)
    assert CANARY not in str(info.value), str(info.value)


def test_mcp_get_config_answers_an_ash_config_value_error(tmp_path, monkeypatch):
    """The tool answers a refusal; it does not raise it at the client."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    config = tmp_path / "env.yaml"
    config.write_text(f"project_name: t\napi_key: !!int {CANARY}\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))

    result = mcp_get_config(search_dir=str(tmp_path))

    assert result.get("success") is not True, result
    assert CANARY not in repr(result), result


def test_config_update_refuses_a_value_error_without_the_value(tmp_path, monkeypatch):
    """The rewrite pre-check refuses a constructor's ValueError as a parse error,
    so config update prints nothing of the value."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "u.yaml"
    config.write_text(f"project_name: t\napi_key: !!int {CANARY}\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["config", "update", "--config", str(config), "--set", "project_name=u"]
    )

    assert result.exit_code == 3, result.output
    _a_parse_refusal_without_the_value(result.output)


def test_the_suppression_save_refuses_a_value_error_without_the_value(tmp_path):
    from automated_security_helper.config.ash_config import add_suppression_to_config
    from automated_security_helper.models.core import AshSuppression

    config = tmp_path / "s.yaml"
    config.write_text(f"project_name: t\napi_key: !!int {CANARY}\n", encoding="utf-8")

    with pytest.raises(ValueError) as info:
        add_suppression_to_config(
            config, AshSuppression(rule_id="B101", path="x.py", reason="r")
        )

    assert "could not be parsed" in str(info.value), str(info.value)
    assert CANARY not in str(info.value), str(info.value)


def test_the_workspace_policy_refuses_a_value_error_without_the_value(tmp_path):
    from automated_security_helper.workspace.policy import load_workspace_policy

    policy = tmp_path / "policy.yaml"
    policy.write_text(f"scanners: !!int {CANARY}\n", encoding="utf-8")

    with pytest.raises(Exception) as info:
        load_workspace_policy(policy)

    assert "could not be parsed" in str(info.value), str(info.value)
    assert CANARY not in str(info.value), str(info.value)


def test_the_workspace_check_keeps_an_own_refusal_s_words(tmp_path):
    """The check's re-raise keeps ASH's own refusal by identity. Without
    it, a pyproject whose tool.ash is not a table would be re-formatted
    "could not be parsed (ASHConfigSourceError)" and lose its words."""
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.workspace.resolver import (
        _refuse_a_default_config_that_does_not_load,
    )

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("tool.ash = 3\n", encoding="utf-8")

    with pytest.raises(ASHConfigValidationError, match="must be a table"):
        _refuse_a_default_config_that_does_not_load(pyproject)


def test_a_raw_validation_error_is_never_described_as_a_read(tmp_path, monkeypatch):
    """Pinned: a raw pydantic ValidationError, were one ever to escape the
    loader unwrapped, is neither a parse nor a read. It reaches the resolution
    handler, whose wrap keeps it as the cause, and never the read branch, whose
    "could not read <path>" would send the operator to the filesystem."""
    import pydantic

    from automated_security_helper.config import resolve_config as module
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    class Model(pydantic.BaseModel):
        x: int

    try:
        Model(x="no")
    except pydantic.ValidationError as caught:
        raw = caught

    def _raises(*args, **kwargs):
        raise raw

    monkeypatch.setattr(module, "load_config_file_for_run", _raises)
    config = tmp_path / "v.yaml"
    config.write_text("project_name: t\n", encoding="utf-8")

    with pytest.raises(ASHConfigValidationError) as info:
        module.resolve_config(
            config_path=config, source_dir=tmp_path, fallback_to_default=True
        )

    text = str(info.value)
    assert "could not be resolved" in text, text
    assert "could not read" not in text, text
    assert info.value.__cause__ is raw


def test_the_mcp_load_failure_describes_a_raw_validation_error(tmp_path):
    """The MCP load-failure response describes a raw ValidationError as the CLI
    describes one, one line per field with no input, never by str(), whose text
    quotes every input (input_value=...)."""
    import pydantic

    from automated_security_helper.cli.mcp_tools import _config_load_failure

    class Model(pydantic.BaseModel):
        x: int

    try:
        Model(x=CANARY)
    except pydantic.ValidationError as caught:
        raw = caught

    result = _config_load_failure(raw, tmp_path / "v.yaml")

    text = repr(result)
    assert "cannot be loaded" in text, text
    assert CANARY not in text, text
    assert "input_value" not in text, text


def test_mcp_validate_types_a_constructor_s_value_error_as_a_parse_error(tmp_path):
    """The type comes from the category prefix, so the validator's
    ValueError branch carries its format's prefix too."""
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    config = tmp_path / "v.yaml"
    config.write_text(f"project_name: t\napi_key: !!int {CANARY}\n", encoding="utf-8")

    result = mcp_validate_config(config_path=str(config))

    assert result["valid"] is False, result
    types = [e.get("type") for e in result["errors"]]
    assert "yaml_parse_error" in types, result["errors"]
    assert "validation_error" not in types, result["errors"]


@pytest.mark.parametrize(
    "name",
    ["Unknown-ctor.yaml", "Unknown-ctor.json", "Invalid-ctor.yaml"],
)
def test_mcp_validate_types_a_constructor_error_whatever_its_path(tmp_path, name):
    """The type comes from the category prefix, never from words of the
    path -- an Unknown or Invalid path is not an unknown_field or
    invalid_field."""
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    config = tmp_path / name
    if name.endswith(".json"):
        config.write_text('{"x": %s}' % ("1" * 5000), encoding="utf-8")
        expected = "json_parse_error"
    else:
        config.write_text(f"api_key: !!int {CANARY}\n", encoding="utf-8")
        expected = "yaml_parse_error"

    result = mcp_validate_config(config_path=str(config))

    assert result["valid"] is False, result
    types = [e.get("type") for e in result["errors"]]
    assert expected in types, result["errors"]
    assert "unknown_field" not in types, result["errors"]
    assert "invalid_field" not in types, result["errors"]


def test_mcp_validate_types_a_json_that_is_not_utf8_as_a_parse_error(tmp_path):
    """A .json file that is not UTF-8 carries the
    JSON category prefix, like its YAML sibling."""
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    config = tmp_path / "latin1.json"
    config.write_bytes('{"project_name": "café"}\n'.encode("latin-1"))

    result = mcp_validate_config(config_path=str(config))

    assert result["valid"] is False, result
    types = [e.get("type") for e in result["errors"]]
    assert "json_parse_error" in types, result["errors"]
    for error in result["errors"]:
        assert "can't decode" not in error.get("message", ""), error


def test_config_update_s_refusal_is_not_nested(tmp_path, monkeypatch):
    """The refusal "it is not a valid configuration (<reason>)" nested a reason
    that already says what is wrong with the file."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "n.yaml"
    config.write_text("project_name: [unclosed\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["config", "update", "--config", str(config), "--set", "project_name=u"]
    )

    assert result.exit_code == 3, result.output
    assert "could not be parsed" in result.output, result.output
    assert "not a valid configuration" not in result.output, result.output


@pytest.mark.parametrize(
    "name,text,said",
    [
        pytest.param(
            ".ash.yaml", "project_name: [unclosed\n", "could not be parsed", id="yaml"
        ),
        pytest.param(
            ".ash.json", '{"project_name": \n', "could not be parsed", id="json"
        ),
        # The control: a refusal that does not name the file keeps the frame's.
        pytest.param(
            ".ash.yaml",
            "project_name: t\nfail_on_findings: maybe\n",
            "fail_on_findings",
            id="refused-by-the-model",
        ),
    ],
)
def test_config_update_names_the_file_once(tmp_path, monkeypatch, name, text, said):
    """A parse refusal names the file itself, so the frame leaves its own name
    out; any other refusal is framed with the file's name."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    config = tmp_path / name
    config.write_text(text, encoding="utf-8")

    result = CliRunner().invoke(
        app, ["config", "update", "--config", str(config), "--set", "project_name=u"]
    )

    assert result.exit_code == 3, result.output
    assert said in result.output, result.output
    assert result.output.count(str(config)) == 1, result.output


def test_validate_s_parse_line_is_the_error_itself(tmp_path, monkeypatch):
    """The printer's "The file does not parse:" header stacked over an error
    that already carries its category prefix and reason. The verdict line still
    says the file does not parse."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "p.yaml"
    config.write_text("project_name: [unclosed\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["config", "validate", "--config", str(config)])

    assert result.exit_code == 3, result.output
    assert "could not be parsed" in result.output, result.output
    assert "The file does not parse:" not in result.output, result.output
    assert "does not parse" in result.output, result.output


def test_the_classifier_excludes_refusals_made_to_be_shown():
    """is_config_parse_error says True for a constructor's ValueError and False
    for ASH's own refusals and pydantic's ValidationError, ValueErrors by
    inheritance whose messages are built (and redacted) to be shown."""
    import pydantic

    from automated_security_helper.config.config_sources import is_config_parse_error
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    class Model(pydantic.BaseModel):
        x: int

    with pytest.raises(pydantic.ValidationError) as info:
        Model(x="not an int")

    assert is_config_parse_error(ValueError("the constructor's own text"))
    assert not is_config_parse_error(ASHConfigSourceError("made to be shown"))
    assert not is_config_parse_error(info.value)
