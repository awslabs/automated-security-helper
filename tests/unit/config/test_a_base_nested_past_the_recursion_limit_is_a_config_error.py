# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A base nested past the recursion limit is a chain error, never a raw RecursionError.

A repository can write a config that extends a base nested past the
interpreter's recursion limit. ``resolve_config_document`` promises its callers
an ``ASHConfigSourceError`` for every chain that does not resolve (the module
docstring, its own docstring and ``load_config_file``'s Raises section), and
``ConfigValidator.check_config_file``, which ``ash config validate``, ``ash
config lint`` and the MCP validate tool all call, catches that error and turns
it into an ``errors`` entry. A RecursionError that left the chain walk raw
would skip that catch.

``parse_config_text`` refuses a file nested past the limit as an unparsed
config, naming that file, so a base arrives in the chain walk as an
``ASHConfigUnparsedError``: a plain base is named by its path alone and the file
that extends it is not blamed, and a base the environment chose is ``<value>``
with no path. The chain error is what every caller prints, so the cells below
drive the callers and not only the walk.
"""

import re

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.cli.mcp_tools import mcp_validate_config
from automated_security_helper.config.config_linter import ConfigLinter
from automated_security_helper.config.config_sources import resolve_config_document
from automated_security_helper.config.config_validator import ConfigValidator
from automated_security_helper.core.exceptions import ASHConfigSourceError

pytestmark = pytest.mark.unit

#: Deep enough that every parser a config is read with runs out of recursion on
#: it, whatever the interpreter's limit.
_NESTING = 100_000

#: What the refusal of such a file says after the file's path.
_REASON = "could not be parsed (RecursionError)"


@pytest.fixture(autouse=True)
def _no_environment_config(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _nested_past_the_recursion_limit(path):
    """A real config file nested ``_NESTING`` levels, as the format its name
    says (the same text is a JSON array and a YAML flow sequence)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("[" * _NESTING + "]" * _NESTING, encoding="utf-8")
    return path


def _top_extending(tmp_path, base, name="top.yaml"):
    top = tmp_path / "ops" / name
    top.parent.mkdir(parents=True, exist_ok=True)
    top.write_text(f"extends: {base}\nproject_name: op\n", encoding="utf-8")
    return top


def test_a_base_nested_too_deep_is_refused_as_a_chain_error_naming_the_base(tmp_path):
    """The base is named and the file that extends it, which parses, is not."""
    _nested_past_the_recursion_limit(tmp_path / "ops" / "deep.json")
    top = _top_extending(tmp_path, "deep.json")

    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config_document(top)

    message = str(refused.value)
    assert message.endswith(f"deep.json {_REASON}"), message
    assert "top.yaml" not in message, message


def test_a_base_nested_too_deep_below_another_base_names_the_failing_one(tmp_path):
    """The innermost base is the one named; the files above it pass the chain
    error on, and nothing wraps it in 'Could not resolve'."""
    _nested_past_the_recursion_limit(tmp_path / "ops" / "deep.json")
    _top_extending(tmp_path, "deep.json", name="mid.yaml")
    top = _top_extending(tmp_path, "mid.yaml")

    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config_document(top)

    message = str(refused.value)
    assert message.endswith(f"deep.json {_REASON}"), message
    assert "mid.yaml" not in message, message
    assert "top.yaml" not in message, message
    assert "Could not resolve" not in message, message


def test_a_base_the_environment_chose_is_nested_too_deep_without_naming_the_file(
    tmp_path, monkeypatch
):
    """A base named through an environment reference is ``<value>`` in every
    message about it, so the refusal does not carry the base's path, and it is
    not the generic reason for a chain that depends on the environment, which
    describes a file that is missing, unreadable or outside the root."""
    _nested_past_the_recursion_limit(tmp_path / "ops" / "deep.json")
    monkeypatch.setenv("ASH_NESTED_BASE_CHOSEN_BY_THE_ENVIRONMENT", "deep.json")
    top = _top_extending(tmp_path, "${ASH_NESTED_BASE_CHOSEN_BY_THE_ENVIRONMENT}")

    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config_document(top)

    message = str(refused.value)
    assert message.startswith("Base config <value>, extended by "), message
    assert "deep.json" not in message, message
    assert "is missing, cannot be read" not in message, message


def test_check_config_file_reports_a_base_nested_too_deep_as_an_error(tmp_path):
    _nested_past_the_recursion_limit(tmp_path / "ops" / "deep.json")
    top = _top_extending(tmp_path, "deep.json")

    check = ConfigValidator.check_config_file(top)

    errors = [error for error in check.errors if _REASON in error]
    assert len(errors) == 1, check.errors
    assert errors[0].startswith(ConfigValidator.EXTENDS_ERROR_PREFIX), errors
    assert check.scan_accepts is False


def test_lint_reports_a_base_nested_too_deep_as_an_issue_that_blocks_the_scan(
    tmp_path,
):
    _nested_past_the_recursion_limit(tmp_path / "ops" / "deep.json")
    top = _top_extending(tmp_path, "deep.json")

    result = ConfigLinter.lint(top)

    blocking = [
        issue
        for issue in result.issues
        if issue.blocks_scan and _REASON in issue.message
    ]
    assert len(blocking) == 1, [str(issue) for issue in result.issues]


def test_config_validate_prints_a_base_nested_too_deep_and_exits_nonzero(tmp_path):
    _nested_past_the_recursion_limit(tmp_path / "ops" / "deep.json")
    top = _top_extending(tmp_path, "deep.json")

    result = CliRunner().invoke(app, ["config", "validate", "--config", str(top)])

    assert not isinstance(result.exception, RecursionError), result.exception
    assert result.exit_code != 0, result.output
    assert re.sub(r"\s+", "", _REASON) in re.sub(r"\s+", "", result.output), (
        result.output
    )


def test_mcp_validate_reports_a_base_nested_too_deep_as_an_extends_error(tmp_path):
    _nested_past_the_recursion_limit(tmp_path / "ops" / "deep.json")
    top = _top_extending(tmp_path, "deep.json")

    result = mcp_validate_config(config_path=str(top))

    assert result["valid"] is False, result
    problems = [item for item in result["errors"] if _REASON in item["message"]]
    assert len(problems) == 1, result
    assert problems[0]["type"] == "extends_error", problems
