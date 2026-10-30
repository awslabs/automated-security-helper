# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--cli-json-input`` refuses a JSON number where its type cannot read one.

click reads a boolean from text (``"yes"``, ``"1"``), so a JSON number for a
true/false parameter reached its text handling and raised an AttributeError:
an internal error with a traceback, not a refusal naming the key. click's
integer type is ``int(value)``, which truncates a float, so ``"shard_index":
1.9`` ran shard 1 and ``1e2`` shard 100. Both are refused as the other
structural checks are: usage error, the key named.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from automated_security_helper.cli.json_input import CliJsonInputCommand

pytestmark = pytest.mark.unit

_PANEL_BORDER = str.maketrans("", "", "│╭╮╰╯─")


def _flat(output: str) -> str:
    return "".join(output.translate(_PANEL_BORDER).split())


def _app(captured: dict) -> typer.Typer:
    demo = typer.Typer()

    @demo.command(cls=CliJsonInputCommand)
    def run(
        verbose: bool = typer.Option(False, "--verbose"),
        shard_index: int = typer.Option(0, "--shard-index"),
        ratio: float = typer.Option(0.5, "--ratio"),
    ):
        captured.update(verbose=verbose, shard_index=shard_index, ratio=ratio)

    @demo.command()
    def other():  # a second command, so `run` is addressed by name
        pass

    return demo


def _invoke(tmp_path: Path, payload: dict):
    document = tmp_path / "params.json"
    document.write_text(json.dumps(payload), encoding="utf-8")
    captured: dict = {}
    result = CliRunner().invoke(
        _app(captured), ["run", "--cli-json-input", str(document)]
    )
    return result, captured


@pytest.mark.parametrize("number", [2, 1, 0, 1.0], ids=["two", "one", "zero", "float"])
def test_a_number_for_a_boolean_parameter_is_refused_naming_the_key(tmp_path, number):
    result, captured = _invoke(tmp_path, {"verbose": number})

    assert result.exit_code == 2, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit), (
        result.exception
    )
    assert captured == {}
    flat = _flat(result.output)
    assert "'verbose'" in flat
    assert "boolean" in flat


def test_a_json_boolean_for_a_boolean_parameter_is_accepted(tmp_path):
    result, captured = _invoke(tmp_path, {"verbose": True})

    assert result.exit_code == 0, result.output
    assert captured == {"verbose": True, "shard_index": 0, "ratio": 0.5}


def test_an_infinite_number_for_a_float_parameter_is_refused(tmp_path):
    """json reads 1e400 as infinity and click's float type accepted it; argv
    has no spelling for it, so it is refused naming the key."""
    document = tmp_path / "params.json"
    document.write_text('{"ratio": 1e400}', encoding="utf-8")
    captured: dict = {}

    result = CliRunner().invoke(
        _app(captured), ["run", "--cli-json-input", str(document)]
    )

    assert result.exit_code == 2, result.output
    assert captured == {}
    flat = _flat(result.output)
    assert "'ratio'" in flat
    assert "toolarge" in flat


def test_an_integer_too_large_for_a_float_parameter_is_refused(tmp_path):
    """float(10**400) raises OverflowError past click's own check; it is the
    one shape that reaches the OverflowError arm, and is refused the same way."""
    document = tmp_path / "params.json"
    document.write_text('{"ratio": ' + "1" + "0" * 400 + "}", encoding="utf-8")
    captured: dict = {}

    result = CliRunner().invoke(
        _app(captured), ["run", "--cli-json-input", str(document)]
    )

    assert result.exit_code == 2, result.output
    assert captured == {}
    flat = _flat(result.output)
    assert "'ratio'" in flat
    assert "toolarge" in flat
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "number", [1.9, 2.0, 1e2], ids=["fraction", "whole", "exponent"]
)
def test_a_non_integral_number_for_an_integer_parameter_is_refused(tmp_path, number):
    result, captured = _invoke(tmp_path, {"shard_index": number})

    assert result.exit_code == 2, result.output
    assert captured == {}
    flat = _flat(result.output)
    assert "'shard_index'" in flat
    assert "integer" in flat


def test_an_integer_and_an_integer_string_are_still_accepted(tmp_path):
    result, captured = _invoke(tmp_path, {"shard_index": 2})
    assert result.exit_code == 0, result.output
    assert captured["shard_index"] == 2

    # click converts a string as it converts a flag's text; nothing here stops it.
    result, captured = _invoke(tmp_path, {"shard_index": "3"})
    assert result.exit_code == 0, result.output
    assert captured["shard_index"] == 3
