# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--cli-json-input`` refuses a JSON number where its type cannot read one.

The boolean type reads text (``"yes"``, ``"1"``), so a JSON number for a
true/false parameter, 0 and 1 included, reached its text handling and raised an
AttributeError: an internal error with a traceback, not a refusal naming the key.
click's integer type is ``int(value)``, which truncates a float, so ``"shard_index":
1.9`` ran shard 1; argv takes only the digits of an integer, so a number with a
fraction or an exponent (``2.0``, ``1e2``) is refused too. Both are refused as
the other structural checks are: usage error, the key named. The constants JSON
leaves to the parser (``Infinity``, ``NaN``) and an integer with more digits than
Python reads are refused as a document that is not valid JSON.
"""

from __future__ import annotations

import json
import sys
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

    @demo.command(cls=CliJsonInputCommand)
    def scale(ratio: float = typer.Option(1.0, "--ratio")):
        captured.update(ratio=ratio)

    @demo.command()
    def other():  # a command that takes no document
        pass

    return demo


def _invoke_text(tmp_path: Path, text: str, command: str = "run"):
    """Run *command* on a document holding exactly *text*, so a number reaches the
    parser as written: ``json.dumps(1e2)`` writes ``100.0``, not ``1e2``."""
    document = tmp_path / "params.json"
    document.write_text(text, encoding="utf-8")
    captured: dict = {}
    result = CliRunner().invoke(
        _app(captured), [command, "--cli-json-input", str(document)]
    )
    return result, captured


def _invoke(tmp_path: Path, payload: dict):
    return _invoke_text(tmp_path, json.dumps(payload))


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


@pytest.mark.parametrize(
    "number",
    ["1.9", "2.0", "1e2", "1E+2", "100.0e-2"],
    ids=["fraction", "whole", "exponent", "upper-exponent", "negative-exponent"],
)
def test_a_number_with_a_fraction_or_exponent_for_an_integer_is_refused(
    tmp_path, number
):
    """Written as the document holds it: ``json.dumps(1e2)`` writes ``100.0``, so a
    document built from a float never carried the exponent to the parser."""
    result, captured = _invoke_text(tmp_path, '{"shard_index": ' + number + "}")

    assert result.exit_code == 2, result.output
    assert captured == {}
    flat = _flat(result.output)
    assert "'shard_index'" in flat
    assert "integer" in flat


@pytest.mark.parametrize("constant", ["Infinity", "-Infinity", "NaN"])
def test_a_constant_json_leaves_to_the_parser_is_refused_as_not_json(
    tmp_path, constant
):
    """Python's parser reads these three words as numbers unless told not to; the
    document is refused as JSON that is not valid, with no traceback."""
    result, captured = _invoke_text(tmp_path, '{"shard_index": ' + constant + "}")

    assert result.exit_code == 2, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert captured == {}
    flat = _flat(result.output)
    assert "notvalidJSON" in flat
    assert f"{constant}isnotaJSONnumber" in flat
    assert "Traceback" not in result.output


def test_an_integer_with_more_digits_than_python_reads_is_refused_as_not_json(
    tmp_path,
):
    """Python 3.10.7 and later refuse to turn a very long digit string into an
    integer, with a ValueError; the document is refused, not a traceback."""
    limit = getattr(sys, "get_int_max_str_digits", lambda: 0)()
    if limit == 0:
        pytest.skip("this interpreter reads an integer of any length")

    result, captured = _invoke_text(tmp_path, '{"shard_index": 1' + "0" * limit + "}")

    assert result.exit_code == 2, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert captured == {}
    assert "notvalidJSON" in _flat(result.output)
    assert "Traceback" not in result.output


def test_an_integer_too_large_for_a_float_parameter_is_refused(tmp_path):
    """The conversion of an integer of more than 308 digits to a float raises
    OverflowError past click's own check; the key is named, as for any bad value."""
    result, captured = _invoke_text(
        tmp_path, '{"ratio": 1' + "0" * 400 + "}", command="scale"
    )

    assert result.exit_code == 2, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert captured == {}
    flat = _flat(result.output)
    assert "'ratio'" in flat
    assert "toolarge" in flat


def test_an_ordinary_number_for_a_float_parameter_is_accepted(tmp_path):
    result, captured = _invoke_text(tmp_path, '{"ratio": 2}', command="scale")

    assert result.exit_code == 0, result.output
    assert captured == {"ratio": 2.0}


def test_an_integer_and_an_integer_string_are_still_accepted(tmp_path):
    result, captured = _invoke(tmp_path, {"shard_index": 2})
    assert result.exit_code == 0, result.output
    assert captured["shard_index"] == 2

    # click converts a string as it converts a flag's text; nothing here stops it.
    result, captured = _invoke(tmp_path, {"shard_index": "3"})
    assert result.exit_code == 0, result.output
    assert captured["shard_index"] == 3
