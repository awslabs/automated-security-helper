# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``--cli-json-input`` value is read in place of the parameter's environment
variable, whatever that variable holds.

The documented precedence puts the document above the environment. click ranks
the environment above ``default_map`` and converts a value as it consumes it,
so a variable the parameter's type refused was a usage error before the
document's value was ever read, even though the document had set the
parameter. The environment is not read for a parameter the document sets, and
it is read again, as before, once the command has parsed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from automated_security_helper.cli.json_input import CliJsonInputCommand

pytestmark = pytest.mark.unit

VARIABLE = "ASH_TEST_DOCUMENT_COUNT"


def _app(captured: dict) -> typer.Typer:
    demo = typer.Typer()

    @demo.command(cls=CliJsonInputCommand)
    def run(count: int = typer.Option(7, "--count", envvar=VARIABLE)):
        captured.update(count=count)

    @demo.command()
    def other():  # a second command, so `run` is addressed by name
        pass

    return demo


def _document(tmp_path: Path, payload: dict) -> str:
    path = tmp_path / "params.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_the_document_is_read_when_the_environment_holds_a_refused_value(tmp_path):
    captured: dict = {}
    result = CliRunner().invoke(
        _app(captured),
        ["run", "--cli-json-input", _document(tmp_path, {"count": 3})],
        env={VARIABLE: "nine"},
    )

    assert result.exit_code == 0, result.output
    assert captured == {"count": 3}


def test_the_environment_is_still_refused_when_the_document_omits_the_key(tmp_path):
    captured: dict = {}
    result = CliRunner().invoke(
        _app(captured),
        ["run", "--cli-json-input", _document(tmp_path, {})],
        env={VARIABLE: "nine"},
    )

    assert result.exit_code == 2, result.output
    assert captured == {}


def test_the_environment_variable_is_read_again_after_a_document_set_the_key(
    tmp_path,
):
    """The command's parameter objects outlive one invocation: the variable
    suspended for a parse the document set must be back for the next one."""
    captured: dict = {}
    demo = _app(captured)
    first = CliRunner().invoke(
        demo,
        ["run", "--cli-json-input", _document(tmp_path, {"count": 3})],
        env={VARIABLE: "5"},
    )
    assert first.exit_code == 0, first.output
    assert captured == {"count": 3}

    second = CliRunner().invoke(demo, ["run"], env={VARIABLE: "5"})
    assert second.exit_code == 0, second.output
    assert captured == {"count": 5}
