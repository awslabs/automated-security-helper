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
from typer.main import get_command
from typer.testing import CliRunner

from automated_security_helper.cli.json_input import CliJsonInputCommand

pytestmark = pytest.mark.unit

VARIABLE = "ASH_TEST_DOCUMENT_COUNT"


def _app(captured: dict, on_count=None) -> typer.Typer:
    demo = typer.Typer()

    @demo.command(cls=CliJsonInputCommand)
    def run(
        count: int = typer.Option(7, "--count", envvar=VARIABLE, callback=on_count),
    ):
        captured.update(count=count)

    @demo.command()
    def other():  # a second command, so `run` is addressed by name
        pass

    return demo


def _one_command(monkeypatch, demo: typer.Typer):
    """The click command every invocation below uses.

    CliRunner builds the command from the Typer app on each call, so two runs
    never met the same parameter objects: what one parse did to them could not
    show in the next. Here the command is built once and handed back each time."""
    command = get_command(demo)
    monkeypatch.setattr("typer.testing._get_command", lambda _app: command)
    return command


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
    tmp_path, monkeypatch
):
    """The command's parameter objects outlive one invocation: the variable
    set aside for a parse the document set must be back for the next one. Both
    runs use the one command object, as a server running many scans in one
    process does."""
    captured: dict = {}
    demo = _app(captured)
    _one_command(monkeypatch, demo)
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


def test_the_environment_variable_is_read_again_after_a_parse_that_failed(
    tmp_path, monkeypatch
):
    """A parse the document set the key for can still end in a usage error (a
    bad value on the command line). The variable must be back for the next run
    then too."""
    captured: dict = {}
    demo = _app(captured)
    _one_command(monkeypatch, demo)
    failed = CliRunner().invoke(
        demo,
        [
            "run",
            "--cli-json-input",
            _document(tmp_path, {"count": 3}),
            "--count",
            "nine",
        ],
        env={VARIABLE: "5"},
    )
    assert failed.exit_code == 2, failed.output
    assert captured == {}

    second = CliRunner().invoke(demo, ["run"], env={VARIABLE: "5"})
    assert second.exit_code == 0, second.output
    assert captured == {"count": 5}


def test_a_key_set_to_null_leaves_the_environment_variable_in_force(tmp_path):
    """The skeleton writes null for a parameter an environment variable backs,
    so an unedited skeleton must not suspend the variable: null is "not
    provided", and the variable's value is read."""
    captured: dict = {}
    result = CliRunner().invoke(
        _app(captured),
        ["run", "--cli-json-input", _document(tmp_path, {"count": None})],
        env={VARIABLE: "5"},
    )

    assert result.exit_code == 0, result.output
    assert captured == {"count": 5}


def test_a_key_set_to_null_does_not_hide_a_refused_environment_value(tmp_path):
    captured: dict = {}
    result = CliRunner().invoke(
        _app(captured),
        ["run", "--cli-json-input", _document(tmp_path, {"count": None})],
        env={VARIABLE: "nine"},
    )

    assert result.exit_code == 2, result.output
    assert captured == {}


def test_the_commands_own_parameter_objects_keep_their_variable_during_a_parse(
    tmp_path, monkeypatch
):
    """The parameter objects belong to the command, which a server shares between
    scans running at once. A parse that set the variable aside by clearing it on
    those objects hid it from every other parse in flight; the variable is set
    aside on this parse's own copy, and the command's parameter keeps it.

    The app registers two commands, so the object built from it is a group;
    the parameter read here is the one on its ``run`` subcommand."""
    seen: list = []
    holder: dict = {}

    def on_count(value: int):
        parameter = next(
            p for p in holder["command"].commands["run"].params if p.name == "count"
        )
        seen.append(parameter.envvar)
        return value

    captured: dict = {}
    demo = _app(captured, on_count=on_count)
    holder["command"] = _one_command(monkeypatch, demo)

    result = CliRunner().invoke(
        demo,
        ["run", "--cli-json-input", _document(tmp_path, {"count": 3})],
        env={VARIABLE: "nine"},
    )

    assert result.exit_code == 0, result.output
    assert captured == {"count": 3}
    assert seen == [VARIABLE]
