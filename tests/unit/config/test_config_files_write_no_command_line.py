# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No line of a config file ASH writes, or of the config it prints, is a CI
workflow command.

A config value can come from the repository: the project name ``ash config init``
takes from the directory, a value a file already holds. A CI runner reads a line
of its log that starts, after its indentation, with ``::`` (GitHub Actions) or
``##`` (Azure Pipelines' ``##[`` and ``##vso[``, TeamCity's ``##teamcity[``) as a
command, and a config file is printed to a CI log like any other. Each writer
below goes through config_writer's dumpers (``IndentableYamlDumper`` and
``_AsWrittenYamlDumper``): ``ash config update``, ``init``, ``wizard``, ``lint
--fix``, ``AshConfig.save`` and ``ash config get``. Each cell writes a value
holding a command after a line break, checks that no line of what was written
starts with one, and reads the value back as a scan reads it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.ash_config import AshConfig, load_yaml_config
from automated_security_helper.config.config_linter import ConfigLinter
from automated_security_helper.config.config_writer import (
    IndentableYamlDumper,
    _AsWrittenYamlDumper,
    _as_reference,
)
from automated_security_helper.core.constants import ASH_DEFAULT_CONFIG_FILE_NAME

#: Values a config can hold, each with a line that is a CI command unless the
#: writer writes it on one line.
VALUES = {
    "newline-add-mask": "x\n::add-mask::secret-a",
    "newline-vso": "x\n##vso[task.setvariable variable=x]secret-b",
    "folded-after-an-escape": "A" * 68 + "\n::add-mask::secret-c",
}

CASES = [pytest.param(value, id=name) for name, value in VALUES.items()]

#: The values short enough that ``ash config get`` prints them uncropped.
SHORT_CASES = [
    pytest.param(value, id=name)
    for name, value in VALUES.items()
    if not name.startswith("folded")
]


def _command_lines(text: str) -> List[str]:
    return [
        line for line in text.splitlines() if line.lstrip().startswith(("::", "##"))
    ]


def _read(text: str) -> Dict[str, Any]:
    """What a scan reads from ``text``."""
    return load_yaml_config(text) or {}


def _config_file(tmp_path: Path, project_name: str, rest: str = "") -> Path:
    """A config file holding ``project_name`` on one line, as JSON quotes it."""
    path = tmp_path / ".ash" / ".ash.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"project_name: {json.dumps(project_name)}\n{rest}", "utf-8")
    assert _command_lines(path.read_text(encoding="utf-8")) == []
    return path


def _cli(*args: str, answers: str | None = None) -> str:
    result = CliRunner().invoke(app, list(args), input=answers)
    assert result.exit_code == 0, result.output
    return result.stdout


def _assert_written_without_a_command(text: str) -> None:
    assert _command_lines(text) == [], _command_lines(text)


@pytest.mark.parametrize("value", CASES)
def test_config_update(tmp_path, value):
    path = _config_file(tmp_path, value)

    _cli("config", "update", str(path), "--set", "fail_on_findings=false")

    written = path.read_text(encoding="utf-8")
    _assert_written_without_a_command(written)
    assert _read(written)["project_name"] == value
    assert _read(written)["fail_on_findings"] is False


@pytest.mark.parametrize("value", CASES)
def test_config_init(tmp_path, monkeypatch, value):
    project = tmp_path / value
    project.mkdir()
    monkeypatch.chdir(project)

    _cli("config", "init")

    written = (project / ASH_DEFAULT_CONFIG_FILE_NAME).read_text(encoding="utf-8")
    _assert_written_without_a_command(written)
    assert _read(written)["project_name"] == value


@pytest.mark.parametrize("value", CASES)
def test_config_wizard(tmp_path, value):
    """Driven with every prompt answered by its default."""
    path = _config_file(tmp_path, value)

    _cli("config", "wizard", "--config", str(path), answers="\n" * 400)

    written = path.read_text(encoding="utf-8")
    _assert_written_without_a_command(written)
    assert _read(written)["project_name"] == value


#: A suppression whose reason spans two lines, which the fix collapses, so the
#: file is written back.
_FIXABLE = (
    "global_settings:\n"
    "  suppressions:\n"
    "  - rule_id: R1\n"
    "    path: a.py\n"
    '    reason: "line one\\nline two"\n'
)


@pytest.mark.parametrize("value", CASES)
def test_config_lint_fix(tmp_path, value):
    path = _config_file(tmp_path, value, _FIXABLE)

    _cli("config", "lint", "--config", str(path), "--fix", "--non-interactive")

    written = path.read_text(encoding="utf-8")
    _assert_written_without_a_command(written)
    reread = _read(written)
    assert reread["project_name"] == value
    assert "\n" not in reread["global_settings"]["suppressions"][0]["reason"]


@pytest.mark.parametrize("value", CASES)
def test_config_lint_fix_content(tmp_path, value):
    """The fixed content ``ConfigLinter.fix`` returns, as ``--fix`` writes it."""
    path = _config_file(tmp_path, value, _FIXABLE)

    fixed, fixed_issues = ConfigLinter.fix(path)

    assert fixed_issues, "control: the fix found the multi-line reason"
    _assert_written_without_a_command(fixed)
    assert _read(fixed)["project_name"] == value


@pytest.mark.parametrize("as_written", [False, True])
@pytest.mark.parametrize("value", CASES)
def test_ash_config_save(tmp_path, value, as_written):
    path = tmp_path / "saved.yaml"

    AshConfig(project_name=value).save(path, as_written=as_written)

    written = path.read_text(encoding="utf-8")
    _assert_written_without_a_command(written)
    assert _read(written)["project_name"] == value


@pytest.mark.parametrize("value", SHORT_CASES)
def test_config_get(tmp_path, value):
    """The config ``ash config get`` prints, into a pipe. A long value is left
    out: get crops each line at the console width."""
    path = _config_file(tmp_path, value)

    printed = _cli("config", "get", "--no-color", str(path))

    _assert_written_without_a_command(printed)
    assert _read(printed)["project_name"] == value


# ---------------------------------------------------------------------------
# The two config dumpers
# ---------------------------------------------------------------------------

DUMPERS = [
    pytest.param(IndentableYamlDumper, id="IndentableYamlDumper"),
    pytest.param(_AsWrittenYamlDumper, id="_AsWrittenYamlDumper"),
]

#: One command of each form a runner reads.
FORMS = [
    "::add-mask::secret",
    "##[group]x",
    "##vso[task.setvariable variable=x]y",
    "##teamcity[message text='x']",
]

#: Where in a value the command sits: first, after whitespace, or after a
#: character YAML writes as an escape.
PLACES = ["", "a ", "a\t", "x\n", "x\r", "x\a", "x\x85", "${X}\n"]


@pytest.mark.parametrize("dumper", DUMPERS)
@pytest.mark.parametrize("form", FORMS)
def test_a_dumper_writes_no_command_line_and_reads_back(dumper, form):
    for place in PLACES:
        for length in (0, 40, 68, 75, 120):
            value = "A" * length + place + form + " and more"
            for data in ({"name": value}, {value: "x"}, [value], {"a": {"b": [value]}}):
                text = yaml.dump(
                    data, Dumper=dumper, default_flow_style=False, sort_keys=False
                )
                assert _command_lines(text) == [], text
                assert yaml.safe_load(text) == data, text


def test_the_as_written_dumper_keeps_its_own_representers():
    """A tagged reference is tagged and a plain one plain; a reference text with
    no command keeps its quoting, and one holding a command is double-quoted
    and is text, read as no reference."""
    shown = {
        "text": "${ASH_CANARY}",
        "tagged": _as_reference("!ENV ${ASH_CANARY}"),
        "plain": _as_reference("${ASH_CANARY}"),
        "text-with-a-command": "${ASH_CANARY}\n::add-mask::x",
    }
    text = yaml.dump(
        shown, Dumper=_AsWrittenYamlDumper, default_flow_style=False, sort_keys=False
    )

    assert text.splitlines() == [
        "text: '${ASH_CANARY}'",
        "tagged: !ENV '${ASH_CANARY}'",
        "plain: ${ASH_CANARY}",
        'text-with-a-command: "${ASH_CANARY}\\n::add-mask::x"',
    ]
