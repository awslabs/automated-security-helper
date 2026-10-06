# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the ``ashx config`` subcommands print, and exit with, for a bad config file.

Three kinds of bad file, each given to every subcommand that reads one: a path that
does not exist, a file that is not YAML, and YAML that does not satisfy the schema.
The schema-invalid file breaks two rules at once so the snapshot shows how a list of
errors is laid out, not only how one is.
"""

from __future__ import annotations

from pathlib import Path

import pytest

NOT_YAML = "project_name: snapshot\nscanners: [bandit\n"

# Two violations: a field of the wrong type, and an internal-only field that a user
# config must not set.
SCHEMA_INVALID = """\
project_name: snapshot
fail_on_findings: sometimes
scanners:
  bandit:
    enabled: true
    tool_version: "1.0"
"""


def _config(root: Path, text: str) -> str:
    path = root / "ash.yaml"
    path.write_text(text, encoding="utf-8")
    return path.name


# Each subcommand, and how it is told which file to read.
COMMANDS = {
    "get": lambda path: ["config", "get", path],
    "lint": lambda path: ["config", "lint", "--config", path],
    "validate": lambda path: ["config", "validate", "--config", path],
    "update": lambda path: [
        "config",
        "update",
        path,
        "--set",
        "fail_on_findings=false",
    ],
    "validate-plugin-dependencies": lambda path: [
        "config",
        "validate-plugin-dependencies",
        path,
    ],
}


@pytest.mark.parametrize("command", sorted(COMMANDS))
def test_missing_file(run_cli, snapshot, command):
    assert run_cli(COMMANDS[command]("missing.yaml")) == snapshot


@pytest.mark.parametrize("command", sorted(COMMANDS))
def test_not_yaml(run_cli, snapshot, in_tmp, command):
    assert run_cli(COMMANDS[command](_config(in_tmp, NOT_YAML))) == snapshot


@pytest.mark.parametrize("command", sorted(COMMANDS))
def test_schema_invalid(run_cli, snapshot, in_tmp, command):
    assert run_cli(COMMANDS[command](_config(in_tmp, SCHEMA_INVALID))) == snapshot


def test_update_finds_no_config(run_cli, snapshot):
    """``update`` with no path searches the working directory and finds nothing.

    ``lint`` and ``validate`` have a default too, ``.ash/.ash.yaml``, but they quote
    it as a native path, which reads ``.ash\\.ash.yaml`` on Windows; their missing-file
    wording is covered above with a path that has no separator.
    """
    assert run_cli(["config", "update", "--set", "fail_on_findings=false"]) == snapshot


def test_init_refuses_to_overwrite(run_cli, snapshot, in_tmp):
    (in_tmp / ".ash").mkdir()
    (in_tmp / ".ash" / ".ash.yaml").write_text("project_name: x\n", encoding="utf-8")
    assert run_cli(["config", "init"]) == snapshot


def test_update_to_an_invalid_value(run_cli, snapshot, in_tmp):
    path = _config(in_tmp, "project_name: snapshot\n")
    assert (
        run_cli(["config", "update", path, "--set", "fail_on_findings=sometimes"])
        == snapshot
    )
    assert (in_tmp / path).read_text(encoding="utf-8") == "project_name: snapshot\n"
