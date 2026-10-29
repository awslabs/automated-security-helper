# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config path that names no readable file is a configuration error: exit 3.

Why this exists
---------------
``ash config validate --config typo.yaml`` exited 1, the code these commands also
give when the directory has no config file, so a script could not tell a mistyped
path from a project without a config. It was then made a usage error, exit 5. Since
then, a config path that names nothing is a problem with the
configuration the command was given, not with the command line, so it exits 3
(``INVALID_CONFIG_EXIT_CODE``), the code for a configuration ASH cannot use. That
holds for a missing file, a directory, and a file that cannot be read, named by
``--config``, by ``ASH_CONFIG``, or by the path argument ``get``, ``update`` and
``validate-plugin-dependencies`` take. Exit 5 stays for unknown options and
unknown selections.

What the tests check
--------------------
Each subcommand that reads a named config exits 3 for each of those, and a
missing file is named in one line ("Config file not found: <path>"). The control
is the state case: ``validate``, ``lint`` and ``update`` in a directory with no
config file, given no path, exit 1.

"Cannot be read" is a socket file, which no user can open (``open`` fails with
ENXIO), and a file that is not UTF-8. A file with no read permission would not do
on its own: root reads it anyway, and skipping the case for root would hide it.
"""

from __future__ import annotations

import socket

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

INVALID_CONFIG = 3
MISSING = "no-such-config.yaml"

#: Every way a subcommand names its config file. ``{path}`` is the path.
INVOCATIONS = [
    ["validate", "--config", "{path}"],
    ["lint", "--config", "{path}"],
    ["get", "--config", "{path}"],
    ["get", "{path}"],
    ["update", "--config", "{path}", "--set", "fail_on_findings=false"],
    ["update", "{path}", "--set", "fail_on_findings=false"],
    ["validate-plugin-dependencies", "--config", "{path}"],
    ["validate-plugin-dependencies", "{path}"],
]
IDS = [" ".join(a for a in args if a != "{path}") for args in INVOCATIONS]


@pytest.fixture(autouse=True)
def _in_an_empty_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _invoke(*args: str, env: dict | None = None):
    return CliRunner().invoke(
        app, ["config", *args], env={"COLUMNS": "300", **(env or {})}
    )


def _with(args: list, path: str) -> list:
    return [a.replace("{path}", path) for a in args]


def _a_directory(tmp_path) -> str:
    (tmp_path / "config-dir.yaml").mkdir()
    return "config-dir.yaml"


def _a_socket(tmp_path) -> str:
    # Bound by a relative name, from the test's own directory, so the path stays
    # within AF_UNIX's length limit wherever the temporary directory is.
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind("sock.yaml")
    finally:
        server.close()
    assert (tmp_path / "sock.yaml").exists()
    return "sock.yaml"


def _not_utf8(tmp_path) -> str:
    (tmp_path / "latin1.yaml").write_bytes(b"project_name: caf\xe9\n")
    return "latin1.yaml"


@pytest.mark.parametrize("args", INVOCATIONS, ids=IDS)
def test_a_named_config_that_does_not_exist_exits_3(args):
    result = _invoke(*_with(args, MISSING))

    assert result.exit_code == INVALID_CONFIG, result.output
    assert f"Config file not found: {MISSING}" in result.output, result.output


@pytest.mark.parametrize("command", ["validate", "lint", "get"])
def test_ash_config_naming_a_missing_file_exits_3(command):
    result = _invoke(command, env={"ASH_CONFIG": MISSING})

    assert result.exit_code == INVALID_CONFIG, result.output
    assert MISSING in result.output, result.output


@pytest.mark.parametrize(
    "make",
    [_a_directory, _a_socket, _not_utf8],
    ids=["directory", "unreadable", "not-utf8"],
)
@pytest.mark.parametrize("args", INVOCATIONS, ids=IDS)
def test_a_named_config_that_cannot_be_read_exits_3(tmp_path, args, make):
    path = make(tmp_path)

    result = _invoke(*_with(args, path))

    assert result.exit_code == INVALID_CONFIG, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit), (
        result.exception
    )


@pytest.mark.parametrize("command", ["validate", "lint"])
def test_control_no_config_in_the_directory_is_exit_1(command):
    """No path was given, so no configuration was named: the directory has none."""
    result = _invoke(command)

    assert result.exit_code == 1, result.output
    assert "No config file found" in result.output, result.output


def test_update_without_a_config_in_the_directory_is_exit_1():
    result = _invoke("update", "--set", "fail_on_findings=false")

    assert result.exit_code == 1, result.output
