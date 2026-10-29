# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The lines ``ash config init``, ``update``, ``wizard`` and
``validate-plugin-dependencies`` print about a config's path are one line,
whatever the path holds.

A path is the caller's text, and printed as given, a newline in it would start
the rest of the path on a line of its own. Each such line is shown on one line, the newline
written as ``\\x0a``. A file that cannot be read is named by its name as given,
not by the repr Python's error text quotes it with, so the newline is written
once, as ``\\x0a``, and not as the two characters of ``\\n``.
"""

from __future__ import annotations

import os
import sys

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="Windows file names hold no newline"
    ),
]

VALID = "project_name: t\n"
#: A value the model refuses.
REFUSED = "project_name: t\nfail_on_findings: maybe\n"


@pytest.fixture(autouse=True)
def _here(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    # A console this wide wraps none of these lines, so a line that starts with
    # the path's rest started there because of the newline.
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")


def _assert_one_line(output: str, tail: str) -> None:
    """No line of *output* starts with *tail*, the part after the newline, and
    the newline is written once, as its escape."""
    starts = [line for line in output.splitlines() if line.startswith(tail)]
    assert starts == [], f"the path's rest began a line of its own:\n{output}"
    assert "\\x0a" + tail in output, output
    assert "\\n" + tail not in output, output


def _run(*args: str, **kwargs):
    return CliRunner().invoke(app, list(args), **kwargs)


def _unreadable(path):
    path.write_text(VALID, encoding="utf-8")
    path.chmod(0)
    if os.access(path, os.R_OK):
        pytest.skip("this user reads a file with no permissions (root)")


def test_init_names_the_file_it_saves_on_one_line(tmp_path):
    result = _run("config", "init", "--config", str(tmp_path / "a\nnew.yaml"))

    assert result.exit_code == 0, result.output
    assert "Saving ASH config to path" in result.output, result.output
    _assert_one_line(result.output, "new.yaml")


def test_init_names_a_file_that_exists_on_one_line(tmp_path):
    existing = tmp_path / "a\nexists.yaml"
    existing.write_text(VALID, encoding="utf-8")

    result = _run("config", "init", "--config", str(existing))

    assert result.exit_code == 1, result.output
    assert "already exists" in result.output, result.output
    _assert_one_line(result.output, "exists.yaml")


def test_init_names_a_toml_file_it_refuses_on_one_line(tmp_path):
    result = _run("config", "init", "--config", str(tmp_path / "a\nnew.toml"))

    assert result.exit_code == 1, result.output
    _assert_one_line(result.output, "new.toml")


def test_update_names_the_file_it_updates_on_one_line(tmp_path):
    path = tmp_path / "a\nupdated.yaml"
    path.write_text(VALID, encoding="utf-8")

    result = _run("config", "update", "--config", str(path), "--set", "project_name=u")

    assert result.exit_code == 0, result.output
    assert "Successfully updated" in result.output, result.output
    _assert_one_line(result.output, "updated.yaml")


def test_update_names_an_invalid_file_on_one_line(tmp_path):
    path = tmp_path / "a\ninvalid.yaml"
    path.write_text(REFUSED, encoding="utf-8")

    result = _run("config", "update", "--config", str(path), "--set", "project_name=u")

    assert result.exit_code == 3, result.output
    _assert_one_line(result.output, "invalid.yaml")


def test_update_names_a_file_it_cannot_read_once_on_one_line(tmp_path):
    path = tmp_path / "a\nunreadable.yaml"
    _unreadable(path)

    result = _run("config", "update", "--config", str(path), "--set", "project_name=u")

    assert result.exit_code == 3, result.output
    _assert_one_line(result.output, "unreadable.yaml")


def test_validate_plugin_dependencies_names_a_valid_file_on_one_line(tmp_path):
    path = tmp_path / "a\nvalid.yaml"
    path.write_text(VALID, encoding="utf-8")

    result = _run("config", "validate-plugin-dependencies", "--config", str(path))

    assert result.exit_code == 0, result.output
    assert "is valid" in result.output, result.output
    _assert_one_line(result.output, "valid.yaml")


def test_validate_plugin_dependencies_names_a_file_it_cannot_read_once(tmp_path):
    path = tmp_path / "a\nunreadable.yaml"
    _unreadable(path)

    result = _run("config", "validate-plugin-dependencies", "--config", str(path))

    assert result.exit_code == 3, result.output
    assert "could not be read" in result.output, result.output
    _assert_one_line(result.output, "unreadable.yaml")


def test_the_wizard_names_a_file_it_cannot_edit_on_one_line(tmp_path):
    """Its "Loading existing config from" panel and its refusal of an invalid
    file both name the path."""
    path = tmp_path / "a\ninvalid.yaml"
    path.write_text(REFUSED, encoding="utf-8")

    result = _run("config", "wizard", "--config", str(path))

    assert result.exit_code == 3, result.output
    assert "Loading existing config from" in result.output, result.output
    _assert_one_line(result.output, "invalid.yaml")


def test_the_wizard_names_a_file_it_cannot_read_once_on_one_line(tmp_path):
    path = tmp_path / "a\nunreadable.yaml"
    _unreadable(path)

    result = _run("config", "wizard", "--config", str(path))

    assert result.exit_code == 1, result.output
    _assert_one_line(result.output, "unreadable.yaml")
