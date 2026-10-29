# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file that cannot be read is described as unread, never as unparsed.

``ash config validate`` and ``ash config lint`` refuse a file the command may
not read with exit 3, as a scan does, but described it as a parse failure:
validate's header read "The file does not parse: Could not read the config
file", and lint's issue "Failed to parse config file: PermissionError". A
reader sent to fix the file's syntax finds nothing wrong with it; the problem
is the read. Each description now says read for a read failure, and keeps
parse for a file that was read and did not parse.
"""

from __future__ import annotations

import os

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
        reason="needs POSIX permission bits, which root reads past",
    ),
]


@pytest.fixture
def unreadable(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NO_COLOR", "1")
    config = tmp_path / "unreadable.yaml"
    config.write_text("project_name: t\n", encoding="utf-8")
    config.chmod(0)
    yield config
    config.chmod(0o600)


def _no_parse_claim(output: str) -> None:
    lowered = output.lower()
    assert "parse" not in lowered, output
    assert "read" in lowered, output


@pytest.mark.parametrize("command", ["validate", "lint", "get"])
def test_the_check_commands_say_read(unreadable, command):
    result = CliRunner().invoke(app, ["config", command, "--config", str(unreadable)])

    assert result.exit_code == 3, result.output
    _no_parse_claim(result.output)


def test_lint_s_issue_says_read(unreadable):
    from automated_security_helper.config.config_linter import ConfigLinter

    result = ConfigLinter.lint(unreadable)

    messages = [issue.message for issue in result.issues]
    assert messages, result
    for message in messages:
        assert "parse" not in message.lower(), message
    assert any("read" in message.lower() for message in messages), messages
