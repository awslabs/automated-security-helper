# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash config validate`` says which plugin sections it cannot check, as lint does.

Why this exists
---------------
Neither ``ash config validate`` nor ``ash config lint`` loads the modules named in
``ash_plugin_modules``, so neither knows the options those plugins declare, and a
config both pass can still be refused by a scan (exit 3) for such an option. lint
says so in one INFO issue (``plugin-options-unchecked``). A validate that says
nothing and prints "Configuration is valid! A scan accepts it." would leave that
out, so the sentence lint prints, from ``options_checked_at_scan_note``, is
printed by validate too.

What the tests check
--------------------
A config with a section no built-in plugin reads gets the note naming the section,
whether or not the config is otherwise valid; a config with built-in sections only
gets none.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

NOTE = "are not checked here"


@pytest.fixture(autouse=True)
def _in_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _validate(tmp_path, body: str):
    path = tmp_path / "ash.yaml"
    path.write_text(body, encoding="utf-8")
    return CliRunner().invoke(
        app,
        ["config", "validate", "--config", str(path), "--no-color"],
        env={"COLUMNS": "300"},
    )


def test_a_section_of_a_plugin_module_is_named_as_unchecked(tmp_path):
    result = _validate(
        tmp_path,
        "project_name: demo\n"
        "ash_plugin_modules:\n"
        "  - automated_security_helper.plugin_modules.ash_aws_plugins\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      max_retries: three\n",
    )

    assert result.exit_code == 0, result.output
    assert NOTE in result.output, result.output
    assert "reporters.aws-security-hub" in result.output, result.output


def test_the_note_is_printed_beside_errors(tmp_path):
    result = _validate(
        tmp_path,
        "project_name: demo\n"
        "fail_on_findings: banana\n"
        "scanners:\n"
        "  my-community-scanner:\n"
        "    options:\n"
        "      anything: 1\n",
    )

    assert result.exit_code == 3, result.output
    assert NOTE in result.output, result.output
    assert "scanners.my-community-scanner" in result.output, result.output


def test_control_built_in_sections_only_get_no_note(tmp_path):
    result = _validate(
        tmp_path,
        "project_name: demo\nscanners:\n  bandit:\n    enabled: true\n",
    )

    assert result.exit_code == 0, result.output
    assert NOTE not in result.output, result.output
