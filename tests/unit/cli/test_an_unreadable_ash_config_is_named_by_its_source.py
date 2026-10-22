# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An unreadable config source is refused with exit 3, named as its source.

``ash report`` and ``ash merge`` resolve the operator's ``--config`` with the
fallback off. Two files can be the unreadable one: the ``--config`` file
itself, which resolve_config re-raises raw for the command's own OSError arm
to name, and the file ASH_CONFIG names, which get_default_config refuses as
that file's own error, already named. Either way the refusal is exit 3 and
names the file that could not be read: a valid ``--config`` file is not
blamed for an unreadable ASH_CONFIG file, and no path ends in a traceback.
"""

from __future__ import annotations

import os

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app


def _skip_unless_permission_bits_hold():
    if os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0):
        pytest.skip("needs POSIX permission bits, which root reads past")


@pytest.fixture
def runner_env(monkeypatch, tmp_path):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _unreadable(tmp_path, name: str):
    _skip_unless_permission_bits_hold()
    config = tmp_path / name
    config.write_text("project_name: t\n", encoding="utf-8")
    config.chmod(0)
    return config


def test_report_names_the_ash_config_file_it_could_not_read(runner_env, monkeypatch):
    """With a readable --config file and an unreadable ASH_CONFIG file, the
    refusal names the file ASH_CONFIG names: the --config file is not the one
    that could not be read, so it is not named at all."""
    operator = _unreadable(runner_env, "operator.yaml")
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    named = runner_env / "ok.yaml"
    named.write_text("project_name: t\n", encoding="utf-8")

    try:
        result = CliRunner().invoke(app, ["report", "--config", str(named)])
    finally:
        operator.chmod(0o600)

    assert result.exit_code == 3, result.output
    assert "could not read" in result.output, result.output
    assert "operator.yaml" in result.output, result.output
    assert "ok.yaml" not in result.output, result.output


def test_report_refuses_an_unreadable_config_file_by_name(runner_env):
    """Control: the --config file itself unreadable is named as given."""
    config = _unreadable(runner_env, "unreadable.yaml")

    try:
        result = CliRunner().invoke(app, ["report", "--config", str(config)])
    finally:
        config.chmod(0o600)

    assert result.exit_code == 3, result.output
    assert "could not read" in result.output, result.output
    assert "unreadable.yaml" in result.output, result.output


def test_merge_refuses_an_unreadable_config_with_exit_3(runner_env):
    """An existing but unreadable --config refuses the merge with exit 3 in
    the words report uses, never a traceback: the file could not be read, so
    there is no syntax to fix and nothing was merged."""
    config = _unreadable(runner_env, "unreadable.yaml")

    try:
        result = CliRunner().invoke(
            app,
            [
                "merge",
                "--results",
                str(runner_env),
                "--output-dir",
                str(runner_env / "merged"),
                "--config",
                str(config),
            ],
        )
    finally:
        config.chmod(0o600)

    assert result.exit_code == 3, result.output
    assert "could not read" in result.output, result.output
    assert "unreadable.yaml" in result.output, result.output
    assert "Traceback" not in result.output, result.output


def test_merge_names_the_ash_config_file_it_could_not_read(runner_env, monkeypatch):
    """As for report: a readable --config file is not blamed for the
    unreadable file ASH_CONFIG names."""
    operator = _unreadable(runner_env, "operator.yaml")
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    named = runner_env / "ok.yaml"
    named.write_text("project_name: t\n", encoding="utf-8")

    try:
        result = CliRunner().invoke(
            app,
            [
                "merge",
                "--results",
                str(runner_env),
                "--output-dir",
                str(runner_env / "merged"),
                "--config",
                str(named),
            ],
        )
    finally:
        operator.chmod(0o600)

    assert result.exit_code == 3, result.output
    assert "could not read" in result.output, result.output
    assert "operator.yaml" in result.output, result.output
    assert "ok.yaml" not in result.output, result.output
    assert "Traceback" not in result.output, result.output
