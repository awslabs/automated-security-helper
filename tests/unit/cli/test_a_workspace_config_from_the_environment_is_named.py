# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan refused for a workspace policy names the source the policy came from.

``--workspace-config`` is also read from ASH_WORKSPACE_CONFIG. Outside workspace
mode the refusal named the flag alone, so an operator with the variable exported
was told every scan carried a flag the command line did not; named both at once,
it told the operator who passed the flag to look for a variable that was not set.
click records where the value came from, and the refusal names that source only.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit


def _refusal(tmp_path, arguments: list[str]) -> str:
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    with patch("automated_security_helper.cli.scan.run_ash_scan") as mock_run:
        result = CliRunner().invoke(
            app,
            ["scan", "--source-dir", str(source), "--output-dir", str(tmp_path / "o")]
            + arguments,
        )
    assert result.exit_code != 0, result.output
    mock_run.assert_not_called()
    return result.stderr


def test_the_refusal_names_the_environment_variable(tmp_path, monkeypatch):
    policy = tmp_path / "ash-workspace.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("ASH_WORKSPACE_CONFIG", str(policy))

    refusal = _refusal(tmp_path, [])

    assert "ASH_WORKSPACE_CONFIG" in refusal, refusal
    assert "--workspace-config" not in refusal, refusal


def test_the_refusal_names_the_flag_when_the_flag_was_passed(tmp_path, monkeypatch):
    policy = tmp_path / "ash-workspace.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    monkeypatch.delenv("ASH_WORKSPACE_CONFIG", raising=False)

    refusal = _refusal(tmp_path, ["--workspace-config", str(policy)])

    assert "--workspace-config" in refusal, refusal
    assert "ASH_WORKSPACE_CONFIG" not in refusal, refusal
