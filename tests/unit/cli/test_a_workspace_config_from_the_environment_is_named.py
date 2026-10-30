# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan refused for a workspace policy read from the environment says so.

``--workspace-config`` is also read from ASH_WORKSPACE_CONFIG. Outside workspace
mode the refusal named the flag alone, so an operator with the variable exported
was told every scan carried a flag the command line did not.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit


def test_the_refusal_names_the_environment_variable(tmp_path, monkeypatch):
    source = tmp_path / "src"
    source.mkdir()
    policy = tmp_path / "ash-workspace.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("ASH_WORKSPACE_CONFIG", str(policy))

    with patch("automated_security_helper.cli.scan.run_ash_scan") as mock_run:
        result = CliRunner().invoke(
            app,
            ["scan", "--source-dir", str(source), "--output-dir", str(tmp_path / "o")],
        )

    assert result.exit_code != 0, result.output
    assert "--workspace-config" in result.stderr, result.stderr
    assert "ASH_WORKSPACE_CONFIG" in result.stderr, result.stderr
    mock_run.assert_not_called()
