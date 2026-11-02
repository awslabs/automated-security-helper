# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash config lint --fix --fix-unused`` runs no fixer once ``--fix`` is refused.

``--fix`` refuses to rewrite a file that reads the environment (its references
would be replaced by their values) and exits 1. Given ``--fix-unused`` beside it,
the unused-suppression fixer still ran and rewrote the file the first fixer had
just refused to touch. Once one fixer is refused the remaining ones are not run;
the file is left as it was and the exit is the refusal's.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import config as config_cli

pytestmark = pytest.mark.unit

# An internal field (a fixable warning) in a file that reads the environment.
CONFIG = "project_name: ${PROJECT_NAME}\nscanners:\n  bandit:\n    name: bandit\n"


def test_the_unused_fixer_does_not_run_after_fix_is_refused(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PROJECT_NAME", "demo")
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(CONFIG, encoding="utf-8")
    unused_fixer_calls: list = []
    monkeypatch.setattr(
        config_cli,
        "_apply_unused_fixes",
        lambda *args, **kwargs: unused_fixer_calls.append(args) or False,
    )

    result = CliRunner().invoke(
        config_cli.config_app,
        [
            "lint",
            "--config",
            str(config_path),
            "--fix",
            "--fix-unused",
            "--non-interactive",
        ],
        env={"COLUMNS": "300", "NO_COLOR": "1"},
    )

    assert result.exit_code == 1, result.output
    assert "--fix rewrites the file from its parsed values" in result.output
    assert unused_fixer_calls == [], result.output
    assert config_path.read_text(encoding="utf-8") == CONFIG


def test_control_the_unused_fixer_runs_when_no_fix_is_refused(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text("project_name: demo\n", encoding="utf-8")
    unused_fixer_calls: list = []
    monkeypatch.setattr(
        config_cli,
        "_apply_unused_fixes",
        lambda *args, **kwargs: unused_fixer_calls.append(args) or False,
    )

    result = CliRunner().invoke(
        config_cli.config_app,
        ["lint", "--config", str(config_path), "--fix-unused", "--non-interactive"],
        env={"COLUMNS": "300", "NO_COLOR": "1"},
    )

    assert result.exit_code == 0, result.output
    assert len(unused_fixer_calls) == 1, result.output
