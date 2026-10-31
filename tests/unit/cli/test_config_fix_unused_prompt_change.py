# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--fix-unused`` writes only the entries the operator was shown.

Why this file exists
--------------------
The text to write is computed again after the confirmation prompt, so an edit
made while the prompt waited is not written over. But the entries shown at the
prompt were those of the first computation, and a file that changed meanwhile
could now comment out others, which the operator never approved. The command
now compares the two lists and writes nothing, exit 1, when they differ.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.config import config_app
from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintIssue,
    LintSeverity,
)

pytestmark = pytest.mark.unit

BEFORE = "project_name: before\n"


def _commented(index: int) -> LintIssue:
    return LintIssue(
        severity=LintSeverity.INFO,
        category=LintCategory.SUPPRESSION_UNUSED,
        message=f"Commented out unused suppression: path='src/{index}.py'",
        path=f"global_settings.suppressions[{index}]",
        fixable=True,
    )


def _run(tmp_path: Path, monkeypatch, shown, written):
    config = tmp_path / ".ashrc.yaml"
    config.write_text(BEFORE, encoding="utf-8")
    monkeypatch.setattr(
        ConfigLinter,
        "get_unused_report_age",
        staticmethod(lambda *_a, **_k: (tmp_path / "r.json", datetime.now(), 0.0)),
    )
    answers = iter([("project_name: first\n", shown, None), written])
    monkeypatch.setattr(
        ConfigLinter,
        "fix_unused_suppressions",
        staticmethod(lambda *_a, **_k: next(answers)),
    )
    result = CliRunner().invoke(
        config_app, ["lint", "--config", str(config), "--fix-unused"], input="y\n"
    )
    return config, result


def test_a_list_that_changed_during_the_prompt_is_not_written(tmp_path, monkeypatch):
    """Red at the base: the second computation was written without a look at
    whether it named the entries the prompt showed."""
    config, result = _run(
        tmp_path,
        monkeypatch,
        shown=[_commented(0)],
        written=("project_name: second\n", [_commented(0), _commented(1)], None),
    )

    assert result.exit_code == 1, result.output
    assert "changed while the prompt was open" in result.output
    assert config.read_text(encoding="utf-8") == BEFORE


def test_the_same_list_after_the_prompt_is_written(tmp_path, monkeypatch):
    """The positive control: the text computed after the prompt is the one
    written when it names the entries that were shown."""
    config, result = _run(
        tmp_path,
        monkeypatch,
        shown=[_commented(0)],
        written=("project_name: second\n", [_commented(0)], None),
    )

    assert result.exit_code == 0, result.output
    assert config.read_text(encoding="utf-8") == "project_name: second\n"
