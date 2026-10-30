# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan --workspace ... --dry-run`` refuses the command lines the real run
refuses, with the run's code and text.

The dry run exited 0, its plan printed, for an invalid --format, an --output-dir
that is a file and --use-existing with no results to use: each is refused by the
real run only after the workspace block, which the dry run never reached. A dry
run that exits 0 tells the operator the command line is good; the run then
refused it.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _here(tmp_path, monkeypatch):
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_CONFIG", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)


def _workspace(root) -> str:
    (root / "api").mkdir(parents=True)
    workspace = root / "dev.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    return str(workspace)


def _dry_run(workspace: str, *options: str):
    return CliRunner().invoke(
        app, ["scan", "--workspace", workspace, "--dry-run", *options]
    )


def _real_run_code(workspace: str, *options: str) -> int:
    """The exit code of the same command without --dry-run, its scan replaced."""
    with patch("automated_security_helper.cli.scan.run_ash_scan"):
        return CliRunner().invoke(app, ["scan", "--workspace", workspace, *options])


def test_a_plain_dry_run_still_prints_its_plan(tmp_path):
    result = _dry_run(_workspace(tmp_path / "ws"))

    assert result.exit_code == 0, result.output


def test_an_invalid_format_is_refused_as_the_run_refuses_it(tmp_path):
    workspace = _workspace(tmp_path / "ws")

    result = _dry_run(workspace, "--format", "bogus")

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "'bogus' is not a valid format" in result.output, result.output
    assert _real_run_code(workspace, "--format", "bogus").exit_code == result.exit_code


def test_an_output_dir_that_is_a_file_is_refused_as_the_run_refuses_it(tmp_path):
    workspace = _workspace(tmp_path / "ws")
    a_file = tmp_path / "a-file"
    a_file.write_text("x\n", encoding="utf-8")

    result = _dry_run(workspace, "--output-dir", str(a_file))

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "Output directory is not a directory" in result.output, result.output
    assert (
        _real_run_code(workspace, "--output-dir", str(a_file)).exit_code
        == result.exit_code
    )


def test_an_output_dir_the_scan_would_clear_is_refused_as_the_run_refuses_it(tmp_path):
    """The preflight runs before the plan is printed, in the run's order: the output
    directory inside the workspace root whose reports/ holds the tree's own files."""
    workspace = _workspace(tmp_path / "ws")
    docs = tmp_path / "ws" / "docs"
    (docs / "reports").mkdir(parents=True)
    (docs / "reports" / "index.md").write_text("# docs\n", encoding="utf-8")

    result = _dry_run(workspace, "--output-dir", str(docs))

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "already holds files that are not ASH's" in result.output, result.output
    assert (
        _real_run_code(workspace, "--output-dir", str(docs)).exit_code
        == result.exit_code
    )


def test_use_existing_with_no_results_is_refused_as_the_run_refuses_it(tmp_path):
    workspace = _workspace(tmp_path / "ws")

    result = _dry_run(workspace, "--use-existing")

    assert result.exit_code == 1, result.output
    assert "--use-existing was given" in result.output, result.output
    assert _real_run_code(workspace, "--use-existing").exit_code == result.exit_code
