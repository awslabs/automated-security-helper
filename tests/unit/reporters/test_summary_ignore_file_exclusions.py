# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ignore-file record in every summary built from stored results.

``metadata.ignore_file_exclusions`` says whether the scanned repository's
``.gitignore`` and ``.ignore`` files were honored and how many files they removed
from the scan set. The text and markdown summaries print it; a workspace's merged
results carry the workspace total, and each project's own record rides on its
``workspace.projects[]`` entry; the MCP ``get_scan_summary`` tool returns it.

The whole-scan tests in ``tests/unit/interactions/test_scan_ignore_file_switch.py``
cover a single scan end to end. These cover the renderers on their own (absent,
honored, not honored, compact markdown), the workspace aggregate, a real workspace
scan, and the MCP summary read back from a results file on disk.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Dict
from unittest.mock import AsyncMock, MagicMock

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import IgnoreFileExclusions
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
    MarkdownReporterConfig,
    MarkdownReporterConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)
from automated_security_helper.workspace.aggregation import (
    WorkspaceAggregator,
    workspace_ignore_file_exclusions,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

HONORED = IgnoreFileExclusions(
    honored=True,
    excluded_file_count=7,
    by_ignore_file={".gitignore": 3, ".ignore": 1, "vendor/.gitignore": 3},
)
NOT_HONORED = IgnoreFileExclusions(honored=False)


def _model(record: IgnoreFileExclusions | None) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.metadata.ignore_file_exclusions = record
    return model


def _lines(text: str):
    return [line for line in text.splitlines() if "Ignore files" in line]


@pytest.fixture
def text_reporter(test_plugin_context):
    return TextReporter(context=test_plugin_context)


@pytest.fixture
def markdown_reporter(test_plugin_context):
    return MarkdownReporter(context=test_plugin_context)


class TestTheSummaryLine:
    def test_text_prints_the_total(self, text_reporter):
        lines = _lines(text_reporter.report(_model(HONORED)))
        assert lines == [
            (
                "Ignore files: the scanned repository's .gitignore and .ignore "
                "files excluded 7 files from the scan set"
            )
        ], lines

    def test_markdown_prints_the_total(self, markdown_reporter):
        lines = _lines(markdown_reporter.report(_model(HONORED)))
        assert lines == [
            (
                "- **Ignore files**: the scanned repository's .gitignore and "
                ".ignore files excluded 7 files from the scan set"
            )
        ], lines

    @pytest.mark.parametrize("fixture", ["text_reporter", "markdown_reporter"])
    def test_not_honored_says_so(self, request, fixture):
        lines = _lines(request.getfixturevalue(fixture).report(_model(NOT_HONORED)))
        assert len(lines) == 1, lines
        assert "not honored" in lines[0] and "honor_ignore_files: false" in lines[0]

    def test_one_file_is_singular(self, text_reporter):
        record = IgnoreFileExclusions(
            honored=True, excluded_file_count=1, by_ignore_file={".gitignore": 1}
        )
        (line,) = _lines(text_reporter.report(_model(record)))
        assert line.endswith("excluded 1 file from the scan set"), line

    @pytest.mark.parametrize("fixture", ["text_reporter", "markdown_reporter"])
    def test_results_without_a_record_print_no_line(self, request, fixture):
        """Results an older ASH wrote, or a run that built no scan set."""
        assert _lines(request.getfixturevalue(fixture).report(_model(None))) == []

    def test_compact_markdown_leaves_it_out_with_the_scan_metadata(
        self, test_plugin_context
    ):
        reporter = MarkdownReporter(
            context=test_plugin_context,
            config=MarkdownReporterConfig(
                options=MarkdownReporterConfigOptions(compact=True)
            ),
        )
        report = reporter.report(_model(HONORED))
        assert "## Scan Metadata" not in report
        assert _lines(report) == []

    def test_a_record_read_back_from_json_renders_the_same(self, text_reporter):
        stored = AshAggregatedResults.model_validate_json(
            _model(HONORED).model_dump_json()
        )
        assert isinstance(stored.metadata.ignore_file_exclusions, IgnoreFileExclusions)
        assert _lines(text_reporter.report(stored)) == _lines(
            text_reporter.report(_model(HONORED))
        )


def _outcome(key: str, relative_path: str, record=None, **kwargs):
    return WorkspaceProjectResult(
        project=key,
        relative_path=relative_path,
        display_label=key,
        status=ProjectRunStatus.COMPLETED,
        output_path=f"projects/{key}",
        ignore_file_exclusions=record,
        **kwargs,
    )


class TestTheWorkspaceAggregate:
    def test_counts_are_summed_and_keyed_from_the_workspace_root(self):
        aggregate = workspace_ignore_file_exclusions(
            [
                _outcome("api", "services/api", HONORED),
                _outcome(
                    "root",
                    ".",
                    IgnoreFileExclusions(
                        honored=True,
                        excluded_file_count=2,
                        by_ignore_file={".gitignore": 2},
                    ),
                ),
            ]
        )
        assert aggregate == {
            "honored": True,
            "excluded_file_count": 9,
            "by_ignore_file": {
                "services/api/.gitignore": 3,
                "services/api/.ignore": 1,
                "services/api/vendor/.gitignore": 3,
                ".gitignore": 2,
            },
        }

    def test_projects_without_a_record_are_left_out(self):
        aggregate = workspace_ignore_file_exclusions(
            [_outcome("api", "api", HONORED), _outcome("web", "web", None)]
        )
        assert aggregate["excluded_file_count"] == 7

    def test_not_honored_in_any_project_reads_not_honored(self):
        aggregate = workspace_ignore_file_exclusions(
            [_outcome("api", "api", HONORED), _outcome("web", "web", NOT_HONORED)]
        )
        assert aggregate["honored"] is False

    def test_no_record_at_all_gives_none(self):
        assert workspace_ignore_file_exclusions([_outcome("api", "api")]) is None

    def test_the_merged_results_file_carries_it(self, tmp_path):
        plan = WorkspacePlan(
            workspace_file=(tmp_path / "w.code-workspace").as_posix(),
            workspace_root=tmp_path.as_posix(),
            projects=[
                ProjectPlan(
                    key="api",
                    relative_path="api",
                    path=(tmp_path / "api").as_posix(),
                    label="api",
                    display_label="api",
                    severity_threshold="MEDIUM",
                )
            ],
        )
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / "out")
        aggregator.add(_outcome("api", "api", HONORED), None, plan.projects[0])
        path = aggregator.write(exit_code=0, wall_clock_seconds=1.0)
        model = AshAggregatedResults.model_validate_json(
            path.read_text(encoding="utf-8")
        )
        merged = model.metadata.ignore_file_exclusions
        assert merged is not None and merged.excluded_file_count == 7
        assert merged.by_ignore_file["api/.gitignore"] == 3
        assert model.workspace.projects[0].ignore_file_exclusions == HONORED


# --------------------------------------------------------------------------- whole runs

# Run in a child, as the whole-scan tests do: ASH's own CLI, nothing replaced.
_DRIVER = textwrap.dedent(
    """
    import sys

    from automated_security_helper.cli.main import app

    sys.argv = ["ash", *sys.argv[1:]]
    app()
    """
)

_PROJECT = {
    ".gitignore": "build/\n*.log\n",
    "app.py": "print('hello')\n",
    "debug.log": "log\n",
    "build/out1.txt": "out\n",
    "build/out2.txt": "out\n",
}


def _child_env() -> Dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("AWS_", "ASH_"))
    }
    env.update(
        {
            "AWS_CONFIG_FILE": os.devnull,
            "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_ENDPOINT_URL": "http://127.0.0.1:9",
            "AWS_REGION": "us-east-1",
            "ASH_OFFLINE": "YES",
            "NO_COLOR": "1",
            "COLUMNS": "200",
        }
    )
    return env


def _write(root: Path, files: Dict[str, str]) -> None:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


@pytest.fixture(scope="module")
def workspace_run(tmp_path_factory):
    work = tmp_path_factory.mktemp("ws-ignore-record")
    _write(work / "api", _PROJECT)
    _write(work / "web", {**_PROJECT, ".ignore": "app.py\n"})
    (work / "w.code-workspace").write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}), encoding="utf-8"
    )
    output = work / "out"
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            _DRIVER,
            "scan",
            "--workspace",
            str(work / "w.code-workspace"),
            "--output-dir",
            str(output),
            "--phases",
            "convert",
            "--phases",
            "report",
            "--no-progress",
            "--no-fail-on-findings",
        ],
        capture_output=True,
        text=True,
        timeout=600,
        env=_child_env(),
        cwd=work,
    )
    assert completed.returncode == 0, (
        completed.stdout[-4000:] + completed.stderr[-4000:]
    )
    return output


class TestAWorkspaceScan:
    def test_each_project_records_its_own(self, workspace_run):
        results = json.loads(
            (workspace_run / "ash_aggregated_results.json").read_text(encoding="utf-8")
        )
        by_project = {
            entry["project"]: entry["ignore_file_exclusions"]
            for entry in results["workspace"]["projects"]
        }
        assert by_project["api"]["by_ignore_file"] == {".gitignore": 3}
        assert by_project["web"]["by_ignore_file"] == {".gitignore": 3, ".ignore": 1}

    def test_the_merged_metadata_has_the_workspace_total(self, workspace_run):
        results = json.loads(
            (workspace_run / "ash_aggregated_results.json").read_text(encoding="utf-8")
        )
        record = results["metadata"]["ignore_file_exclusions"]
        assert record == {
            "honored": True,
            "excluded_file_count": 7,
            "by_ignore_file": {
                "api/.gitignore": 3,
                "web/.gitignore": 3,
                "web/.ignore": 1,
            },
        }

    @pytest.mark.parametrize("extension", ["txt", "md"])
    def test_the_workspace_summary_prints_the_total(self, workspace_run, extension):
        text = (workspace_run / "reports" / f"ash.summary.{extension}").read_text(
            encoding="utf-8"
        )
        lines = _lines(text)
        assert len(lines) == 1 and re.search(r"\b7 files\b", lines[0]), lines


class TestTheMcpSummary:
    @pytest.mark.asyncio
    async def test_get_scan_summary_returns_the_record(self, tmp_path, monkeypatch):
        """Read back from a results file on disk, through the tool itself."""
        from automated_security_helper.cli.mcp_server import get_scan_summary

        output = tmp_path / "project" / ".ash" / "ash_output"
        _model(HONORED).save_model(output)
        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
        ctx = MagicMock()
        ctx.headers = None
        for name in ("info", "error", "warning", "debug"):
            setattr(ctx, name, AsyncMock())

        summary = await get_scan_summary(ctx, output_dir=str(output))

        assert summary.get("success") is True, summary
        assert summary["metadata"]["ignore_file_exclusions"] == HONORED.model_dump()

    @pytest.mark.asyncio
    async def test_control_results_without_a_record_return_none(
        self, tmp_path, monkeypatch
    ):
        from automated_security_helper.cli.mcp_server import get_scan_summary

        output = tmp_path / "project" / ".ash" / "ash_output"
        _model(None).save_model(output)
        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
        ctx = MagicMock()
        ctx.headers = None
        for name in ("info", "error", "warning", "debug"):
            setattr(ctx, name, AsyncMock())

        summary = await get_scan_summary(ctx, output_dir=str(output))

        assert summary.get("success") is True, summary
        assert summary["metadata"]["ignore_file_exclusions"] is None
