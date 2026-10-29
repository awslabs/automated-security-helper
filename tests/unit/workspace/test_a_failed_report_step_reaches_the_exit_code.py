# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace report step that fails ends the run non-zero, and the file agrees.

Why this file exists
--------------------
The workspace report step runs after the results file is written, so the exit code
was already fixed from the projects alone. A reporter that raised, a report file that
could not be written, or a manifest that could not be written was recorded in
``WorkspaceReportOutcome`` and in the manifest, and nothing read it: a workspace of
clean projects exited 0 with the reports the operator asked for missing.

The contract these cells pin, all through the real ``execute_workspace``:

- clean projects and a failed report step exit 1 (``INTERNAL_ERROR``);
- a failed report step ranks as an incomplete project does in
  ``workspace_exit_code``: it raises 0 and 2 to 1, and an invalid project
  configuration (3) and nothing attempted (4) keep their codes;
- ``workspace.exit_code`` in the results file is the code the process exits with;
- a reporter that has nothing to say, or a clean report step, changes nothing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.models.workspace import WorkspaceExitCode
from automated_security_helper.workspace.aggregation import (
    RESULTS_FILENAME,
    stamp_run_record,
)
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    execute_workspace,
)
from automated_security_helper.workspace.reporting import (
    MANIFEST_FILENAME,
    REPORTS_DIR_NAME,
    WorkspaceReportOutcome,
)
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _sarif,
)
from tests.unit.workspace.test_workspace_reporting import (
    FakeMergedReporter,
    FakeRaisingReporter,
)

pytestmark = pytest.mark.unit

INTERNAL_ERROR = int(WorkspaceExitCode.INTERNAL_ERROR)


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _run(tmp_path: Path, *reporter_classes: type, threshold: str = "CRITICAL"):
    """A one-project workspace whose only finding is below *threshold*'s bar."""
    _, plan = _make_workspace(tmp_path, ("api", threshold))
    FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(level="warning")}
    return execute_workspace(
        plan,
        ProjectScanSettings(
            output_dir=tmp_path / "out",
            phases=("scan", "report"),
            max_parallel_projects=1,
        ),
        orchestrator_factory=FakeOrchestrator.create,
        reporter_classes=list(reporter_classes),
    )


def _recorded_exit_code(tmp_path: Path) -> int:
    written = json.loads((tmp_path / "out" / RESULTS_FILENAME).read_text("utf-8"))
    return written["workspace"]["exit_code"]


def _reports(tmp_path: Path) -> Path:
    return tmp_path / "out" / REPORTS_DIR_NAME


def _assert_exits(tmp_path: Path, result: Any, expected: int) -> None:
    assert result.exit_code == expected
    assert result.payload.exit_code == expected
    assert _recorded_exit_code(tmp_path) == expected


def test_control_a_clean_report_step_leaves_a_clean_run_at_zero(tmp_path):
    result = _run(tmp_path, FakeMergedReporter)

    assert result.report_outcome is not None
    assert result.report_outcome.failed_reporters == {}
    _assert_exits(tmp_path, result, int(WorkspaceExitCode.SUCCESS))


def test_a_reporter_that_raises_ends_a_clean_run_non_zero(tmp_path):
    result = _run(tmp_path, FakeMergedReporter, FakeRaisingReporter)

    assert result.report_outcome is not None
    assert "fake-raising" in result.report_outcome.failed_reporters
    _assert_exits(tmp_path, result, INTERNAL_ERROR)


def test_a_report_file_that_cannot_be_written_ends_a_clean_run_non_zero(tmp_path):
    (_reports(tmp_path) / "ash.merged.txt").mkdir(parents=True)

    result = _run(tmp_path, FakeMergedReporter)

    assert result.report_outcome is not None
    assert "fake-merged" in result.report_outcome.failed_reporters
    _assert_exits(tmp_path, result, INTERNAL_ERROR)


def test_a_manifest_that_cannot_be_written_ends_a_clean_run_non_zero(tmp_path):
    (_reports(tmp_path) / MANIFEST_FILENAME).mkdir(parents=True)

    result = _run(tmp_path, FakeMergedReporter)

    assert result.report_outcome is not None
    assert result.report_outcome.manifest_path is None
    assert result.report_outcome.failed_reporters == {}
    _assert_exits(tmp_path, result, INTERNAL_ERROR)


def test_a_failed_report_step_outranks_findings(tmp_path):
    """Ranked as an incomplete project is: 1 ahead of 2, as workspace_exit_code does."""
    result = _run(tmp_path, FakeRaisingReporter, threshold="LOW")

    assert result.report_outcome is not None
    assert "fake-raising" in result.report_outcome.failed_reporters
    _assert_exits(tmp_path, result, INTERNAL_ERROR)


def test_a_reporter_with_nothing_to_say_does_not_fail_the_run(tmp_path):
    from automated_security_helper.base.reporter_plugin import (
        ReporterPluginBase,
        ReporterPluginConfigBase,
        ReporterWorkspaceBehaviour,
    )

    class _SilentConfig(ReporterPluginConfigBase):
        name: str = "fake-silent"
        extension: str = "silent.txt"
        enabled: bool = True

    class _Silent(ReporterPluginBase[_SilentConfig]):
        workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

        def model_post_init(self, context):
            if self.config is None:
                self.config = _SilentConfig()
            return super().model_post_init(context)

        def report(self, model) -> str:
            return ""

    result = _run(tmp_path, _Silent)

    assert result.report_outcome is not None
    assert result.report_outcome.failed_reporters == {}
    _assert_exits(tmp_path, result, int(WorkspaceExitCode.SUCCESS))


@pytest.mark.parametrize("code", list(WorkspaceExitCode), ids=lambda c: c.name)
@pytest.mark.parametrize(
    "outcome",
    [
        WorkspaceReportOutcome(manifest_path=Path("m"), failed_reporters={"r": "x"}),
        WorkspaceReportOutcome(manifest_path=None),
        WorkspaceReportOutcome(manifest_path=Path("m"), unsupported_reporters=("r",)),
    ],
    ids=["reporter-failed", "manifest-unwritten", "reporter-refused"],
)
def test_only_a_clean_code_is_raised_by_a_failed_report_step(outcome, code):
    from automated_security_helper.workspace.reporting import (
        exit_code_after_report_step,
    )

    raised = (WorkspaceExitCode.SUCCESS, WorkspaceExitCode.ACTIONABLE_FINDINGS)
    expected = INTERNAL_ERROR if code in raised else int(code)
    assert exit_code_after_report_step(int(code), outcome) == expected


@pytest.mark.parametrize("code", list(WorkspaceExitCode), ids=lambda c: c.name)
def test_a_report_step_that_wrote_everything_changes_no_code(code):
    from automated_security_helper.workspace.reporting import (
        exit_code_after_report_step,
    )

    outcome = WorkspaceReportOutcome(
        manifest_path=Path("m"), per_project_reporters=("ghas",)
    )

    assert outcome.failed is False
    assert exit_code_after_report_step(int(code), outcome) == int(code)


def test_rewriting_the_workspace_block_changes_only_that_block(tmp_path):
    from automated_security_helper.workspace.aggregation import (
        rewrite_workspace_block,
    )

    _, plan = _make_workspace(tmp_path, ("api", "CRITICAL"))
    FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(level="warning")}
    result = execute_workspace(
        plan,
        ProjectScanSettings(
            output_dir=tmp_path / "out", phases=("scan",), max_parallel_projects=1
        ),
        orchestrator_factory=FakeOrchestrator.create,
    )
    before = json.loads(result.results_path.read_text("utf-8"))
    assert before["workspace"]["exit_code"] == 0

    rewritten = result.payload.model_copy(update={"exit_code": INTERNAL_ERROR})
    assert rewrite_workspace_block(result.results_path, rewritten) is True

    after = json.loads(result.results_path.read_text("utf-8"))
    assert after["workspace"]["exit_code"] == INTERNAL_ERROR
    assert after["workspace"]["projects"] == before["workspace"]["projects"]
    assert after["sarif"] == before["sarif"]
    assert {k: v for k, v in after.items() if k != "workspace"} == {
        k: v for k, v in before.items() if k != "workspace"
    }
    assert stamp_run_record(result.results_path, {"marker": "after-rewrite"}) is True


def test_rewriting_a_file_write_did_not_make_changes_nothing(tmp_path):
    from automated_security_helper.workspace.aggregation import (
        rewrite_workspace_block,
    )

    _, plan = _make_workspace(tmp_path, ("api", "CRITICAL"))
    FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(level="warning")}
    payload = execute_workspace(
        plan,
        ProjectScanSettings(
            output_dir=tmp_path / "out", phases=("scan",), max_parallel_projects=1
        ),
        orchestrator_factory=FakeOrchestrator.create,
    ).payload
    foreign = tmp_path / "foreign.json"
    foreign.write_text('{"a": 1}\n', encoding="utf-8")

    assert rewrite_workspace_block(foreign, payload) is False

    assert foreign.read_text("utf-8") == '{"a": 1}\n'
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".foreign")] == []
