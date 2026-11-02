# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A project whose previous results were put back is not listed as this run's.

With ``keep_previous_results`` (the MCP workspace tool) a project's orchestrator
sets the previous results aside when it starts, and puts them back, ``reports/``
included, when its scan ends without finishing (core/previous_results.py). The
workspace marks such a project as having had an orchestrator run for it, so the
report step has to tell "this run wrote these reports" from "an earlier run did":
the manifest lists a per-project artefact only for the first. The directory says
which it is: a restore leaves ``.ash_previous_results_restored`` beside what it
put back.

The orchestrator double here drives the real :class:`PreviousResults`, so the
set-aside, the restore and the marker are the product's own and not a stand-in
for them. The workspace run is the real ``execute_workspace``, for the reason
given in ``test_execution_hands_the_report_step_the_projects_that_wrote_output``:
a call assertion on a stand-in would not notice a wrong set being handed over.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.core.previous_results import (
    RESTORED_MARKER_NAME,
    PreviousResults,
    holds_restored_results,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    execute_workspace,
)
from automated_security_helper.workspace.reporting import (
    MANIFEST_FILENAME,
    REPORTS_DIR_NAME,
)
from tests.unit.workspace.test_workspace_reporting import (
    FakePerProjectReporter,
    _plan,
    _run,
)

pytestmark = pytest.mark.unit

STALE_REPORT = "ash.ghas.sarif"
STALE_TEXT = '{"note": "the previous run wrote this"}'


def _orchestrator(raising_keys, writes_before_raising):
    """An orchestrator whose scan keeps and settles the previous results as the
    real one does: set them aside when it is built, put them back when the scan
    raises, drop them when it finishes."""

    class _Orchestrator:
        def __init__(self, **kwargs):
            self.key = Path(kwargs["source_dir"]).name
            self.output_dir = Path(kwargs["output_dir"])
            self.previous = None
            if kwargs["keep_previous_results"]:
                self.previous = PreviousResults(self.output_dir)
                self.previous.set_aside()

        @classmethod
        def create(cls, **kwargs):
            return cls(**kwargs)

        def _write_report(self):
            reports = self.output_dir / REPORTS_DIR_NAME
            reports.mkdir(parents=True, exist_ok=True)
            (reports / STALE_REPORT).write_text("{}", encoding="utf-8")

        def execute_scan(self, phases=None):
            if self.key in raising_keys:
                if writes_before_raising:
                    self._write_report()
                if self.previous is not None:
                    self.previous.restore()
                raise RuntimeError("fixture failure inside the scan")
            self._write_report()
            if self.previous is not None:
                self.previous.discard()
            model = AshAggregatedResults()
            model.sarif = SarifReport.model_validate(
                {
                    "version": "2.1.0",
                    "runs": [
                        _run(
                            self.key,
                            rule=f"RULE-{self.key.upper()}",
                            uri=f"src/{self.key}.py",
                        )
                    ],
                }
            )
            return model

    return _Orchestrator


def _execute(
    tmp_path,
    *,
    keep_previous_results,
    raising_keys,
    writes_before_raising,
    previous_results_of=(),
    markers_of=(),
):
    root = tmp_path / "ws"
    for key in ("api", "web"):
        (root / key / "src").mkdir(parents=True, exist_ok=True)
    (root / "fixture.code-workspace").write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    # The previous run's report, where the workspace puts a project's output.
    for key in previous_results_of:
        reports = out / "projects" / key / REPORTS_DIR_NAME
        reports.mkdir(parents=True, exist_ok=True)
        (reports / STALE_REPORT).write_text(STALE_TEXT, encoding="utf-8")
    for key in markers_of:
        directory = out / "projects" / key
        directory.mkdir(parents=True, exist_ok=True)
        (directory / RESTORED_MARKER_NAME).write_text("left behind", encoding="utf-8")
    result = execute_workspace(
        _plan(root, "api", "web"),
        ProjectScanSettings(
            output_dir=out,
            phases=("scan", "report"),
            max_parallel_projects=1,
            keep_previous_results=keep_previous_results,
        ),
        orchestrator_factory=_orchestrator(
            set(raising_keys), writes_before_raising
        ).create,
        reporter_classes=[FakePerProjectReporter],
    )
    manifest = json.loads(
        (out / REPORTS_DIR_NAME / MANIFEST_FILENAME).read_text(encoding="utf-8")
    )
    return result, manifest["reporters"]["fake-per-project"], out


def _statuses(result):
    return {p.project: p.status.value for p in result.payload.projects}


def test_a_failed_project_whose_previous_reports_were_put_back_is_missing(tmp_path):
    result, entry, out = _execute(
        tmp_path,
        keep_previous_results=True,
        raising_keys={"web"},
        writes_before_raising=False,
        previous_results_of={"web"},
    )

    # Control: web failed before it wrote anything, and its previous report is
    # back on disk with the marker beside it, so the listing below is a decision
    # about a file that IS there and is an earlier run's.
    assert _statuses(result) == {"api": "completed", "web": "failed"}
    web_output = out / "projects" / "web"
    assert (web_output / REPORTS_DIR_NAME / STALE_REPORT).read_text(
        encoding="utf-8"
    ) == STALE_TEXT
    assert holds_restored_results(web_output)

    assert [item["project"] for item in entry["per_project_artifacts"]] == ["api"]
    assert entry["missing_per_project_artifacts"] == ["web"]


@pytest.mark.parametrize("keep_previous_results", [True, False])
def test_a_failed_project_that_wrote_its_own_reports_is_still_listed(
    tmp_path, keep_previous_results
):
    """The control: nothing was put back (no previous results to set aside, or
    the run keeps none), so what the scan wrote before it raised is this run's."""
    result, entry, out = _execute(
        tmp_path,
        keep_previous_results=keep_previous_results,
        raising_keys={"web"},
        writes_before_raising=True,
    )

    assert _statuses(result) == {"api": "completed", "web": "failed"}
    assert not holds_restored_results(out / "projects" / "web")

    assert [item["project"] for item in entry["per_project_artifacts"]] == [
        "api",
        "web",
    ]
    assert entry["missing_per_project_artifacts"] == []


def test_a_completed_project_is_listed_even_beside_a_leftover_marker(tmp_path):
    """A scan that finished has its own results whatever a marker beside them
    says, as when dropping the previous results was refused and left it."""
    result, entry, _ = _execute(
        tmp_path,
        keep_previous_results=False,
        raising_keys=set(),
        writes_before_raising=False,
        markers_of={"api"},
    )

    assert _statuses(result) == {"api": "completed", "web": "completed"}
    assert [item["project"] for item in entry["per_project_artifacts"]] == [
        "api",
        "web",
    ]
    assert entry["missing_per_project_artifacts"] == []
