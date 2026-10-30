# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two edges of the project verdict and the cross-project masking pass.

Why this file exists
--------------------
A scanner only the workspace policy added, with ``policy_scanners_gate`` off,
"cannot fail the project": its findings are reported and decide nothing, and
its MISSING tool is left out of the completeness verdict. Its stale content
database was not: ``scan_incomplete`` read every stale record, so a workspace
that added grype for visibility failed every project on a host whose grype
database had aged, with no finding and no project setting involved.

The cross-project masking pass re-masked every project in ``collected``,
which includes a project recorded FAILED because its ``projects/<key>`` was a
link the scan refused to write through. The pass then walked and rewrote
through that same link.

The contract these cases pin:

- a stale database of a non-gating policy scanner is reported and does not fail
  the project; with the gate on it does;
- the masking pass skips a project whose output directory the scan refused as
  a link, and re-masks the others;
- the masking pass skips a project that failed before an orchestrator existed
  for it (a previous run's files are not this run's to rewrite), and re-masks a
  project whose scan raised after writing its reports (those files are this
  run's, and quote the other projects' values).
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.models.workspace import WorkspaceExitCode
from automated_security_helper.utils.output_dir_links import OutputDirLinkRefused
from automated_security_helper.workspace import execution
from automated_security_helper.workspace.execution import execute_workspace
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _run,
    _sarif,
    _scanner,
    _settings,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _stale_grype_sarif() -> dict:
    from datetime import datetime, timedelta, timezone

    from automated_security_helper.schemas.sarif_schema_model import SarifReport
    from automated_security_helper.utils import content_db_staleness as staleness
    from automated_security_helper.utils.content_databases import get

    entry = get("grype-db")
    now = datetime.now(timezone.utc)
    record = staleness.ContentDbAgeRecord(
        name=entry.name,
        scanner=entry.scanner,
        built=now - timedelta(days=10),
        measured_by=entry.age_source,
        max_age=entry.max_age,
        measured_at=now,
        policy="fail",
        bound_source=entry.bound_source,
        bound_is_tool_default=entry.bound_is_tool_default,
        refresh=entry.refresh,
    )
    report = SarifReport.model_validate(_sarif(count=0))
    staleness.attach_records(report, [record])
    return json.loads(report.model_dump_json(by_alias=True, exclude_none=True))


@pytest.mark.parametrize(
    "gate,incomplete,code",
    [
        (False, False, WorkspaceExitCode.SUCCESS),
        (True, True, WorkspaceExitCode.INTERNAL_ERROR),
    ],
)
def test_a_policy_scanners_stale_database_follows_the_policy_gate(
    tmp_path, gate, incomplete, code
):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    plan.projects[0] = plan.projects[0].model_copy(
        update={"policy_scanners": ["grype"], "policy_scanners_gate": gate}
    )
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _stale_grype_sarif(),
        "scanner_results": {"bandit": _scanner("PASSED"), "grype": _scanner("PASSED")},
    }

    outcome = _run(tmp_path, plan)
    project = outcome.payload.projects[0]

    # Reported either way, as the incomplete scanner of a policy scanner is.
    assert [r["name"] for r in project.stale_content_databases] == ["grype-db"]
    assert project.scan_incomplete is incomplete
    assert outcome.exit_code == code


def test_the_masking_pass_skips_a_project_whose_output_was_a_refused_link(
    tmp_path, monkeypatch
):
    real_refusal = execution.refuse_linked_output_dir

    def refuse_linked(output_dir, project_output):
        if project_output.name == "linked":
            raise OutputDirLinkRefused(
                f"the output directory {project_output} is a link"
            )
        return real_refusal(output_dir, project_output)

    masked: list = []
    monkeypatch.setattr(execution, "refuse_linked_output_dir", refuse_linked)
    monkeypatch.setattr(execution, "exposed_secret_values", lambda results: {"hunter2"})
    monkeypatch.setattr(
        execution,
        "_mask_project_output",
        lambda project_output, values, shapes: masked.append(project_output.name),
    )
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("linked", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(count=1)}
    FakeOrchestrator.behaviour["linked"] = {"sarif": _sarif(count=1)}

    outcome = _run(tmp_path, plan)

    statuses = {p.project: p.status.value for p in outcome.payload.projects}
    assert statuses["linked"] == "failed", statuses
    assert masked == ["api"]


def test_the_masking_pass_skips_a_project_this_run_never_scanned(tmp_path, monkeypatch):
    """A previous run's projects/<key> is not rewritten for a project that failed before scanning.

    The refusal is raised where the executor raises it, from the config
    resolution that runs before an orchestrator is built (``_project_config_with_policy``):
    an orchestrator that raised after it was built is the case below, and it IS
    masked.
    """
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    masked: list = []
    monkeypatch.setattr(execution, "exposed_secret_values", lambda results: {"hunter2"})
    monkeypatch.setattr(
        execution,
        "_mask_project_output",
        lambda project_output, values, shapes: masked.append(project_output.name),
    )
    real_resolution = execution._project_config_with_policy

    def refuse_brokens_config(project, settings):
        if project.key == "broken":
            raise ASHConfigValidationError("fixture: the config is invalid")
        return real_resolution(project, settings)

    monkeypatch.setattr(execution, "_project_config_with_policy", refuse_brokens_config)
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("broken", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(count=1)}
    # What a previous run left under the never-scanned project's output tree.
    stale = tmp_path / "out" / "projects" / "broken" / "ash_aggregated_results.json"
    stale.parent.mkdir(parents=True)
    stale.write_text("{}", encoding="utf-8")

    outcome = _run(tmp_path, plan)

    statuses = {p.project: p.status.value for p in outcome.payload.projects}
    assert statuses["broken"] == "failed", statuses
    assert [b.key for b in FakeOrchestrator.built] == ["api"], (
        "an orchestrator was built for the refused project"
    )
    assert masked == ["api"]


class _WritesThenRaises(FakeOrchestrator):
    """A scan that wrote its reports, then raised: its files are this run's."""

    def execute_scan(self, phases=None):
        reports = self.output_dir / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        (reports / "ash.html").write_text("<pre>partial</pre>\n", encoding="utf-8")
        raise RuntimeError("the report phase broke after ash.html")


def test_the_masking_pass_covers_a_project_whose_scan_raised_after_writing(
    tmp_path, monkeypatch
):
    """Partial write, then a raise: the reports left behind quote what the
    other projects exposed, so they are masked like a finished project's. An
    implementation that skips every FAILED project passes the two skip cases
    above and leaves another project's secret in clear here."""
    masked: list = []
    monkeypatch.setattr(execution, "exposed_secret_values", lambda results: {"hunter2"})
    monkeypatch.setattr(
        execution,
        "_mask_project_output",
        lambda project_output, values, shapes: masked.append(project_output.name),
    )
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"), ("broken", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(count=1)}

    def factory(**kwargs):
        if kwargs["source_dir"].name == "broken":
            return _WritesThenRaises(**kwargs)
        return FakeOrchestrator(**kwargs)

    outcome = execute_workspace(plan, _settings(tmp_path), orchestrator_factory=factory)

    statuses = {p.project: p.status.value for p in outcome.payload.projects}
    assert statuses["broken"] == "failed", statuses
    assert (tmp_path / "out" / "projects" / "broken" / "reports" / "ash.html").exists()
    assert sorted(masked) == ["api", "broken"], masked
