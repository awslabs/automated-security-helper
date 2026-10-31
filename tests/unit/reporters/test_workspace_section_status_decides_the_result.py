# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A project's recorded status decides its row, not the truthiness of its texts.

``workspace_project_rows`` read FAILED from ``project.error`` and SKIPPED from
``project.skip_reason`` and never consulted ``project.status``, so a FAILED
project whose error text was null or empty, and a SKIPPED project with no
recorded reason, fell through to PASSED with zero counts: the same row a clean
scan produces, for a project that was never scanned, while workspace_exit_code
fails the run for the FAILED one.
"""

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_section import (
    html_workspace_section,
    workspace_project_rows,
)

pytestmark = pytest.mark.unit


def _project(key: str, **overrides) -> WorkspaceProjectResult:
    fields = {
        "project": key,
        "relative_path": key,
        "display_label": key,
        "status": ProjectRunStatus.COMPLETED,
        "severity_threshold": "MEDIUM",
        "output_path": f"projects/{key}",
    }
    fields.update(overrides)
    return WorkspaceProjectResult(**fields)


def _model(*projects: WorkspaceProjectResult) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.workspace = WorkspaceResults(
        workspace_file="/w/.ash-workspace.yaml",
        workspace_root="/w",
        exit_code=0,
        projects=list(projects),
    )
    return model


def _result(model: AshAggregatedResults, key: str) -> str:
    return next(
        row["result"] for row in workspace_project_rows(model) if row["key"] == key
    )


@pytest.mark.parametrize("error", [None, ""], ids=["null-error", "empty-error"])
def test_a_failed_project_without_an_error_text_reads_failed(error):
    model = _model(
        _project(
            "svc", status=ProjectRunStatus.FAILED, error=error, severity_threshold=None
        )
    )
    assert _result(model, "svc") == "FAILED"
    assert 'class="failed"' in html_workspace_section(model)


def test_a_skipped_project_without_a_reason_reads_skipped():
    model = _model(
        _project(
            "docs",
            status=ProjectRunStatus.SKIPPED,
            skip_reason=None,
            severity_threshold=None,
        )
    )
    assert _result(model, "docs").startswith("SKIPPED")


def test_a_skip_with_a_reason_still_names_it():
    from automated_security_helper.models.workspace import SkippedProjectReason

    model = _model(
        _project(
            "docs",
            status=ProjectRunStatus.SKIPPED,
            skip_reason=SkippedProjectReason.NO_CHANGES,
            severity_threshold=None,
        )
    )
    assert _result(model, "docs") == "SKIPPED (no-changes)"


def test_a_skipped_project_that_also_carries_an_error_text_reads_skipped():
    """The recorded status is read ahead of the error text.

    The arms used to read error text before the SKIPPED status, so a skipped
    project whose record also held an error line read FAILED, a status
    workspace_exit_code never gave it.
    """
    from automated_security_helper.models.workspace import SkippedProjectReason

    model = _model(
        _project(
            "docs",
            status=ProjectRunStatus.SKIPPED,
            skip_reason=SkippedProjectReason.ERROR,
            error="the project's config could not be read",
            severity_threshold=None,
        )
    )
    assert _result(model, "docs") == "SKIPPED (error)"


def test_a_failed_project_that_also_carries_a_skip_reason_reads_failed():
    """The recorded status is read ahead of the skip reason.

    The arms used to read a skip reason before the FAILED status, so a failed
    project whose record also held one read SKIPPED while workspace_exit_code
    failed the run for it.
    """
    from automated_security_helper.models.workspace import SkippedProjectReason

    model = _model(
        _project(
            "svc",
            status=ProjectRunStatus.FAILED,
            skip_reason=SkippedProjectReason.NO_CHANGES,
            error="scanner crashed",
            severity_threshold=None,
        )
    )
    assert _result(model, "svc") == "FAILED"
    assert 'class="failed"' in html_workspace_section(model)


def test_a_completed_clean_project_still_passes():
    assert _result(_model(_project("svc")), "svc") == "PASSED"


def _unvalidated(key: str, **fields) -> WorkspaceProjectResult:
    """A project record built without validation, so its status is a plain string."""
    return WorkspaceProjectResult.model_construct(
        project=key,
        relative_path=key,
        display_label=key,
        output_path=f"projects/{key}",
        **fields,
    )


def test_a_plain_string_status_is_read_as_the_status_it_names():
    """The arms read the status by identity, so a record whose status arrived as
    the string ``"failed"`` (built without validation) matched none of them and
    fell through to PASSED with zero counts.

    RED at the base: the row read PASSED.
    """
    model = _model(_unvalidated("svc", status="failed"))
    assert _result(model, "svc") == "FAILED"
    assert 'class="failed"' in html_workspace_section(model)


def test_a_plain_string_skip_reason_of_error_is_styled_as_a_failure():
    """Whether a skip is an error is the reason's own answer, in either spelling."""
    model = _model(_unvalidated("docs", status="skipped", skip_reason="error"))
    (row,) = workspace_project_rows(model)
    assert row["result"] == "SKIPPED (error)"
    assert row["state"] == "failed"
    model = _model(_unvalidated("docs", status="skipped", skip_reason="no-changes"))
    (row,) = workspace_project_rows(model)
    assert row["state"] == "skipped"


def test_a_completed_project_that_also_carries_an_error_text_never_reads_passed():
    """A record that holds an error text is not shown as a clean scan.

    ``workspace_exit_code`` reads the recorded status and its flags and not the
    text, so it counts such a project as completed; the row errs on the failing
    side rather than print PASSED over a record that names an error.
    """
    model = _model(_project("svc", error="the scanner reported a failure"))
    assert _result(model, "svc") == "FAILED"


def test_a_completed_project_that_also_carries_a_skip_reason_never_reads_passed():
    from automated_security_helper.models.workspace import SkippedProjectReason

    model = _model(_project("svc", skip_reason=SkippedProjectReason.NO_CHANGES))
    assert _result(model, "svc") == "SKIPPED (no-changes)"
