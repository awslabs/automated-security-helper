# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A project whose scan did not finish must not render as PASSED.

``workspace_project_rows`` tested ``skip_reason``, ``error`` and
``exceeds_threshold`` and nothing else, so a COMPLETED project carrying
``scan_incomplete=True`` with no error and no threshold breach fell through to
the ``else`` and was emitted as ``result='PASSED'`` with its finding counts. That
is the same row a project with a clean, complete scan produces, so the table gave
an operator no way to tell "nothing was found" from "the scanner that would have
found it did not run" -- while ``workspace_exit_code`` failed the run for exactly
that project. Two verdicts for one project, and the human-readable one was the
optimistic half.

The HTML renderer keys its row class on ``result.startswith('FAILED')``, so the
state name and the colour are one decision rather than two: a name that does not
start with ``FAILED`` changes the text and leaves the row green. Both are
asserted here for that reason.
"""

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    SkippedProjectReason,
    WorkspaceProjectResult,
    WorkspaceResults,
    workspace_exit_code,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_section import (
    html_workspace_section,
    markdown_workspace_section,
    text_workspace_section,
    workspace_project_rows,
)


def _project(key: str, **overrides) -> WorkspaceProjectResult:
    """A COMPLETED, clean project, with the field under test overridden."""
    fields = {
        "project": key,
        "relative_path": key,
        "display_label": key,
        "status": ProjectRunStatus.COMPLETED,
        "severity_threshold": "MEDIUM",
        "output_path": f"projects/{key}",
        "scanners": {"bandit": "COMPLETED"},
        "incomplete_scanners": [],
        "ceiling_unreachable_findings": {},
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


def _row(model: AshAggregatedResults, key: str) -> dict:
    return next(row for row in workspace_project_rows(model) if row["key"] == key)


class TestIncompleteScanIsNotPassed:
    def test_incomplete_project_does_not_render_passed(self):
        """The fixture the cascade had no arm for: incomplete, no error, under threshold."""
        model = _model(
            _project(
                "svc",
                scan_incomplete=True,
                incomplete_scanners=["semgrep"],
                exceeds_threshold=False,
                error=None,
            )
        )

        row = _row(model, "svc")

        assert row["result"] != "PASSED", (
            "a project whose scan did not complete reads as a clean pass, while "
            "workspace_exit_code fails the run for the same project"
        )

    def test_the_state_reads_as_a_failure_to_the_css_predicate(self):
        """``html_workspace_section`` colours on ``startswith('FAILED')``."""
        model = _model(
            _project("svc", scan_incomplete=True, incomplete_scanners=["semgrep"])
        )

        row = _row(model, "svc")

        assert row["result"].startswith("FAILED"), (
            "the HTML row class is derived from this prefix, so a state that does "
            "not carry it changes the text and leaves the row green"
        )

    def test_the_html_row_is_not_green(self):
        model = _model(
            _project("svc", scan_incomplete=True, incomplete_scanners=["semgrep"])
        )

        fragment = html_workspace_section(model)

        assert 'class="failed"' in fragment
        assert 'class="passed"' not in fragment

    def test_the_incomplete_scanner_is_named(self):
        """Which tool did not run is the actionable half of the row."""
        model = _model(
            _project(
                "svc",
                scan_incomplete=True,
                incomplete_scanners=["semgrep", "grype"],
            )
        )

        row = _row(model, "svc")

        assert "semgrep" in row["detail"]
        assert "grype" in row["detail"]

    def test_the_verdict_agrees_with_the_exit_code(self):
        """The table and the process status must not disagree for one project."""
        project = _project("svc", scan_incomplete=True, incomplete_scanners=["semgrep"])

        exit_code = workspace_exit_code([project])
        row = _row(_model(project), "svc")

        assert exit_code != 0, "fixture no longer exercises a failing project"
        assert row["result"].startswith("FAILED")


class TestTheOtherArmsAreUnchanged:
    """The new arm must not capture rows the cascade already classified."""

    def test_a_clean_project_still_passes(self):
        model = _model(_project("svc"))

        assert _row(model, "svc")["result"] == "PASSED"

    def test_a_threshold_breach_still_reads_failed(self):
        model = _model(_project("svc", exceeds_threshold=True))

        assert _row(model, "svc")["result"] == "FAILED"

    def test_an_errored_project_still_reads_failed(self):
        model = _model(
            _project("svc", status=ProjectRunStatus.FAILED, error="scanner blew up")
        )

        assert _row(model, "svc")["result"] == "FAILED"

    def test_a_skip_still_names_its_reason(self):
        model = _model(
            _project(
                "svc",
                status=ProjectRunStatus.SKIPPED,
                skip_reason=SkippedProjectReason.NO_CHANGES,
                skip_detail="no changed files",
            )
        )

        assert _row(model, "svc")["result"].startswith("SKIPPED")

    def test_a_skip_outranks_incompleteness(self):
        """A project that never ran has no scan to call incomplete."""
        model = _model(
            _project(
                "svc",
                status=ProjectRunStatus.SKIPPED,
                skip_reason=SkippedProjectReason.NO_CHANGES,
                scan_incomplete=True,
                incomplete_scanners=["semgrep"],
            )
        )

        assert _row(model, "svc")["result"].startswith("SKIPPED")

    def test_an_error_outranks_incompleteness(self):
        """``FAILED`` for a project that produced no verdict is the stronger claim."""
        model = _model(
            _project(
                "svc",
                status=ProjectRunStatus.FAILED,
                error="scanner blew up",
                scan_incomplete=True,
                incomplete_scanners=["semgrep"],
            )
        )

        assert _row(model, "svc")["result"] == "FAILED"


class TestEveryRendererCarriesTheState:
    """The three renderers share the rows, so none of them may drop the state."""

    def test_markdown_carries_it(self):
        model = _model(
            _project("svc", scan_incomplete=True, incomplete_scanners=["semgrep"])
        )

        body = "\n".join(markdown_workspace_section(model))

        assert "FAILED" in body

    def test_text_carries_it(self):
        model = _model(
            _project("svc", scan_incomplete=True, incomplete_scanners=["semgrep"])
        )

        body = "\n".join(text_workspace_section(model))

        assert "FAILED" in body
