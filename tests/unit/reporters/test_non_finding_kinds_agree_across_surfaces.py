# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every surface agrees on a result that states no finding.

A result of kind ``pass``, ``notApplicable`` or ``informational`` states no finding
when nothing in it reports a problem: its level is ``none`` and it declares no
severity above INFO. One whose level reports a problem contradicts its kind and is
a finding. The exit code, the headline, the cards, the hotspots and the Markdown
"Showing N of M" line each read that rule, and a scan and a one-project workspace
over the same results give the same answers.

Four variants, each run for every such kind:

* A: threshold ALL; one such result at level none, and nothing else. Exit 0 and
  every figure 0.
* B: A and a HIGH failing result. Exit 2 and every actionable figure 1.
* C: threshold MEDIUM; a result of the kind at level warning. Exit 2 and every
  figure 1: a card, a hotspot, and "Showing 1 of 1".
* D: B with the note suppressed. Exit 2, actionable 1, and the suppressed figure 0
  in the headline and the scanner table: the note is no finding, so there is
  nothing for its suppression to hide.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceExitCode,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
    MarkdownReporterConfig,
    MarkdownReporterConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.inner_run_outcome import record_reports_written
from automated_security_helper.utils.sarif_utils import NON_FINDING_KINDS
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _run,
)
from tests.utils.scanner_thresholds import without_scanner_thresholds

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

# Sorted, so every pytest-xdist worker collects the same ids in the same order.
NON_FINDING = sorted(NON_FINDING_KINDS)


def _result(
    rule: str,
    kind: str | None,
    *,
    level: str,
    severity: str | None = None,
    suppressed: bool = False,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "ruleId": rule,
        "level": level,
        "message": {"text": rule},
        "properties": {"scanner_name": "bandit"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": 3},
                }
            }
        ],
    }
    if kind is not None:
        entry["kind"] = kind
    if severity:
        entry["properties"]["issue_severity"] = severity
    if suppressed:
        entry["suppressions"] = [{"kind": "external", "justification": "accepted"}]
    return entry


def _high() -> dict[str, Any]:
    return _result("R-HIGH", None, level="error", severity="HIGH")


# variant -> (threshold, results of a kind, expected exit code, expected actionable)
def _variant_a(kind):
    return "ALL", [_result("N1", kind, level="none")], 0, 0


def _variant_b(kind):
    return "ALL", [_result("N1", kind, level="none"), _high()], 2, 1


def _variant_c(kind):
    return "MEDIUM", [_result("N1", kind, level="warning")], 2, 1


def _variant_d(kind):
    note = _result("N1", kind, level="none", suppressed=True)
    return "ALL", [note, _high()], 2, 1


VARIANTS = {"A": _variant_a, "B": _variant_b, "C": _variant_c, "D": _variant_d}


def _sarif(results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "ASH"}}, "results": results}],
    }


# ---------------------------------------------------------------------------
# The single scan
# ---------------------------------------------------------------------------


def _report_model(
    results: list[dict[str, Any]], threshold: str
) -> AshAggregatedResults:
    """The scan as the reports read it: a bandit row, graded at *threshold*."""
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    without_scanner_thresholds(model)
    model.ash_config.global_settings.severity_threshold = threshold
    model.sarif = SarifReport.model_validate(_sarif(results))
    model.additional_reports["bandit"] = {
        "source": {"scanner_name": "bandit", "status": "PASSED", "duration": 1.0}
    }
    return model


def _gate_model(tmp_path, results: list[dict[str, Any]], threshold: str):
    """The same results gated at *threshold*, with the report this run wrote."""
    model = AshAggregatedResults()
    model.ash_config = AshConfig.model_validate(
        {
            "project_name": "agree",
            "global_settings": {"severity_threshold": threshold},
        }
    )
    model.sarif = SarifReport.model_validate(_sarif(results))
    record_reports_written(model, [("ash.sarif", "sarif")])
    report = tmp_path / "out" / "reports" / "ash.sarif"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(_sarif(results)), encoding="utf-8")
    return model


def _markdown(context, model) -> str:
    options = MarkdownReporterConfigOptions(
        include_findings_table=True, include_detailed_findings=True
    )
    return MarkdownReporter(
        context=context, config=MarkdownReporterConfig(options=options)
    ).report(model)


@pytest.mark.parametrize("kind", NON_FINDING)
@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_the_exit_code_of_a_single_scan(tmp_path, monkeypatch, kind, variant):
    threshold, results, expected_exit, _ = VARIANTS[variant](kind)
    monkeypatch.setattr(
        ras, "get_unified_scanner_metrics", lambda *_args, **_kwargs: []
    )
    model = _gate_model(tmp_path, results, threshold)
    opts = ras.ScanOptions(source_dir=tmp_path / "src", output_dir=tmp_path / "out")

    code = ras._compute_exit_code(model, opts, report_sarif_written_this_run=True)

    assert code == expected_exit


@pytest.mark.parametrize("kind", NON_FINDING)
@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_the_headline_actionable_figure_of_a_single_scan(kind, variant):
    threshold, results, _, actionable = VARIANTS[variant](kind)
    emitter = ReportContentEmitter(_report_model(results, threshold))

    assert emitter.get_scan_summary()["actionable"] == actionable


@pytest.mark.parametrize("kind", NON_FINDING)
@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_the_cards_of_a_single_scan(test_plugin_context, kind, variant):
    threshold, results, _, actionable = VARIANTS[variant](kind)

    document = HtmlReporter(context=test_plugin_context).report(
        _report_model(results, threshold)
    )

    assert document.count('<article class="finding-card"') == actionable


@pytest.mark.parametrize("kind", NON_FINDING)
@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_the_hotspots_of_a_single_scan(kind, variant):
    threshold, results, _, actionable = VARIANTS[variant](kind)
    emitter = ReportContentEmitter(_report_model(results, threshold))

    # One file holds every result, so one hotspot when anything is actionable.
    assert len(emitter.get_top_hotspots(10)) == actionable


@pytest.mark.parametrize("kind", NON_FINDING)
@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_the_showing_line_of_a_single_scan(test_plugin_context, kind, variant):
    threshold, results, _, actionable = VARIANTS[variant](kind)

    text = _markdown(test_plugin_context, _report_model(results, threshold))

    found = re.search(r"Showing (\d+) of (\d+) actionable findings", text)
    shown = (int(found[1]), int(found[2])) if found else (0, 0)
    assert shown == (actionable, actionable)


@pytest.mark.parametrize("kind", NON_FINDING)
def test_a_suppressed_result_that_states_no_finding_is_in_no_suppressed_figure(kind):
    """Variant D: the headline and the scanner table agree, at 0."""
    threshold, results, _, _ = VARIANTS["D"](kind)
    emitter = ReportContentEmitter(_report_model(results, threshold))

    assert emitter.get_scan_summary()["suppressed"] == 0
    assert sum(row["suppressed"] for row in emitter.get_scanner_results()) == 0


# ---------------------------------------------------------------------------
# The same results in a one-project workspace
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _workspace(tmp_path, kind: str, variant: str):
    threshold, results, expected_exit, actionable = VARIANTS[variant](kind)
    _, plan = _make_workspace(tmp_path, ("api", threshold))
    FakeOrchestrator.behaviour["api"] = {"sarif": _sarif(results)}
    outcome = _run(tmp_path, plan)
    entry = next(e for e in outcome.payload.projects if e.project == "api")
    assert entry.status is ProjectRunStatus.COMPLETED, entry.error
    return outcome, entry, expected_exit, actionable


@pytest.mark.parametrize("kind", NON_FINDING)
@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_the_project_verdict_of_a_workspace(tmp_path, kind, variant):
    _, entry, expected_exit, _ = _workspace(tmp_path, kind, variant)

    assert entry.exceeds_threshold is (expected_exit == 2)


@pytest.mark.parametrize("kind", NON_FINDING)
@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_the_exit_code_of_a_workspace(tmp_path, kind, variant):
    outcome, _, expected_exit, _ = _workspace(tmp_path, kind, variant)

    assert outcome.exit_code == (
        WorkspaceExitCode.ACTIONABLE_FINDINGS
        if expected_exit == 2
        else WorkspaceExitCode.SUCCESS
    )


@pytest.mark.parametrize("kind", NON_FINDING)
@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_the_headline_actionable_figure_of_a_workspace(tmp_path, kind, variant):
    _, _, _, actionable = _workspace(tmp_path, kind, variant)
    written = json.loads(
        (tmp_path / "out" / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    model = AshAggregatedResults.model_validate(written)

    assert ReportContentEmitter(model).get_scan_summary()["actionable"] == actionable
